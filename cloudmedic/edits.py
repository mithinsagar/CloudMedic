"""Typed edit language for configuration fixes.

Every fix, whether written by a language model, the repair engine or a benchmark operator,
is a list of edits. Edits are validated against the snapshot, so an edit that names a
resource that does not exist, or that is malformed, is rejected and counted (this is how
hallucinated fixes are measured).
"""
from __future__ import annotations

import copy
import ipaddress

from .iam import statements
from .policy import SUPPORTED_OPS, as_list

PROTOS = {"tcp", "udp", "icmp", "-1"}

OPS = {
    "sg_add_rule": "{sg, direction: ingress|egress, proto, from, to, cidr | source_sg}",
    "sg_remove_rule": "{sg, direction, proto, from, to, cidr | source_sg}",
    "nacl_add_rule": "{nacl, direction, rule, proto, from, to, cidr, action: allow|deny}",
    "nacl_remove_rule": "{nacl, direction, rule}",
    "route_add": "{route_table, dest, target}",
    "route_replace": "{route_table, dest, target}",
    "route_remove": "{route_table, dest}",
    "subnet_set_route_table": "{subnet, route_table}",
    "igw_attach": "{igw, vpc}",
    "compute_set_public_ip": "{compute}",
    "compute_set_subnet": "{compute, subnet}",
    "compute_listen": "{compute, proto, port}",
    "nat_set_subnet": "{nat, subnet}",
    "peering_accept": "{peering}",
    "phz_associate": "{zone, vpc}",
    "vpc_set_attr": "{vpc, attr: enable_dns_support|enable_dns_hostnames, value}",
    "policy_add_statement": "{target: policy id | SCP id | resource ARN | vpce id, statement}",
    "policy_remove_statement": "{target, sid}",
    "policy_replace_statement": "{target, sid, statement}",
    "role_attach_policy": "{role, policy}",
    "role_detach_policy": "{role, policy}",
    "role_set_boundary": "{role, policy | null}",
    "role_put_inline": "{role, statement}",
}


class EditError(ValueError):
    pass


def _need(cond: bool, msg: str):
    if not cond:
        raise EditError(msg)


def _get(snap, table, key):
    _need(isinstance(key, str) and key in snap.get(table, {}), f"{table[:-1] if table.endswith('s') else table} '{key}' does not exist")
    return snap[table][key]


def _cidr(v):
    try:
        ipaddress.ip_network(v, strict=False)
    except (ValueError, TypeError):
        raise EditError(f"invalid CIDR {v!r}")
    return str(v)


def _port(v):
    _need(isinstance(v, int) and 0 <= v <= 65535, f"invalid port {v!r}")
    return v


def _rule_fields(e, extra=()):
    proto = str(e.get("proto", "tcp")).lower()
    proto = "-1" if proto in ("all", "-1") else proto
    _need(proto in PROTOS, f"invalid protocol {proto}")
    if proto == "-1":
        lo, hi = 0, 65535
    else:
        lo, hi = _port(e.get("from")), _port(e.get("to", e.get("from")))
        _need(lo <= hi, "port range from > to")
    return proto, lo, hi


def _policy_doc(snap, target):
    if target in snap.get("iam", {}).get("policies", {}):
        return snap["iam"]["policies"][target]
    if target in snap.get("organizations", {}).get("scps", {}):
        return snap["organizations"]["scps"][target]
    if target in snap.get("resources", {}):
        rec = snap["resources"][target]
        if rec.get("policy") is None:
            rec["policy"] = {"Version": "2012-10-17", "Statement": []}
        return rec["policy"]
    if target in snap.get("vpc_endpoints", {}):
        ep = snap["vpc_endpoints"][target]
        if ep.get("policy") is None:
            ep["policy"] = {"Version": "2012-10-17", "Statement": []}
        return ep["policy"]
    raise EditError(f"policy target '{target}' does not exist")


def validate_statement(st) -> dict:
    _need(isinstance(st, dict), "statement must be an object")
    _need(st.get("Effect") in ("Allow", "Deny"), "statement Effect must be Allow or Deny")
    _need("Action" in st or "NotAction" in st, "statement needs Action or NotAction")
    for a in as_list(st.get("Action")) + as_list(st.get("NotAction")):
        _need(isinstance(a, str) and (a == "*" or ":" in a), f"invalid action {a!r}")
    for op in (st.get("Condition") or {}):
        base = op[:-8] if op.endswith("IfExists") else op
        _need(base in SUPPORTED_OPS, f"unsupported condition operator {op}")
    return copy.deepcopy(st)


def _ensure_sid(doc, st):
    existing = {s.get("Sid") for s in statements(doc)}
    if not st.get("Sid"):
        n = len(existing) + 1
        while f"CloudMedic{n}" in existing:
            n += 1
        st["Sid"] = f"CloudMedic{n}"
    return st


def apply_edit(snap: dict, e: dict) -> None:
    """Apply one edit in place. Raises EditError if it is invalid."""
    _need(isinstance(e, dict), "edit must be an object")
    op = e.get("op")
    _need(op in OPS, f"unknown edit op {op!r}")

    if op in ("sg_add_rule", "sg_remove_rule"):
        sg = _get(snap, "security_groups", e.get("sg"))
        d = e.get("direction")
        _need(d in ("ingress", "egress"), "direction must be ingress or egress")
        proto, lo, hi = _rule_fields(e)
        rule = {"proto": proto, "from": lo, "to": hi}
        if e.get("source_sg"):
            _get(snap, "security_groups", e["source_sg"])
            rule["sg"] = e["source_sg"]
        else:
            rule["cidr"] = _cidr(e.get("cidr"))
        if op == "sg_add_rule":
            sg.setdefault(d, []).append(rule)
        else:
            def same(r):
                return r.get("proto") == proto and r.get("from", 0) == lo and r.get("to", 65535) == hi and \
                    r.get("cidr") == rule.get("cidr") and r.get("sg") == rule.get("sg")
            before = len(sg.get(d, []))
            sg[d] = [r for r in sg.get(d, []) if not same(r)]
            _need(len(sg[d]) < before, "no matching security group rule to remove")

    elif op == "nacl_add_rule":
        nacl = _get(snap, "nacls", e.get("nacl"))
        d = e.get("direction")
        _need(d in ("ingress", "egress"), "direction must be ingress or egress")
        num = e.get("rule")
        _need(isinstance(num, int) and 1 <= num <= 32766, f"invalid NACL rule number {num!r}")
        _need(all(r["rule"] != num for r in nacl.get(d, [])), f"NACL rule {num} already exists in {d}")
        proto, lo, hi = _rule_fields(e)
        _need(e.get("action") in ("allow", "deny"), "action must be allow or deny")
        nacl.setdefault(d, []).append({"rule": num, "proto": proto, "from": lo, "to": hi,
                                       "cidr": _cidr(e.get("cidr")), "action": e["action"]})
    elif op == "nacl_remove_rule":
        nacl = _get(snap, "nacls", e.get("nacl"))
        d = e.get("direction")
        _need(d in ("ingress", "egress"), "direction must be ingress or egress")
        before = len(nacl.get(d, []))
        nacl[d] = [r for r in nacl.get(d, []) if r["rule"] != e.get("rule")]
        _need(len(nacl[d]) < before, f"NACL rule {e.get('rule')} not found")

    elif op in ("route_add", "route_replace", "route_remove"):
        rt = _get(snap, "route_tables", e.get("route_table"))
        dest = _cidr(e.get("dest"))
        idx = [i for i, r in enumerate(rt["routes"]) if r["dest"] == dest]
        if op == "route_remove":
            _need(idx, f"no route for {dest}")
            _need(rt["routes"][idx[0]]["target"] != "local", "the local route cannot be removed")
            del rt["routes"][idx[0]]
            return
        t = e.get("target")
        _need(isinstance(t, str), "route target required")
        table = {"igw-": "internet_gateways", "nat-": "nat_gateways", "pcx-": "vpc_peerings"}
        prefix = next((p for p in table if t.startswith(p)), None)
        _need(prefix is not None, f"unsupported route target {t}")
        _get(snap, table[prefix], t)
        if op == "route_add":
            _need(not idx, f"route for {dest} already exists (use route_replace)")
            rt["routes"].append({"dest": dest, "target": t})
        else:
            _need(idx, f"no route for {dest} to replace")
            rt["routes"][idx[0]]["target"] = t

    elif op == "subnet_set_route_table":
        sub = _get(snap, "subnets", e.get("subnet"))
        rt = _get(snap, "route_tables", e.get("route_table"))
        _need(rt["vpc"] == sub["vpc"], "route table belongs to another VPC")
        sub["route_table"] = e["route_table"]
    elif op == "igw_attach":
        igw = _get(snap, "internet_gateways", e.get("igw"))
        _get(snap, "vpcs", e.get("vpc"))
        _need(not any(g.get("vpc") == e["vpc"] for k, g in snap["internet_gateways"].items() if k != e["igw"]),
              "VPC already has an internet gateway")
        igw["vpc"] = e["vpc"]
    elif op == "compute_set_public_ip":
        c = _get(snap, "compute", e.get("compute"))
        _need(c.get("kind") in ("ec2", "rds"), "only EC2 instances and RDS can hold a public IP")
        c["public_ip"] = c.get("public_ip") or f"3.90.{len(snap['compute']) % 250}.{sum(map(ord, e['compute'])) % 250 + 1}"
    elif op == "compute_set_subnet":
        c = _get(snap, "compute", e.get("compute"))
        sub = _get(snap, "subnets", e.get("subnet"))
        _need(c.get("kind") == "lambda", "only Lambda functions can be moved between subnets without redeploying")
        old = c.get("subnet")
        _need(old is None or snap["subnets"][old]["vpc"] == sub["vpc"], "subnet is in a different VPC")
        net = ipaddress.ip_network(sub["cidr"])
        c["subnet"] = e["subnet"]
        c["private_ip"] = str(net.network_address + 200)
    elif op == "compute_listen":
        c = _get(snap, "compute", e.get("compute"))
        proto = str(e.get("proto", "tcp"))
        port = _port(e.get("port"))
        if not any(l["proto"] == proto and l["port"] == port for l in c.get("listening", [])):
            c.setdefault("listening", []).append({"proto": proto, "port": port})
    elif op == "nat_set_subnet":
        nat = _get(snap, "nat_gateways", e.get("nat"))
        sub = _get(snap, "subnets", e.get("subnet"))
        _need(snap["subnets"][nat["subnet"]]["vpc"] == sub["vpc"], "subnet is in a different VPC")
        nat["subnet"] = e["subnet"]
    elif op == "peering_accept":
        p = _get(snap, "vpc_peerings", e.get("peering"))
        _need(p["status"] in ("pending-acceptance", "active"), f"peering in state {p['status']} cannot be accepted")
        p["status"] = "active"
    elif op == "phz_associate":
        z = _get(snap, "private_zones", e.get("zone"))
        _get(snap, "vpcs", e.get("vpc"))
        if e["vpc"] not in z["vpcs"]:
            z["vpcs"].append(e["vpc"])
    elif op == "vpc_set_attr":
        v = _get(snap, "vpcs", e.get("vpc"))
        _need(e.get("attr") in ("enable_dns_support", "enable_dns_hostnames"), "unsupported VPC attribute")
        _need(isinstance(e.get("value"), bool), "value must be true or false")
        v[e["attr"]] = e["value"]

    elif op == "policy_add_statement":
        doc = _policy_doc(snap, e.get("target"))
        st = validate_statement(e.get("statement"))
        doc.setdefault("Statement", []).append(_ensure_sid(doc, st))
    elif op in ("policy_remove_statement", "policy_replace_statement"):
        doc = _policy_doc(snap, e.get("target"))
        sts = statements(doc)
        idx = [i for i, s in enumerate(sts) if s.get("Sid") == e.get("sid") or f"#{i}" == e.get("sid")]
        _need(idx, f"statement {e.get('sid')!r} not found in {e.get('target')}")
        if op == "policy_remove_statement":
            del sts[idx[0]]
        else:
            st = validate_statement(e.get("statement"))
            st.setdefault("Sid", sts[idx[0]].get("Sid"))
            sts[idx[0]] = st
        doc["Statement"] = sts

    elif op in ("role_attach_policy", "role_detach_policy"):
        role = _get(snap["iam"], "roles", e.get("role"))
        _get(snap["iam"], "policies", e.get("policy"))
        pols = role.setdefault("policies", [])
        if op == "role_attach_policy":
            _need(e["policy"] not in pols, "policy already attached")
            pols.append(e["policy"])
        else:
            _need(e["policy"] in pols, "policy not attached")
            pols.remove(e["policy"])
    elif op == "role_set_boundary":
        role = _get(snap["iam"], "roles", e.get("role"))
        if e.get("policy") is not None:
            _get(snap["iam"], "policies", e["policy"])
        role["boundary"] = e.get("policy")
    elif op == "role_put_inline":
        role = _get(snap["iam"], "roles", e.get("role"))
        st = validate_statement(e.get("statement"))
        pid = f"inline-{e['role']}"
        pols = snap["iam"]["policies"]
        if pid not in pols:
            pols[pid] = {"name": f"{role['name']}-inline", "kind": "inline", "Statement": []}
        if pid not in role.setdefault("policies", []):
            role["policies"].append(pid)
        pols[pid]["Statement"].append(_ensure_sid(pols[pid], st))


def apply_edits(snap: dict, edits: list) -> tuple[dict, list, list]:
    """Return (new snapshot, applied edits, [(edit, error message)]). The input is not modified."""
    out = copy.deepcopy(snap)
    applied, errors = [], []
    for e in edits or []:
        trial = copy.deepcopy(out)
        try:
            apply_edit(trial, e)
        except EditError as err:
            errors.append((e, str(err)))
            continue
        except (KeyError, TypeError, AttributeError) as err:
            errors.append((e, f"malformed edit: {err!r}"))
            continue
        out = trial
        applied.append(e)
    return out, applied, errors
