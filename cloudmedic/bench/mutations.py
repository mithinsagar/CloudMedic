"""Fault-injection (mutation) operators.

Each operator takes a healthy snapshot, one intent and that intent's healthy trace, and
returns candidate faults. A fault is the mutated snapshot plus:
  * label: {fault_class, resource, aliases}: the ground truth, set by construction
  * reference_fix: edits in the CloudMedic edit language that undo the fault
  * change: a one-line, operator-written description used for the ticket's change log
Operators read targets from the healthy trace (which security group, NACL rule or policy
statement carried the traffic), so they are template-independent.
"""
from __future__ import annotations

import copy
import random

from ..checks import PASS


def _pass(trace, cid):
    return [c for c in trace.checks if c.id == cid and c.status == PASS]


def _fault(snap, cls, resource, fix, change, aliases=(), operator=""):
    return {"snap": snap, "label": {"fault_class": cls, "resource": resource, "aliases": list(aliases)},
            "reference_fix": fix, "change": change, "operator": operator}


def _name(snap, table, key):
    return snap.get(table, {}).get(key, {}).get("name", key)


# ======================================================================= security groups

def sg_ingress_remove(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "dst_sg_ingress"):
        s = copy.deepcopy(snap)
        sg = s["security_groups"][c.ctx["sg"]]
        rule = sg["ingress"][c.ctx["rule_index"]]
        del sg["ingress"][c.ctx["rule_index"]]
        fix = [{"op": "sg_add_rule", "sg": c.ctx["sg"], "direction": "ingress", "proto": rule["proto"], "from": rule["from"],
                "to": rule["to"], **({"source_sg": rule["sg"]} if "sg" in rule else {"cidr": rule["cidr"]})}]
        out.append(_fault(s, "sg_ingress_block", c.ctx["sg"], fix,
                          f"Cleaned up inbound rules on security group {sg['name']} ({c.ctx['sg']})", operator="sg_ingress_remove"))
        if rule["proto"] != "-1":
            s2 = copy.deepcopy(snap)
            sg2 = s2["security_groups"][c.ctx["sg"]]
            wrong = rule["from"] + rng.choice([1, -1, 1000]) if rule["from"] not in (443, 80) else rng.choice([8443, 4443])
            wrong = max(1, min(65535, wrong))
            sg2["ingress"][c.ctx["rule_index"]] = {**rule, "from": wrong, "to": wrong}
            fix2 = [{"op": "sg_remove_rule", "sg": c.ctx["sg"], "direction": "ingress", "proto": rule["proto"], "from": wrong, "to": wrong,
                     **({"source_sg": rule["sg"]} if "sg" in rule else {"cidr": rule["cidr"]})}, fix[0]]
            out.append(_fault(s2, "sg_ingress_block", c.ctx["sg"], fix2,
                              f"Updated the port on an inbound rule of {sg2['name']} ({c.ctx['sg']})", operator="sg_ingress_wrong_port"))
    return out


def sg_egress_restrict(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "src_sg_egress"):
        s = copy.deepcopy(snap)
        sg = s["security_groups"][c.ctx["sg"]]
        rule = sg["egress"][c.ctx["rule_index"]]
        keep = 443 if c.ctx["port"] != 443 else 80
        sg["egress"][c.ctx["rule_index"]] = {"proto": "tcp", "from": keep, "to": keep, "cidr": "0.0.0.0/0"}
        fix = [{"op": "sg_remove_rule", "sg": c.ctx["sg"], "direction": "egress", "proto": "tcp", "from": keep, "to": keep, "cidr": "0.0.0.0/0"},
               {"op": "sg_add_rule", "sg": c.ctx["sg"], "direction": "egress", "proto": rule["proto"], "from": rule["from"], "to": rule["to"],
                **({"source_sg": rule["sg"]} if "sg" in rule else {"cidr": rule["cidr"]})}]
        out.append(_fault(s, "sg_egress_block", c.ctx["sg"], fix,
                          f"Hardened outbound rules on {sg['name']} ({c.ctx['sg']}) to only allow tcp/{keep}", operator="sg_egress_restrict"))
    return out


# ======================================================================= NACLs

REQUEST_NACL_CHECKS = {"src_nacl_egress": "nacl_egress_block", "dst_nacl_ingress": "nacl_ingress_block",
                       "nat_nacl_ingress": "nacl_ingress_block", "nat_nacl_egress": "nacl_egress_block"}


def _free_rule_below(nacl, direction, below):
    used = {r["rule"] for r in nacl[direction]}
    for n in range(below - 1, 0, -1):
        if n not in used and n % 5 == 0 or (n not in used and n < 5):
            return n
    return None


def nacl_request_deny(snap, intent, trace, rng):
    out = []
    for cid, cls in REQUEST_NACL_CHECKS.items():
        for c in _pass(trace, cid):
            s = copy.deepcopy(snap)
            nacl = s["nacls"][c.resource]
            d = c.ctx["direction"]
            num = _free_rule_below(nacl, d, c.ctx["rule"])
            if num is None:
                continue
            cidr = c.ctx["peer_ip"] + "/32" if rng.random() < 0.5 else "0.0.0.0/0"
            nacl[d].append({"rule": num, "proto": "tcp", "from": c.ctx["lo"], "to": c.ctx["hi"], "cidr": cidr, "action": "deny"})
            fix = [{"op": "nacl_remove_rule", "nacl": c.resource, "direction": d, "rule": num}]
            out.append(_fault(s, cls, c.resource, fix,
                              f"Added a deny rule {num} to network ACL {nacl['name']} ({c.resource})", operator="nacl_request_deny"))
            rule = next(r for r in snap["nacls"][c.resource][d] if r["rule"] == c.ctx["rule"])
            if rule["proto"] != "-1":
                s2 = copy.deepcopy(snap)
                s2["nacls"][c.resource][d] = [r for r in s2["nacls"][c.resource][d] if r["rule"] != rule["rule"]]
                fix2 = [{"op": "nacl_add_rule", "nacl": c.resource, "direction": d, **{k: rule[k] for k in ("rule", "proto", "from", "to", "cidr", "action")}}]
                out.append(_fault(s2, cls, c.resource, fix2,
                                  f"Removed rule {rule['rule']} from network ACL {s2['nacls'][c.resource]['name']} ({c.resource})",
                                  operator="nacl_request_remove"))
    return out


RETURN_CHECKS = ("return_dst_nacl_egress", "return_src_nacl_ingress", "return_nat_nacl_ingress", "return_nat_nacl_egress")


def nacl_return_break(snap, intent, trace, rng):
    from ..network import nacl_decision
    out = []
    for cid in RETURN_CHECKS:
        for c in _pass(trace, cid):
            nacl0 = snap["nacls"][c.resource]
            d, lo, hi = c.ctx["direction"], c.ctx["lo"], c.ctx["hi"]
            _, rule = nacl_decision(nacl0, d, "tcp", lo, c.ctx["peer_ip"])
            if rule is None:
                continue
            s = copy.deepcopy(snap)
            nacl = s["nacls"][c.resource]
            if rule["proto"] != "-1" and rule["from"] <= 1024 and rule["to"] >= 65535 and rng.random() < 0.6:
                # narrow the ephemeral rule to the "Windows" range: intermittent or total failure depending on client OS
                new_lo = rng.choice([32768, 49152])
                for r in nacl[d]:
                    if r["rule"] == rule["rule"]:
                        r["from"] = new_lo
                fix = [{"op": "nacl_remove_rule", "nacl": c.resource, "direction": d, "rule": rule["rule"]},
                       {"op": "nacl_add_rule", "nacl": c.resource, "direction": d, **{k: rule[k] for k in ("rule", "proto", "from", "to", "cidr", "action")}}]
                change = f"Tightened the ephemeral port range of rule {rule['rule']} on network ACL {nacl['name']} ({c.resource}) to {new_lo}-{rule['to']}"
                op = "nacl_ephemeral_narrow"
            else:
                num = _free_rule_below(nacl, d, rule["rule"])
                if num is None:
                    continue
                lo_deny, hi_deny = 1024, rng.choice([32767, 49151, 65535])
                if lo_deny <= intent["port"] <= hi_deny:  # keep the fault on the return path only
                    lo_deny = intent["port"] + 1
                if lo_deny > min(hi_deny, hi) or hi_deny < lo:
                    continue
                nacl[d].append({"rule": num, "proto": "tcp", "from": lo_deny, "to": hi_deny, "cidr": "0.0.0.0/0", "action": "deny"})
                fix = [{"op": "nacl_remove_rule", "nacl": c.resource, "direction": d, "rule": num}]
                change = f"Added deny rule {num} for high ports to network ACL {nacl['name']} ({c.resource}) as part of a security review"
                op = "nacl_ephemeral_deny"
            out.append(_fault(s, "nacl_return_block", c.resource, fix, change, operator=op))
    return out


# ======================================================================= routing and addressing

def route_internet_remove(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "route") + _pass(trace, "dst_igw_route"):
        t = c.ctx.get("target")
        if not t or not t.startswith(("igw-", "nat-")):
            continue
        s = copy.deepcopy(snap)
        rt = s["route_tables"][c.ctx["rt"]]
        rt["routes"] = [r for r in rt["routes"] if r["dest"] != c.ctx["dest"]]
        fix = [{"op": "route_add", "route_table": c.ctx["rt"], "dest": c.ctx["dest"], "target": t}]
        out.append(_fault(s, "route_missing_internet", c.ctx["rt"], fix,
                          f"Removed the default route from route table {rt['name']} ({c.ctx['rt']})", operator="route_internet_remove"))
    return out


def igw_detach(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "igw_attached"):
        s = copy.deepcopy(snap)
        vpc = s["internet_gateways"][c.resource]["vpc"]
        s["internet_gateways"][c.resource]["vpc"] = None
        fix = [{"op": "igw_attach", "igw": c.resource, "vpc": vpc}]
        out.append(_fault(s, "igw_detached", c.resource, fix,
                          f"Internet gateway {c.resource} was detached during a VPC migration", aliases=[vpc], operator="igw_detach"))
        break
    return out


def public_ip_remove(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "src_public_ip") + _pass(trace, "dst_public_ip"):
        s = copy.deepcopy(snap)
        comp = s["compute"][c.resource]
        old = comp["public_ip"]
        comp["public_ip"] = None
        fix = [{"op": "compute_set_public_ip", "compute": c.resource}]
        out.append(_fault(s, "no_public_ip", c.resource, fix,
                          f"Instance {comp['name']} ({c.resource}) was stopped/started and lost its auto-assigned public IP {old}",
                          operator="public_ip_remove"))
    return out


def lambda_to_public_subnet(snap, intent, trace, rng):
    src = intent.get("src")
    comp = snap["compute"].get(src)
    if not comp or comp["kind"] != "lambda" or not comp.get("subnet") or not _pass(trace, "route"):
        return []
    if not str(_pass(trace, "route")[0].ctx.get("target", "")).startswith("nat-"):
        return []
    vpc = snap["subnets"][comp["subnet"]]["vpc"]
    pubs = [k for k, sub in snap["subnets"].items() if sub["vpc"] == vpc and any(
        str(r["target"]).startswith("igw-") for r in snap["route_tables"][sub["route_table"]]["routes"])]
    if not pubs:
        return []
    s = copy.deepcopy(snap)
    from ..edits import apply_edit
    apply_edit(s, {"op": "compute_set_subnet", "compute": src, "subnet": pubs[0]})
    fix = [{"op": "compute_set_subnet", "compute": src, "subnet": comp["subnet"]}]
    return [_fault(s, "lambda_public_subnet", src, fix,
                   f"Moved Lambda {comp['name']} to subnet {_name(snap, 'subnets', pubs[0])} so it would 'have internet access'",
                   operator="lambda_to_public_subnet")]


def nat_to_private(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "route"):
        t = c.ctx.get("target", "")
        if not str(t).startswith("nat-"):
            continue
        nat = snap["nat_gateways"][t]
        vpc = snap["subnets"][nat["subnet"]]["vpc"]
        privs = [k for k, sub in snap["subnets"].items() if sub["vpc"] == vpc and k != nat["subnet"] and not any(
            str(r["target"]).startswith("igw-") for r in snap["route_tables"][sub["route_table"]]["routes"])]
        if not privs:
            continue
        s = copy.deepcopy(snap)
        s["nat_gateways"][t]["subnet"] = privs[0]
        fix = [{"op": "nat_set_subnet", "nat": t, "subnet": nat["subnet"]}]
        out.append(_fault(s, "nat_misplaced", t, fix,
                          f"Recreated NAT gateway {t} in subnet {_name(snap, 'subnets', privs[0])} with Terraform", operator="nat_to_private"))
    return out


def peering_route_remove(snap, intent, trace, rng):
    out = []
    for cid in ("route", "return_route"):
        for c in _pass(trace, cid):
            if "pcx" not in c.ctx or not c.ctx.get("pcx"):
                continue
            s = copy.deepcopy(snap)
            rt = s["route_tables"][c.resource]
            rt["routes"] = [r for r in rt["routes"] if r["dest"] != c.ctx["dest"]]
            fix = [{"op": "route_add", "route_table": c.resource, "dest": c.ctx["dest"], "target": c.ctx["pcx"]}]
            side = "requester" if cid == "route" else "accepter (return) side"
            out.append(_fault(s, "peering_route_missing", c.resource, fix,
                              f"Route table {rt['name']} ({c.resource}) on the {side} was rebuilt from a template",
                              operator="peering_route_remove"))
    return out


def peering_pending(snap, intent, trace, rng):
    for c in _pass(trace, "peering_status"):
        s = copy.deepcopy(snap)
        s["vpc_peerings"][c.resource]["status"] = "pending-acceptance"
        return [_fault(s, "peering_not_active", c.resource, [{"op": "peering_accept", "peering": c.resource}],
                       f"Peering connection {c.resource} was recreated by a new CloudFormation stack", operator="peering_pending")]
    return []


# ======================================================================= DNS and host

def phz_disassociate(snap, intent, trace, rng):
    for c in _pass(trace, "dns_resolution"):
        if not c.resource or c.resource not in snap.get("private_zones", {}):
            continue
        src = snap["compute"].get(intent["src"])
        vpc = snap["subnets"][src["subnet"]]["vpc"]
        s = copy.deepcopy(snap)
        s["private_zones"][c.resource]["vpcs"].remove(vpc)
        return [_fault(s, "dns_phz_not_associated", c.resource, [{"op": "phz_associate", "zone": c.resource, "vpc": vpc}],
                       f"Private hosted zone {snap['private_zones'][c.resource]['name']} was recreated in a new stack",
                       aliases=[vpc], operator="phz_disassociate")]
    return []


def dns_support_off(snap, intent, trace, rng):
    for c in _pass(trace, "dns_resolution"):
        src = snap["compute"].get(intent["src"])
        if not src or not src.get("subnet"):
            continue
        vpc = snap["subnets"][src["subnet"]]["vpc"]
        s = copy.deepcopy(snap)
        s["vpcs"][vpc]["enable_dns_support"] = False
        return [_fault(s, "dns_support_disabled", vpc, [{"op": "vpc_set_attr", "vpc": vpc, "attr": "enable_dns_support", "value": True}],
                       f"VPC {snap['vpcs'][vpc]['name']} settings were changed by a compliance automation", operator="dns_support_off")]
    return []


def service_down(snap, intent, trace, rng):
    for c in _pass(trace, "dst_listening"):
        if c.resource not in snap.get("compute", {}):
            continue
        s = copy.deepcopy(snap)
        port = intent["port"]
        s["compute"][c.resource]["listening"] = [l for l in s["compute"][c.resource]["listening"] if l["port"] != port]
        return [_fault(s, "service_not_listening", c.resource, [{"op": "compute_listen", "compute": c.resource, "proto": "tcp", "port": port}],
                       f"Application on {snap['compute'][c.resource]['name']} was redeployed", operator="service_down")]
    return []


# ======================================================================= IAM

def _stmt(snap, target, sid):
    from ..edits import _policy_doc
    doc = _policy_doc(copy.deepcopy(snap), target)
    for i, st in enumerate(doc.get("Statement", [])):
        if st.get("Sid") == sid or f"#{i}" == sid:
            return i, st
    return None, None


def _doc(s, target):
    from ..edits import _policy_doc
    return _policy_doc(s, target)


def iam_remove_action(snap, intent, trace, rng):
    out = []
    for cid in ("identity_allow", "kms_identity"):
        for c in _pass(trace, cid):
            for pid, sid in c.ctx.get("allowed_by", [])[:1]:
                i, st = _stmt(snap, pid, sid)
                action = c.ctx["action"]
                acts = st.get("Action") if isinstance(st.get("Action"), list) else [st.get("Action")]
                s = copy.deepcopy(snap)
                doc = _doc(s, pid)
                remaining = [a for a in acts if a.lower() != action.lower()]
                if remaining and remaining != acts:
                    doc["Statement"][i] = {**st, "Action": remaining}
                    fix = [{"op": "policy_replace_statement", "target": pid, "sid": st["Sid"], "statement": st}]
                elif remaining == acts:
                    continue  # granted through a wildcard; handled by resource/condition operators
                else:
                    del doc["Statement"][i]
                    fix = [{"op": "policy_add_statement", "target": pid, "statement": st}]
                out.append(_fault(s, "iam_action_missing", intent["principal"], fix,
                                  f"Policy {snap['iam']['policies'][pid]['name']} ({pid}) was rewritten to follow least privilege",
                                  aliases=[pid], operator="iam_remove_action"))
    return out


def iam_resource_typo(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "identity_allow"):
        for pid, sid in c.ctx.get("allowed_by", [])[:1]:
            i, st = _stmt(snap, pid, sid)
            res = st.get("Resource")
            res_l = res if isinstance(res, list) else [res]
            hit = next((r for r in res_l if r != "*" and __import__("cloudmedic.policy", fromlist=["wild_match"]).wild_match(r, intent["resource"])), None)
            if hit is None:
                continue
            if hit.endswith("/*"):
                bad = hit[:-2]  # bucket ARN instead of object ARN: classic
            elif ":table/" in hit or ":secret:" in hit or ":sqs:" in hit or ":log-group:" in hit:
                bad = hit.replace(snap["region"], "us-west-2") if snap["region"] in hit else hit + "-old"
            else:
                bad = hit + "-v2"
            s = copy.deepcopy(snap)
            _doc(s, pid)["Statement"][i] = {**st, "Resource": [bad if r == hit else r for r in res_l]}
            fix = [{"op": "policy_replace_statement", "target": pid, "sid": st["Sid"], "statement": st}]
            out.append(_fault(s, "iam_resource_mismatch", intent["principal"], fix,
                              f"Policy {snap['iam']['policies'][pid]['name']} ({pid}) was refactored by a teammate",
                              aliases=[pid], operator="iam_resource_typo"))
    return out


def iam_condition_break(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "identity_allow"):
        for pid, sid in c.ctx.get("allowed_by", [])[:1]:
            i, st = _stmt(snap, pid, sid)
            cond = copy.deepcopy(st.get("Condition") or {})
            if "IpAddress" in cond and "aws:SourceIp" in cond["IpAddress"]:
                cond["IpAddress"]["aws:SourceIp"] = rng.choice(["198.18.0.0/24", "203.0.114.0/24", "10.0.0.0/8"])
                why = "the office CIDR in the policy was updated after a network change"
            elif rng.random() < 0.5:
                cond["StringEquals"] = {"aws:RequestedRegion": rng.choice(["eu-west-1", "ap-south-1", "us-west-2"])}
                why = "a region restriction was added to the policy"
            else:
                cond["StringEquals"] = {"aws:PrincipalTag/team": rng.choice(["data-eng", "platform", "payments"])}
                why = "an ABAC tag condition was added to the policy"
            s = copy.deepcopy(snap)
            _doc(s, pid)["Statement"][i] = {**st, "Condition": cond}
            fix = [{"op": "policy_replace_statement", "target": pid, "sid": st["Sid"], "statement": st}]
            out.append(_fault(s, "iam_condition_mismatch", intent["principal"], fix,
                              f"Policy {snap['iam']['policies'][pid]['name']} ({pid}): {why}", aliases=[pid], operator="iam_condition_break"))
    return out


def iam_detach(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "identity_allow"):
        for pid, sid in c.ctx.get("allowed_by", [])[:1]:
            if snap["iam"]["policies"][pid].get("kind") == "inline":
                continue
            s = copy.deepcopy(snap)
            s["iam"]["roles"][intent["principal"]]["policies"].remove(pid)
            out.append(_fault(s, "iam_policy_not_attached", intent["principal"],
                              [{"op": "role_attach_policy", "role": intent["principal"], "policy": pid}],
                              f"Role {snap['iam']['roles'][intent['principal']]['name']} was recreated by a new deployment pipeline",
                              aliases=[pid], operator="iam_detach"))
    return out


def iam_explicit_deny(snap, intent, trace, rng):
    role = snap["iam"]["roles"][intent["principal"]]
    if not role.get("policies"):
        return []
    pid = role["policies"][0]
    service = intent["action"].split(":")[0]
    res = intent["resource"]
    pattern = res.rsplit("/", 1)[0] + "/*" if "/" in res and res.startswith("arn:aws:s3") else res
    deny = {"Sid": "DenyProdData", "Effect": "Deny", "Action": rng.choice([f"{service}:*", intent["action"]]), "Resource": pattern}
    s = copy.deepcopy(snap)
    _doc(s, pid)["Statement"].append(deny)
    return [_fault(s, "iam_explicit_deny", pid, [{"op": "policy_remove_statement", "target": pid, "sid": "DenyProdData"}],
                   f"A deny statement was added to {snap['iam']['policies'][pid]['name']} ({pid}) during an access review",
                   aliases=[intent["principal"]], operator="iam_explicit_deny")]


def boundary_restrict(snap, intent, trace, rng):
    role = snap["iam"]["roles"][intent["principal"]]
    service = intent["action"].split(":")[0]
    s = copy.deepcopy(snap)
    if role.get("boundary"):
        pid = role["boundary"]
        doc = _doc(s, pid)
        changed = False
        for i, st in enumerate(doc["Statement"]):
            if st.get("Effect") == "Allow":
                acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                new = [a for a in acts if not (a.lower().startswith(service + ":") or a == "*")]
                if new != acts:
                    fix = [{"op": "policy_replace_statement", "target": pid, "sid": st["Sid"], "statement": copy.deepcopy(st)}]
                    doc["Statement"][i] = {**st, "Action": new or ["logs:*"]}
                    changed = True
                    break
        if not changed:
            return []
        return [_fault(s, "iam_boundary_block", pid, fix, f"Permissions boundary {snap['iam']['policies'][pid]['name']} was trimmed",
                       aliases=[intent["principal"]], operator="boundary_restrict")]
    pid = "pol-standard-boundary"
    s["iam"]["policies"][pid] = {"name": "StandardWorkloadBoundary", "kind": "boundary", "Statement": [
        {"Sid": "Allowed", "Effect": "Allow", "Action": ["logs:*", "cloudwatch:*", "xray:*", "ssm:GetParameter*"], "Resource": "*"}]}
    s["iam"]["roles"][intent["principal"]]["boundary"] = pid
    return [_fault(s, "iam_boundary_block", pid, [{"op": "role_set_boundary", "role": intent["principal"], "policy": None}],
                   f"A standard permissions boundary was attached to role {role['name']} by the platform team",
                   aliases=[intent["principal"]], operator="boundary_attach")]


def scp_deny(snap, intent, trace, rng):
    acct = snap["iam"]["roles"][intent["principal"]].get("account", snap["account_id"])
    scps = snap.get("organizations", {}).get("accounts", {}).get(acct, [])
    if "p-guardrails" not in scps:
        return []
    s = copy.deepcopy(snap)
    doc = s["organizations"]["scps"]["p-guardrails"]
    st_i = next(i for i, st in enumerate(doc["Statement"]) if st.get("Sid") == "RegionLock")
    old = copy.deepcopy(doc["Statement"][st_i])
    if rng.random() < 0.5:
        doc["Statement"][st_i]["Condition"] = {"StringNotEquals": {"aws:RequestedRegion": [rng.choice(["eu-west-1", "eu-central-1", "us-west-2"])]}}
        fix = [{"op": "policy_replace_statement", "target": "p-guardrails", "sid": "RegionLock", "statement": old}]
        change = "The organisation's region-lock SCP was updated for data residency"
    else:
        service = intent["action"].split(":")[0]
        doc["Statement"].append({"Sid": "DenyUnapprovedServices", "Effect": "Deny", "Action": f"{service}:*", "Resource": "*"})
        fix = [{"op": "policy_remove_statement", "target": "p-guardrails", "sid": "DenyUnapprovedServices"}]
        change = "Security added a service deny-list to the organisation guardrail SCP"
    return [_fault(s, "scp_block", "p-guardrails", fix, change, operator="scp_deny")]


def resource_policy_deny(snap, intent, trace, rng):
    from ..iam import resource_record
    rkey, rec = resource_record(snap, intent["resource"])
    if not rec:
        return []
    s = copy.deepcopy(snap)
    _, rec2 = resource_record(s, intent["resource"])
    pol = rec2.get("policy")
    vpce_deny = pol and next((i for i, st in enumerate(pol["Statement"]) if "aws:SourceVpce" in str(st.get("Condition"))), None)
    if vpce_deny is not None:
        old = copy.deepcopy(pol["Statement"][vpce_deny])
        pol["Statement"][vpce_deny]["Condition"] = {"StringNotEquals": {"aws:SourceVpce": "vpce-0" + "%016x" % rng.getrandbits(64)}}
        fix = [{"op": "policy_replace_statement", "target": rkey, "sid": old["Sid"], "statement": old}]
        change = f"The bucket policy on {rec['name']} was copied from the staging account"
    else:
        arn = __import__("cloudmedic.iam", fromlist=["role_arn"]).role_arn(snap, intent["principal"])
        if pol is None:
            rec2["policy"] = pol = {"Version": "2012-10-17", "Statement": []}
        pol["Statement"].append({"Sid": "DenyUntaggedPrincipals", "Effect": "Deny", "Principal": "*", "Action": intent["action"],
                                 "Resource": intent["resource"] if "/" not in intent["resource"] or not rkey.startswith("arn:aws:s3") else rkey + "/*",
                                 "Condition": {"StringNotEquals": {"aws:PrincipalTag/data-access": "approved"}}})
        fix = [{"op": "policy_remove_statement", "target": rkey, "sid": "DenyUntaggedPrincipals"}]
        change = f"A tag-based guard was added to the resource policy of {rec['name']}"
    return [_fault(s, "resource_policy_deny", rkey, fix, change, operator="resource_policy_deny")]


def cross_account_grant_remove(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "resource_allow"):
        for target, sid in c.ctx.get("allowed_by", [])[:1]:
            i, st = _stmt(snap, target, sid)
            s = copy.deepcopy(snap)
            del _doc(s, target)["Statement"][i]
            out.append(_fault(s, "cross_account_resource_policy_missing", target,
                              [{"op": "policy_add_statement", "target": target, "statement": st}],
                              "The bucket policy was overwritten when encryption settings were changed", operator="cross_account_grant_remove"))
    return out


def kms_key_policy_break(snap, intent, trace, rng):
    out = []
    for c in _pass(trace, "kms_key_policy"):
        key = c.resource
        s = copy.deepcopy(snap)
        doc = _doc(s, key)
        removed = [st for st in doc["Statement"] if st.get("Sid") in c.ctx.get("granting", [])]
        doc["Statement"] = [st for st in doc["Statement"] if st.get("Sid") not in c.ctx.get("granting", [])]
        doc["Statement"].append({"Sid": "KeyAdministrators", "Effect": "Allow",
                                 "Principal": {"AWS": f"arn:aws:iam::{snap['resources'][key]['account']}:role/kms-admins"},
                                 "Action": ["kms:Create*", "kms:Describe*", "kms:Put*", "kms:ScheduleKeyDeletion"], "Resource": "*"})
        fix = [{"op": "policy_remove_statement", "target": key, "sid": "KeyAdministrators"}] + \
              [{"op": "policy_add_statement", "target": key, "statement": st} for st in removed]
        out.append(_fault(s, "kms_key_policy_block", key, fix,
                          f"The key policy of {snap['resources'][key]['name']} was replaced with the security team's template",
                          operator="kms_key_policy_break"))
    return out


def endpoint_policy_break(snap, intent, trace, rng):
    for c in _pass(trace, "endpoint_allow"):
        s = copy.deepcopy(snap)
        doc = s["vpc_endpoints"][c.resource]["policy"]
        old = copy.deepcopy(doc["Statement"][0])
        other = "arn:aws:s3:::shared-artifacts-" + "%06x" % rng.getrandbits(24)
        doc["Statement"][0] = {**old, "Resource": [other, other + "/*"]}
        return [_fault(s, "endpoint_policy_block", c.resource,
                       [{"op": "policy_replace_statement", "target": c.resource, "sid": old["Sid"], "statement": old}],
                       f"The S3 gateway endpoint policy on {c.resource} was scoped down to the artifacts bucket", operator="endpoint_policy_break")]
    return []


NETWORK_OPERATORS = [sg_ingress_remove, sg_egress_restrict, nacl_request_deny, nacl_return_break, route_internet_remove,
                     igw_detach, public_ip_remove, lambda_to_public_subnet, nat_to_private, peering_route_remove,
                     peering_pending, phz_disassociate, dns_support_off, service_down]
IAM_OPERATORS = [iam_remove_action, iam_resource_typo, iam_condition_break, iam_detach, iam_explicit_deny, boundary_restrict,
                 scp_deny, resource_policy_deny, cross_account_grant_remove, kms_key_policy_break, endpoint_policy_break]


OPERATORS = {op.__name__: op for op in NETWORK_OPERATORS + IAM_OPERATORS}


def candidate_faults(snap, intent, trace, rng):
    """All faults every applicable operator can inject; each remembers how to be re-derived."""
    ops = NETWORK_OPERATORS if intent["kind"] == "network" else IAM_OPERATORS
    out = []
    for op in ops:
        seed = rng.random()
        for idx, f in enumerate(op(snap, intent, trace, random.Random(seed))):
            f["recipe"] = {"fn": op.__name__, "seed": seed, "index": idx}
            out.append(f)
    return out


def replay(recipe, snap, intent, trace):
    """Re-apply a fault (identified by its recipe) on top of another snapshot, for composing faults."""
    faults = OPERATORS[recipe["fn"]](snap, intent, trace, random.Random(recipe["seed"]))
    return faults[recipe["index"]] if recipe["index"] < len(faults) else None
