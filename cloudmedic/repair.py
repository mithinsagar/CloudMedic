"""Least-privilege repair: counterexample-guided MaxSMT over candidate edits.

1. Evaluate the intent; every failing check is an obligation to discharge.
2. For each failing check, generate candidate edits at several breadths (exact /32 or exact
   ARN, subnet or prefix, service-wide or 0.0.0.0/0, remove-the-guardrail).
3. Measure each candidate in isolation: privilege gained and access lost against the broken
   snapshot over the frozen universe.
4. Z3 Optimize picks the minimum-cost set of candidates that covers every obligation, with
   mutual-exclusion constraints for edits that cannot coexist.
5. Apply the chosen set and re-verify concretely. If the intent still fails, the new failing
   checks become obligations (faults masked by earlier ones surface here); if the combined
   set fails or causes collateral loss, block that combination and re-solve.
The cost of a candidate is  W_EDIT + W_GAIN*gained + W_EXPOSE*internet_exposure
+ W_SENSITIVE*sensitive_iam + W_LOST*lost, so a privilege-widening fix is only chosen when
nothing narrower discharges the obligation.
"""
from __future__ import annotations

import ipaddress
import random
import time
from dataclasses import dataclass, field

import z3

from .edits import apply_edits
from .expansion import expansion, fixed_universe, intent_keys, surface
from .iam import resource_record, statements
from .intents import evaluate_intent

W_EDIT, W_GAIN, W_EXPOSE, W_SENSITIVE, W_LOST = 10, 20, 60, 60, 400


@dataclass
class Candidate:
    edits: list
    covers: set
    label: str
    slot: str | None = None
    rank: int = 0  # generation order: narrowest first, used to break cost ties
    cost: int = 0
    stats: dict = field(default_factory=dict)


@dataclass
class RepairResult:
    edits: list
    verified: bool
    iterations: int
    candidates: int
    stats: dict
    seconds: float
    log: list


def check_key(c) -> tuple:
    return (c.id, c.resource, c.fault_class)


# ------------------------------------------------------------------ helpers

def _subnet_of_ip(snap, ip):
    for sid, s in snap["subnets"].items():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(s["cidr"]):
            return sid, s
    return None, None


def _free_rule(nacl, direction, below=None):
    used = {r["rule"] for r in nacl.get(direction, [])}
    if below:
        for n in range(below - 1, 0, -1):
            if n not in used:
                return n
        return None
    n = (max(used) if used else 0) + 10
    while n in used:
        n += 1
    return n if n <= 32766 else None


def _vpc_of(snap, ref):
    c = snap.get("compute", {}).get(ref)
    if c and c.get("subnet"):
        return snap["subnets"][c["subnet"]]["vpc"]
    return None


def _prefix(resource):
    if resource.startswith("arn:aws:s3:::") and "/" in resource:
        return resource.rsplit("/", 1)[0] + "/*"
    return None


def _merge_condition(cond, op, key, value):
    cond = {k: dict(v) for k, v in (cond or {}).items()}
    block = cond.setdefault(op, {})
    cur = block.get(key)
    vals = cur if isinstance(cur, list) else ([cur] if cur else [])
    block[key] = vals + [value] if vals else value
    return cond


# ------------------------------------------------------------------ candidate generation

def candidates_for(snap: dict, chk) -> list[Candidate]:
    k = {check_key(chk)}
    cls, ctx, res = chk.fault_class, chk.ctx, chk.resource
    out: list[Candidate] = []

    def add(edits, label, slot=None):
        out.append(Candidate(edits, set(k), label, slot, rank=len(out)))

    if cls in ("sg_ingress_block", "sg_egress_block"):
        sg = (ctx.get("sgs") or [None])[0]
        if not sg:
            return out
        d, proto, port, peer_ip = ctx["direction"], ctx["proto"], ctx["port"], ctx["peer_ip"]
        base = {"op": "sg_add_rule", "sg": sg, "direction": d, "proto": proto, "from": port, "to": port}
        same_vpc = _vpc_of(snap, ctx.get("peer")) == snap["security_groups"][sg]["vpc"]
        if ctx.get("peer_sgs") and same_vpc:
            add([{**base, "source_sg": ctx["peer_sgs"][0]}], "sg: exact port from peer security group")
        add([{**base, "cidr": f"{peer_ip}/32"}], "sg: exact port from peer /32")
        sid, sub = _subnet_of_ip(snap, peer_ip)
        if sub:
            add([{**base, "cidr": sub["cidr"]}], "sg: exact port from peer subnet")
        add([{**base, "cidr": "0.0.0.0/0"}], "sg: exact port from anywhere")
        add([{**base, "proto": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}], "sg: all traffic from anywhere")

    elif cls in ("nacl_ingress_block", "nacl_egress_block", "nacl_return_block"):
        nacl = snap["nacls"].get(res)
        if nacl is None:
            return out
        d, lo, hi, peer_ip = ctx["direction"], ctx["lo"], ctx["hi"], ctx["peer_ip"]
        deny = ctx.get("deny_rule")
        num = _free_rule(nacl, d, below=deny) if deny else _free_rule(nacl, d)
        slot = f"nacl:{res}:{d}:{num}"
        if num:
            def rule(cidr, lo_=lo, hi_=hi):
                return {"op": "nacl_add_rule", "nacl": res, "direction": d, "rule": num, "proto": ctx["proto"],
                        "from": lo_, "to": hi_, "cidr": cidr, "action": "allow"}
            add([rule(f"{peer_ip}/32")], "nacl: allow exact ports for peer /32", slot)
            _, sub = _subnet_of_ip(snap, peer_ip)
            if sub:
                add([rule(sub["cidr"])], "nacl: allow exact ports for peer subnet", slot)
            if cls == "nacl_return_block":
                add([rule("0.0.0.0/0", 1024, 65535)], "nacl: allow 1024-65535 from anywhere", slot)
            else:
                add([rule("0.0.0.0/0")], "nacl: allow exact ports from anywhere", slot)
            add([{"op": "nacl_add_rule", "nacl": res, "direction": d, "rule": num, "proto": "-1", "from": 0, "to": 65535,
                  "cidr": "0.0.0.0/0", "action": "allow"}], "nacl: allow all traffic", slot)
        if deny:
            add([{"op": "nacl_remove_rule", "nacl": res, "direction": d, "rule": deny}], "nacl: delete the blocking deny rule",
                f"nacl-rm:{res}:{d}:{deny}")

    elif cls == "route_missing_internet":
        rt = snap["route_tables"].get(res)
        if rt is None:
            return out
        vpc = rt["vpc"]
        has_default = any(r["dest"] == "0.0.0.0/0" for r in rt["routes"])
        op = "route_replace" if has_default else "route_add"
        slot = f"route:{res}:0.0.0.0/0"
        if chk.id != "dst_igw_route":
            for nid, n in snap["nat_gateways"].items():
                if snap["subnets"].get(n["subnet"], {}).get("vpc") == vpc and snap["subnets"][n["subnet"]]["route_table"] != res:
                    add([{"op": op, "route_table": res, "dest": "0.0.0.0/0", "target": nid}], "route: default via NAT gateway", slot)
        for gid, g in snap["internet_gateways"].items():
            if g.get("vpc") == vpc or g.get("vpc") is None:
                edits = [{"op": op, "route_table": res, "dest": "0.0.0.0/0", "target": gid}]
                if g.get("vpc") is None:
                    edits = [{"op": "igw_attach", "igw": gid, "vpc": vpc}] + edits
                add(edits, "route: default via internet gateway", slot)

    elif cls == "igw_detached":
        vpc = ctx.get("vpc")
        igws = [res] if res else [g for g, x in snap["internet_gateways"].items() if not x.get("vpc")]
        for g in igws:
            add([{"op": "igw_attach", "igw": g, "vpc": vpc}], "igw: re-attach internet gateway", f"igw:{vpc}")

    elif cls == "no_public_ip":
        add([{"op": "compute_set_public_ip", "compute": res}], "addressing: assign an Elastic IP")
        if chk.id == "src_public_ip":
            sub = snap["subnets"][snap["compute"][res]["subnet"]]
            for nid, n in snap["nat_gateways"].items():
                if snap["subnets"][n["subnet"]]["vpc"] == sub["vpc"] and n["subnet"] != snap["compute"][res]["subnet"]:
                    add([{"op": "route_replace", "route_table": sub["route_table"], "dest": "0.0.0.0/0", "target": nid}],
                        "route: send the subnet's internet traffic through NAT", f"route:{sub['route_table']}:0.0.0.0/0")

    elif cls == "lambda_public_subnet":
        vpc = _vpc_of(snap, res)
        for sid, s in snap["subnets"].items():
            if s["vpc"] != vpc:
                continue
            if any(str(r["target"]).startswith("nat-") for r in snap["route_tables"][s["route_table"]]["routes"]):
                add([{"op": "compute_set_subnet", "compute": res, "subnet": sid}], "lambda: move to a private subnet with NAT",
                    f"lambda:{res}")

    elif cls == "nat_misplaced":
        nat = snap["nat_gateways"][ctx["nat"]]
        for sid, s in snap["subnets"].items():
            if s["vpc"] == ctx["vpc"] and any(str(r["target"]).startswith("igw-") for r in snap["route_tables"][s["route_table"]]["routes"]):
                add([{"op": "nat_set_subnet", "nat": ctx["nat"], "subnet": sid}], "nat: move NAT gateway to a public subnet", f"nat:{ctx['nat']}")
        rt = snap["route_tables"][ctx["rt"]]
        igw = next((g for g, x in snap["internet_gateways"].items() if x.get("vpc") == ctx["vpc"]), None)
        if igw:
            op = "route_replace" if any(r["dest"] == "0.0.0.0/0" for r in rt["routes"]) else "route_add"
            add([{"op": op, "route_table": ctx["rt"], "dest": "0.0.0.0/0", "target": igw}],
                "route: give the NAT's subnet an internet-gateway route", f"route:{ctx['rt']}:0.0.0.0/0")

    elif cls == "peering_route_missing":
        pcx = ctx.get("pcx")
        if not pcx:
            return out
        rt = snap["route_tables"][res]
        for dest, label in ((ctx["dest_ip"] + "/32", "exact host"), (ctx["dest_subnet_cidr"], "peer subnet"), (ctx["dest_vpc_cidr"], "peer VPC")):
            existing = any(r["dest"] == dest for r in rt["routes"])
            add([{"op": "route_replace" if existing else "route_add", "route_table": res, "dest": dest, "target": pcx}],
                f"route: {label} via peering", f"route:{res}:{dest}")

    elif cls == "peering_not_active":
        add([{"op": "peering_accept", "peering": res}], "peering: accept the connection")
    elif cls == "dns_phz_not_associated":
        add([{"op": "phz_associate", "zone": res, "vpc": ctx["vpc"]}], "dns: associate the private zone with the VPC")
    elif cls == "dns_support_disabled":
        add([{"op": "vpc_set_attr", "vpc": ctx["vpc"], "attr": "enable_dns_support", "value": True}], "dns: enable DNS support")
    elif cls == "service_not_listening":
        add([{"op": "compute_listen", "compute": res, "proto": ctx["proto"], "port": ctx["port"]}],
            "host: start/bind the service on the expected port")

    elif cls in ("iam_action_missing", "iam_resource_mismatch", "iam_condition_mismatch", "iam_policy_not_attached"):
        principal, action, resource = ctx["principal"], ctx["action"], ctx["resource"]
        st = {"Effect": "Allow", "Action": action, "Resource": resource}
        add([{"op": "role_put_inline", "role": principal, "statement": st}], "iam: allow the exact action on the exact resource")
        if _prefix(resource):
            add([{"op": "role_put_inline", "role": principal, "statement": {**st, "Resource": _prefix(resource)}}],
                "iam: allow the exact action on the object prefix")
        svc = action.split(":")[0]
        add([{"op": "role_put_inline", "role": principal, "statement": {"Effect": "Allow", "Action": f"{svc}:*", "Resource": "*"}}],
            "iam: allow the whole service on all resources")
        if ctx.get("policy") and ctx.get("sid") and cls in ("iam_resource_mismatch", "iam_condition_mismatch"):
            pol = snap["iam"]["policies"].get(ctx["policy"])
            orig = next((s for i, s in enumerate(statements(pol)) if s.get("Sid") == ctx["sid"] or f"#{i}" == ctx["sid"]), None)
            if orig:
                if cls == "iam_resource_mismatch":
                    rs = orig.get("Resource") if isinstance(orig.get("Resource"), list) else [orig.get("Resource")]
                    add([{"op": "policy_replace_statement", "target": ctx["policy"], "sid": ctx["sid"],
                          "statement": {**orig, "Resource": rs + [resource]}}], "iam: add the resource to the existing statement")
                else:
                    add([{"op": "policy_replace_statement", "target": ctx["policy"], "sid": ctx["sid"],
                          "statement": {k: v for k, v in orig.items() if k != "Condition"}}], "iam: drop the statement's condition")
        if cls == "iam_policy_not_attached" and ctx.get("policy"):
            add([{"op": "role_attach_policy", "role": principal, "policy": ctx["policy"]}], "iam: attach the existing policy")

    elif chk.id == "explicit_deny":
        target, sid = ctx["target"], ctx["sid"]
        add([{"op": "policy_remove_statement", "target": target, "sid": sid}], "deny: delete the deny statement")
        doc = _policy_doc_ro(snap, ctx["source"], target)
        orig = next((s for i, s in enumerate(statements(doc)) if s.get("Sid") == sid or f"#{i}" == sid), None)
        if orig:
            ex = _merge_condition(orig.get("Condition"), "ArnNotEquals", "aws:PrincipalArn", ctx_principal_arn(snap, ctx))
            add([{"op": "policy_replace_statement", "target": target, "sid": sid, "statement": {**orig, "Condition": ex}}],
                "deny: exempt this principal from the deny")
            from .iam import request_context, _scope_context
            rctx = _scope_context(snap, request_context(snap, ctx["principal"], {}), ctx["action"])
            for op_name, block in (orig.get("Condition") or {}).items():
                for key in block:
                    if key in rctx and op_name.startswith(("StringNot", "ArnNot")):
                        cond = _merge_condition(orig.get("Condition"), op_name, key, rctx[key])
                        add([{"op": "policy_replace_statement", "target": target, "sid": sid, "statement": {**orig, "Condition": cond}}],
                            f"deny: add the caller's {key} to the condition's allow-list")
                    elif key in rctx:
                        cond = {k: dict(v) for k, v in orig["Condition"].items()}
                        del cond[op_name][key]
                        cond = {k: v for k, v in cond.items() if v}
                        st2 = {**orig, "Condition": cond} if cond else {kk: vv for kk, vv in orig.items() if kk != "Condition"}
                        add([{"op": "policy_replace_statement", "target": target, "sid": sid, "statement": st2}],
                            f"deny: drop the {key} condition")

    elif cls == "scp_block" and chk.id == "scp_allow":
        add([{"op": "policy_add_statement", "target": ctx["target"], "statement": {"Effect": "Allow", "Action": ctx["action"], "Resource": "*"}}],
            "scp: allow the action")
    elif cls == "iam_boundary_block":
        t, action, resource = ctx["target"], ctx["action"], ctx["resource"]
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Action": action, "Resource": resource}}],
            "boundary: allow the exact action on the exact resource")
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Action": action, "Resource": "*"}}],
            "boundary: allow the action on all resources")
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Action": action.split(":")[0] + ":*", "Resource": "*"}}],
            "boundary: allow the whole service")
        add([{"op": "role_set_boundary", "role": ctx["principal"], "policy": None}], "boundary: remove the permissions boundary")
    elif cls == "endpoint_policy_block":
        t, action, resource = ctx["target"], ctx["action"], ctx["resource"]
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Principal": {"AWS": ctx["principal_arn"]},
                                                                      "Action": action, "Resource": resource}}],
            "endpoint: allow this principal, action and resource")
        if _prefix(resource):
            add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Principal": "*", "Action": action,
                                                                          "Resource": _prefix(resource)}}], "endpoint: allow the action on the prefix")
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}}],
            "endpoint: allow everything (default policy)")
    elif cls == "cross_account_resource_policy_missing":
        t, action, resource = ctx["target"], ctx["action"], ctx["resource"]
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Principal": {"AWS": ctx["principal_arn"]},
                                                                      "Action": action, "Resource": resource}}],
            "resource policy: grant the role the exact action on the exact object")
        if _prefix(resource):
            add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Principal": {"AWS": ctx["principal_arn"]},
                                                                          "Action": action, "Resource": _prefix(resource)}}],
                "resource policy: grant the role the action on the prefix")
        acct = ctx["principal_arn"].split(":")[4]
        add([{"op": "policy_add_statement", "target": t, "statement": {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
                                                                      "Action": action.split(":")[0] + ":*", "Resource": [t, t + "/*"]}}],
            "resource policy: grant the whole partner account the service")
    elif cls == "kms_key_policy_block":
        key, kms_action = ctx["key"], ctx["kms_action"]
        add([{"op": "policy_add_statement", "target": key, "statement": {"Effect": "Allow", "Principal": {"AWS": ctx["principal_arn"]},
                                                                        "Action": kms_action, "Resource": "*"}}],
            "kms: grant the role the exact KMS action in the key policy")
        acct = ctx["principal_arn"].split(":")[4]
        add([{"op": "policy_add_statement", "target": key, "statement": {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
                                                                        "Action": "kms:*", "Resource": "*"}}],
            "kms: delegate the key to the account (default key policy)")
    return out


def ctx_principal_arn(snap, ctx):
    from .iam import role_arn
    return role_arn(snap, ctx["principal"])


def _policy_doc_ro(snap, source, target):
    if source in ("identity", "boundary"):
        return snap["iam"]["policies"].get(target)
    if source == "scp":
        return snap["organizations"]["scps"].get(target)
    if source == "resource":
        return (snap["resources"].get(target) or {}).get("policy")
    if source == "endpoint":
        return snap["vpc_endpoints"].get(target, {}).get("policy")
    return None


# ------------------------------------------------------------------ optimisation

def _cost(stats: dict) -> int:
    return (W_EDIT + W_GAIN * stats["total_gained"] + W_EXPOSE * stats["internet_exposure"]
            + W_SENSITIVE * stats["iam_sensitive_gained"] + W_LOST * stats["total_lost"])


def repair(snap: dict, intent: dict, least_privilege: bool = True, max_iter: int = 12, seed: int = 0,
           universe: dict | None = None) -> RepairResult:
    t0 = time.time()
    rng = random.Random(seed)
    uni = universe or fixed_universe(snap)
    base_surface = surface(snap, uni)
    ikeys = intent_keys(intent, snap)
    log = []
    cands: list[Candidate] = []
    seen_checks: set = set()
    blocked: list[list[int]] = []

    surf_cache = {}

    def add_obligations(result):
        ref_surface = base_surface if snap_for_candidates is snap else surf_cache.setdefault(
            id(snap_for_candidates), surface(snap_for_candidates, uni))
        new = 0
        for c in result.failing:
            key = check_key(c)
            if key in seen_checks or c.fault_class is None:
                continue
            seen_checks.add(key)
            for cand in candidates_for(snap_for_candidates, c):
                dup = next((x for x in cands if x.edits == cand.edits), None)
                if dup:
                    dup.covers |= cand.covers
                    continue
                trial, applied, errs = apply_edits(snap_for_candidates, cand.edits)
                if errs:
                    continue
                cand.stats = expansion(ref_surface, surface(trial, uni), ikeys, snap)
                cand.cost = _cost(cand.stats) + cand.rank if least_privilege else 100 + rng.randint(0, 9)
                cands.append(cand)
                new += 1
        return new

    snap_for_candidates = snap
    result = evaluate_intent(snap, intent)
    if result.ok:
        return RepairResult([], True, 0, 0, expansion(base_surface, base_surface, ikeys, snap), time.time() - t0,
                            ["intent already satisfied"])
    add_obligations(result)
    best = None
    for it in range(1, max_iter + 1):
        opt = z3.Optimize()
        xs = [z3.Bool(f"x{i}") for i in range(len(cands))]
        for key in seen_checks:
            covering = [xs[i] for i, c in enumerate(cands) if key in c.covers]
            if covering:
                opt.add(z3.Or(covering))
        slots: dict = {}
        for i, c in enumerate(cands):
            if c.slot:
                slots.setdefault(c.slot, []).append(xs[i])
        for group in slots.values():
            if len(group) > 1:
                opt.add(z3.AtMost(*group, 1))
        for b in blocked:
            opt.add(z3.Not(z3.And([xs[i] for i in b])))
        opt.minimize(z3.Sum([z3.If(xs[i], c.cost, 0) for i, c in enumerate(cands)]) if cands else z3.IntVal(0))
        if opt.check() != z3.sat:
            log.append(f"iter {it}: no candidate set covers the obligations")
            break
        m = opt.model()
        chosen = [i for i in range(len(cands)) if z3.is_true(m.eval(xs[i], model_completion=True))]
        if best is not None and sum(cands[i].cost for i in chosen) >= best[2]:
            log.append(f"iter {it}: optimum lower bound reached; keeping best verified fix")
            break
        edits = [e for i in chosen for e in cands[i].edits]
        fixed, applied, errs = apply_edits(snap, edits)
        r2 = evaluate_intent(fixed, intent)
        labels = [cands[i].label for i in chosen]
        predicted = sum(cands[i].cost for i in chosen)
        if r2.ok:
            stats = expansion(base_surface, surface(fixed, uni), ikeys, snap)
            # isolated costs are a lower bound: grants can interact (boundary x identity), so score the set as a whole
            actual = _cost(stats) + sum(W_EDIT + cands[i].rank for i in chosen) - W_EDIT
            log.append(f"iter {it}: verified with {labels}; gained={stats['total_gained']} lost={stats['total_lost']} "
                       f"cost predicted={predicted} actual={actual}")
            if not least_privilege:
                return RepairResult(edits, True, it, len(cands), stats, time.time() - t0, log)
            if best is None or actual < best[2]:
                best = (edits, stats, actual)
            if actual <= predicted and stats["total_lost"] == 0:
                return RepairResult(edits, True, it, len(cands), stats, time.time() - t0, log)
            blocked.append(chosen)
            continue
        if best is not None and predicted >= best[2]:
            break  # no remaining set can beat the best verified one
        snap_for_candidates = fixed  # masked faults: generate candidates in the partially repaired state
        new = add_obligations(r2)
        snap_for_candidates = snap
        log.append(f"iter {it}: {labels} left {len(r2.failing)} failing checks; {new} new candidates")
        if new == 0:
            blocked.append(chosen)
    if best:
        return RepairResult(best[0], True, it, len(cands), best[1], time.time() - t0, log + ["returned best verified fix"])
    return RepairResult([], False, max_iter, len(cands), {}, time.time() - t0, log)
