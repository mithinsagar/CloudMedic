"""Formal model of AWS IAM request authorisation (documented subset).

Evaluation order follows the AWS policy evaluation logic:
  1. An explicit Deny in any applicable policy (identity, permissions boundary, SCP,
     resource policy, VPC endpoint policy) denies the request.
  2. Every attached SCP must allow the action (one SCP per OU level is modelled as a list).
  3. If the request goes through a VPC endpoint, its policy must allow the request.
  4. If the role has a permissions boundary, the boundary must allow the action.
  5. Same account: an identity-policy Allow or a resource-policy Allow naming the principal.
     Cross account: an identity-policy Allow AND a resource-policy Allow naming the principal
     or its account.
  6. Dependent KMS call: reading or writing an SSE-KMS object also needs kms:Decrypt or
     kms:GenerateDataKey on the key. The key policy must either grant the principal directly
     or delegate to the principal's account root, in which case an identity policy must allow it.
Simplification: a resource-policy Allow for a role is still subject to its permissions boundary.
"""
from __future__ import annotations

from .checks import FAIL, PASS, Check, Result, finish
from .policy import as_list, action_matches, conditions_hold, principal_match_kind, resource_matches, statement_applies

KMS_DEPENDENCY = {"s3:GetObject": "kms:Decrypt", "s3:PutObject": "kms:GenerateDataKey"}

DENY_CLASS = {
    "identity": "iam_explicit_deny",
    "boundary": "iam_boundary_block",
    "scp": "scp_block",
    "resource": "resource_policy_deny",
    "endpoint": "endpoint_policy_block",
}


def role_arn(snap: dict, role_id: str) -> str:
    r = snap["iam"]["roles"][role_id]
    return f"arn:aws:iam::{r.get('account', snap['account_id'])}:role/{r['name']}"


def resource_record(snap: dict, arn: str):
    res = snap.get("resources", {})
    if arn in res:
        return arn, res[arn]
    if arn.startswith("arn:aws:s3:::"):
        bucket = "arn:aws:s3:::" + arn[len("arn:aws:s3:::"):].split("/")[0]
        if bucket in res:
            return bucket, res[bucket]
    return None, None


def statements(doc: dict | None) -> list[dict]:
    if not doc:
        return []
    s = doc.get("Statement", [])
    return s if isinstance(s, list) else [s]


def _sid(stmt: dict, i: int) -> str:
    return stmt.get("Sid") or f"#{i}"


def request_context(snap: dict, principal: str, context: dict | None) -> dict:
    role = snap["iam"]["roles"][principal]
    acct = role.get("account", snap["account_id"])
    ctx = {**role.get("default_context", {}), **(context or {}),
           "aws:PrincipalArn": role_arn(snap, principal), "aws:PrincipalAccount": acct}
    return ctx


def _scope_context(snap: dict, ctx: dict, action: str) -> dict:
    """aws:SourceVpce is only present when the call actually traverses that endpoint's service."""
    vpce = ctx.get("aws:SourceVpce")
    if vpce:
        ep = snap.get("vpc_endpoints", {}).get(vpce)
        if not ep or action.split(":")[0].lower() != ep.get("service", "").lower():
            ctx = {k: v for k, v in ctx.items() if k != "aws:SourceVpce"}
    return ctx


def policy_sources(snap: dict, principal: str, resource: str, ctx: dict):
    """(source_kind, target_id, statement_list, needs_principal_match) for every applicable policy."""
    role = snap["iam"]["roles"][principal]
    acct = role.get("account", snap["account_id"])
    out = []
    for pid in role.get("policies", []):
        p = snap["iam"]["policies"].get(pid)
        if p:
            out.append(("identity", pid, statements(p), False))
    if role.get("boundary") and role["boundary"] in snap["iam"]["policies"]:
        out.append(("boundary", role["boundary"], statements(snap["iam"]["policies"][role["boundary"]]), False))
    org = snap.get("organizations", {})
    for sid in org.get("accounts", {}).get(acct, []):
        if sid in org.get("scps", {}):
            out.append(("scp", sid, statements(org["scps"][sid]), False))
    rkey, rec = resource_record(snap, resource)
    if rec and rec.get("policy"):
        out.append(("resource", rkey, statements(rec["policy"]), True))
    vpce = ctx.get("aws:SourceVpce")
    if vpce and vpce in snap.get("vpc_endpoints", {}):
        out.append(("endpoint", vpce, statements(snap["vpc_endpoints"][vpce].get("policy")), True))
    return out


def evaluate_request(snap: dict, principal: str, action: str, resource: str, context: dict | None = None,
                     _dependent: bool = True) -> Result:
    if principal not in snap["iam"]["roles"]:
        return Result(False, [Check("principal", "inventory", principal, FAIL, f"unknown principal {principal}")], "unknown_principal")
    role = snap["iam"]["roles"][principal]
    acct = role.get("account", snap["account_id"])
    arn = role_arn(snap, principal)
    ctx = _scope_context(snap, request_context(snap, principal, context), action)
    sources = policy_sources(snap, principal, resource, ctx)
    checks: list[Check] = []

    def applies(stmt, needs_principal):
        if needs_principal and principal_match_kind(stmt, arn, acct) is None:
            return False
        return statement_applies(stmt, action, resource, ctx)

    # 1. explicit deny
    denies = []
    for kind, target, stmts, needs_p in sources:
        for i, st in enumerate(stmts):
            if st.get("Effect") == "Deny" and applies(st, needs_p):
                denies.append((kind, target, _sid(st, i)))
    for kind, target, sid in denies:
        checks.append(Check("explicit_deny", "iam", target, FAIL,
                            f"explicit Deny in {kind} policy {target} (statement {sid}) matches {action} on {resource}",
                            DENY_CLASS[kind], {"source": kind, "target": target, "sid": sid, "principal": principal,
                                               "action": action, "resource": resource}))
    if not denies:
        checks.append(Check("explicit_deny", "iam", None, PASS, "no explicit Deny applies"))

    def allowed_by(kind_filter):
        return [(t, _sid(st, i)) for k, t, stmts, needs_p in sources if k == kind_filter
                for i, st in enumerate(stmts) if st.get("Effect") == "Allow" and applies(st, needs_p)]

    base_ctx = {"principal": principal, "action": action, "resource": resource, "principal_arn": arn}
    # 2. SCPs
    for kind, target, stmts, _ in sources:
        if kind != "scp":
            continue
        ok = any(st.get("Effect") == "Allow" and statement_applies(st, action, resource, ctx) for st in stmts)
        checks.append(Check("scp_allow", "iam", target, PASS if ok else FAIL,
                            f"SCP {target} {'allows' if ok else 'does not allow'} {action}",
                            None if ok else "scp_block", {**base_ctx, "target": target}))
    # 3. VPC endpoint policy
    for kind, target, stmts, _ in sources:
        if kind != "endpoint":
            continue
        ok = any(st.get("Effect") == "Allow" and applies(st, True) for st in stmts)
        checks.append(Check("endpoint_allow", "iam", target, PASS if ok else FAIL,
                            f"VPC endpoint policy {target} {'allows' if ok else 'does not allow'} {action} on {resource}",
                            None if ok else "endpoint_policy_block", {**base_ctx, "target": target}))
    # 4. permissions boundary
    if role.get("boundary"):
        ok = bool(allowed_by("boundary"))
        checks.append(Check("boundary_allow", "iam", role["boundary"], PASS if ok else FAIL,
                            f"permissions boundary {role['boundary']} {'allows' if ok else 'does not allow'} {action}",
                            None if ok else "iam_boundary_block", {**base_ctx, "target": role["boundary"]}))
    # 5. grant
    rkey, rec = resource_record(snap, resource)
    res_acct = (rec or {}).get("account", snap["account_id"])
    id_allow = allowed_by("identity")
    identity_ok = bool(id_allow)
    res_direct = res_account = False
    res_allow = []
    for kind, target, stmts, _ in sources:
        if kind == "resource":
            for i, st in enumerate(stmts):
                if st.get("Effect") == "Allow" and statement_applies(st, action, resource, ctx):
                    m = principal_match_kind(st, arn, acct)
                    res_direct |= m == "direct"
                    res_account |= m == "account"
                    if m:
                        res_allow.append((target, _sid(st, i)))
    if res_acct == acct:
        if identity_ok or res_direct:
            how = "identity policy" if identity_ok else f"resource policy on {rkey}"
            checks.append(Check("identity_allow", "iam", principal, PASS, f"{how} allows {action} on {resource}", None,
                                {**base_ctx, "allowed_by": id_allow, "resource_allowed_by": res_allow}))
        else:
            checks.append(_identity_fail(snap, principal, action, resource, ctx, base_ctx))
    else:
        if identity_ok:
            checks.append(Check("identity_allow", "iam", principal, PASS, f"identity policy allows {action} on {resource}", None,
                                {**base_ctx, "allowed_by": id_allow}))
        else:
            checks.append(_identity_fail(snap, principal, action, resource, ctx, base_ctx))
        ok = res_direct or res_account
        checks.append(Check("resource_allow", "iam", rkey, PASS if ok else FAIL,
                            f"cross-account: resource policy on {rkey} {'grants' if ok else 'does not grant'} {action} to {arn}",
                            None if ok else "cross_account_resource_policy_missing",
                            {**base_ctx, "target": rkey, "allowed_by": res_allow}))
    # 6. dependent KMS call
    if _dependent and rec and rec.get("kms_key") and action in KMS_DEPENDENCY:
        checks += _kms_checks(snap, principal, KMS_DEPENDENCY[action], rec["kms_key"], ctx, base_ctx)
    return finish(checks, lambda c: "access_denied_kms" if c.id.startswith("kms") else "access_denied")


def _identity_fail(snap, principal, action, resource, ctx, base_ctx) -> Check:
    role = snap["iam"]["roles"][principal]
    near = {"condition": None, "resource": None}
    for pid in role.get("policies", []):
        for i, st in enumerate(statements(snap["iam"]["policies"].get(pid))):
            if st.get("Effect") != "Allow" or not action_matches(st, action):
                continue
            if resource_matches(st, resource):
                if not conditions_hold(st, ctx) and near["condition"] is None:
                    near["condition"] = (pid, _sid(st, i))
            elif near["resource"] is None:
                near["resource"] = (pid, _sid(st, i))
    ctx_out = dict(base_ctx)
    if near["condition"]:
        pid, sid = near["condition"]
        return Check("identity_allow", "iam", principal, FAIL,
                     f"statement {sid} in {pid} allows {action} on {resource} but its Condition is not met",
                     "iam_condition_mismatch", {**ctx_out, "policy": pid, "sid": sid})
    if near["resource"]:
        pid, sid = near["resource"]
        return Check("identity_allow", "iam", principal, FAIL,
                     f"statement {sid} in {pid} allows {action} but not on {resource} (Resource mismatch)",
                     "iam_resource_mismatch", {**ctx_out, "policy": pid, "sid": sid})
    attached_anywhere = {x for r in snap["iam"]["roles"].values() for x in r.get("policies", []) + [r.get("boundary")]}
    for pid, p in snap["iam"]["policies"].items():
        if pid in attached_anywhere or p.get("kind") == "boundary":
            continue  # only orphaned policies count: another role's policy is not "the" missing attachment
        if any("*" in as_list(st.get("Action")) for st in statements(p)):
            continue  # an admin-style policy is not "the" policy meant for this access
        if any(st.get("Effect") == "Allow" and statement_applies(st, action, resource, ctx) for st in statements(p)):
            return Check("identity_allow", "iam", principal, FAIL,
                         f"policy {pid} would allow {action} on {resource} but is not attached to {principal}",
                         "iam_policy_not_attached", {**ctx_out, "policy": pid})
    return Check("identity_allow", "iam", principal, FAIL,
                 f"no identity-based policy attached to {principal} allows {action} on {resource}",
                 "iam_action_missing", ctx_out)


def _kms_checks(snap, principal, kms_action, key_arn, ctx, base_ctx) -> list[Check]:
    arn = base_ctx["principal_arn"]
    role = snap["iam"]["roles"][principal]
    acct = role.get("account", snap["account_id"])
    key = snap.get("resources", {}).get(key_arn)
    kctx = {**base_ctx, "kms_action": kms_action, "key": key_arn, "action": kms_action, "resource": key_arn}
    if key is None:
        return [Check("kms_key_policy", "kms", key_arn, FAIL, f"KMS key {key_arn} does not exist", "kms_key_policy_block", kctx)]
    direct = account = denied = False
    granting = []
    for i, st in enumerate(statements(key.get("policy"))):
        if not statement_applies(st, kms_action, key_arn, ctx):
            continue
        m = principal_match_kind(st, arn, acct)
        if m is None:
            continue
        if st.get("Effect") == "Deny":
            denied = True
        elif m == "direct":
            direct = True
            granting.append(_sid(st, i))
        else:
            account = True
            granting.append(_sid(st, i))
    if denied or not (direct or account):
        why = "explicitly denies" if denied else "neither grants the role nor delegates to its account"
        return [Check("kms_key_policy", "kms", key_arn, FAIL, f"key policy of {key_arn} {why} {kms_action}",
                      "kms_key_policy_block", kctx)]
    out = [Check("kms_key_policy", "kms", key_arn, PASS,
                 f"key policy {'grants the role' if direct else 'delegates to account'} {kms_action}", None,
                 {**kctx, "granting": granting, "mode": "direct" if direct else "account"})]
    if not direct:
        sub = evaluate_request(snap, principal, kms_action, key_arn, ctx, _dependent=False)
        idc = next(c for c in sub.checks if c.id == "identity_allow")
        if idc.ok:
            out.append(Check("kms_identity", "kms", principal, PASS, f"identity policy allows {kms_action} on the key", None,
                             {**kctx, "allowed_by": idc.ctx.get("allowed_by", [])}))
        else:
            out.append(Check("kms_identity", "kms", principal, FAIL,
                             f"key policy delegates to the account, but no identity policy on {principal} allows {kms_action} on {key_arn}",
                             idc.fault_class or "iam_action_missing", {**kctx, **{k: v for k, v in idc.ctx.items() if k in ("policy", "sid")}}))
    return out
