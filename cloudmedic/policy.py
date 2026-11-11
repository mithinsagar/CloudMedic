"""IAM policy language primitives: wildcard matching, principals and condition operators.

Scope (documented subset of the AWS policy language):
  * Effect, Action, NotAction, Resource, NotResource, Principal, Condition
  * Condition operators: String{Equals,NotEquals,Like,NotLike}, Arn{Equals,Like,NotEquals,NotLike},
    {Not}IpAddress, Bool, Null, each optionally with the IfExists suffix
  * Multiple values inside one condition key are OR-ed; multiple keys and operators are AND-ed
Not modelled: policy variables (${aws:username}), ForAllValues/ForAnyValue set operators,
numeric/date operators, session policies.
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache


def as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@lru_cache(maxsize=8192)
def _wild_re(pattern: str, ignore_case: bool) -> re.Pattern:
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(f"^{rx}$", re.IGNORECASE if ignore_case else 0)


def wild_match(pattern: str, value: str, ignore_case: bool = False) -> bool:
    return bool(_wild_re(pattern, ignore_case).match(value))


def action_matches(stmt: dict, action: str) -> bool:
    if "NotAction" in stmt:
        return not any(wild_match(p, action, True) for p in as_list(stmt["NotAction"]))
    return any(wild_match(p, action, True) for p in as_list(stmt.get("Action")))


def resource_matches(stmt: dict, resource: str) -> bool:
    if "NotResource" in stmt:
        return not any(wild_match(p, resource) for p in as_list(stmt["NotResource"]))
    if "Resource" not in stmt:  # resource policies may omit Resource; they apply to the owner
        return True
    return any(wild_match(p, resource) for p in as_list(stmt["Resource"]))


def principal_values(stmt: dict) -> list[str]:
    p = stmt.get("Principal")
    if p is None:
        return []
    if p == "*":
        return ["*"]
    out = []
    for k, v in p.items():
        out += [f"{k}:{x}" if k != "AWS" else x for x in as_list(v)]
    return out


def principal_match_kind(stmt: dict, principal_arn: str, principal_account: str) -> str | None:
    """How a resource-policy statement's Principal relates to the caller.

    Returns "direct" (names this principal or everyone), "account" (names the caller's
    account root, which delegates the decision to that account's identity policies) or None.
    """
    for v in principal_values(stmt):
        if v == "*" or v == principal_arn:
            return "direct"
        if v in (principal_account, f"arn:aws:iam::{principal_account}:root"):
            return "account"
    return None


def _ip_in(value: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _base_op(op: str, key_present: bool, ctx_vals: list[str], cond_vals: list[str]) -> bool:
    if op == "Null":
        want_null = str(cond_vals[0]).lower() == "true"
        return (not key_present) == want_null
    negated = op.startswith(("StringNot", "ArnNot", "NotIp"))
    if not key_present:
        return negated  # AWS: negated operators match when the key is absent
    if op in ("StringEquals", "ArnEquals"):
        return any(c == v for c in ctx_vals for v in cond_vals)
    if op in ("StringNotEquals", "ArnNotEquals"):
        return not any(c == v for c in ctx_vals for v in cond_vals)
    if op in ("StringLike", "ArnLike"):
        return any(wild_match(v, c) for c in ctx_vals for v in cond_vals)
    if op in ("StringNotLike", "ArnNotLike"):
        return not any(wild_match(v, c) for c in ctx_vals for v in cond_vals)
    if op == "IpAddress":
        return any(_ip_in(c, v) for c in ctx_vals for v in cond_vals)
    if op == "NotIpAddress":
        return not any(_ip_in(c, v) for c in ctx_vals for v in cond_vals)
    if op == "Bool":
        return any(str(c).lower() == str(v).lower() for c in ctx_vals for v in cond_vals)
    raise ValueError(f"unsupported condition operator {op}")


SUPPORTED_OPS = {
    "StringEquals", "StringNotEquals", "StringLike", "StringNotLike",
    "ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike",
    "IpAddress", "NotIpAddress", "Bool", "Null",
}


def conditions_hold(stmt: dict, context: dict) -> bool:
    for op, block in (stmt.get("Condition") or {}).items():
        if_exists = op.endswith("IfExists")
        base = op[: -len("IfExists")] if if_exists else op
        if base not in SUPPORTED_OPS:
            raise ValueError(f"unsupported condition operator {op}")
        for key, vals in block.items():
            present = key in context
            if if_exists and not present:
                continue
            ctx_vals = [str(x) for x in as_list(context.get(key))]
            if not _base_op(base, present, ctx_vals, [str(x) for x in as_list(vals)]):
                return False
    return True


def statement_applies(stmt: dict, action: str, resource: str, context: dict) -> bool:
    return action_matches(stmt, action) and resource_matches(stmt, resource) and conditions_hold(stmt, context)
