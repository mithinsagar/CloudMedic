"""Privilege expansion: how much access a fix grants beyond what the ticket needed.

The access surface of a snapshot is computed over a finite universe:
  * network: every (src, dst, tcp, port) for all compute endpoints and external hosts and a
    fixed set of commonly attacked ports plus every port any host listens on. A flow counts
    as reachable when the network path permits it, whether or not a service is listening,
    because an open path is exposure even before something binds to it.
  * IAM: every (role, action, resource) over the benchmark action catalogue and all modelled
    resources (plus one sample object per bucket).
For a fix, gained = surface(after) - surface(reference) - intent and lost = surface(reference) -
surface(after). At repair time the reference is the broken snapshot (all the tool can see). In
evaluation, excess privilege uses the healthy pre-fault snapshot as reference (what the customer
intended) and regression uses the broken snapshot (what worked before the fix was applied).
Excess privilege counts only access that neither the healthy nor the broken configuration
granted, so leftovers of the fault itself are not blamed on the fix. Because the universe is finite, wildcard grants are
under-counted rather than over-counted, so reported expansion is a lower bound.
"""
from __future__ import annotations

from .iam import evaluate_request
from .network import evaluate_flow

COMMON_PORTS = [22, 80, 443, 3306, 3389, 5432, 6379, 8080, 9200, 27017]

ACTION_CATALOG = [
    "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:PutBucketPolicy", "s3:GetBucketPolicy",
    "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy",
    "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteTable", "dynamodb:Query",
    "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteQueue",
    "secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret",
    "logs:PutLogEvents", "logs:CreateLogStream",
    "ec2:DescribeInstances", "ec2:TerminateInstances", "ec2:AuthorizeSecurityGroupIngress",
    "iam:PassRole", "iam:CreateUser", "iam:AttachRolePolicy", "iam:PutRolePolicy",
    "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
    "sts:AssumeRole", "cloudtrail:StopLogging", "organizations:LeaveOrganization",
]

SENSITIVE = {
    "s3:DeleteObject", "s3:PutBucketPolicy", "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy", "dynamodb:DeleteTable",
    "sqs:DeleteQueue", "secretsmanager:DeleteSecret", "ec2:TerminateInstances", "ec2:AuthorizeSecurityGroupIngress",
    "iam:PassRole", "iam:CreateUser", "iam:AttachRolePolicy", "iam:PutRolePolicy", "lambda:UpdateFunctionCode",
    "cloudtrail:StopLogging", "organizations:LeaveOrganization",
}


def network_universe(snap: dict) -> list[tuple]:
    eps = list(snap.get("compute", {})) + list(snap.get("external_hosts", {}))
    ports = set(COMMON_PORTS)
    for c in list(snap.get("compute", {}).values()) + list(snap.get("external_hosts", {}).values()):
        ports |= {l["port"] for l in c.get("listening", []) if l.get("proto", "tcp") == "tcp"}
    ext = set(snap.get("external_hosts", {}))
    return [(s, d, "tcp", p) for s in eps for d in eps if s != d and not (s in ext and d in ext) for p in sorted(ports)]


def iam_universe(snap: dict) -> list[tuple]:
    res = []
    for arn, r in snap.get("resources", {}).items():
        res.append(arn)
        if r.get("type") == "s3_bucket":
            res.append(arn + "/data/sample-object.csv")
    return [(p, a, r) for p in snap.get("iam", {}).get("roles", {}) for a in ACTION_CATALOG for r in res]


def surface(snap: dict, universe: dict | None = None) -> dict:
    universe = universe or {"network": network_universe(snap), "iam": iam_universe(snap)}
    net = {("network",) + f for f in universe["network"]
           if evaluate_flow(snap, f[0], f[1], f[2], f[3], ignore_listening=True).ok}
    iam = {("iam",) + q for q in universe["iam"] if evaluate_request(snap, q[0], q[1], q[2]).ok}
    return {"network": net, "iam": iam}


def fixed_universe(snap: dict) -> dict:
    """Freeze the universe of the *original* snapshot so before/after are compared on the same set."""
    return {"network": network_universe(snap), "iam": iam_universe(snap)}


def excess(healthy: dict, broken: dict, after: dict, intent_keys: set, snap: dict) -> dict:
    """Privilege the fix introduced beyond both the intended (healthy) and the pre-fix configuration."""
    ref = {k: healthy[k] | broken[k] for k in ("network", "iam")}
    return expansion(ref, after, intent_keys, snap)


def expansion(before: dict, after: dict, intent_keys: set, snap: dict) -> dict:
    """Compare two surfaces. `before` is the reference surface."""
    ext_untrusted = {k for k, h in snap.get("external_hosts", {}).items() if not h.get("trusted", False)}
    gained = {k: after[k] - before[k] - intent_keys for k in ("network", "iam")}
    lost = {k: before[k] - after[k] for k in ("network", "iam")}
    return {
        "network_gained": len(gained["network"]),
        "internet_exposure": sum(1 for g in gained["network"] if g[1] in ext_untrusted),
        "iam_gained": len(gained["iam"]),
        "iam_sensitive_gained": sum(1 for g in gained["iam"] if g[2] in SENSITIVE),
        "total_gained": len(gained["network"]) + len(gained["iam"]),
        "network_lost": len(lost["network"]),
        "iam_lost": len(lost["iam"]),
        "total_lost": len(lost["network"]) + len(lost["iam"]),
        "examples_gained": sorted(map(str, gained["network"] | gained["iam"]))[:5],
        "examples_lost": sorted(map(str, lost["network"] | lost["iam"]))[:5],
    }


def resolve_dst_id(snap: dict, dst: str) -> str:
    if dst in snap.get("compute", {}) or dst in snap.get("external_hosts", {}):
        return dst
    for z in snap.get("private_zones", {}).values():
        ip = z.get("records", {}).get(dst)
        if ip:
            return next((k for k, c in snap["compute"].items() if c.get("private_ip") == ip), dst)
    return next((k for k, h in snap.get("external_hosts", {}).items() if h.get("hostname") == dst), dst)


def intent_keys(intent: dict, snap: dict) -> set:
    """Surface entries the intent legitimately needs."""
    if intent["kind"] == "network":
        return {("network", intent["src"], resolve_dst_id(snap, intent["dst"]), intent.get("proto", "tcp"), int(intent["port"]))}
    return {("iam", intent["principal"], intent["action"], intent["resource"])}
