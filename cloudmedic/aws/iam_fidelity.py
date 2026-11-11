"""Measure the fidelity of the IAM model against AWS's own policy simulator.

Random but realistic cases (identity policy, optional permissions boundary, optional bucket
policy, request context) are evaluated by CloudMedic and by iam:SimulateCustomPolicy, and the
decisions (allowed / explicitDeny / implicitDeny) are compared. SimulateCustomPolicy is free and
touches no resources; it needs `iam:SimulateCustomPolicy` permission. The simulator requires
an IAM *user* ARN as caller when a resource policy is supplied; pass --caller-arn with an
existing user (e.g. the one whose keys you use).

    python -m cloudmedic.aws.iam_fidelity --profile cloudmedic --caller-arn arn:aws:iam::123456789012:user/me --n 400
"""
from __future__ import annotations

import argparse
import collections
import json
import random
import time
from pathlib import Path

from ..iam import evaluate_request

ACTIONS = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketPolicy"]
ACTION_PATTERNS = ["s3:GetObject", "s3:PutObject", "s3:Get*", "s3:*", "s3:*Object", "s3:List*", "*"]
REGIONS = ["us-east-1", "eu-west-1", "ap-south-1"]


def _resources(bucket):
    b = f"arn:aws:s3:::{bucket}"
    return [b, f"{b}/*", f"{b}/data/*", f"{b}/data/reports/*", f"{b}/logs/*", "*", "arn:aws:s3:::other-bucket/*"]


def _condition(rng, office):
    kind = rng.choice(["ip", "notip", "region", "regionnot", "secure", "tag", "ifexists", None, None])
    if kind == "ip":
        return {"IpAddress": {"aws:SourceIp": rng.choice([office, "198.18.0.0/15"])}}
    if kind == "notip":
        return {"NotIpAddress": {"aws:SourceIp": office}}
    if kind == "region":
        return {"StringEquals": {"aws:RequestedRegion": rng.sample(REGIONS, rng.randint(1, 2))}}
    if kind == "regionnot":
        return {"StringNotEquals": {"aws:RequestedRegion": rng.choice(REGIONS)}}
    if kind == "secure":
        return {"Bool": {"aws:SecureTransport": rng.choice(["true", "false"])}}
    if kind == "tag":
        return {"StringLike": {"aws:PrincipalTag/team": rng.choice(["data*", "platform"])}}
    if kind == "ifexists":
        return {"StringEqualsIfExists": {"aws:PrincipalTag/env": "prod"}}
    return None


def _statement(rng, bucket, office, principal=None):
    st = {"Effect": rng.choice(["Allow", "Allow", "Allow", "Deny"]),
          ("NotAction" if rng.random() < 0.1 else "Action"): rng.sample(ACTION_PATTERNS, rng.randint(1, 2)),
          "Resource": rng.sample(_resources(bucket), rng.randint(1, 2))}
    c = _condition(rng, office)
    if c:
        st["Condition"] = c
    if principal is not None:
        st["Principal"] = principal
    return st


def random_case(rng, account, caller_arn):
    bucket = "cloudmedic-fidelity-bucket"
    office = "203.0.113.0/24"
    identity = {"Version": "2012-10-17", "Statement": [_statement(rng, bucket, office) for _ in range(rng.randint(1, 3))]}
    boundary = None
    if rng.random() < 0.35:
        boundary = {"Version": "2012-10-17", "Statement": [_statement(rng, bucket, office) for _ in range(rng.randint(1, 2))]}
    resource_policy = None
    if rng.random() < 0.5:
        principals = [{"AWS": caller_arn}, "*", {"AWS": f"arn:aws:iam::{account}:root"}, {"AWS": "arn:aws:iam::999999999999:root"}]
        resource_policy = {"Version": "2012-10-17", "Statement": [
            {**_statement(rng, bucket, office, rng.choice(principals)),
             "Resource": rng.choice([f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/data/*"])}
            for _ in range(rng.randint(1, 2))]}
    action = rng.choice(ACTIONS)
    resource = f"arn:aws:s3:::{bucket}" if action in ("s3:ListBucket", "s3:GetBucketPolicy") else \
        f"arn:aws:s3:::{bucket}/" + rng.choice(["data/reports/q3.csv", "data/x.json", "logs/app.log", "top.txt"])
    context = {"aws:SourceIp": rng.choice(["203.0.113.25", "198.51.100.7"]), "aws:RequestedRegion": rng.choice(REGIONS),
               "aws:SecureTransport": rng.choice(["true", "false"])}
    if rng.random() < 0.5:
        context["aws:PrincipalTag/team"] = rng.choice(["data-eng", "platform", "web"])
    return {"identity": identity, "boundary": boundary, "resource_policy": resource_policy, "action": action,
            "resource": resource, "context": context, "bucket": bucket}


def cloudmedic_decision(case, account, caller_arn) -> str:
    snap = {"account_id": account, "region": "us-east-1", "vpc_endpoints": {}, "organizations": {"scps": {}, "accounts": {}},
            "iam": {"roles": {"caller": {"name": caller_arn.split("/")[-1], "arn": caller_arn, "account": account,
                                         "principal_type": "user", "policies": ["id"], "boundary": "b" if case["boundary"] else None,
                                         "default_context": {}}},
                    "policies": {"id": case["identity"], **({"b": case["boundary"]} if case["boundary"] else {})}},
            "resources": {f"arn:aws:s3:::{case['bucket']}": {"type": "s3_bucket", "name": case["bucket"], "account": account,
                                                            "policy": case["resource_policy"], "kms_key": None}}}
    r = evaluate_request(snap, "caller", case["action"], case["resource"], case["context"])
    if r.ok:
        return "allowed"
    if any(c.id == "explicit_deny" and not c.ok for c in r.checks):
        return "explicitDeny"
    return "implicitDeny"


def aws_decision(iam, case, account, caller_arn) -> str:
    types = {"aws:SourceIp": "ip", "aws:SecureTransport": "boolean"}
    kw = {"PolicyInputList": [json.dumps(case["identity"])], "ActionNames": [case["action"]], "ResourceArns": [case["resource"]],
          "ContextEntries": [{"ContextKeyName": k, "ContextKeyValues": [v], "ContextKeyType": types.get(k, "string")}
                             for k, v in case["context"].items()]}
    if case["boundary"]:
        kw["PermissionsBoundaryPolicyInputList"] = [json.dumps(case["boundary"])]
    if case["resource_policy"]:
        kw.update(ResourcePolicy=json.dumps(case["resource_policy"]), ResourceOwner=f"arn:aws:iam::{account}:root", CallerArn=caller_arn)
    res = iam.simulate_custom_policy(**kw)["EvaluationResults"][0]
    return res["EvalDecision"]


def main():
    import boto3
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=None)
    ap.add_argument("--caller-arn", required=True)
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="results/iam_fidelity.json")
    a = ap.parse_args()
    session = boto3.Session(profile_name=a.profile)
    iam = session.client("iam")
    account = a.caller_arn.split(":")[4]
    rng = random.Random(a.seed)
    rows, confusion = [], collections.Counter()
    for i in range(a.n):
        case = random_case(rng, account, a.caller_arn)
        ours = cloudmedic_decision(case, account, a.caller_arn)
        theirs = aws_decision(iam, case, account, a.caller_arn)
        confusion[(theirs, ours)] += 1
        rows.append({"case": case, "cloudmedic": ours, "aws": theirs, "agree": ours == theirs})
        if i % 50 == 0:
            print(f"{i}/{a.n} agreement so far {sum(r['agree'] for r in rows) / len(rows):.3f}", flush=True)
        time.sleep(0.05)  # stay well under the IAM API rate limit
    agree = sum(r["agree"] for r in rows) / len(rows)
    out = {"n": len(rows), "agreement": agree, "confusion_aws_vs_cloudmedic": {f"{k[0]}|{k[1]}": v for k, v in confusion.items()},
           "disagreements": [r for r in rows if not r["agree"]][:50], "seed": a.seed}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in ("n", "agreement", "confusion_aws_vs_cloudmedic")}, indent=1))


if __name__ == "__main__":
    main()
