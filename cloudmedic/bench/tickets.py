"""Customer-ticket writer.

Tickets are written the way customers write them: names rather than IDs, partial error
output, guesses, and a change log that may contain the real cause, unrelated changes, or both.
  L1: verbose error text, resource IDs, the real change listed.
  L2: terse error, names only, red-herring changes; the real change is listed vaguely or not at all.
  L3: multi-fault scenarios, written at L2 verbosity.
The ticket never states the fault class; observable symptoms come from the simulated trace.
"""
from __future__ import annotations

import random

from ..checks import Result

OPENERS = [
    "Hi team,", "Hello AWS Support,", "Hi,", "Urgent - production impact.", "Good morning,", "Hey folks,",
]
TIMES = ["since this morning", "after last night's deploy", "since about 14:00 UTC", "since Friday", "for the last two hours",
         "since we rolled out the new release"]
TRIED = [
    "We already rebooted the instance.", "We redeployed the service twice.", "Restarting did not help.",
    "We checked the application logs and they show nothing useful.", "It works from my laptop, not from AWS.",
    "We have not changed the application code.", "We tried increasing the timeout to 60s.",
]
RED_HERRINGS = [
    "Upgraded the AMI to the latest Amazon Linux 2023 release",
    "Rotated the database password in Secrets Manager",
    "Enabled detailed CloudWatch monitoring",
    "Bumped the Lambda memory from 512 MB to 1024 MB",
    "Added cost-allocation tags to all resources",
    "Upgraded the Python runtime from 3.11 to 3.12",
    "Turned on S3 server access logging",
    "Changed the CloudWatch log retention to 30 days",
    "Renamed the CloudFormation stack outputs",
    "Enabled GuardDuty in the account",
]


def _nm(snap, ref):
    for table in ("compute", "external_hosts"):
        if ref in snap.get(table, {}):
            return snap[table][ref].get("name", ref)
    return ref


def _host(snap, ref):
    if ref in snap.get("compute", {}):
        c = snap["compute"][ref]
        return c.get("private_ip") or c.get("public_ip") or ref
    if ref in snap.get("external_hosts", {}):
        h = snap["external_hosts"][ref]
        return h.get("hostname") or h["ip"]
    return ref


def _client_cmd(port, host):
    if port == 22:
        return f"ssh: connect to host {host} port 22: Operation timed out", f"ssh: connect to host {host} port 22: Connection refused"
    if port in (5432,):
        return (f'psql: error: connection to server at "{host}", port 5432 failed: Connection timed out',
                f'psql: error: connection to server at "{host}", port 5432 failed: Connection refused')
    if port in (3306,):
        return (f"ERROR 2003 (HY000): Can't connect to MySQL server on '{host}:3306' (110)",
                f"ERROR 2003 (HY000): Can't connect to MySQL server on '{host}:3306' (111)")
    if port == 6379:
        return (f"Could not connect to Redis at {host}:6379: Connection timed out",
                f"Could not connect to Redis at {host}:6379: Connection refused")
    return (f"curl: (28) Failed to connect to {host} port {port} after 130002 ms: Timeout was reached",
            f"curl: (7) Failed to connect to {host} port {port}: Connection refused")


DENY_REASON = {
    "iam_action_missing": "because no identity-based policy allows the {a} action",
    "iam_resource_mismatch": "because no identity-based policy allows the {a} action",
    "iam_condition_mismatch": "because no identity-based policy allows the {a} action",
    "iam_policy_not_attached": "because no identity-based policy allows the {a} action",
    "iam_explicit_deny": "with an explicit deny in an identity-based policy",
    "iam_boundary_block": "because no permissions boundary allows the {a} action",
    "scp_block": "with an explicit deny in a service control policy",
    "resource_policy_deny": "with an explicit deny in a resource-based policy",
    "cross_account_resource_policy_missing": "because no resource-based policy allows the {a} action",
    "kms_key_policy_block": "because no resource-based policy allows the {a} action",
    "endpoint_policy_block": "because no VPC endpoint policy allows the {a} action",
}


def _iam_error(snap, intent, result: Result, verbose: bool):
    first = result.failing[0]
    role = snap["iam"]["roles"][intent["principal"]]
    acct = role.get("account", snap["account_id"])
    action = first.ctx.get("action", intent["action"])
    resource = first.ctx.get("resource", intent["resource"])
    api = intent["action"].split(":")[1]
    if first.fault_class == "scp_block" and "RegionLock" not in str(first.ctx):
        reason = DENY_REASON["scp_block"]
    else:
        reason = DENY_REASON.get(first.fault_class, "")
    if not verbose:
        if intent["action"].startswith("s3:"):
            return f"An error occurred (AccessDenied) when calling the {api} operation: Access Denied"
        return f"An error occurred (AccessDeniedException) when calling the {api} operation: not authorized"
    msg = (f"An error occurred (AccessDenied) when calling the {api} operation: User: arn:aws:sts::{acct}:assumed-role/"
           f"{role['name']}/session-{random.Random(len(resource)).randint(1000, 9999)} is not authorized to perform: {action} "
           f"on resource: {resource} " + reason.format(a=action))
    return msg


def _flow_logs(snap, intent, result: Result):
    lines = []
    src = snap["compute"].get(intent["src"])
    if not src or not src.get("private_ip"):
        return lines
    first = result.failing[0]
    if first.layer not in ("security_group", "nacl"):
        return lines
    dst_ip = first.ctx.get("peer_ip") if first.id.startswith("src") else src["private_ip"]
    eni = "eni-0" + "%016x" % random.Random(intent["src"]).getrandbits(64)
    for i in range(2):
        lines.append(f"2 {snap['account_id']} {eni} {src['private_ip']} {dst_ip} {41000 + i * 37} {intent['port']} 6 1 60 "
                     f"1731300{i}00 1731300{i}60 REJECT OK")
    return lines


def write_ticket(snap: dict, intent: dict, result: Result, changes: list[str], level: str, rng: random.Random) -> dict:
    verbose = level == "L1"
    lines = [rng.choice(OPENERS), ""]
    when = rng.choice(TIMES)
    if intent["kind"] == "network":
        src, dst = intent["src"], intent["dst"]
        src_label = f"{_nm(snap, src)} ({src})" if verbose and src in snap.get("compute", {}) else _nm(snap, src)
        dst_label = dst if dst not in snap.get("compute", {}) else (f"{_nm(snap, dst)} ({dst})" if verbose else _nm(snap, dst))
        host = _host(snap, dst) if dst in snap.get("compute", {}) or dst in snap.get("external_hosts", {}) else dst
        to, refused = _client_cmd(intent["port"], host)
        sym = result.symptom
        if sym == "dns_failure":
            err = f"curl: (6) Could not resolve host: {dst}" if intent["port"] not in (5432, 3306) else \
                f'could not translate host name "{dst}" to address: Name or service not known'
            subject = f"{_nm(snap, src)} cannot resolve {dst}"
        elif sym == "connection_refused":
            err, subject = refused, f"Connection refused from {_nm(snap, src)} to {_nm(snap, dst)}"
        elif sym == "intermittent_timeout":
            err = to + "  (only some requests; retries often succeed)"
            subject = f"Intermittent timeouts between {_nm(snap, src)} and {_nm(snap, dst)}"
        else:
            err, subject = to, f"{_nm(snap, src)} cannot reach {_nm(snap, dst)} on port {intent['port']}"
        lines.append(f"Our setup: {intent['desc']}. {when.capitalize()} this is broken: traffic from {src_label} to "
                     f"{dst_label} on {intent.get('proto', 'tcp')}/{intent['port']} {'fails' if sym != 'intermittent_timeout' else 'fails intermittently'}.")
        lines.append("")
        lines.append("Error we see:" if verbose else "What we get (roughly):")
        lines.append("    " + (err if verbose else err.split(":")[0] + ": " + err.split(":")[-1].strip()))
        if verbose:
            fl = _flow_logs(snap, intent, result)
            if fl:
                lines += ["", "VPC flow log excerpt:"] + ["    " + l for l in fl]
    else:
        role = snap["iam"]["roles"][intent["principal"]]
        err = _iam_error(snap, intent, result, verbose)
        subject = f"AccessDenied for {role['name']} on {intent['action']}"
        res_txt = intent["resource"] if verbose else intent["resource"].split(":::")[-1].split(":")[-1]
        lines.append(f"Our setup: {intent['desc']}. {when.capitalize()} the call {intent['action']} made with role "
                     f"{role['name']} fails for {res_txt}.")
        lines += ["", "Error:", "    " + err]
    lines.append("")
    reds = rng.sample(RED_HERRINGS, 2 if verbose else 3)
    log = list(reds)
    if verbose:
        log += changes
    elif rng.random() < 0.5:
        log += ["Some infrastructure clean-up by the platform team (details unknown)"]
    rng.shuffle(log)
    lines.append("Recent changes we know about:")
    lines += [f"  - {c}" for c in log]
    lines += ["", rng.choice(TRIED), "Can you tell us what is wrong and how to fix it?"]
    return {"subject": subject, "body": "\n".join(lines)}
