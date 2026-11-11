"""Prompts. The same ticket, snapshot, fault vocabulary and edit language are given to every system."""
from __future__ import annotations

import json

from ..edits import OPS
from ..taxonomy import FAULT_CLASSES

SYSTEM = ("You are a senior AWS Cloud Support Engineer. You diagnose customer tickets against a JSON snapshot of "
          "their AWS configuration and answer with strict JSON only, no prose outside the JSON.")

TAXONOMY_TXT = "\n".join(f"- {k}: {v}" for k, v in FAULT_CLASSES.items())
OPS_TXT = "\n".join(f"- {k} {v}" for k, v in OPS.items())

INTENT_SCHEMA = """The intent is what the customer expects to work, using IDs from the snapshot:
  network: {"kind": "network", "src": "<compute id or external host id>", "dst": "<compute id, external host id, or the DNS name the client uses>", "proto": "tcp", "port": <int>}
  iam:     {"kind": "iam", "principal": "<role id, e.g. role-app>", "action": "<service:Action>", "resource": "<full ARN of the object/resource>"}"""

CHECKLIST = """Work through this checklist in order before answering.
Connectivity: (1) DNS: does the name resolve from the source VPC (private hosted zone association, enableDnsSupport)?
(2) source security group egress, (3) source subnet NACL egress, (4) route table of the source subnet (local, igw, nat, pcx;
public IP needed for igw; Lambda never has a public IP; NAT gateway must be in a subnet routed to an igw; igw attached?),
(5) for peering: active status and a return route in the peer route table, (6) destination subnet NACL ingress,
(7) destination security group ingress, (8) is the service listening, (9) NACLs are stateless: the reply on the client's
ephemeral ports must be allowed outbound at the destination subnet and inbound at the source subnet (and at a NAT subnet).
Access denied: (1) explicit Deny in any policy (identity, boundary, SCP, bucket/key/queue policy, VPC endpoint policy),
(2) every SCP must allow, (3) VPC endpoint policy must allow, (4) permissions boundary must allow, (5) an identity policy
Allow with matching Action, Resource and Condition (or a resource policy naming the role); cross-account needs both,
(6) SSE-KMS objects also need kms:Decrypt / kms:GenerateDataKey allowed by the key policy (directly or via the account root
plus an identity policy). Prefer the narrowest fix: exact port and source, exact action and ARN; never open 0.0.0.0/0 or use
wildcards unless nothing narrower works, and do not delete guardrails when an exception is enough."""


def compact(snapshot: dict) -> str:
    return json.dumps(snapshot, separators=(",", ":"))


def inventory(snap: dict) -> str:
    lines = ["Compute:"]
    for k, c in snap.get("compute", {}).items():
        lines.append(f"  {k}: name={c['name']} kind={c['kind']} private_ip={c.get('private_ip')} public_ip={c.get('public_ip')}")
    lines.append("External hosts:")
    for k, h in snap.get("external_hosts", {}).items():
        lines.append(f"  {k}: name={h['name']} ip={h['ip']} hostname={h.get('hostname')}")
    lines.append("Private DNS names: " + ", ".join(n for z in snap.get("private_zones", {}).values() for n in z.get("records", {})))
    lines.append("IAM roles:")
    for k, r in snap.get("iam", {}).get("roles", {}).items():
        lines.append(f"  {k}: name={r['name']} account={r.get('account')}")
    lines.append("Resources:")
    for k, r in snap.get("resources", {}).items():
        lines.append(f"  {k} ({r['type']}, name={r['name']})")
    return "\n".join(lines)


def intent_prompt(ticket: dict, snap: dict, feedback: str | None = None) -> str:
    fb = f"\nA previous attempt was rejected: {feedback}\nRe-read the ticket and correct the intent.\n" if feedback else ""
    return f"""Read the support ticket and extract the single intent that is failing.

{INTENT_SCHEMA}
For S3 objects the ARN is arn:aws:s3:::<bucket>/<key>. Use the exact IDs from the inventory.
{fb}
Inventory:
{inventory(snap)}

Ticket subject: {ticket['subject']}
Ticket:
{ticket['body']}

Answer with JSON: {{"intent": {{...}}}}"""


def diagnose_prompt(ticket: dict, snap: dict, checklist: bool, feedback: str | None = None) -> str:
    cl = f"\n{CHECKLIST}\n" if checklist else ""
    fb = f"\nYour previous fix was applied and verified against the configuration, and it did NOT work:\n{feedback}\nRevise the diagnosis and the fix.\n" if feedback else ""
    return f"""Diagnose this AWS support ticket using the configuration snapshot.

Fault classes (use these names exactly):
{TAXONOMY_TXT}

Fix edit language (each edit is a JSON object with "op" plus the listed fields):
{OPS_TXT}
SG rules use "cidr" or "source_sg"; protocols are "tcp", "udp" or "-1"; policy statements are IAM JSON with a "Sid".

{INTENT_SCHEMA}
{cl}{fb}
Snapshot:
{compact(snap)}

Ticket subject: {ticket['subject']}
Ticket:
{ticket['body']}

Answer with JSON of this shape:
{{"intent": {{...}},
 "root_causes": [{{"fault_class": "<class>", "resource": "<id or ARN of the misconfigured resource>", "explanation": "<one sentence>"}}],
 "fix": [{{"op": "...", ...}}]}}
List up to three root causes, most likely first."""
