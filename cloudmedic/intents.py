"""An intent is the formal statement of what the customer expects to work.

    network: {"kind": "network", "src": <compute|external id>, "dst": <id|hostname>, "proto": "tcp", "port": 5432}
    iam:     {"kind": "iam", "principal": <role id>, "action": "s3:GetObject", "resource": <arn>, "context": {...}}
"""
from __future__ import annotations

from .checks import Check, Result, FAIL
from .iam import evaluate_request
from .network import evaluate_flow


def evaluate_intent(snap: dict, intent: dict, ignore_listening: bool = False) -> Result:
    try:
        if intent.get("kind") == "network":
            return evaluate_flow(snap, intent["src"], intent["dst"], intent.get("proto", "tcp"), int(intent["port"]),
                                 ignore_listening=ignore_listening)
        if intent.get("kind") == "iam":
            return evaluate_request(snap, intent["principal"], intent["action"], intent["resource"], intent.get("context"))
    except (KeyError, TypeError, ValueError) as e:
        return Result(False, [Check("intent", "inventory", None, FAIL, f"malformed intent: {e!r}")], "malformed_intent")
    return Result(False, [Check("intent", "inventory", None, FAIL, f"unknown intent kind {intent.get('kind')}")], "malformed_intent")


def intent_key(intent: dict) -> tuple:
    if intent["kind"] == "network":
        return ("network", intent["src"], intent["dst"], intent.get("proto", "tcp"), int(intent["port"]))
    return ("iam", intent["principal"], intent["action"], intent["resource"])


def describe(intent: dict) -> str:
    if intent["kind"] == "network":
        return f"{intent['src']} -> {intent['dst']} {intent.get('proto', 'tcp')}/{intent['port']}"
    return f"{intent['principal']} {intent['action']} {intent['resource']}"
