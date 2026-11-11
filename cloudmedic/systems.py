"""The systems compared in the evaluation. Each maps (ticket, snapshot) to a prediction:
    {"intent": ..., "root_causes": [{"fault_class", "resource", ...}], "fix": [edits], "meta": {...}}
Gold labels and the healthy snapshot are never visible to any system except `symbolic_oracle`,
which receives only the gold intent (an upper bound that isolates intent extraction).
"""
from __future__ import annotations

import re
import time

from .diagnose import diagnose
from .edits import apply_edits
from .intents import evaluate_intent
from .llm.backend import parse_json
from .llm.prompts import SYSTEM, diagnose_prompt, intent_prompt


def _empty(meta):
    return {"intent": None, "root_causes": [], "fix": [], "meta": meta}


def _clean_causes(rc):
    out = []
    for c in rc or []:
        if isinstance(c, dict) and c.get("fault_class"):
            out.append({"fault_class": str(c.get("fault_class")), "resource": str(c.get("resource")),
                        "explanation": str(c.get("explanation", ""))[:400]})
    return out[:3]


def _clean_fix(fix):
    return [e for e in (fix or []) if isinstance(e, dict)]


def intent_status(snap, intent) -> str:
    """"invalid" if the intent names things the snapshot does not have, else "ok" or "failing"."""
    r = evaluate_intent(snap, intent)
    if r.ok:
        return "ok"
    if any(c.fault_class is None for c in r.failing):
        return "invalid"
    return "failing"


def _normalise_intent(it, snap=None):
    """Accept {"kind": ...}, a {"network": {...}} wrapper, or both kinds side by side. When several
    candidates are present, keep the one that is well-formed and actually fails in the snapshot
    (the ticket reports something broken), so the verifier, not position, decides."""
    if not isinstance(it, dict):
        return None
    if "kind" not in it and set(it) & {"network", "iam"}:
        cands = [_normalise_intent({"kind": k, **v}, snap) for k, v in it.items()
                 if k in ("network", "iam") and isinstance(v, dict) and v]
        cands = [c for c in cands if c]
        if snap is not None:
            for want in ("failing", "ok"):
                for c in cands:
                    if intent_status(snap, c) == want:
                        return c
        return cands[0] if cands else None
    it = dict(it)
    if snap and it.get("kind") == "iam" and isinstance(it.get("principal"), str):
        for rid in snap.get("iam", {}).get("roles", {}):
            r = snap["iam"]["roles"][rid]
            if it["principal"] in (f"arn:aws:iam::{r.get('account')}:role/{r['name']}", r["name"]):
                it["principal"] = rid
    if it.get("kind") == "network":
        try:
            it["port"] = int(it.get("port"))
        except (TypeError, ValueError):
            return None
        it.setdefault("proto", "tcp")
    return it


# ------------------------------------------------------------------ LLM baselines

def llm_direct(scn, llm, checklist: bool, verify_rounds: int = 0):
    t0 = time.time()
    snap, ticket = scn["snapshot"], scn["ticket"]
    feedback, calls, tokens = None, 0, 0
    pred = None
    for rnd in range(verify_rounds + 1):
        r = llm.complete(SYSTEM, diagnose_prompt(ticket, snap, checklist, feedback))
        calls += 1
        tokens += r.get("prompt_tokens", 0) + r.get("completion_tokens", 0)
        js = parse_json(r["text"]) or {}
        cur = {"intent": _normalise_intent(js.get("intent"), snap), "root_causes": _clean_causes(js.get("root_causes")),
               "fix": _clean_fix(js.get("fix")), "customer_reply": js.get("customer_reply", "")}
        if pred is None or cur["fix"] or cur["root_causes"]:
            pred = cur
        if rnd == verify_rounds:
            break
        # verifier feedback uses only the model's own intent, never the gold one
        fixed, applied, errs = apply_edits(snap, cur["fix"])
        if cur["intent"] is None:
            feedback = "your answer had no usable intent, so the fix could not be checked."
            continue
        res = evaluate_intent(fixed, cur["intent"])
        if res.ok and not errs:
            break
        lines = [f"- edit rejected: {msg}" for _, msg in errs[:5]]
        lines += [f"- still failing: {c.detail}" for c in res.failing[:5]]
        feedback = "\n".join(lines) or "the intent still fails."
    pred["meta"] = {"llm_calls": calls, "tokens": tokens, "seconds": time.time() - t0, "parse_ok": bool(pred["root_causes"] or pred["fix"])}
    return pred


# ------------------------------------------------------------------ CloudMedic (hybrid)

def extract_intent(scn, llm, max_tries: int = 3):
    snap, ticket = scn["snapshot"], scn["ticket"]
    feedback, intent, calls, tokens = None, None, 0, 0
    for _ in range(max_tries):
        r = llm.complete(SYSTEM, intent_prompt(ticket, snap, feedback), max_tokens=300)
        calls += 1
        tokens += r.get("prompt_tokens", 0) + r.get("completion_tokens", 0)
        js = parse_json(r["text"]) or {}
        cand = _normalise_intent(js.get("intent", js if "kind" in js else None), snap)
        if cand is None:
            feedback = "the answer was not a valid intent object."
            continue
        res = evaluate_intent(snap, cand)
        status = intent_status(snap, cand)
        if status == "invalid":
            bad = next(c for c in res.failing if c.fault_class is None)
            feedback = f"the intent references something not in the snapshot ({bad.detail})."
            continue
        intent = cand
        if status == "ok":
            feedback = (f"that intent ({cand}) succeeds in the snapshot, so it cannot be what the ticket reports as broken; "
                        "check source, destination/hostname, port, role, action and the exact resource ARN.")
            continue
        break
    return intent, {"llm_calls": calls, "tokens": tokens}


def cloudmedic(scn, llm, least_privilege: bool = True, intent=None, extract_meta=None):
    t0 = time.time()
    meta = dict(extract_meta or {})
    if intent is None and llm is not None:
        intent, meta = extract_intent(scn, llm)
    if intent is None:
        return _empty({**meta, "seconds": time.time() - t0, "intent_failed": True})
    d = diagnose(scn["snapshot"], intent, least_privilege=least_privilege)
    return {"intent": intent, "root_causes": d["root_causes"][:3], "fix": d["fix"],
            "meta": {**meta, "seconds": time.time() - t0, "repair_iterations": d["repair_iterations"],
                     "candidates": d["candidates_considered"], "fix_verified": d["fix_verified"], "repair_log": d["repair_log"]}}


# ------------------------------------------------------------------ rule-based intent parser (no LLM)

ARN_RE = re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d*:[^\s,)]+")
ACTION_RE = re.compile(r"\b([a-z0-9-]+:[A-Z][A-Za-z]+)\b")


def rule_intent(scn):
    snap, t = scn["snapshot"], scn["ticket"]
    text = t["subject"] + "\n" + t["body"]
    roles = snap.get("iam", {}).get("roles", {})
    role = next((rid for rid, r in roles.items() if r["name"] in text), None)
    action = ACTION_RE.search(text)
    if role and action:
        arn = ARN_RE.search(text)
        res = arn.group(0) if arn else None
        if res is None:
            for rarn, rec in snap.get("resources", {}).items():
                m = re.search(re.escape(rec["name"]) + r"(/[^\s]*)?", text)
                if m and rec["type"] == "s3_bucket":
                    res = rarn + (m.group(1) or "").rstrip(".")
                    break
                if m:
                    res = rarn
        if res:
            return {"kind": "iam", "principal": role, "action": action.group(1), "resource": res.rstrip(".")}
    port = re.search(r"(?:tcp/|port )(\d+)", text)
    m = re.search(r"from (.+?) to (.+?) on", text)
    if not (port and m):
        return None

    def find(label):
        label = label.strip()
        for table in ("compute", "external_hosts"):
            for k, v in snap.get(table, {}).items():
                if k in label or v.get("name") == label.split(" (")[0]:
                    return k
        for z in snap.get("private_zones", {}).values():
            if label in z.get("records", {}):
                return label
        for k, h in snap.get("external_hosts", {}).items():
            if h.get("hostname") and h["hostname"] in label:
                return h["hostname"]
        return None
    src, dst = find(m.group(1)), find(m.group(2))
    if not (src and dst):
        return None
    return {"kind": "network", "src": src, "dst": dst, "proto": "tcp", "port": int(port.group(1))}


SYSTEMS = {
    "llm_only": lambda scn, llm: llm_direct(scn, llm, checklist=False),
    "llm_checklist": lambda scn, llm: llm_direct(scn, llm, checklist=True),
    "llm_verifier_loop": lambda scn, llm: llm_direct(scn, llm, checklist=True, verify_rounds=2),
    "cloudmedic": lambda scn, llm: cloudmedic(scn, llm),
    "cloudmedic_no_lp": lambda scn, llm: cloudmedic(scn, llm, least_privilege=False),
    "symbolic_rules": lambda scn, llm: cloudmedic(scn, None, intent=rule_intent(scn)),
    "symbolic_oracle": lambda scn, llm: cloudmedic(scn, None, intent=scn["gold"]["intent"]),
}
NEEDS_LLM = {"llm_only", "llm_checklist", "llm_verifier_loop", "cloudmedic", "cloudmedic_no_lp"}
