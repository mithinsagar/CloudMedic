"""Symbolic diagnosis: evaluate the intent, rank the failing checks, then repair."""
from __future__ import annotations

import time

from .intents import evaluate_intent
from .repair import repair


def root_causes(snap: dict, intent: dict) -> tuple[list[dict], object]:
    """Failing checks in path order, de-duplicated by (fault_class, resource)."""
    result = evaluate_intent(snap, intent)
    out, seen = [], set()
    for c in result.failing:
        if c.fault_class is None:
            continue
        key = (c.fault_class, c.resource)
        if key in seen:
            continue
        seen.add(key)
        out.append({"fault_class": c.fault_class, "resource": c.resource, "explanation": c.detail, "check": c.id})
    return out, result


def diagnose(snap: dict, intent: dict, least_privilege: bool = True, universe: dict | None = None) -> dict:
    t0 = time.time()
    causes, result = root_causes(snap, intent)
    rep = repair(snap, intent, least_privilege=least_privilege, universe=universe)
    return {
        "intent": intent,
        "intent_ok_before": result.ok,
        "symptom": result.symptom,
        "trace": result.to_dict()["checks"],
        "root_causes": causes,
        "fix": rep.edits,
        "fix_verified": rep.verified,
        "repair_stats": rep.stats,
        "repair_log": rep.log,
        "repair_iterations": rep.iterations,
        "candidates_considered": rep.candidates,
        "seconds": time.time() - t0,
    }
