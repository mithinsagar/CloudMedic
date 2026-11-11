"""Per-scenario scoring and aggregate statistics.

Resource names are canonicalised for every system alike (a role ARN or role name counts as the
role id, a security-group name as its id, and so on), so systems are not penalised for naming
a resource differently from the snapshot key.
"""
from __future__ import annotations

import math
import random

from ..edits import apply_edits
from ..expansion import excess, expansion, fixed_universe, intent_keys, resolve_dst_id, surface
from ..intents import evaluate_intent

TABLES = ("vpcs", "subnets", "route_tables", "internet_gateways", "nat_gateways", "vpc_peerings", "vpc_endpoints",
          "security_groups", "nacls", "compute", "private_zones")


def canonical(snap: dict, ref) -> str:
    ref = str(ref)
    for table in TABLES:
        if ref in snap.get(table, {}):
            return ref
    for table in TABLES:
        for k, v in snap.get(table, {}).items():
            if isinstance(v, dict) and v.get("name") == ref:
                return k
    roles = snap.get("iam", {}).get("roles", {})
    for rid, r in roles.items():
        if ref in (rid, r["name"], f"arn:aws:iam::{r.get('account')}:role/{r['name']}"):
            return rid
    for pid, p in snap.get("iam", {}).get("policies", {}).items():
        if ref in (pid, p.get("name")):
            return pid
    for sid, p in snap.get("organizations", {}).get("scps", {}).items():
        if ref in (sid, p.get("name")):
            return sid
    for arn, r in snap.get("resources", {}).items():
        if ref == arn or ref == r.get("name") or (r["type"] == "s3_bucket" and ref.startswith(arn + "/")):
            return arn
    return ref


def _label_set(snap, labels):
    out = []
    for l in labels:
        out.append({(l["fault_class"], canonical(snap, l["resource"]))} |
                   {(l["fault_class"], canonical(snap, a)) for a in l.get("aliases", [])})
    return out


def _intent_match(snap, pred, gold) -> bool:
    if not pred or pred.get("kind") != gold["kind"]:
        return False
    if gold["kind"] == "network":
        try:
            return (pred.get("src") == gold["src"] and resolve_dst_id(snap, str(pred.get("dst"))) == resolve_dst_id(snap, gold["dst"])
                    and int(pred.get("port")) == int(gold["port"]))
        except (TypeError, ValueError):
            return False
    return pred.get("principal") == gold["principal"] and str(pred.get("action", "")).lower() == gold["action"].lower() \
        and pred.get("resource") == gold["resource"]


def score(scn: dict, pred: dict, cache: dict | None = None) -> dict:
    snap, gold = scn["snapshot"], scn["gold"]
    labels = _label_set(snap, gold["labels"])
    rc = [(c["fault_class"], canonical(snap, c["resource"])) for c in pred.get("root_causes", [])]
    classes = [c[0] for c in rc]
    gold_classes = {l["fault_class"] for l in gold["labels"]}
    top1 = bool(rc) and any(rc[0] in ls for ls in labels)
    top3 = any(any(r in ls for r in rc[:3]) for ls in labels)
    recall3 = sum(any(r in ls for r in rc[:3]) for ls in labels) / len(labels)

    fixed, applied, errs = apply_edits(snap, pred.get("fix", []))
    success = evaluate_intent(fixed, gold["intent"]).ok
    if cache is None:
        cache = {}
    if "uni" not in cache:
        cache["uni"] = fixed_universe(scn["healthy_snapshot"])
        cache["healthy"] = surface(scn["healthy_snapshot"], cache["uni"])
        cache["broken"] = surface(snap, cache["uni"])
    after = surface(fixed, cache["uni"])
    ik = intent_keys(gold["intent"], snap)
    ex = excess(cache["healthy"], cache["broken"], after, ik, snap)
    reg = expansion(cache["broken"], after, ik, snap)
    healthy_intents_broken = sum(1 for it in scn["healthy_intents"]
                                 if evaluate_intent(scn["healthy_snapshot"], it).ok and evaluate_intent(snap, it).ok
                                 and not evaluate_intent(fixed, it).ok)
    return {
        "id": scn["id"], "template": scn["template"], "difficulty": scn["difficulty"],
        "gold_classes": sorted(gold_classes), "multi": len(gold["labels"]) > 1,
        "intent_exact": _intent_match(snap, pred.get("intent"), gold["intent"]),
        "rca_top1": top1, "rca_top3": top3, "label_recall3": recall3,
        "class_top1": bool(classes) and classes[0] in gold_classes,
        "n_edits": len(pred.get("fix", [])), "invalid_edits": len(errs), "hallucinated": len(errs) > 0,
        "fix_success": success,
        "excess_total": ex["total_gained"], "excess_internet": ex["internet_exposure"], "excess_iam": ex["iam_gained"],
        "excess_sensitive": ex["iam_sensitive_gained"], "excess_examples": ex["examples_gained"][:3],
        "regression_lost": reg["total_lost"], "healthy_intents_broken": healthy_intents_broken,
        "safe_fix": success and ex["total_gained"] == 0 and reg["total_lost"] == 0,
        "over_privileged": success and ex["total_gained"] > 0,
        "seconds": pred.get("meta", {}).get("seconds", 0.0), "tokens": pred.get("meta", {}).get("tokens", 0),
        "llm_calls": pred.get("meta", {}).get("llm_calls", 0),
    }


# ------------------------------------------------------------------ statistics

def bootstrap_ci(values, n=2000, seed=0, alpha=0.05):
    if not values:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    k = len(values)
    means = sorted(sum(values[rng.randrange(k)] for _ in range(k)) / k for _ in range(n))
    return means[int(n * alpha / 2)], means[int(n * (1 - alpha / 2)) - 1]


def mcnemar_exact(a: list[bool], b: list[bool]) -> dict:
    """Exact two-sided McNemar test on paired binary outcomes."""
    n01 = sum(1 for x, y in zip(a, b) if not x and y)
    n10 = sum(1 for x, y in zip(a, b) if x and not y)
    n = n01 + n10
    if n == 0:
        return {"b_only": n01, "a_only": n10, "p": 1.0}
    k = min(n01, n10)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return {"a_only": n10, "b_only": n01, "p": min(1.0, 2 * p)}


METRICS = ["intent_exact", "rca_top1", "rca_top3", "class_top1", "label_recall3", "fix_success", "safe_fix", "over_privileged",
           "hallucinated", "excess_total", "excess_internet", "excess_sensitive", "regression_lost", "seconds"]


def aggregate(rows: list[dict]) -> dict:
    out = {"n": len(rows)}
    for m in METRICS:
        vals = [float(r[m]) for r in rows]
        mean = sum(vals) / len(vals) if vals else float("nan")
        lo, hi = bootstrap_ci(vals)
        out[m] = {"mean": mean, "ci95": [lo, hi]}
    return out
