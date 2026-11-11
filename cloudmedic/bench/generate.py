"""Benchmark generation: templates x seeds x intents x fault operators, validated and balanced.

Validation applied to every scenario (failures are dropped and counted in the stats):
  V1 the fault breaks the target intent
  V2 the reference fix applies cleanly in the edit language and restores the intent
  V3 the reference fix restores the exact healthy access surface (no residual drift)
  V4 (multi-fault) each fault's fix alone leaves the intent broken; both together fix it
We also record whether the evaluator's own diagnosis agrees with the construction label
(label/evaluator agreement), reported in the dataset card rather than used as a filter.
"""
from __future__ import annotations

import argparse
import collections
import copy
import json
import random
from pathlib import Path

from ..edits import apply_edits
from ..expansion import fixed_universe, surface
from ..intents import evaluate_intent, intent_key
from .mutations import candidate_faults, replay
from .templates import TEMPLATES
from .tickets import write_ticket


def _agrees(result, label):
    for c in result.failing:
        if c.fault_class == label["fault_class"] and (c.resource == label["resource"] or c.resource in label["aliases"]):
            return True
    return False


def _collateral(snap, intents, target):
    return [it["desc"] for it in intents if intent_key(it) != intent_key(target) and not evaluate_intent(snap, it).ok]


def build_pool(seeds, stats):
    pool = []
    for tname, tfn in TEMPLATES.items():
        for seed in seeds:
            b = tfn(random.Random(f"{tname}:{seed}"))
            healthy = b.snap
            uni = fixed_universe(healthy)
            healthy_surface = surface(healthy, uni)
            rng = random.Random(f"faults:{tname}:{seed}")
            for ii, intent in enumerate(b.intents):
                trace = evaluate_intent(healthy, intent)
                assert trace.ok, (tname, seed, intent)
                for f in candidate_faults(healthy, intent, trace, rng):
                    stats["candidates"] += 1
                    r = evaluate_intent(f["snap"], intent)
                    if r.ok:
                        stats["drop_v1_not_broken"] += 1
                        continue
                    fixed, _, errs = apply_edits(f["snap"], f["reference_fix"])
                    if errs or not evaluate_intent(fixed, intent).ok:
                        stats["drop_v2_fix_invalid"] += 1
                        continue
                    if surface(fixed, uni) != healthy_surface:
                        stats["drop_v3_surface_drift"] += 1
                        continue
                    f.update(template=tname, seed=seed, intent_index=ii, intent=intent, healthy=healthy, intents=b.intents,
                             agree=_agrees(r, f["label"]), result=r, trace=trace)
                    pool.append(f)
    return pool


def compose(f1, f2, stats):
    """Inject f2's fault on top of f1's snapshot; keep only genuinely jointly-necessary pairs (V4)."""
    stats["multi_candidates"] += 1
    if f1["label"]["resource"] == f2["label"]["resource"] or f1["label"]["fault_class"] == f2["label"]["fault_class"]:
        return None
    g = replay(f2["recipe"], copy.deepcopy(f1["snap"]), f1["intent"], f1["trace"])
    if g is None:
        return None
    snap = g["snap"]
    intent = f1["intent"]
    if evaluate_intent(snap, intent).ok:
        return None
    for fix in (f1["reference_fix"], g["reference_fix"]):
        s, _, errs = apply_edits(snap, fix)
        if errs or evaluate_intent(s, intent).ok:
            stats["drop_v4_not_jointly_necessary"] += 1
            return None
    s, _, errs = apply_edits(snap, g["reference_fix"] + f1["reference_fix"])
    if errs or not evaluate_intent(s, intent).ok:
        stats["drop_v4_fix_invalid"] += 1
        return None
    uni = fixed_universe(f1["healthy"])
    if surface(s, uni) != surface(f1["healthy"], uni):
        stats["drop_v3_surface_drift"] += 1
        return None
    r = evaluate_intent(snap, intent)
    return {**f1, "snap": snap, "labels": [f1["label"], g["label"]], "reference_fix": g["reference_fix"] + f1["reference_fix"],
            "changes": [f1["change"], g["change"]], "operators": [f1["operator"], g["operator"]],
            "agree": _agrees(r, f1["label"]) and _agrees(r, g["label"]), "result": r}


def to_scenario(f, sid, level, rng):
    labels = f.get("labels") or [f["label"]]
    changes = f.get("changes") or [f["change"]]
    return {
        "id": sid, "template": f["template"], "seed": f["seed"], "difficulty": level,
        "ticket": write_ticket(f["snap"], f["intent"], f["result"], changes, level, rng),
        "snapshot": f["snap"],
        "gold": {
            "intent": {k: v for k, v in f["intent"].items() if k != "desc"},
            "labels": labels,
            "reference_fix": f["reference_fix"],
            "operators": f.get("operators") or [f["operator"]],
            "changes": changes,
            "symptom": f["result"].symptom,
            "label_evaluator_agreement": f["agree"],
            "collateral_broken_intents": _collateral(f["snap"], f["intents"], f["intent"]),
        },
        "healthy_snapshot": f["healthy"],
        "healthy_intents": [{k: v for k, v in it.items()} for it in f["intents"]],
    }


def balanced_sample(pool, per_class, rng):
    by_class = collections.defaultdict(list)
    for f in pool:
        by_class[f["label"]["fault_class"]].append(f)
    chosen = []
    for cls in sorted(by_class):
        items = by_class[cls]
        rng.shuffle(items)
        # spread across templates and operators before taking repeats
        items.sort(key=lambda f: sum(1 for g in chosen if g["template"] == f["template"] and g["operator"] == f["operator"]))
        seen_ops = collections.Counter()
        picked = []
        for f in items:
            if len(picked) >= per_class:
                break
            key = (f["template"], f["operator"], f["intent_index"])
            if seen_ops[key] >= 2:
                continue
            seen_ops[key] += 1
            picked.append(f)
        for f in items:  # rare classes: fill from what is left once diversity is exhausted
            if len(picked) >= per_class:
                break
            if not any(f is p for p in picked):
                picked.append(f)
        chosen += picked
    return chosen


def generate(out_dir: Path, split: str, seeds, per_class: int, n_multi: int, seed: int):
    stats = collections.Counter()
    rng = random.Random(f"{split}:{seed}")
    pool = build_pool(seeds, stats)
    stats["valid_single_pool"] = len(pool)
    singles = balanced_sample(pool, per_class, rng)
    groups = collections.defaultdict(list)
    for f in pool:
        groups[(f["template"], f["seed"], f["intent_index"])].append(f)
    multis, keys = [], list(groups)
    rng.shuffle(keys)
    attempts = 0
    while len(multis) < n_multi and attempts < 20000:
        attempts += 1
        k = rng.choice(keys)
        if len(groups[k]) < 2:
            continue
        f1, f2 = rng.sample(groups[k], 2)
        m = compose(f1, f2, stats)
        if m and not any(set(map(lambda l: (l["fault_class"], l["resource"]), m["labels"])) ==
                         set(map(lambda l: (l["fault_class"], l["resource"]), x["labels"])) and x["template"] == m["template"]
                         and x["seed"] == m["seed"] for x in multis):
            multis.append(m)
    scenarios = []
    for i, f in enumerate(singles):
        scenarios.append(to_scenario(f, f"{split}-{i:04d}", rng.choice(["L1", "L2"]), rng))
    for j, m in enumerate(multis):
        scenarios.append(to_scenario(m, f"{split}-m{j:03d}", "L3", rng))
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"{split}.jsonl", "w") as fh:
        for s in scenarios:
            fh.write(json.dumps(s) + "\n")
    card = {
        "split": split, "seeds": list(seeds), "n_scenarios": len(scenarios), "n_single": len(singles), "n_multi": len(multis),
        "per_class": dict(collections.Counter(l["fault_class"] for s in scenarios for l in s["gold"]["labels"])),
        "per_template": dict(collections.Counter(s["template"] for s in scenarios)),
        "per_difficulty": dict(collections.Counter(s["difficulty"] for s in scenarios)),
        "per_operator": dict(collections.Counter(o for s in scenarios for o in s["gold"]["operators"])),
        "label_evaluator_agreement": sum(s["gold"]["label_evaluator_agreement"] for s in scenarios) / max(1, len(scenarios)),
        "pool_label_evaluator_agreement": sum(f["agree"] for f in pool) / max(1, len(pool)),
        "validation": dict(stats),
    }
    (out_dir / f"{split}_card.json").write_text(json.dumps(card, indent=2))
    return card


def main():
    ap = argparse.ArgumentParser(description="Generate the CloudMedic benchmark")
    ap.add_argument("--out", default="data")
    ap.add_argument("--per-class-dev", type=int, default=3)
    ap.add_argument("--per-class-test", type=int, default=10)
    ap.add_argument("--multi-dev", type=int, default=10)
    ap.add_argument("--multi-test", type=int, default=50)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    out = Path(a.out)
    for split, seeds, pc, nm in (("dev", range(0, 3), a.per_class_dev, a.multi_dev),
                                 ("test", range(100, 112), a.per_class_test, a.multi_test)):
        card = generate(out, split, seeds, pc, nm, a.seed)
        print(json.dumps({k: card[k] for k in ("split", "n_scenarios", "n_single", "n_multi", "label_evaluator_agreement",
                                               "pool_label_evaluator_agreement", "validation")}, indent=1))


if __name__ == "__main__":
    main()
