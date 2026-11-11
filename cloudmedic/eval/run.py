"""Run systems over a split and score them. Resumable: finished scenario IDs are skipped.

    python -m cloudmedic.eval.run --split test --systems symbolic_oracle symbolic_rules
    python -m cloudmedic.eval.run --split test --subset core --model qwen2.5-7b --systems cloudmedic llm_only
"""
from __future__ import annotations

import argparse
import collections
import json
import random
import time
from pathlib import Path

from ..systems import NEEDS_LLM, SYSTEMS
from .metrics import score


def load_split(path: Path) -> list[dict]:
    return [json.loads(l) for l in open(path)]


def core_subset(scenarios: list[dict], per_class: int = 4, seed: int = 11) -> list[dict]:
    """Stratified subset for the expensive LLM baselines: `per_class` single-fault scenarios per
    fault class (spread over templates and difficulties) plus every multi-fault scenario."""
    rng = random.Random(seed)
    singles = [s for s in scenarios if len(s["gold"]["labels"]) == 1]
    multis = [s for s in scenarios if len(s["gold"]["labels"]) > 1]
    by_cls = collections.defaultdict(list)
    for s in singles:
        by_cls[s["gold"]["labels"][0]["fault_class"]].append(s)
    chosen = []
    for cls in sorted(by_cls):
        items = by_cls[cls][:]
        rng.shuffle(items)
        picked, seen = [], collections.Counter()
        while items and len(picked) < per_class:
            items.sort(key=lambda s: (seen[s["template"]], seen[s["difficulty"]]))
            s = items.pop(0)
            seen[s["template"]] += 1
            seen[s["difficulty"]] += 1
            picked.append(s)
        chosen += picked
    return sorted(chosen + multis, key=lambda s: s["id"])


def run(split: str, systems: list[str], model: str | None, subset: str, out_root: Path, limit: int | None = None):
    scns = load_split(Path("data") / f"{split}.jsonl")
    if subset == "core":
        scns = core_subset(scns)
    if limit:
        scns = scns[:limit]
    llm = None
    if any(s in NEEDS_LLM for s in systems):
        from ..llm.backend import MLXBackend
        llm = MLXBackend(model or "qwen2.5-7b")
    tag = model if model else "nollm"
    for sysname in systems:
        out = out_root / split / subset / f"{sysname}__{tag if sysname in NEEDS_LLM else 'nollm'}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        done = set()
        if out.exists():
            done = {json.loads(l)["id"] for l in open(out)}
        t0 = time.time()
        with open(out, "a") as fh:
            for i, scn in enumerate(scns):
                if scn["id"] in done:
                    continue
                pred = SYSTEMS[sysname](scn, llm)
                row = score(scn, pred)
                fh.write(json.dumps({"id": scn["id"], "system": sysname, "model": tag if sysname in NEEDS_LLM else None,
                                     "prediction": pred, "score": row}) + "\n")
                fh.flush()
                print(f"[{sysname}/{tag}] {i + 1}/{len(scns)} {scn['id']} top1={row['rca_top1']} fix={row['fix_success']} "
                      f"safe={row['safe_fix']} {row['seconds']:.1f}s", flush=True)
        print(f"[{sysname}/{tag}] finished in {time.time() - t0:.0f}s -> {out}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    ap.add_argument("--subset", default="all", choices=["all", "core"])
    ap.add_argument("--systems", nargs="+", default=["symbolic_oracle"])
    ap.add_argument("--model", default=None)
    ap.add_argument("--out", default="results/runs")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    run(a.split, a.systems, a.model, a.subset, Path(a.out), a.limit)


if __name__ == "__main__":
    main()
