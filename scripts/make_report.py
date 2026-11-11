"""Build every table, statistic and figure in the paper from the raw run files.

Nothing is typed by hand: a cell whose run is missing prints PENDING. Re-run after any experiment.

    .venv/bin/python scripts/make_report.py
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloudmedic.eval.metrics import aggregate, bootstrap_ci, mcnemar_exact  # noqa: E402
from cloudmedic.taxonomy import IAM_CLASSES, NETWORK_CLASSES  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "results" / "runs" / "test"
OUT = ROOT / "results"
TAB = OUT / "tables"
FIG = OUT / "figures"
TAB.mkdir(parents=True, exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)

# palette: reference categorical slot 1 for the proposed system, secondary ink for baselines
BLUE, GRAY, INK, INK2, SURFACE, GRID = "#2a78d6", "#a3a29c", "#0b0b0b", "#52514e", "#fcfcfb", "#e6e5e0"

SYSTEMS = [  # (file stem, display name)
    ("llm_only__qwen2.5-7b", "LLM only (7B)"),
    ("llm_checklist__qwen2.5-7b", "LLM + checklist (7B)"),
    ("llm_verifier_loop__qwen2.5-7b", "LLM + verifier loop (7B)"),
    ("symbolic_rules__nollm", "Symbolic + template parser"),
    ("cloudmedic_no_lp__qwen2.5-7b", "CloudMedic, no LP cost (7B)"),
    ("cloudmedic__qwen2.5-7b", "CloudMedic (7B)"),
    ("llm_checklist__qwen2.5-3b", "LLM + checklist (3B)"),
    ("cloudmedic__qwen2.5-3b", "CloudMedic (3B)"),
    ("symbolic_oracle__nollm", "Oracle intent (upper bound)"),
]
MAIN = "cloudmedic__qwen2.5-7b"


def load(subset, stem):
    p = RUNS / subset / f"{stem}.jsonl"
    if not p.exists():
        return None
    rows = [json.loads(l)["score"] for l in open(p)]
    return rows


def pct(m):
    return f"{100 * m['mean']:.1f} [{100 * m['ci95'][0]:.1f}, {100 * m['ci95'][1]:.1f}]"


def num(m, d=2):
    return f"{m['mean']:.{d}f}"


def complete(rows, n_expected):
    return rows is not None and len(rows) == n_expected


def main_table(subset, n_expected):
    cols = [("intent_exact", "Intent", pct), ("rca_top1", "RCA@1", pct), ("rca_top3", "RCA@3", pct), ("fix_success", "Fix works", pct),
            ("safe_fix", "Safe fix", pct), ("over_privileged", "Over-priv.", pct), ("hallucinated", "Invalid edit", pct),
            ("excess_total", "Excess (mean)", num), ("seconds", "Sec/ticket", lambda m: f"{m['mean']:.1f}")]
    md = ["| System | n | " + " | ".join(c[1] for c in cols) + " |", "|" + "---|" * (len(cols) + 2)]
    tex = []
    summary = {}
    for stem, name in SYSTEMS:
        rows = load(subset, stem)
        if not complete(rows, n_expected):
            done = 0 if rows is None else len(rows)
            md.append(f"| {name} | {done}/{n_expected} | " + " | ".join("PENDING" for _ in cols) + " |")
            tex.append(f"{name} & \\multicolumn{{{len(cols)}}}{{c}}{{PENDING ({done}/{n_expected})}} \\\\")
            continue
        agg = aggregate(rows)
        summary[stem] = agg
        cells = [f(agg[k]) for k, _, f in cols]
        md.append(f"| {name} | {agg['n']} | " + " | ".join(cells) + " |")
        tcells = [c.split(" [")[0] for c in cells]
        tex.append(f"{name} & " + " & ".join(tcells) + " \\\\")
    (TAB / f"main_{subset}.md").write_text("\n".join(md) + "\n\nPercentages with 95% bootstrap CI. Intent = exact intent extraction; "
                                           "RCA@k = a gold (class, resource) among the top k; Safe fix = fix works, zero excess privilege, "
                                           "zero regression; Over-priv. = fix works but grants access beyond the healthy and pre-fix "
                                           "configuration; Invalid edit = at least one edit references a missing resource or is malformed.\n")
    (TAB / f"main_{subset}.tex").write_text("\n".join(tex) + "\n")
    return summary


def significance(subset):
    base = load(subset, MAIN)
    if base is None:
        return "PENDING\n"
    by_id = {r["id"]: r for r in base}
    lines = ["| CloudMedic (7B) vs | metric | CloudMedic only | baseline only | exact McNemar p |", "|---|---|---|---|---|"]
    for stem, name in SYSTEMS:
        if stem == MAIN:
            continue
        rows = load(subset, stem)
        if rows is None:
            continue
        common = [r for r in rows if r["id"] in by_id]
        for metric in ("fix_success", "safe_fix", "rca_top1"):
            t = mcnemar_exact([by_id[r["id"]][metric] for r in common], [r[metric] for r in common])
            lines.append(f"| {name} (n={len(common)}) | {metric} | {t['a_only']} | {t['b_only']} | {t['p']:.2g} |")
    text = "\n".join(lines) + "\n"
    (TAB / f"significance_{subset}.md").write_text(text)
    return text


def breakdown(subset):
    lines = ["| System | " + " | ".join(["Network RCA@1", "IAM RCA@1", "Network safe", "IAM safe", "L1 safe", "L2 safe", "L3 (multi) safe", "L3 label recall@3"]) + " |",
             "|" + "---|" * 9]
    for stem, name in SYSTEMS:
        rows = load(subset, stem)
        if rows is None:
            continue

        def m(filt, key):
            xs = [float(r[key]) for r in rows if filt(r)]
            return f"{100 * sum(xs) / len(xs):.1f}" if xs else "n/a"
        net = lambda r: set(r["gold_classes"]) <= NETWORK_CLASSES
        iam = lambda r: set(r["gold_classes"]) <= IAM_CLASSES
        lines.append(f"| {name} | " + " | ".join([
            m(net, "rca_top1"), m(iam, "rca_top1"), m(net, "safe_fix"), m(iam, "safe_fix"),
            m(lambda r: r["difficulty"] == "L1", "safe_fix"), m(lambda r: r["difficulty"] == "L2", "safe_fix"),
            m(lambda r: r["difficulty"] == "L3", "safe_fix"), m(lambda r: r["difficulty"] == "L3", "label_recall3")]) + " |")
    (TAB / f"breakdown_{subset}.md").write_text("\n".join(lines) + "\n")


def dataset_table():
    card = json.loads((ROOT / "data" / "test_card.json").read_text())
    dev = json.loads((ROOT / "data" / "dev_card.json").read_text())
    lines = ["| Fault class | family | test labels |", "|---|---|---|"]
    for cls, n in sorted(card["per_class"].items()):
        lines.append(f"| {cls} | {'network' if cls in NETWORK_CLASSES else 'IAM'} | {n} |")
    v = card["validation"]
    lines += ["", f"Test split: {card['n_scenarios']} scenarios ({card['n_single']} single-fault, {card['n_multi']} multi-fault), "
              f"{len(card['per_class'])} fault classes, {len(card['per_template'])} architectures, seeds {card['seeds'][0]}-{card['seeds'][-1]}. "
              f"Dev split: {dev['n_scenarios']} scenarios (seeds {dev['seeds'][0]}-{dev['seeds'][-1]}).",
              f"Candidate faults generated: {v.get('candidates')}; dropped because the intent still worked (V1): {v.get('drop_v1_not_broken', 0)}; "
              f"reference fix invalid (V2): {v.get('drop_v2_fix_invalid', 0)}; surface drift (V3): {v.get('drop_v3_surface_drift', 0)}; "
              f"multi-fault pairs rejected as not jointly necessary (V4): {v.get('drop_v4_not_jointly_necessary', 0)}.",
              f"Label/evaluator agreement on the valid pool: {100 * card['pool_label_evaluator_agreement']:.1f}%; on the released test split: "
              f"{100 * card['label_evaluator_agreement']:.1f}%.",
              f"Difficulty: {card['per_difficulty']}. Templates: {card['per_template']}."]
    (TAB / "dataset.md").write_text("\n".join(lines) + "\n")


def figures(subset, n_expected):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                         "axes.spines.top": False, "axes.spines.right": False, "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
                         "savefig.facecolor": SURFACE})
    data = [(name, stem, load(subset, stem)) for stem, name in SYSTEMS]
    data = [(n, s, r) for n, s, r in data if complete(r, n_expected)]
    if not data:
        return
    # Fig 1: safe-fix and fix-works rates with CI (two panels, one measure each, shared system order)
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 0.42 * len(data) + 0.9), sharey=True)
    for ax, metric, title in ((axes[0], "fix_success", "Fix works (%)"), (axes[1], "safe_fix", "Safe fix (%)")):
        for i, (name, stem, rows) in enumerate(data):
            vals = [float(r[metric]) for r in rows]
            mean = 100 * sum(vals) / len(vals)
            lo, hi = bootstrap_ci(vals)
            color = BLUE if stem.startswith("cloudmedic__") else GRAY
            ax.barh(i, mean, height=0.6, color=color)
            ax.errorbar(mean, i, xerr=[[mean - 100 * lo], [100 * hi - mean]], fmt="none", ecolor=INK2, elinewidth=1, capsize=2)
            ax.text(100 * hi + 2, i, f"{mean:.0f}", va="center", fontsize=8, color=INK)
        ax.set_xlim(0, 114)
        ax.set_xticks([0, 20, 40, 60, 80, 100])
        ax.set_title(title, fontsize=9, color=INK, loc="left")
        ax.xaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
    axes[0].set_yticks(range(len(data)))
    axes[0].set_yticklabels([d[0] for d in data])
    axes[0].invert_yaxis()
    fig.tight_layout()
    fig.savefig(FIG / f"fix_rates_{subset}.png", dpi=220)
    fig.savefig(FIG / f"fix_rates_{subset}.pdf")
    plt.close(fig)
    # Fig 2: excess privilege per successful fix (strip plot, symlog scale)
    fig, ax = plt.subplots(figsize=(7.2, 0.42 * len(data) + 0.9))
    import random
    rng = random.Random(0)
    for i, (name, stem, rows) in enumerate(data):
        xs = [r["excess_total"] for r in rows if r["fix_success"]]
        ys = [i + rng.uniform(-0.18, 0.18) for _ in xs]
        ax.scatter(xs, ys, s=10, color=BLUE if stem.startswith("cloudmedic__") else GRAY, alpha=0.6, linewidths=0)
        over = sum(1 for x in xs if x > 0)
        ax.text(1.02, i, f"{over}/{len(xs)} over-privileged", transform=ax.get_yaxis_transform(), va="center", fontsize=8, color=INK2)
    ax.set_xscale("symlog", linthresh=1)
    ax.set_yticks(range(len(data)))
    ax.set_yticklabels([d[0] for d in data])
    ax.invert_yaxis()
    ax.set_xlabel("Excess privilege of a working fix (new flows + new IAM grants, symlog)")
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(FIG / f"excess_{subset}.png", dpi=220)
    fig.savefig(FIG / f"excess_{subset}.pdf")
    plt.close(fig)
    # Fig 3: per-class RCA@1, CloudMedic vs strongest LLM baseline (sequential single hue)
    a = load(subset, MAIN)
    b = load(subset, "llm_checklist__qwen2.5-7b")
    if complete(a, n_expected) and complete(b, n_expected):
        classes = sorted({c for r in a for c in r["gold_classes"]})
        def per(rows):
            d = collections.defaultdict(list)
            for r in rows:
                for c in r["gold_classes"]:
                    d[c].append(r["rca_top1"])
            return [100 * sum(d[c]) / len(d[c]) for c in classes]
        import numpy as np
        M = np.array([per(b), per(a)])
        fig, ax = plt.subplots(figsize=(7.2, 2.2))
        im = ax.imshow(M, cmap="Blues", vmin=0, vmax=100, aspect="auto")
        ax.set_yticks([0, 1])
        ax.set_yticklabels(["LLM + checklist (7B)", "CloudMedic (7B)"])
        ax.set_xticks(range(len(classes)))
        ax.set_xticklabels(classes, rotation=60, ha="right", fontsize=7)
        for i in range(2):
            for j in range(len(classes)):
                ax.text(j, i, f"{M[i, j]:.0f}", ha="center", va="center", fontsize=6.5, color="white" if M[i, j] > 60 else INK)
        cb = fig.colorbar(im, ax=ax, fraction=0.02, pad=0.01)
        cb.set_label("RCA@1 (%)")
        fig.tight_layout()
        fig.savefig(FIG / f"per_class_{subset}.png", dpi=220)
        fig.savefig(FIG / f"per_class_{subset}.pdf")
        plt.close(fig)


def fidelity_tables():
    lines = []
    p = OUT / "iam_fidelity.json"
    if p.exists():
        f = json.loads(p.read_text())
        lines.append(f"IAM model vs AWS IAM policy simulator: {100 * f['agreement']:.1f}% agreement on {f['n']} random cases. "
                     f"Confusion (AWS|CloudMedic): {f['confusion_aws_vs_cloudmedic']}")
    else:
        lines.append("IAM model vs AWS IAM policy simulator: PENDING (needs AWS credentials; see README).")
    p = OUT / "live_network.json"
    if p.exists():
        f = json.loads(p.read_text())
        lines.append(f"Network model vs live AWS probes: {100 * f['agreement']:.1f}% agreement over {f['n']} probe groups.")
        for r in f["rows"]:
            o = r["observation"]
            lines.append(f"  - {r['experiment']} ({r['client']} -> server:{r['port']}): predicted {r['expected']} "
                         f"(success fraction {r['prediction']['predicted_success_fraction']:.2f}), observed {r['observed']} "
                         f"({o['success']}/{o['n']} ok, {o['refused']} refused, {o['timeout']} timeout)")
    else:
        lines.append("Network model vs live AWS probes: PENDING (needs AWS credentials; see README).")
    (TAB / "fidelity.md").write_text("\n".join(lines) + "\n")


MACRO_NAMES = {"llm_only__qwen2.5-7b": "LLMOnly", "llm_checklist__qwen2.5-7b": "LLMCheck", "llm_verifier_loop__qwen2.5-7b": "LLMVerify",
               "symbolic_rules__nollm": "Rules", "cloudmedic_no_lp__qwen2.5-7b": "CMNoLP", "cloudmedic__qwen2.5-7b": "CM",
               "llm_checklist__qwen2.5-3b": "LLMCheckSmall", "cloudmedic__qwen2.5-3b": "CMSmall", "symbolic_oracle__nollm": "Oracle"}
MACRO_METRICS = {"intent_exact": "Intent", "rca_top1": "RcaOne", "rca_top3": "RcaThree", "fix_success": "Fix", "safe_fix": "Safe",
                 "over_privileged": "OverPriv", "hallucinated": "Halluc", "excess_total": "Excess", "seconds": "Sec",
                 "label_recall3": "Recall"}


def write_macros(summary):
    """paper/generated/macros.tex: one \\newcommand per quoted number; missing runs render as PENDING."""
    out = ["% generated by scripts/make_report.py; do not edit", "\\providecommand{\\pending}{\\textbf{\\textsc{pending}}}"]
    for subset, tag in (("core", ""), ("all", "Full")):
        for stem, name in MACRO_NAMES.items():
            agg = summary.get(subset, {}).get(stem)
            for key, mname in MACRO_METRICS.items():
                if agg is None:
                    val = "\\pending{}"
                elif key in ("excess_total",):
                    val = f"{agg[key]['mean']:.2f}"
                elif key == "seconds":
                    val = f"{agg[key]['mean']:.1f}"
                else:
                    val = f"{100 * agg[key]['mean']:.1f}\\%"
                out.append(f"\\newcommand{{\\{name}{mname}{tag}}}{{{val}}}")
    card = json.loads((ROOT / "data" / "test_card.json").read_text())
    dev = json.loads((ROOT / "data" / "dev_card.json").read_text())
    out += [f"\\newcommand{{\\NTest}}{{{card['n_scenarios']}}}", f"\\newcommand{{\\NSingle}}{{{card['n_single']}}}",
            f"\\newcommand{{\\NMulti}}{{{card['n_multi']}}}", f"\\newcommand{{\\NDev}}{{{dev['n_scenarios']}}}",
            f"\\newcommand{{\\NClasses}}{{{len(card['per_class'])}}}", f"\\newcommand{{\\NTemplates}}{{{len(card['per_template'])}}}",
            f"\\newcommand{{\\NCandidates}}{{{card['validation'].get('candidates')}}}",
            f"\\newcommand{{\\NDropOne}}{{{card['validation'].get('drop_v1_not_broken', 0)}}}",
            f"\\newcommand{{\\NDropFour}}{{{card['validation'].get('drop_v4_not_jointly_necessary', 0)}}}",
            f"\\newcommand{{\\Agreement}}{{{100 * card['pool_label_evaluator_agreement']:.1f}\\%}}",
            f"\\newcommand{{\\NCore}}{{{sum(1 for _ in open(RUNS / 'core' / 'symbolic_oracle__nollm.jsonl')) if (RUNS / 'core' / 'symbolic_oracle__nollm.jsonl').exists() else 154}}}"]
    f1, f2 = OUT / "iam_fidelity.json", OUT / "live_network.json"
    out.append("\\newcommand{\\IamFidelity}{" + (f"{100 * json.loads(f1.read_text())['agreement']:.1f}\\%" if f1.exists() else "\\pending{}") + "}")
    out.append("\\newcommand{\\IamFidelityN}{" + (str(json.loads(f1.read_text())['n']) if f1.exists() else "\\pending{}") + "}")
    out.append("\\newcommand{\\LiveFidelity}{" + (f"{100 * json.loads(f2.read_text())['agreement']:.1f}\\%" if f2.exists() else "\\pending{}") + "}")
    out.append("\\newcommand{\\LiveFidelityN}{" + (str(json.loads(f2.read_text())['n']) if f2.exists() else "\\pending{}") + "}")
    gen = ROOT / "paper" / "generated"
    gen.mkdir(parents=True, exist_ok=True)
    (gen / "macros.tex").write_text("\n".join(out) + "\n")
    for f in ("main_core.tex", "main_all.tex"):
        (gen / f).write_text((TAB / f).read_text())
    md = (TAB / "dataset.md").read_text().split("\n")
    rows = [l for l in md if l.startswith("| ") and not l.startswith("| Fault") and "---" not in l]
    (gen / "dataset.tex").write_text("\n".join(
        " & ".join(c.strip().replace("_", "\\_") for c in r.strip("|").split("|")) + " \\\\" for r in rows) + "\n")


def main():
    n_core = sum(1 for _ in open(RUNS / "core" / "symbolic_oracle__nollm.jsonl")) if (RUNS / "core" / "symbolic_oracle__nollm.jsonl").exists() else 154
    n_all = sum(1 for _ in open(ROOT / "data" / "test.jsonl"))
    summary = {"core": main_table("core", n_core), "all": main_table("all", n_all)}
    significance("core")
    breakdown("core")
    breakdown("all")
    dataset_table()
    figures("core", n_core)
    fidelity_tables()
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1))
    write_macros(summary)
    for f in ("main_core.md", "main_all.md", "significance_core.md", "breakdown_core.md", "fidelity.md"):
        print(f"\n## {f}\n" + (TAB / f).read_text())


if __name__ == "__main__":
    main()
