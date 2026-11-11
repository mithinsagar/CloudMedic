"""Command-line interface.

    cloudmedic diagnose --scenario data/test.jsonl --id test-0042            # benchmark scenario, LLM intent extraction
    cloudmedic diagnose --scenario data/test.jsonl --id test-0042 --oracle   # use the gold intent
    cloudmedic diagnose --snapshot snap.json --ticket ticket.txt             # your own snapshot + free-text ticket
    cloudmedic diagnose --snapshot snap.json --intent '{"kind":"network","src":"i-0ab","dst":"db.corp.internal","port":5432}'
    cloudmedic check --snapshot snap.json --intent '{...}'                   # just evaluate (trace only)
"""
from __future__ import annotations

import argparse
import json
import sys

from .diagnose import diagnose
from .intents import evaluate_intent
from .taxonomy import FAULT_CLASSES

C = {"pass": "\033[32m", "fail": "\033[31m", "partial": "\033[33m", "skip": "\033[90m", "end": "\033[0m", "b": "\033[1m"}


def _load_scenario(path, sid):
    for line in open(path):
        s = json.loads(line)
        if s["id"] == sid:
            return s
    sys.exit(f"scenario {sid} not found in {path}")


def print_trace(checks):
    for c in checks:
        st = c["status"]
        print(f"  {C.get(st, '')}{st:>7}{C['end']}  {c['id']:<26} {c['detail']}")


def print_report(d):
    print(f"\n{C['b']}Intent{C['end']}: {json.dumps(d['intent'])}")
    print(f"{C['b']}Symptom{C['end']}: {d['symptom']}\n")
    print(f"{C['b']}Trace{C['end']}")
    print_trace(d["trace"])
    print(f"\n{C['b']}Root causes{C['end']}")
    for i, rc in enumerate(d["root_causes"], 1):
        print(f"  {i}. {rc['fault_class']} on {rc['resource']}: {FAULT_CLASSES.get(rc['fault_class'], '')}")
        print(f"     {rc['explanation']}")
    print(f"\n{C['b']}Least-privilege fix{C['end']} (verified={d['fix_verified']}, {d['candidates_considered']} candidates, "
          f"{d['repair_iterations']} iteration(s))")
    for e in d["fix"]:
        print("  " + json.dumps(e))
    st = d["repair_stats"]
    if st:
        print(f"\n  privilege gained beyond the intent: {st.get('total_gained', 0)} "
              f"(internet-exposed {st.get('internet_exposure', 0)}, sensitive IAM {st.get('iam_sensitive_gained', 0)}); "
              f"access lost: {st.get('total_lost', 0)}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cloudmedic", description="Verified least-privilege troubleshooting for AWS")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("diagnose", "check"):
        p = sub.add_parser(name)
        p.add_argument("--scenario")
        p.add_argument("--id")
        p.add_argument("--snapshot")
        p.add_argument("--ticket", help="path to a text file with the customer ticket")
        p.add_argument("--intent", help="intent as JSON (skips the language model)")
        p.add_argument("--oracle", action="store_true", help="benchmark only: use the gold intent")
        p.add_argument("--model", default="qwen2.5-7b")
        p.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    scn = _load_scenario(a.scenario, a.id) if a.scenario else None
    snap = scn["snapshot"] if scn else json.load(open(a.snapshot))
    ticket = scn["ticket"] if scn else None
    if a.ticket:
        body = open(a.ticket).read()
        ticket = {"subject": body.splitlines()[0][:120] if body else "", "body": body}
    if scn and not a.json:
        print(f"{C['b']}Ticket{C['end']}: {ticket['subject']}\n{ticket['body']}")

    intent = json.loads(a.intent) if a.intent else (scn["gold"]["intent"] if (scn and a.oracle) else None)
    if intent is None:
        if ticket is None:
            sys.exit("give --intent, --ticket, or a benchmark --scenario")
        from .llm.backend import MLXBackend
        from .systems import extract_intent
        intent, meta = extract_intent({"snapshot": snap, "ticket": ticket}, MLXBackend(a.model))
        if intent is None:
            sys.exit("could not extract a valid intent from the ticket; pass --intent explicitly")
    if a.cmd == "check":
        r = evaluate_intent(snap, intent)
        print(json.dumps(r.to_dict(), indent=1) if a.json else "")
        if not a.json:
            print_trace(r.to_dict()["checks"])
        return
    d = diagnose(snap, intent)
    if a.json:
        print(json.dumps(d, indent=1, default=str))
    else:
        print_report(d)
        if scn:
            print(f"\n{C['b']}Gold labels{C['end']}: {[(l['fault_class'], l['resource']) for l in scn['gold']['labels']]}")


if __name__ == "__main__":
    main()
