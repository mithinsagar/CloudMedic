# CloudMedic

**Verified, least-privilege troubleshooting of AWS network and IAM misconfigurations.**

A customer writes *"our Lambda can't reach the payments API since last night"* or *"AccessDenied reading from S3, but the
policy allows it"*. CloudMedic turns the ticket into a formal intent with a small local language model, then uses formal
models of AWS VPC reachability and IAM policy evaluation to find **every** failing hop and synthesises the fix that restores
the intent while **adding the least privilege**, verified before it is shown.

Language models alone tend to "fix" tickets by opening `0.0.0.0/0` or granting `s3:*`. CloudMedic measures that with an
**excess-privilege** metric and minimises it with a counterexample-guided MaxSMT search (Z3).

Zero cost: runs on a laptop with open-weight models (Qwen2.5 via MLX on Apple silicon). AWS access is optional and only used
to validate the models against AWS itself.

```
ticket ──► LLM: extract intent ──► verifier rejects invalid/succeeding intents, retries
                                   │
snapshot ──────────────────────────┼──► network model (DNS, SG, NACL, routes, NAT, IGW, peering, return path)
                                   └──► IAM model (deny, SCP, endpoint, boundary, identity/resource, KMS)
                                              │ failing checks = root causes
                                              ▼
                              candidate edits (narrow ... broad), each costed by measured privilege gain
                                              ▼
                              Z3 MaxSMT: min-cost set covering all failures ──► apply, re-verify
                                   ▲                                              │
                                   └──── new failing checks / interaction / collateral loss
```

## What is in the box

| Part | Path |
|---|---|
| IAM policy language and evaluator (explicit deny, SCPs, endpoint policies, boundaries, cross-account, KMS) | `cloudmedic/policy.py`, `cloudmedic/iam.py` |
| VPC reachability model with full-path and return-path evaluation (stateless NACLs, partial ephemeral coverage) | `cloudmedic/network.py` |
| Typed edit language (23 operations) with validation, used for every fix | `cloudmedic/edits.py` |
| Access surface and excess-privilege metric | `cloudmedic/expansion.py` |
| Least-privilege repair: CEGAR + MaxSMT with branch-and-bound | `cloudmedic/repair.py` |
| **CloudMedic-Bench** generator: 5 architectures, 25 fault operators, 26 fault classes, validity checks V1 to V4, L1/L2/L3 tickets | `cloudmedic/bench/` |
| Systems compared (LLM-only, checklist, verifier loop, template parser, CloudMedic, ablations, oracle) | `cloudmedic/systems.py` |
| Metrics, bootstrap CIs, McNemar tests, report and figures | `cloudmedic/eval/`, `scripts/make_report.py` |
| AWS: live account importer, IAM fidelity vs policy simulator, live network probes | `cloudmedic/aws/` |
| CLI and local web demo | `cloudmedic/cli.py`, `cloudmedic/webui.py` |
| Paper (IEEE format; every number generated from run files) | `paper/` |
| Tests (26) | `tests/` |

## Quick start

```bash
cd ~/Desktop/CloudMedic
/opt/homebrew/bin/python3.12 -m venv .venv && .venv/bin/pip install -e ".[llm,aws,report,dev]"
.venv/bin/pytest -q                                              # 26 tests

# diagnose a benchmark ticket (gold intent, no LLM needed)
.venv/bin/cloudmedic diagnose --scenario data/test.jsonl --id test-m010 --oracle

# same, with the local LLM reading the ticket (downloads ~4 GB once)
.venv/bin/cloudmedic diagnose --scenario data/test.jsonl --id test-m010

# web demo at http://127.0.0.1:8765  (add --llm for intent extraction from ticket text)
.venv/bin/python -m cloudmedic.webui

# your own account (read-only), then ask a question
.venv/bin/python -m cloudmedic.aws.importer --profile cloudmedic --out snap.json
.venv/bin/cloudmedic diagnose --snapshot snap.json --intent '{"kind":"network","src":"i-0abc...","dst":"db.corp.internal","port":5432}'
```

## Reproducing the paper

```bash
.venv/bin/python -m cloudmedic.bench.generate          # data/dev.jsonl, data/test.jsonl (+ dataset cards); deterministic
./scripts/run_experiments.sh                           # resumable; LLM completions cached in results/llm_cache
.venv/bin/python scripts/make_report.py                # results/tables, results/figures, paper/generated
cd paper && tectonic -X compile main.tex               # paper/main.pdf
```

Optional AWS fidelity experiments: see [docs/AWS_SETUP.md](docs/AWS_SETUP.md).

## Results

Generated tables live in `results/tables/` (`main_core.md`, `significance_core.md`, `breakdown_core.md`, `dataset.md`,
`fidelity.md`). Any number not yet measured is printed as `PENDING`; nothing in the tables or the paper is typed by hand.

## Honest limitations

* Tickets are generated from templates; real tickets are messier. The rule-based parser baseline exploits template
  regularity, which is why it is a baseline. A study on human-written tickets is future work.
* The same formal models are used to simulate symptoms and to diagnose, so the *oracle intent* row is an upper bound for a
  perfect model, not for reality. Labels come from the fault operators, not from the models, and the AWS fidelity experiments
  measure how far the models are from AWS.
* The models cover a documented subset of AWS: no transit gateways, load balancers, IPv6, policy variables or session policies.
* Excess privilege is computed over a finite universe of flows and permissions, so it is a lower bound.
* One open model family (Qwen2.5, 3B and 7B).

## License

MIT
