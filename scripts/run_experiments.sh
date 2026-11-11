#!/usr/bin/env bash
# Full experiment queue. Resumable: re-running skips finished scenarios (LLM calls are cached too).
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
R="$PY -m cloudmedic.eval.run --split test"
$R --subset all  --systems symbolic_oracle symbolic_rules
$R --subset core --systems symbolic_oracle symbolic_rules
$R --subset core --model qwen2.5-7b --systems cloudmedic
$R --subset core --model qwen2.5-7b --systems llm_only
$R --subset core --model qwen2.5-7b --systems llm_checklist
$R --subset core --model qwen2.5-7b --systems cloudmedic_no_lp
$R --subset core --model qwen2.5-7b --systems llm_verifier_loop
$R --subset core --model qwen2.5-3b --systems cloudmedic llm_checklist
$R --subset all  --model qwen2.5-7b --systems cloudmedic
echo ALL_DONE
