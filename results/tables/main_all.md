| System | n | Intent | RCA@1 | RCA@3 | Fix works | Safe fix | Over-priv. | Invalid edit | Excess (mean) | Sec/ticket |
|---|---|---|---|---|---|---|---|---|---|---|
| LLM only (7B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| LLM + checklist (7B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| LLM + verifier loop (7B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Symbolic + template parser | 310 | 90.6 [87.1, 93.9] | 90.6 [87.1, 93.9] | 90.6 [87.1, 93.9] | 90.6 [87.1, 93.9] | 90.6 [87.1, 93.9] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.00 | 0.1 |
| CloudMedic, no LP cost (7B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| CloudMedic (7B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| LLM + checklist (3B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| CloudMedic (3B) | 0/310 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Oracle intent (upper bound) | 310 | 100.0 [100.0, 100.0] | 100.0 [100.0, 100.0] | 100.0 [100.0, 100.0] | 100.0 [100.0, 100.0] | 100.0 [100.0, 100.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.00 | 0.1 |

Percentages with 95% bootstrap CI. Intent = exact intent extraction; RCA@k = a gold (class, resource) among the top k; Safe fix = fix works, zero excess privilege, zero regression; Over-priv. = fix works but grants access beyond the healthy and pre-fix configuration; Invalid edit = at least one edit references a missing resource or is malformed.
