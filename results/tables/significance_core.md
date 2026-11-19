| CloudMedic (7B) vs | metric | CloudMedic only | baseline only | exact McNemar p |
|---|---|---|---|---|
| LLM only (7B) (n=154) | fix_success | 107 | 3 | 3.4e-28 |
| LLM only (7B) (n=154) | safe_fix | 106 | 4 | 9.2e-27 |
| LLM only (7B) (n=154) | rca_top1 | 114 | 2 | 1.6e-31 |
| LLM + checklist (7B) (n=154) | fix_success | 113 | 6 | 1.1e-26 |
| LLM + checklist (7B) (n=154) | safe_fix | 110 | 4 | 6.7e-28 |
| LLM + checklist (7B) (n=154) | rca_top1 | 112 | 3 | 1.2e-29 |
| LLM + verifier loop (7B) (n=154) | fix_success | 107 | 7 | 4.2e-24 |
| LLM + verifier loop (7B) (n=154) | safe_fix | 104 | 5 | 3.8e-25 |
| LLM + verifier loop (7B) (n=154) | rca_top1 | 98 | 5 | 1.8e-23 |
| Symbolic + template parser (n=154) | fix_success | 4 | 19 | 0.0026 |
| Symbolic + template parser (n=154) | safe_fix | 4 | 23 | 0.00031 |
| Symbolic + template parser (n=154) | rca_top1 | 4 | 14 | 0.031 |
| CloudMedic, no LP cost (7B) (n=154) | fix_success | 0 | 3 | 0.25 |
| CloudMedic, no LP cost (7B) (n=154) | safe_fix | 11 | 0 | 0.00098 |
| CloudMedic, no LP cost (7B) (n=154) | rca_top1 | 0 | 0 | 1 |
| LLM + checklist (3B) (n=154) | fix_success | 123 | 0 | 1.9e-37 |
| LLM + checklist (3B) (n=154) | safe_fix | 119 | 0 | 3e-36 |
| LLM + checklist (3B) (n=154) | rca_top1 | 125 | 3 | 2.1e-33 |
| CloudMedic (3B) (n=154) | fix_success | 19 | 18 | 1 |
| CloudMedic (3B) (n=154) | safe_fix | 18 | 15 | 0.73 |
| CloudMedic (3B) (n=154) | rca_top1 | 20 | 22 | 0.88 |
| Oracle intent (upper bound) (n=154) | fix_success | 0 | 31 | 9.3e-10 |
| Oracle intent (upper bound) (n=154) | safe_fix | 0 | 35 | 5.8e-11 |
| Oracle intent (upper bound) (n=154) | rca_top1 | 0 | 26 | 3e-08 |
