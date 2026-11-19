| System | Network RCA@1 | IAM RCA@1 | Network safe | IAM safe | L1 safe | L2 safe | L3 (multi) safe | L3 label recall@3 |
|---|---|---|---|---|---|---|---|---|
| LLM only (7B) | 14.1 | 5.8 | 14.1 | 7.2 | 24.0 | 7.4 | 2.0 | 29.0 |
| LLM + checklist (7B) | 17.6 | 5.8 | 14.1 | 1.4 | 16.0 | 9.3 | 0.0 | 22.0 |
| LLM + verifier loop (7B) | 27.1 | 17.4 | 18.8 | 5.8 | 20.0 | 14.8 | 4.0 | 37.0 |
| Symbolic + template parser | 81.2 | 100.0 | 81.2 | 100.0 | 92.0 | 88.9 | 88.0 | 87.0 |
| CloudMedic, no LP cost (7B) | 78.8 | 88.4 | 68.2 | 72.5 | 78.0 | 66.7 | 66.0 | 85.0 |
| CloudMedic (7B) | 78.8 | 88.4 | 77.6 | 76.8 | 82.0 | 68.5 | 82.0 | 85.0 |
| LLM + checklist (3B) | 7.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 5.0 |
| CloudMedic (3B) | 88.2 | 79.7 | 74.1 | 76.8 | 84.0 | 70.4 | 72.0 | 82.0 |
| Oracle intent (upper bound) | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 100.0 | 98.0 |
