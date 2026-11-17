198 attack sessions and 396 normal sessions. A rule fires on a session if it raises a medium or high alert.

| Rule | Attack sessions flagged | Normal sessions flagged | Precision | Recall |
|---|---|---|---|---|
| R1 | 26 | 0 | 100% | 13% |
| R2 | 66 | 0 | 100% | 33% |
| R3 | 48 | 96 | 33% | 24% |
| R4 | 39 | 28 | 58% | 20% |
| R5 | 59 | 0 | 100% | 30% |
| R6 | 64 | 0 | 100% | 32% |
| R7 | 38 | 0 | 100% | 19% |
| R8 | 198 | 0 | 100% | 100% |
| R1 at any severity | 88 | 74 | 54% | 44% |
| Any rule except R3, R4 | 198 | 0 | 100% | 100% |

R3 and R4 are configuration findings, so they fire on normal sessions too and are left out of the combined row.

Attack sessions that caused harm: 100. Of those, missed by every attack rule: 0. Attack sessions that caused no harm and raised no alert: 0.
