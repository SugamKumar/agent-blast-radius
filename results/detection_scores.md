198 attack sessions and 396 normal sessions. A rule fires on a session if it raises a medium or high alert.

| Rule | Attack sessions flagged | Normal sessions flagged | Precision | Recall |
|---|---|---|---|---|
| R1 | 32 | 0 | 100% | 16% |
| R2 | 66 | 0 | 100% | 33% |
| R3 | 48 | 96 | 33% | 24% |
| R4 | 43 | 28 | 61% | 22% |
| R5 | 57 | 0 | 100% | 29% |
| R6 | 68 | 0 | 100% | 34% |
| R7 | 44 | 0 | 100% | 22% |
| R8 | 132 | 0 | 100% | 67% |
| R1 at any severity | 94 | 74 | 56% | 48% |
| Any rule except R3, R4 | 198 | 0 | 100% | 100% |

R3 and R4 are configuration findings, so they fire on normal sessions too and are left out of the combined row.

Attack sessions that caused harm: 106. Of those, missed by every attack rule: 0. Attack sessions that caused no harm and raised no alert: 0.
