# SkillGuard detection benchmark

- binary: `E:\skillguard\target\release\skillguard.exe`
- version: `0.3.0` / split: `all`
- operating point: `high+` (target FPR <= 3%)
- malicious: 335, benign: 532
- recall: **100.0%** (335/335), 95% CI 98.9%-100.0%
- FPR: **0.0%** (0/532), 95% CI 0.0%-0.7%

| split | malicious | benign | threshold | recall | FPR | FPR upper |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| base | 15 | 12 | high+ | 100.0% | 0.0% | 24.3% |
| dev | 107 | 174 | high+ | 100.0% | 0.0% | 2.2% |
| holdout | 106 | 173 | high+ | 100.0% | 0.0% | 2.2% |
| test | 107 | 173 | high+ | 100.0% | 0.0% | 2.2% |

- missed malicious: 0
- false positives: 0
- new false positives vs baseline: 0

| rule | TP | FP |
| --- | ---: | ---: |
| SG-PERM-001 | 207 | 318 |
| SG-CMD-004 | 25 | 29 |
| SG-PI-008 | 25 | 29 |
| SG-DATA-001 | 71 | 0 |
| SG-DATA-002 | 71 | 0 |
| SG-CONT-001 | 69 | 0 |
| SG-CRED-002 | 49 | 0 |
| SG-PERM-002 | 49 | 0 |
| SG-CONT-002 | 44 | 0 |
| SG-CONT-003 | 44 | 0 |
| SG-HYG-002 | 44 | 0 |
| SG-COMBO-004 | 25 | 0 |
| SG-COMBO-005 | 25 | 0 |
| SG-INIT-001 | 25 | 0 |
| SG-PI-001 | 25 | 0 |
