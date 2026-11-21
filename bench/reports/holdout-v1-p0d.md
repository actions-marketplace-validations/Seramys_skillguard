# SkillGuard detection benchmark

- binary: `E:\skillguard\target\release\skillguard.exe`
- version: `0.3.0` / split: `all`
- operating point: `high+` (target FPR <= 3%)
- malicious: 202, benign: 340
- recall: **81.2%** (164/202), 95% CI 75.2%-86.0%
- FPR: **1.2%** (4/340), 95% CI 0.5%-3.0%

| split | malicious | benign | threshold | recall | FPR | FPR upper |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| holdout-v1 | 202 | 340 | high+ | 81.2% | 1.2% | 3.0% |

- missed malicious: 38 (msb-malicious-holdout-ASB04_000002, msb-malicious-holdout-ASB04_000025, msb-malicious-holdout-ASB04_000030, msb-malicious-holdout-ASB04_000038, msb-malicious-holdout-ASB04_000045, msb-malicious-holdout-ASB04_000053, msb-malicious-holdout-ASB04_000055, msb-malicious-holdout-ASB04_000059, msb-malicious-holdout-ASB04_000069, msb-malicious-holdout-ASB04_000071, msb-malicious-holdout-ASB04_000077, msb-malicious-holdout-ASB04_000081, msb-malicious-holdout-ASB04_000083, msb-malicious-holdout-ASB04_000100, msb-malicious-holdout-ASB04_000110, msb-malicious-holdout-ASB04_000114, msb-malicious-holdout-ASB04_000133, msb-malicious-holdout-ASB04_000136, msb-malicious-holdout-ASB04_000146, msb-malicious-holdout-ASB04_000152)
- false positives: 4 (clawhub-cue-pre-market-strategy, clawhub-postemi, clawhub-rockdesk, clawhub-hookbird)
- new false positives vs baseline: 2

| rule | TP | FP |
| --- | ---: | ---: |
| SG-PERM-001 | 76 | 62 |
| SG-DATA-001 | 28 | 12 |
| SG-EXEC-002 | 5 | 12 |
| SG-SC-001 | 5 | 12 |
| SG-PERM-002 | 20 | 3 |
| SG-CONCEAL-001 | 11 | 2 |
| SG-CMD-003 | 8 | 2 |
| SG-PERSIST-001 | 8 | 2 |
| SG-PI-008 | 8 | 2 |
| SG-EXEC-001 | 8 | 1 |
| SG-HYG-001 | 1 | 1 |
| SG-INIT-001 | 39 | 0 |
| SG-DATA-002 | 24 | 0 |
| SG-CONT-001 | 22 | 0 |
| SG-NET-004 | 18 | 0 |
