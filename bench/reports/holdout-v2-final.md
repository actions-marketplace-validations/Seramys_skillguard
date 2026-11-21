# SkillGuard detection benchmark

- binary: `E:\skillguard\target\release\skillguard.exe`
- version: `0.3.0` / split: `all`
- operating point: `high+` (target FPR <= 3%)
- malicious: 212, benign: 348
- recall: **75.0%** (159/212), 95% CI 68.8%-80.3%
- FPR: **2.3%** (8/348), 95% CI 1.2%-4.5%

| split | malicious | benign | threshold | recall | FPR | FPR upper |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| holdout-v2 | 212 | 348 | high+ | 75.0% | 2.3% | 4.5% |

- missed malicious: 53 (cisco-malicious-eicar-test, cisco-malicious-flowise-cve-2025-59528, msb-malicious-test-ASB04_000016, msb-malicious-test-ASB04_000022, msb-malicious-test-ASB04_000024, msb-malicious-test-ASB04_000028, msb-malicious-test-ASB04_000039, msb-malicious-test-ASB04_000044, msb-malicious-test-ASB04_000048, msb-malicious-test-ASB04_000049, msb-malicious-test-ASB04_000054, msb-malicious-test-ASB04_000075, msb-malicious-test-ASB04_000085, msb-malicious-test-ASB04_000091, msb-malicious-test-ASB04_000095, msb-malicious-test-ASB04_000098, msb-malicious-test-ASB04_000103, msb-malicious-test-ASB04_000108, msb-malicious-test-ASB04_000116, msb-malicious-test-ASB04_000117)
- false positives: 8 (clawhub-cue-after-market-assistant, clawhub-cue-regional-policy-brief, clawhub-cue-technical-analysis, clawhub-outlit, clawhub-x402-trust-check, clawhub-go-dev, clawhub-peen, clawhub-nevermined-catalog-onboarding)
- new false positives vs baseline: 8

| rule | TP | FP |
| --- | ---: | ---: |
| SG-PERM-001 | 74 | 146 |
| SG-DATA-001 | 26 | 21 |
| SG-EXEC-002 | 1 | 17 |
| SG-SC-001 | 9 | 9 |
| SG-PI-008 | 7 | 5 |
| SG-PERM-002 | 17 | 4 |
| SG-NET-004 | 18 | 3 |
| SG-DL-001 | 17 | 3 |
| SG-NET-003 | 17 | 3 |
| SG-PERSIST-001 | 10 | 3 |
| SG-CMD-003 | 9 | 3 |
| SG-DATA-002 | 24 | 1 |
| SG-HYG-001 | 1 | 1 |
| SG-COMBO-001 | 0 | 1 |
| SG-PI-003 | 0 | 1 |
