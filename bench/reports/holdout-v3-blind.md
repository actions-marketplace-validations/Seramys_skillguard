# SkillGuard detection benchmark

- binary: `E:\skillguard\target\release\skillguard.exe`
- version: `0.3.0` / split: `all`
- operating point: `high+` (target FPR <= 3%)
- malicious: 212, benign: 334
- recall: **77.8%** (165/212), 95% CI 71.8%-82.9%
- FPR: **3.0%** (10/334), 95% CI 1.6%-5.4%

| split | malicious | benign | threshold | recall | FPR | FPR upper |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| holdout-v3 | 212 | 334 | high+ | 77.8% | 3.0% | 5.4% |

- missed malicious: 47 (cisco-malicious-mcp-atlassian-cve-2026-27825, cisco-malicious-mcpwn-cve-2026-33032, msb-malicious-dev-ASB04_000010, msb-malicious-dev-ASB04_000013, msb-malicious-dev-ASB04_000017, msb-malicious-dev-ASB04_000020, msb-malicious-dev-ASB04_000031, msb-malicious-dev-ASB04_000035, msb-malicious-dev-ASB04_000041, msb-malicious-dev-ASB04_000047, msb-malicious-dev-ASB04_000052, msb-malicious-dev-ASB04_000060, msb-malicious-dev-ASB04_000072, msb-malicious-dev-ASB04_000086, msb-malicious-dev-ASB04_000090, msb-malicious-dev-ASB04_000093, msb-malicious-dev-ASB04_000101, msb-malicious-dev-ASB04_000104, msb-malicious-dev-ASB04_000105, msb-malicious-dev-ASB04_000106)
- false positives: 10 (clawhub-cue-hotspot-tracker, clawhub-cue-litigation-lawyer-assistant, clawhub-cue-personal-legal-assistant, clawhub-innerwarden-security, clawhub-knowledge-precipitation, clawhub-codethrift, clawhub-gdrive-nextcloud-migration, clawhub-klingai, clawhub-taskfuel, clawhub-wirecat-wordpress)
- new false positives vs baseline: 10

| rule | TP | FP |
| --- | ---: | ---: |
| SG-PERM-001 | 72 | 119 |
| SG-PI-008 | 8 | 30 |
| SG-CMD-004 | 9 | 29 |
| SG-EXEC-002 | 0 | 11 |
| SG-DATA-001 | 26 | 10 |
| SG-PERM-002 | 18 | 6 |
| SG-SC-001 | 9 | 6 |
| SG-DL-001 | 15 | 4 |
| SG-CONCEAL-001 | 11 | 3 |
| SG-PI-003 | 1 | 3 |
| SG-NET-003 | 15 | 2 |
| SG-NET-004 | 15 | 2 |
| SG-PERSIST-001 | 9 | 2 |
| SG-CMD-003 | 9 | 1 |
| SG-PI-007 | 8 | 1 |
