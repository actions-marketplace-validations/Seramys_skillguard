# SkillGuard detection benchmark (superseded)

> This pre-P0 snapshot is kept for history. The current blind quality number is in `holdout-v3-blind.md` (77.8% recall / 3.0% FPR).

- binary: `target\release\skillguard`
- version: `0.2.0` / split: `holdout`
- operating point: `high+` (target FPR <= 5%)
- malicious: 202, benign: 340
- recall: **64.9%** (131/202), 95% CI 58.0%-71.1%
- FPR: **1.5%** (5/340), 95% CI 0.6%-3.4%

| split | malicious | benign | threshold | recall | FPR | FPR upper |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| holdout | 202 | 340 | high+ | 64.9% | 1.5% | 3.4% |

- missed malicious: 71 (msb-malicious-holdout-ASB04_000001, msb-malicious-holdout-ASB04_000002, msb-malicious-holdout-ASB04_000005, msb-malicious-holdout-ASB04_000007, msb-malicious-holdout-ASB04_000015, msb-malicious-holdout-ASB04_000025, msb-malicious-holdout-ASB04_000030, msb-malicious-holdout-ASB04_000038, msb-malicious-holdout-ASB04_000045, msb-malicious-holdout-ASB04_000050, msb-malicious-holdout-ASB04_000053, msb-malicious-holdout-ASB04_000055, msb-malicious-holdout-ASB04_000059, msb-malicious-holdout-ASB04_000062, msb-malicious-holdout-ASB04_000069, msb-malicious-holdout-ASB04_000071, msb-malicious-holdout-ASB04_000073, msb-malicious-holdout-ASB04_000076, msb-malicious-holdout-ASB04_000077, msb-malicious-holdout-ASB04_000081)
- false positives: 5 (clawhub-cue-pre-market-strategy, clawhub-iterate-skill, clawhub-rockdesk, clawhub-kling-ai-mcp, clawhub-your-downloader)
- new false positives vs baseline: 0

| rule | TP | FP |
| --- | ---: | ---: |
| SG-PERM-001 | 74 | 62 |
| SG-DATA-001 | 26 | 12 |
| SG-SC-001 | 2 | 12 |
| SG-PERM-002 | 20 | 3 |
| SG-CMD-003 | 8 | 2 |
| SG-PI-008 | 8 | 2 |
| SG-HYG-001 | 0 | 1 |
| SG-DATA-002 | 24 | 0 |
| SG-CONT-001 | 22 | 0 |
| SG-NET-004 | 18 | 0 |
| SG-NET-003 | 15 | 0 |
| SG-CONT-002 | 14 | 0 |
| SG-CONT-003 | 14 | 0 |
| SG-HYG-002 | 14 | 0 |
| SG-PI-006 | 12 | 0 |
