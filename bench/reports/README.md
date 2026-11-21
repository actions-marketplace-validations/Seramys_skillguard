# Benchmark reports

Committed files are summaries and Markdown reports only. Raw `*.json` reports embed per-sample metadata and are ignored by `.gitignore`.

## Suites

| Suite | Run in CI | Purpose | Current result |
| --- | --- | --- | --- |
| `public` | yes | Harness, rule, and packaging smoke test. Base fixtures + generated corpus only. | 335 malicious / 532 benign; recall 100%, FPR 0% |
| `holdout-v3` | no | Blind quality number, frozen from the untouched dev split. | 212 malicious / 334 benign; recall **77.8%**, FPR **3.0%** |
| `holdout-v2` | no | Frozen from test; inspected during precision tuning. | 212 / 348; recall 75.0%, FPR 2.3% |
| `holdout-v1` | no | Previous public holdout, contaminated by miss analysis. | 202 / 340; recall 81.2%, FPR 1.2% |

The public suite is deliberately easy. Its 100% recall proves the harness and rules run; it is **not** a quality claim. The real samples behind the frozen holdouts cannot be redistributed through this repository, so public CI cannot run them and cannot claim their result.

holdout-v3 is the current blind claim. Do not tune rules against it and keep calling it blind; freeze a new split before the next claim.

## Reproduce

```bash
cargo build --release
python bench/fetch_samples.py
python bench/make_corpus.py

# CI smoke suite
python bench/run.py --exe target/release/skillguard --split all --no-imported \
  --json-out bench/results/public.json --md-out bench/results/public.md

# Blind quality suite (requires local authorized sample trees)
python bench/run.py --exe target/release/skillguard \
  --manifest bench/imported/holdout-v3.manifest.json \
  --generated-manifest bench/imported/__none__.json --no-imported --split all \
  --json-out bench/results/holdout-v3-blind.json \
  --md-out bench/results/holdout-v3-blind.md
```

## Frozen holdout composition

| Source | Malicious | Benign |
| --- | ---: | ---: |
| Generated `holdout` | 106 | 173 |
| MaliciousSkillBench `holdout` | 96 | 0 |
| ClawHub reviewed `holdout` | 0 | 167 |
| v1 total / v2 total / v3 total | 202 / 212 / 212 | 340 / 348 / 334 |

Cisco and Trail of Bits samples are smoke fixtures, not part of the extended holdout. Regeneration requires locally reviewed data under `bench/samples/real/`.

## Gate policy

`bench/manifest.json` sets:

- `target_fpr: 0.03`
- `max_fpr_upper: 0.06` (Wilson upper bound)
- `min_recall_at_fpr: 0.75` (P0 regression floor)
- `target_recall_at_fpr: 0.90` (P2 semantic-layer target)

At the current operating point (`high+`) the blind holdout-v3 meets the P0 target: 77.8% recall and 3.0% FPR. It does **not** meet the 90% target. Most misses are MaliciousSkillBench rewritten malicious prompts; closing that gap is the job of the optional semantic layer, not the default deterministic path.

## Historical reports

- `public*.md`, `public-summary.json`: public smoke snapshot.
- `extended*.md`, `extended-summary.json`: pre-P0 extended baseline (64.9% / 1.5%), now superseded by `holdout-v3-blind.md`. Keep for history; do not quote it as the current result.
- `holdout-v1-p0d.md`, `holdout-v2-final.md`, `holdout-v3-blind.md`, `public-p0-final.md`: P0–P3 snapshots.