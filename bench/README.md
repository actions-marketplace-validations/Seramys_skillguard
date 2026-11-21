# Detection benchmark

This directory keeps the detection-quality gate reproducible. A hit is not a safety certificate, and a miss is a bug report.

## Two suites, two claims

| Suite | CI | Composition | Current result |
| --- | --- | --- | --- |
| Public smoke | yes | 27 base fixtures + 320 generated malicious + 520 generated benign | 335 / 532; recall 100%, FPR 0% |
| **holdout-v3 (blind)** | no | frozen from dev after P0–P3 tuning | **212 / 334; recall 77.8%, FPR 3.0%** |
| holdout-v2 | no | frozen from test; used for precision validation | 212 / 348; recall 75.0%, FPR 2.3% |
| holdout-v1 (contaminated) | no | previous public holdout | 202 / 340; recall 81.2%, FPR 1.2% |

The public suite is synthetic and deliberately easy. Its 100% recall proves the harness and rules run; it is **not** a quality claim. The frozen holdouts are the quality signal, but their real samples cannot be redistributed in this repository, so public CI cannot run them.

holdout-v1 was used for previous miss analysis, so it is contaminated. holdout-v2 was inspected during precision tuning and is also not a blind claim anymore. **holdout-v3 was frozen from the untouched dev split and is the current blind quality number.** Do not tune against v3 and then still call it blind; freeze a new split before the next claim.

## Corpus

| Group | Count | Source |
|---|---:|---|
| Base malicious fixtures | 15 | Trail of Bits, Chinese samples, prompt-injection fixture |
| Base benign fixtures | 12 | clean fixtures and Chinese clean samples |
| Generated malicious | 320 | `samples/generated`, `make_corpus.py`, split dev/test/holdout |
| Generated benign + hard negatives | 520 | `.env.example`, legitimate `curl`, single `os.getenv`, `find -exec` tests, official registry, pinned MCP, remote MCP, Docker, Base64 |
| Real malicious (local only) | 306 | MaliciousSkillBench labels + Cisco test skills |
| Real benign (local only) | 502 | ClawHub samples with recorded review notes |

The Trail of Bits archive is downloaded by `fetch_samples.py` and verified against:

- commit `4ffbf9461ef0505f9ce76a0d3694a18ec33ea531`
- SHA-256 `2a3254e8617b6f8664493ce617464758e910e8a51f6879793f78c0f4e04d21ff`

No malicious binary corpus and no real Hub sample tree is vendored in the repository. `bench/samples/real/` and `bench/imported/manifest.json` are intentionally ignored.

Extended holdout composition:

| Source | Malicious | Benign |
| --- | ---: | ---: |
| Generated `holdout` | 106 | 173 |
| MaliciousSkillBench `holdout` | 96 | 0 |
| ClawHub reviewed `holdout` | 0 | 167 |
| **Total** | **202** | **340** |

Base fixtures use split `base` and are excluded from the holdout number. Cisco and Trail of Bits samples are smoke fixtures, not part of the extended holdout.

## Gate policy

Gate thresholds always come from `manifest.json`; a frozen holdout manifest only supplies samples. `run.py` also derives the reported version from `Cargo.toml` unless `--version` is passed.

`manifest.json` sets:

- `target_fpr: 0.03` and `max_fpr_upper: 0.06` (Wilson upper bound)
- `min_recall_at_fpr: 0.75` — P0 regression floor
- `target_recall_at_fpr: 0.90` — P2 semantic-layer target
- new false positives vs `fp-baseline.json` fail the **public smoke** gate; frozen holdouts are judged by FPR/recall
- per-rule TP/FP and Wilson 95% intervals are reported

At the current operating point (`high+`) the P0 target is met on the blind holdout-v3: 77.8% recall and 3.0% FPR. It does **not** meet the 90% target; that is the role of the optional semantic layer, not the default deterministic path. Most misses are MaliciousSkillBench rewritten malicious prompts. Do not present this gate as "90% recall achieved."

## Run

```bash
cargo build --release
python bench/fetch_samples.py
python bench/make_corpus.py          # 320 malicious / 520 benign

# CI smoke suite (same command as .github/workflows/ci.yml)
python bench/run.py --exe target/release/skillguard --split all --no-imported

# Freeze holdout-v1/v2/v3 manifests (real sample trees stay local)
python bench/freeze_holdout.py

# Blind quality suite (requires local authorized sample trees)
python bench/run.py --exe target/release/skillguard \
  --manifest bench/imported/holdout-v3.manifest.json \
  --generated-manifest bench/imported/__none__.json --no-imported --split all

# v1 regression (contaminated) or v2 precision validation
python bench/run.py --exe target/release/skillguard \
  --manifest bench/imported/holdout-v1.manifest.json \
  --generated-manifest bench/imported/__none__.json --no-imported --split all
```

Results are written to `bench/results/latest.json`, `latest.md`, and a versioned `v<version>-<date>` report. Raw reports are ignored; committed summaries live in `bench/reports/`.

## Current baseline

| Metric | Result |
|---|---:|
| Malicious (holdout-v3 blind) | 212 |
| Benign (holdout-v3 blind) | 334 |
| Recall @ high | 77.8% (165/212) |
| FPR @ high | 3.0% (10/334) |
| Recall @ critical | 30.2% (64/212) |
| FPR @ critical | 0.9% (3/334) |
| holdout-v2 (tuning) | 75.0% / 2.3% |
| Public smoke recall / FPR | 100% / 0% |

## P1/P2 scripts

- `import_samples.py`: import locally provided, licensed Hub samples; no scraping.
- `make_adversarial.py`: deterministic quarterly mutations (Base64, zero-width, split, docx).
- `make_pyc_variants.py`: pyc matrix for the current interpreter.
- `llm_judge.py`: OpenAI-compatible local endpoint prototype; candidate reranking only, optional.
- `calibrate.py`: choose threshold on dev, evaluate holdout.
- `ablation.py`: rules-only vs LLM-only vs combined.
- `candidates.py`: export medium-only candidates.

`private-inference.example.json` documents the local endpoint shape; no model is bundled.

## Limitations

- The public corpus is synthetic and structured; it tests detection primitives, not every real-world variant.
- The extended corpus is a snapshot and its labels are not a substitute for external review.
- Real Hub samples require licensing, sanitization, and human review; use `import_samples.py` rather than scraping.
- The next corpus expansion should add MaliciousSkillBench's held-out split and externally reviewed hard negatives.
- The 90% target is not met yet; the regression floor only prevents silent quality loss.

## Add a sample

1. Put the sample under `samples/zh/<id>/` with a `SKILL.md`.
2. Add an entry to `manifest.json` with a `label`, `split`, and optional `tags`.
3. Run `python bench/run.py --only <id>` and confirm the expected result.
4. If it is a new malicious primitive, add a matching fixture/test under `tests/` so the engine change is covered outside the benchmark.
