#!/usr/bin/env python3
"""Freeze the current holdout and create a fresh holdout-v2 from test/dev.

The manifests keep only paths and labels; the underlying samples stay where
they are. Run a frozen manifest without generated/imported auto-loading:

  python bench/run.py --manifest bench/imported/holdout-v2.manifest.json \
    --generated-manifest bench/imported/__none__.json --no-imported \
    --split all --json-out bench/reports/holdout-v2.json

"""
from pathlib import Path
import argparse
import datetime
import json

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = [
    ROOT / "bench" / "samples" / "generated" / "manifest.json",
    ROOT / "bench" / "imported" / "manifest.json",
]


def load_samples(paths):
    samples = []
    for path in paths:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        samples.extend(data.get("samples", []))
    return samples


def write_manifest(path, split_name, samples):
    payload = {
        "version": 1,
        "frozen_at": datetime.date.today().isoformat(),
        "split": split_name,
        "samples": samples,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    benign = sum(1 for item in samples if item.get("label") == "benign")
    malicious = sum(1 for item in samples if item.get("label") == "malicious")
    print(f"{path}: {len(samples)} samples ({malicious} malicious, {benign} benign)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "bench" / "imported")
    parser.add_argument("--v2-split", choices=["test", "dev", "both"], default="test")
    args = parser.parse_args()
    sources = args.source or DEFAULT_SOURCES
    samples = load_samples(sources)

    v1 = [dict(item, split="holdout-v1") for item in samples if item.get("split") == "holdout"]
    v2_splits = {"test", "dev"} if args.v2_split == "both" else {args.v2_split}
    v2 = [dict(item, split="holdout-v2") for item in samples if item.get("split") in v2_splits]
    v3 = [dict(item, split="holdout-v3") for item in samples if item.get("split") == "dev"]
    if not v1 or not v2 or not v3:
        raise SystemExit("source manifests do not contain enough holdout/dev/test samples")

    write_manifest(args.out_dir / "holdout-v1.manifest.json", "holdout-v1", v1)
    write_manifest(args.out_dir / "holdout-v2.manifest.json", "holdout-v2", v2)
    write_manifest(args.out_dir / "holdout-v3.manifest.json", "holdout-v3", v3)


if __name__ == "__main__":
    main()