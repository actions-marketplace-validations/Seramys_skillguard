from pathlib import Path
import argparse
import datetime
import json
import math
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "bench" / "manifest.json"
DEFAULT_GENERATED = ROOT / "bench" / "samples" / "generated" / "manifest.json"
DEFAULT_IMPORTED = ROOT / "bench" / "imported" / "manifest.json"
DEFAULT_JSON = ROOT / "bench" / "results" / "latest.json"
DEFAULT_MD = ROOT / "bench" / "results" / "latest.md"
FP_BASELINE = ROOT / "bench" / "fp-baseline.json"
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_NAME = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def crate_version() -> str:
    for line in (ROOT / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    return "0.0.0"


def default_exe() -> Path:
    for candidate in ("target/release/skillguard.exe", "target/release/skillguard"):
        path = ROOT / candidate
        if path.exists():
            return path
    raise SystemExit("skillguard binary not found; run `cargo build --release` first")


def scan_sample(exe: Path, path: Path) -> dict:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [str(exe), "scan", str(path), "--format", "json", "--min-severity", "low", "--no-color"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": True,
            "error": "scan timeout (counted as no detection)",
            "elapsed": time.perf_counter() - started,
            "max_severity": "none",
            "rank": 0,
            "rules": [],
            "findings": 0,
        }
    elapsed = time.perf_counter() - started
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "error": (proc.stderr or proc.stdout or "no output").strip()[:500],
            "elapsed": elapsed,
            "max_severity": "none",
            "rank": 0,
            "rules": [],
            "findings": 0,
        }
    findings = data.get("findings", [])
    rank = 0
    for finding in findings:
        rank = max(rank, SEVERITY_RANK.get(finding.get("severity", "low"), 0))
    return {
        "ok": True,
        "error": None,
        "elapsed": elapsed,
        "max_severity": RANK_NAME[rank],
        "rank": rank,
        "rules": sorted({finding.get("rule_id", "") for finding in findings}),
        "findings": len(findings),
        "summary": data.get("summary", {}),
    }


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    if n <= 0:
        return 0.0, 0.0, 0.0
    p = k / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, center - margin), p, min(1.0, center + margin)


def evaluate(items: list, target_fpr: float) -> dict:
    malicious = [item for item in items if item["label"] == "malicious" and item.get("ok")]
    benign = [item for item in items if item["label"] == "benign" and item.get("ok")]
    operating = None
    for rank in range(4, 0, -1):
        tp = sum(1 for item in malicious if item.get("rank", 0) >= rank)
        fp = sum(1 for item in benign if item.get("rank", 0) >= rank)
        recall = tp / len(malicious) if malicious else 0.0
        fpr = fp / len(benign) if benign else 0.0
        candidate = {
            "rank": rank,
            "threshold": RANK_NAME[rank],
            "tp": tp,
            "fn": len(malicious) - tp,
            "fp": fp,
            "tn": len(benign) - fp,
            "recall": recall,
            "fpr": fpr,
        }
        if operating is None or (fpr <= target_fpr and (recall, rank) > (operating["recall"], operating["rank"])):
            if fpr <= target_fpr:
                operating = candidate
    if operating is None:
        rank = 1
        tp = sum(1 for item in malicious if item.get("rank", 0) >= rank)
        fp = sum(1 for item in benign if item.get("rank", 0) >= rank)
        operating = {
            "rank": rank,
            "threshold": RANK_NAME[rank],
            "tp": tp,
            "fn": len(malicious) - tp,
            "fp": fp,
            "tn": len(benign) - fp,
            "recall": tp / len(malicious) if malicious else 0.0,
            "fpr": fp / len(benign) if benign else 0.0,
        }
    recall_low, _, recall_high = wilson(operating["tp"], len(malicious))
    fpr_low, _, fpr_high = wilson(operating["fp"], len(benign))
    precision = operating["tp"] / (operating["tp"] + operating["fp"]) if operating["tp"] + operating["fp"] else 0.0
    f1 = 2 * precision * operating["recall"] / (precision + operating["recall"]) if precision + operating["recall"] else 0.0
    operating.update(
        {
            "malicious": len(malicious),
            "benign": len(benign),
            "recall_ci95": [recall_low, recall_high],
            "fpr_ci95": [fpr_low, fpr_high],
            "precision": precision,
            "f1": f1,
        }
    )
    return operating


def rule_stats(items: list, threshold_rank: int) -> list:
    malicious = [item for item in items if item["label"] == "malicious" and item.get("ok")]
    benign = [item for item in items if item["label"] == "benign" and item.get("ok")]
    rule_ids = sorted({rule for item in items for rule in item.get("rules", [])})
    stats = []
    for rule in rule_ids:
        tp = sum(1 for item in malicious if rule in item.get("rules", []) and item.get("rank", 0) >= threshold_rank)
        fp = sum(1 for item in benign if rule in item.get("rules", []))
        if tp or fp:
            stats.append({"rule_id": rule, "tp": tp, "fp": fp})
    stats.sort(key=lambda item: (-item["fp"], -item["tp"], item["rule_id"]))
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SkillGuard detection benchmark")
    parser.add_argument("--exe", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--generated-manifest", type=Path, default=DEFAULT_GENERATED)
    parser.add_argument("--imported-manifest", type=Path, default=DEFAULT_IMPORTED)
    parser.add_argument("--no-imported", action="store_true", help="ignore local real corpus (public smoke)")
    parser.add_argument("--include-provisional", action="store_true")
    parser.add_argument("--split", default="all", choices=["all", "dev", "test", "holdout", "base"])
    parser.add_argument("--only", default="")
    parser.add_argument("--target-fpr", type=float, default=None)
    parser.add_argument("--version", default=None)
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--md-out", type=Path, default=DEFAULT_MD)
    parser.add_argument("--update-fp-baseline", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    exe = args.exe or default_exe()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    samples = list(manifest.get("samples", []))
    if args.generated_manifest.exists():
        generated = json.loads(args.generated_manifest.read_text(encoding="utf-8"))
        samples.extend(generated.get("samples", []))
    if not args.no_imported and args.imported_manifest.exists():
        imported = json.loads(args.imported_manifest.read_text(encoding="utf-8"))
        samples.extend(imported.get("samples", []))
    gate = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    target_fpr = args.target_fpr if args.target_fpr is not None else gate.get("target_fpr", 0.05)
    min_recall = gate.get("min_recall_at_fpr", 0.75)
    max_fpr_upper = gate.get("max_fpr_upper", 0.06)
    only = {item.strip() for item in args.only.split(",") if item.strip()}

    filtered = []
    for sample in samples:
        if sample.get("label_quality") == "provisional" and not args.include_provisional:
            continue
        if args.split != "all" and sample.get("split", "base") != args.split:
            continue
        if only and sample["id"] not in only:
            continue
        filtered.append(sample)
    if not filtered:
        print("FAIL: no samples selected", file=sys.stderr)
        return 1

    results = []
    for sample in filtered:
        path = ROOT / sample["path"]
        if not path.exists():
            results.append(
                {
                    "id": sample["id"],
                    "label": sample["label"],
                    "split": sample.get("split", "base"),
                    "tags": sample.get("tags", []),
                    "path": sample["path"],
                    "ok": False,
                    "error": "sample path missing (run bench/fetch_samples.py / make_corpus.py)",
                }
            )
            continue
        outcome = scan_sample(exe, path)
        results.append(
            {
                "id": sample["id"],
                "label": sample["label"],
                "split": sample.get("split", "base"),
                "tags": sample.get("tags", []),
                "path": sample["path"],
                **outcome,
            }
        )

    metrics = evaluate(results, target_fpr)
    split_metrics = {}
    for split in sorted({item.get("split", "base") for item in results}):
        split_metrics[split] = evaluate([item for item in results if item.get("split", "base") == split], target_fpr)
    stats = rule_stats(results, metrics["rank"])
    failures = [item["id"] for item in results if item["label"] == "malicious" and item.get("ok") and item.get("rank", 0) < metrics["rank"]]
    false_positives = [item["id"] for item in results if item["label"] == "benign" and item.get("ok") and item.get("rank", 0) >= metrics["rank"]]

    new_fp = []
    if FP_BASELINE.exists():
        baseline = json.loads(FP_BASELINE.read_text(encoding="utf-8"))
        new_fp = sorted(set(false_positives) - set(baseline.get("benign_detected", [])))
    if args.update_fp_baseline:
        FP_BASELINE.write_text(
            json.dumps({"benign_detected": false_positives, "threshold": metrics["threshold"]}, indent=2) + "\n",
            encoding="utf-8",
        )

    version = args.version or crate_version()
    stamp = datetime.date.today().isoformat()
    version_json = args.json_out.parent / f"v{version}-{stamp}.json"
    version_md = args.md_out.parent / f"v{version}-{stamp}.md"
    payload = {
        "exe": str(exe),
        "version": version,
        "split": args.split,
        "metrics": metrics,
        "split_metrics": split_metrics,
        "rule_stats": stats,
        "failures": failures,
        "false_positives": false_positives,
        "new_false_positives": new_fp,
        "samples": results,
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    for path in (args.json_out, version_json):
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# SkillGuard detection benchmark",
        "",
        f"- binary: `{exe}`",
        f"- version: `{version}` / split: `{args.split}`",
        f"- operating point: `{metrics['threshold']}+` (target FPR <= {target_fpr:.0%})",
        f"- malicious: {metrics['malicious']}, benign: {metrics['benign']}",
        f"- recall: **{metrics['recall']:.1%}** ({metrics['tp']}/{metrics['malicious']}), 95% CI {metrics['recall_ci95'][0]:.1%}-{metrics['recall_ci95'][1]:.1%}",
        f"- FPR: **{metrics['fpr']:.1%}** ({metrics['fp']}/{metrics['benign']}), 95% CI {metrics['fpr_ci95'][0]:.1%}-{metrics['fpr_ci95'][1]:.1%}",
        "",
        "| split | malicious | benign | threshold | recall | FPR | FPR upper |",
        "| --- | ---: | ---: | --- | ---: | ---: | ---: |",
    ]
    for split, item in split_metrics.items():
        lines.append(
            f"| {split} | {item['malicious']} | {item['benign']} | {item['threshold']}+ | {item['recall']:.1%} | {item['fpr']:.1%} | {item['fpr_ci95'][1]:.1%} |"
        )
    lines.extend(
        [
            "",
            f"- missed malicious: {len(failures)}" + (f" ({', '.join(failures[:20])})" if failures else ""),
            f"- false positives: {len(false_positives)}" + (f" ({', '.join(false_positives[:20])})" if false_positives else ""),
            f"- new false positives vs baseline: {len(new_fp)}",
            "",
            "| rule | TP | FP |",
            "| --- | ---: | ---: |",
        ]
    )
    for item in stats[:15]:
        lines.append(f"| {item['rule_id']} | {item['tp']} | {item['fp']} |")
    for path in (args.md_out, version_md):
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if not args.quiet:
        print("\n".join(lines))
        print(f"\nwrote {args.json_out}")
        print(f"wrote {version_json}")

    if any(not item.get("ok") for item in results):
        print("FAIL: one or more samples could not be scanned", file=sys.stderr)
        return 1
    if metrics["fpr"] > target_fpr:
        print(f"FAIL: operating FPR {metrics['fpr']:.1%} > {target_fpr:.1%}", file=sys.stderr)
        return 1
    if metrics["fpr_ci95"][1] > max_fpr_upper:
        print(
            f"FAIL: FPR 95% upper bound {metrics['fpr_ci95'][1]:.1%} > {max_fpr_upper:.1%}",
            file=sys.stderr,
        )
        return 1
    if metrics["recall"] < min_recall:
        print(f"FAIL: recall {metrics['recall']:.1%} < {min_recall:.1%}", file=sys.stderr)
        return 1
    if new_fp and args.manifest.resolve() == DEFAULT_MANIFEST.resolve():
        print(f"FAIL: new false positives: {', '.join(new_fp[:10])}", file=sys.stderr)
        return 1
    print("PASS: benchmark gate satisfied", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())