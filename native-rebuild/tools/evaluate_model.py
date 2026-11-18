#!/usr/bin/env python3
"""Offline ML holdout evaluator, NOT a trainer or independent model audit.

Requires disjoint training/holdout sources and unique SHA-256. A mathematical
PASS is not evidence of sample provenance, licensing or real-model inference.
"""
import argparse
import json
import math
import re
import sys
from pathlib import Path

HASH = re.compile(r"[0-9a-f]{64}")
MIN_TEST = 5000
MIN_CLASS = 2000
MAX_FPR = 0.005
MIN_RECALL = 0.85
MIN_AUC = 0.90


def auc_roc(rows):
    """Mann-Whitney U with mid-ranks; ties are not silently misranked."""
    scores = sorted((r["score"], r["label"]) for r in rows)
    positive = sum(r["label"] for r in rows)
    negative = len(rows) - positive
    if positive == 0 or negative == 0:
        raise ValueError("holdout must contain both labels")
    rank_sum = 0.0
    index = 0
    while index < len(scores):
        end = index + 1
        while end < len(scores) and scores[end][0] == scores[index][0]:
            end += 1
        rank = (index + 1 + end) / 2
        rank_sum += sum(label for _, label in scores[index:end]) * rank
        index = end
    return (rank_sum - positive * (positive + 1) / 2) / (positive * negative)


def evaluate(lines, threshold=0.5):
    if not (0.0 < threshold < 1.0):
        raise ValueError("threshold must be within (0,1)")
    hashes = set()
    sources = {"train": set(), "holdout": set()}
    held = []
    train_count = 0
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at row {line_number}") from exc
        sha, split, label, source = (
            row.get("sha256"), row.get("split"), row.get("label"), row.get("source")
        )
        if not isinstance(sha, str) or not HASH.fullmatch(sha):
            raise ValueError(f"invalid SHA256 at row {line_number}")
        if sha in hashes:
            raise ValueError(f"train/test duplicate SHA-256 at row {line_number}")
        hashes.add(sha)
        if split not in sources or type(label) is not int or label not in (0, 1):
            raise ValueError(f"invalid split or label at row {line_number}")
        if not isinstance(source, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{4,80}", source):
            raise ValueError(f"source provenance missing at row {line_number}")
        sources[split].add(source)
        if split == "train":
            train_count += 1
        else:
            score = row.get("score")
            if (not isinstance(score, (int, float)) or isinstance(score, bool)
                    or not math.isfinite(score) or not 0 <= score <= 1):
                raise ValueError(f"invalid model risk score at row {line_number}")
            held.append({"label": label, "score": float(score)})
    if not train_count:
        raise ValueError("missing training fingerprints for leakage review")
    if not held:
        raise ValueError("missing held-out predictions")
    if sources["train"] & sources["holdout"]:
        raise ValueError("source-level train/test leakage")
    benign = sum(1 for r in held if r["label"] == 0)
    malicious = len(held) - benign
    if not benign or not malicious:
        raise ValueError("holdout must contain both labels")
    tp = sum(r["label"] == 1 and r["score"] >= threshold for r in held)
    fp = sum(r["label"] == 0 and r["score"] >= threshold for r in held)
    result = {
        "holdout": len(held), "malicious": malicious, "benign": benign,
        "training_fingerprints": train_count,
        "train_sources": sorted(sources["train"]),
        "holdout_sources": sorted(sources["holdout"]),
        "threshold": threshold, "auc": round(auc_roc(held), 8),
        "false_positive_rate": round(fp / benign, 8),
        "recall": round(tp / malicious, 8),
        "true_positives": tp, "false_positives": fp,
    }
    result["passes_math_gate"] = (
        len(held) >= MIN_TEST and benign >= MIN_CLASS and malicious >= MIN_CLASS and
        result["auc"] >= MIN_AUC and result["false_positive_rate"] <= MAX_FPR and
        result["recall"] >= MIN_RECALL
    )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True,
                   help="licensed metadata JSONL only; no raw APKs")
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        with args.input.open("r", encoding="utf8") as inp:
            result = evaluate(inp, args.threshold)
        data = json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(data + "\n", encoding="utf-8")
        print(data)
        if not result["passes_math_gate"]:
            print("FAIL: insufficient independent data or model performance", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError) as e:
        print("FAIL: " + str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
