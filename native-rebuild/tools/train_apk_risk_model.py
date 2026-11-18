#!/usr/bin/env python3
"""Train a signed, structurally constrained Android APK risk model.

This tool DOES NOT ship a malware detector. It requires separately obtained,
legally usable, correctly labeled Android APK feature records, and an untouched
evaluation holdout. Do not use synthetic datasets for a production release.

Dependencies for offline, manual trainer:
  python -m pip install numpy==2.1.3 scikit-learn==1.6.1
  openssl executable
Input CSV columns (all three disjoint by sha256 and collection_id):
  sha256,collection_id,label,apkDexCount,apkNativeLibraryCount,
  apkUnsafePathCount,dexInvalidHeaderCount,zipUnsafeNameCount,zipEntryCount,zipExpandedBytes
label 1=verified malicious, 0=verified benign
"""
import argparse
import csv
import hashlib
import math
from pathlib import Path
import re
import subprocess

FEATURES = (
    "apkDexCount", "apkNativeLibraryCount", "apkUnsafePathCount",
    "dexInvalidHeaderCount", "zipUnsafeNameCount", "zipEntryCount",
    "zipExpandedBytes",
)
HEADERS = ("sha256", "collection_id", "label", *FEATURES)
MIN_TRAIN = 10000
MIN_TEST = 5000


def read_samples(path):
    import numpy as np

    rows = []
    identifiers = set()
    groups = set()
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != list(HEADERS):
            raise ValueError("Unexpected CSV schema")
        for row in reader:
            identity, group = row["sha256"], row["collection_id"]
            if not re.fullmatch(r"[a-f0-9]{64}", identity):
                raise ValueError("Malformed sha256")
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{2,96}", group):
                raise ValueError("Missing source collection audit ID")
            if identity in identifiers:
                raise ValueError("Duplicate APK in a corpus")
            if row["label"] not in ("0", "1"):
                raise ValueError("No trusted binary ground-truth label")
            identifiers.add(identity)
            groups.add(group)
            values = []
            for key in FEATURES:
                number = int(row[key])
                if number < 0 or number > 1_000_000_000:
                    raise ValueError("Missing/out-of-range feature")
                values.append(math.log1p(number))
            rows.append((values, int(row["label"])))
    if not rows:
        raise ValueError("Empty corpus")
    return (
        np.array([v for v, _ in rows], dtype=np.float64),
        np.array([label for _, label in rows], dtype=np.int64),
        identifiers,
        groups,
    )


def require_independence(samples):
    a, b, c = samples
    for left, right in ((a, b), (a, c), (b, c)):
        if left[2] & right[2]:
            raise ValueError("Train/validation/test share APK SHA-256")
        if left[3] & right[3]:
            raise ValueError("Train/validation/test share source collection IDs")


def choose_threshold(scores, labels):
    import numpy as np
    # Threshold selection is permitted on the validation split ONLY.
    negatives = scores[labels == 0]
    if len(negatives) < 2000:
        raise ValueError("Insufficient validation benign samples")
    choices = np.unique(np.concatenate(([0.5, 0.99, 1.0],
                                       np.quantile(negatives, np.linspace(0.99, 1, 100)))))
    acceptable = [
        float(threshold) for threshold in choices
        if float((negatives >= threshold).mean()) <= 0.005
    ]
    if not acceptable:
        raise ValueError("No acceptable low-FPR threshold on validation set")
    return min(acceptable)


def evaluate(labels, scores, threshold):
    from sklearn.metrics import roc_auc_score
    positives = labels == 1
    negatives = labels == 0
    if positives.sum() == 0 or negatives.sum() == 0:
        raise ValueError("Test dataset lacks a class")
    return {
        "auc": float(roc_auc_score(labels, scores)),
        "fpr": float(((scores >= threshold) & negatives).sum() / negatives.sum()),
        "recall": float(((scores >= threshold) & positives).sum() / positives.sum()),
        "n": int(len(labels)),
        "benign": int(negatives.sum()),
        "malicious": int(positives.sum()),
    }


def train(train_csv, validation_csv, test_csv, private_key, output_dir,
          version, audit_report):
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", version):
        raise ValueError("Invalid model version")
    # Evidence of dataset provenance is mandatory, but its credibility must
    # still be independently reviewed by the production release owner.
    if not audit_report.is_file() or len(audit_report.read_bytes()) < 200:
        raise ValueError("Independent dataset licensing and labeling audit missing")
    train_set = read_samples(train_csv)
    validation_set = read_samples(validation_csv)
    test_set = read_samples(test_csv)
    require_independence((train_set, validation_set, test_set))

    xt, yt, _, _ = train_set
    xv, yv, _, _ = validation_set
    xe, ye, _, _ = test_set
    if len(yt) < MIN_TRAIN or (yt == 0).sum() < 3000 or (yt == 1).sum() < 3000:
        raise ValueError("Insufficient training data")
    if len(yv) < MIN_TEST or (yv == 0).sum() < 2000 or (yv == 1).sum() < 2000:
        raise ValueError("Insufficient validation data")
    if len(ye) < MIN_TEST or (ye == 0).sum() < 2000 or (ye == 1).sum() < 2000:
        raise ValueError("Insufficient untouched test data")
    model = LogisticRegression(C=0.1, solver="liblinear", class_weight="balanced",
                               max_iter=600, random_state=51).fit(xt, yt)
    threshold = choose_threshold(model.predict_proba(xv)[:, 1], yv)
    scores = model.predict_proba(xe)[:, 1]
    metrics = evaluate(ye, scores, threshold)
    if not (metrics["auc"] >= 0.90 and metrics["fpr"] <= 0.005
            and metrics["recall"] >= 0.85):
        raise ValueError("Unbiased test results failed release performance gate")
    weights = model.coef_[0]
    bias = float(model.intercept_[0])
    if not all(math.isfinite(v) and abs(v) <= 100 for v in (bias, *weights)):
        raise ValueError("Model coefficients invalid")
    # Current on-device Prediction conveys the continuous risk score and does
    # NOT issue a malware verdict; threshold is a release-audit input only.
    numbers = [
        "KanafML-1", "1", version, f"{bias:.10f}",
        *(f"{float(w):.10f}" for w in weights),
        f"{metrics['auc']:.8f}", f"{metrics['fpr']:.8f}",
        f"{metrics['recall']:.8f}",
        str(metrics["n"]), str(metrics["benign"]), str(metrics["malicious"])
    ]
    data = ("\n".join(numbers) + "\n").encode("ascii")
    output_dir.mkdir(parents=True, exist_ok=True)
    model_file = output_dir / "validated_model.txt"
    model_file.write_bytes(data)
    signed = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key)],
                            input=data, capture_output=True, check=True).stdout
    import base64
    (output_dir / "validated_model.sig").write_text(
        base64.b64encode(signed).decode("ascii") + "\n", encoding="ascii"
    )
    (output_dir / "release_audit.txt").write_text(
        f"dataset_audit_sha256={hashlib.sha256(audit_report.read_bytes()).hexdigest()}\n"
        f"train_sha256={hashlib.sha256(train_csv.read_bytes()).hexdigest()}\n"
        f"validation_sha256={hashlib.sha256(validation_csv.read_bytes()).hexdigest()}\n"
        f"test_sha256={hashlib.sha256(test_csv.read_bytes()).hexdigest()}\n"
        f"threshold={threshold:.8f}\n"
        f"auc={metrics['auc']:.8f}\nfpr={metrics['fpr']:.8f}\n"
        f"recall={metrics['recall']:.8f}\n", encoding="ascii"
    )
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-csv", type=Path, required=True)
    parser.add_argument("--validation-csv", type=Path, required=True)
    parser.add_argument("--test-csv", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--audit-report", type=Path, required=True)
    args = parser.parse_args()
    metrics = train(args.train_csv, args.validation_csv, args.test_csv,
                    args.private_key, args.output_dir, args.version, args.audit_report)
    print("Evaluation passed. Verify licensing and independently audit labeling.",
          metrics)
