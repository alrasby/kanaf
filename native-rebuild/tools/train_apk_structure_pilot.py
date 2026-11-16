#!/usr/bin/env python3
"""Reproduce Kanaf APK *structural-fixture* pilot weights, NOT malware ML.

12,000 generated training observations and 3,000 separate-seed fixtures.
Labels are controlled archive/DEX structural perturbations, NEVER malware.
AUC on these constructed examples is not real-world antivirus accuracy.
No network, APK execution, or malware downloads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, confusion_matrix

BIAS = -0.45171988984787753
WEIGHTS = np.array([
    -0.27664860827606197, -0.008609034959379622,
    6.906597072929637, 7.737452012358553, 7.0038476022166325,
    -0.0601200244770211, -0.13069583673444082,
], dtype=float)


def sample(rng, anomaly):
    dex = int(rng.integers(1, 13))
    libs = int(rng.integers(0, 30))
    entries = int(rng.integers(15, 1600))
    expanded = int(rng.integers(50_000, 120_000_000))
    features = [dex, libs, 0, 0, 0, entries, expanded]
    if anomaly:
        kind = int(rng.integers(0, 4))
        if kind == 0:
            features[2] = int(rng.integers(1, 9))
        elif kind == 1:
            features[3] = int(rng.integers(1, max(2, dex + 1)))
        elif kind == 2:
            features[4] = int(rng.integers(1, 9))
        else:
            features[2] = int(rng.integers(1, 4))
            features[4] = int(rng.integers(1, 4))
    return features


def generate(seed, count):
    rng = np.random.default_rng(seed)
    labels = np.tile([0, 1], count // 2)
    rng.shuffle(labels)
    samples = np.asarray([sample(rng, int(v)) for v in labels], dtype=float)
    return np.log1p(samples), labels


def apk_features(path):
    """Real APK *sanity control*, not a malware label or training set."""
    with zipfile.ZipFile(path) as apk:
        names = [item.filename for item in apk.infolist()]
        entries = apk.infolist()
    dex = sum(bool(re.fullmatch(r"classes(?:[2-9][0-9]*)?\\.dex", n)) for n in names)
    libs = sum(bool(re.fullmatch(r"lib/[^/]+/[^/]+\\.so", n)) for n in names)
    unsafe = sum(n.startswith("/") or ".." in n.replace("\\", "/").split("/")
                 or "\\" in n for n in names)
    # Cannot reproduce DEX header validation from ZIP names alone;
    # actual Android tests validate the seven-dimensional extraction path.
    return [dex, libs, unsafe, None, unsafe, len(entries),
            sum(i.file_size for i in entries)]


def reproduce(reference=None):
    train_x, train_y = generate(3006, 12_000)
    test_x, test_y = generate(3007, 3_000)
    model = LogisticRegression(
        C=0.2, solver="liblinear", random_state=51, max_iter=600
    ).fit(train_x, train_y)
    if not np.allclose(model.coef_[0], WEIGHTS, atol=1e-6) or not np.isclose(
        model.intercept_[0], BIAS, atol=1e-6
    ):
        raise ValueError("Reproduced coefficients differ from embedded Android weights")
    score = model.decision_function(test_x)
    summary = {
        "mode": "EXPERIMENTAL_APK_STRUCTURAL_FIXTURES_NOT_MALWARE",
        "malware_samples_used": 0,
        "real_world_sensitivity": None,
        "real_world_specificity": None,
        "independent_malware_holdout": False,
        "train_generated": len(train_y),
        "test_generated_separate_seed": len(test_y),
        "fixture_only_auc": roc_auc_score(test_y, score),
        "fixture_only_confusion_matrix": confusion_matrix(test_y, score > 0).tolist(),
        "bias": float(model.intercept_[0]),
        "weights": model.coef_[0].tolist(),
    }
    if reference:
        summary["real_apk_sanity_sha256"] = hashlib.sha256(reference.read_bytes()).hexdigest()
        summary["real_apk_partial_features"] = apk_features(reference)
        summary["real_apk_is_not_malware_ground_truth"] = True
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-apk", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.reference_apk and not args.reference_apk.is_file():
        parser.error("reference APK missing")
    result = reproduce(args.reference_apk)
    text = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
