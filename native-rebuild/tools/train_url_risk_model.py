#!/usr/bin/env python3
"""Reproducible, URL-only Kanaf AI pilot: real CC BY 4.0 PhiUSIIL data.

Downloads text CSV data, NEVER visits any listed URL, runs no APK and makes
no malware-safety claims. A fresh ephemeral CI key signs the resulting
advisory-only linear model. Release-grade APK risk AI is independent and OFF.
"""
import argparse
import csv
import hashlib
import io
import ipaddress
import json
import math
import re
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request
import zipfile

UCI_DATASET_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip"
DOI = "10.17632/shwpxscxy2.2"
MODEL_VERSION = "phiusiiil-url-pilot-1"
COLUMNS = 12
# The collection's original mapping (do NOT swap):
# 1 = legitimate; 0 = phishing.
LABEL_MAPPING = {"0": 1, "1": 0}
COMMON_SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au",
                       "co.jp", "com.br", "com.tr", "co.in", "com.mx"}


def lexical_features(raw):
    """Exact log1p/caps/order contract with KanafUrlAi.kt; no web requests."""
    if not isinstance(raw, str) or not (5 <= len(raw) <= 2048):
        return None
    if any(ord(char) < 33 or ord(char) > 126 for char in raw):
        return None
    try:
        url = urllib.parse.urlsplit(raw)
        scheme = url.scheme.lower()
        host = url.hostname
        if scheme not in ("http", "https") or not host or len(host) > 253:
            return None
        port = url.port  # validate malformed authorities without contacting host
    except ValueError:
        return None
    host = host.lower()
    parts = host.split(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    def count(n, cap=2048):
        return math.log1p(min(max(0, n), cap))
    return [
        count(len(raw)), count(len(host), 253),
        count(sum("0" <= c <= "9" for c in raw)),
        count(raw.count("."), 200), count(raw.count("-"), 200),
        count(len(url.path)), count(len(url.query)),
        float(scheme == "https"), float(url.username is not None),
        float(is_ip), count(max(0, len(parts) - 2), 30),
        count(raw.count("%"), 100)
    ]


def registrable_group(raw):
    """Approximate eTLD+1 solely for leakage prevention (not a PSL implementation)."""
    host = urllib.parse.urlsplit(raw).hostname.lower()
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    suffix = ".".join(parts[-2:])
    if suffix in COMMON_SECOND_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def split_of(group):
    # Frozen group-only 70/15/15 assignment; no label or features in splitting.
    n = int.from_bytes(hashlib.sha256(
        ("kanaf-url-pilot-2026:" + group).encode("utf8")).digest()[:8], "big")
    v = n / 2**64
    return "train" if v < .70 else ("val" if v < .85 else "test")


def download_dataset():
    request = urllib.request.Request(UCI_DATASET_URL, headers={
        "User-Agent": "KanafAIResearch/0.1 (offline URL lexical training)"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise ValueError("dataset download lost HTTPS")
        data = response.read(45_000_001)
        if len(data) > 45_000_000:
            raise ValueError("dataset archive exceeds configured bound")
    archive_sha = hashlib.sha256(data).hexdigest()
    # Independently published reproducible hash, checked before opening CSV.
    expected_sha = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
    if archive_sha != expected_sha:
        raise ValueError("PhiUSIIL archive SHA-256 differs from pinned research source")
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        choices = [n for n in bundle.namelist() if n.lower().endswith(".csv")
                   and not n.startswith("__MACOSX")]
        if len(choices) != 1:
            raise ValueError("expected exactly one original CSV")
        member = bundle.getinfo(choices[0])
        if not 30_000_000 < member.file_size < 100_000_000:
            raise ValueError("unexpected source CSV size")
        csv_bytes = bundle.read(member)
    return csv_bytes, archive_sha


def read_data(csv_bytes):
    sha = hashlib.sha256(csv_bytes).hexdigest()
    sample = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig"), newline=""))
    names = set(sample.fieldnames or [])
    if not {"URL", "label"} <= names:
        raise ValueError("source lacks actual URL/label columns")
    unique = {}
    duplicates = 0
    rejected = 0
    labels = [0, 0]
    for record in sample:
        label = LABEL_MAPPING.get(record["label"].strip())
        if label is None:
            raise ValueError("unexpected PhiUSIIL label (mapping cannot be inferred)")
        url = record["URL"].strip()
        features = lexical_features(url)
        if features is None:
            rejected += 1
            continue
        digest = hashlib.sha256(url.encode("ascii")).hexdigest()
        if digest in unique:
            if unique[digest][1] != label:
                raise ValueError("conflicting ground truth for identical URL")
            duplicates += 1
            continue
        unique[digest] = (url, label, features)
        labels[label] += 1
    if len(unique) < 100_000 or min(labels) < 20_000:
        raise ValueError("dataset too small after URL-only filtering")
    return unique, dict(rows=len(unique), original_sha256=sha,
                        rejected=rejected, duplicate_urls=duplicates,
                        legitimate=labels[0], phishing=labels[1])


def train(data, source, private_key, output):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import roc_auc_score, average_precision_score

    groups = {"train": [], "val": [], "test": []}
    seen_domains = {"train": set(), "val": set(), "test": set()}
    for url, label, features in data.values():
        domain = registrable_group(url)
        part = split_of(domain)
        groups[part].append((features, label))
        seen_domains[part].add(domain)
    assert all(not (seen_domains[a] & seen_domains[b])
               for a, b in (("train","val"),("train","test"),("val","test")))
    arrays = {}
    for part, records in groups.items():
        if len(records) < 10_000 or len(set(label for _, label in records)) != 2:
            raise ValueError("inadequate independent domain-group split " + part)
        x = np.asarray([f for f, _ in records], dtype=np.float64)
        y = np.asarray([y for _, y in records], dtype=np.int64)
        arrays[part] = (x, y)
    xtr, ytr = arrays["train"]
    xval, yval = arrays["val"]
    xte, yte = arrays["test"]
    # Feature ablation is a pre-declared safety measure: the first pilot
    # learned huge, opposite-signed coefficients for dot/subdomain counts,
    # classifying reputable www. domains as almost certainly phishing.
    # Exclude both collinear dimensions; keep their signed slots at zero so
    # Android's 12-feature inference protocol stays backwards compatible.
    active = (0, 1, 2, 4, 5, 6, 7, 8, 9, 11)
    scaler = StandardScaler().fit(xtr[:, active])
    clf = LogisticRegression(C=0.02, class_weight="balanced", max_iter=500,
                             solver="lbfgs", random_state=93)
    clf.fit(scaler.transform(xtr[:, active]), ytr)
    weights = np.zeros(COLUMNS, dtype=np.float64)
    selected = clf.coef_[0] / scaler.scale_
    weights[list(active)] = selected
    bias = float(clf.intercept_[0] - np.dot(selected, scaler.mean_))
    if not np.isfinite(weights).all() or not math.isfinite(bias) or (
        np.max(np.abs(weights)) > 100 or abs(bias) > 100):
        raise ValueError("model weights invalid")
    def score(x):
        logits = np.clip(x @ weights + bias, -40, 40)
        return 1 / (1 + np.exp(-logits))
    val_probs = score(xval)
    test_probs = score(xte)
    # Choose ONE threshold using validation negatives, never test data.
    negatives = val_probs[yval == 0]
    threshold = float(np.quantile(negatives, 0.99))
    test_pred = test_probs >= threshold
    tp = int(((test_pred) & (yte == 1)).sum())
    fp = int(((test_pred) & (yte == 0)).sum())
    malicious = int((yte == 1).sum())
    benign = int((yte == 0).sum())
    metrics = {
        "dataset": "PhiUSIIL Phishing URL Dataset",
        "source": UCI_DATASET_URL,
        "dataset_doi": DOI,
        "license": "CC BY 4.0 (attribution required)",
        "model_version": MODEL_VERSION,
        "mode": "EXPERIMENTAL_URL_ONLY_NOT_APK_ANTIVIRUS",
        "independent_external_corpus": False,
        "split_policy": "deterministic approximated registrable-domain disjoint 70/15/15",
        "counts": {part: len(groups[part]) for part in groups},
        "domain_count": {part: len(seen_domains[part]) for part in groups},
        "holdout_malicious": malicious,
        "holdout_benign": benign,
        "threshold_selected_on_validation": threshold,
        "holdout_auc": float(roc_auc_score(yte, test_probs)),
        "holdout_average_precision": float(average_precision_score(yte, test_probs)),
        "holdout_fpr_at_threshold": fp / benign,
        "holdout_recall_at_threshold": tp / malicious,
        "holdout_tp": tp, "holdout_fp": fp,
        "archive_sha256": source["archive_sha256"],
        "csv_sha256": source["original_sha256"],
        "dropped_urls": source["rejected"],
        "duplicate_urls": source["duplicate_urls"],
        "notes": "URL string only; never fetched/visited sites. Labels historical. "
            "No external-dataset validation. Not a probability calibration or clean verdict."
    }
    # A low false positive rate on historical dataset is not enough:
    # check frozen, real, independently known legitimate *root* URLs.
    # This is a pre-distribution sanity guard, NOT an external ROC benchmark.
    known_benign = (
        "https://www.wikipedia.org/", "https://www.microsoft.com/",
        "https://www.apple.com/", "https://www.google.com/",
        "https://www.mozilla.org/", "https://www.un.org/",
        "https://www.nasa.gov/", "https://www.gov.uk/"
    )
    control = [float(score(np.asarray([lexical_features(url)]))[0])
               for url in known_benign]
    metrics["known_benign_root_controls"] = {
        "urls_tested": len(control),
        "max_pilot_score": max(control),
        "median_pilot_score": float(np.median(control)),
        "falsely_above_80pct": sum(v >= 0.80 for v in control)
    }
    # Persist the honest failure record even if the pilot does not qualify.
    output.mkdir(parents=True, exist_ok=True)
    (output / "evaluation.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf8")
    if any(v >= 0.80 for v in control):
        raise ValueError("pilot blocked: unacceptably high false alarms on known legitimate roots")

    # A deliberately relaxed pilot gate. DO NOT use Android malware release
    # acceptance metrics or claim independent external validation.
    if not (metrics["holdout_auc"] >= 0.68 and
            metrics["holdout_fpr_at_threshold"] <= 0.08):
        raise ValueError("pilot model did not meet minimum discrimination gate")
    output.mkdir(parents=True, exist_ok=True)
    numbers = ["KanafURLML-1", str(COLUMNS), MODEL_VERSION,
               f"{bias:.12f}", *(f"{w:.12f}" for w in weights)]
    model = ("\n".join(numbers) + "\n").encode("ascii")
    (output / "url_risk_model.txt").write_bytes(model)
    signature = subprocess.run(
        ["openssl","dgst","-sha256","-sign",str(private_key)],
        input=model, capture_output=True, check=True).stdout
    import base64
    (output / "url_risk_model.sig").write_text(
        base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
    (output / "evaluation.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf8")
    (output / "PUBLIC_DATA_ATTRIBUTION.txt").write_text(
        "PhiUSIIL Phishing URL Dataset, Arvind Prasad and Shalini Chandra, "
        "Mendeley Data v2 DOI 10.17632/shwpxscxy2.2, CC BY 4.0.\n"
        "Features changed: 12 URL-string-only lexical attributes; logistic "
        "regression; domain-group holdout.\n"
        "This pilot is NOT an antivirus classifier and has NO independent "
        "real-world current-URL validation.\n", encoding="utf8")
    return metrics


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    if not args.private_key.is_file():
        raise ValueError("ephemeral signing key unavailable")
    csv_bytes, archive_sha = download_dataset()
    data, source = read_data(csv_bytes)
    source["archive_sha256"] = archive_sha
    metrics = train(data, source, args.private_key, args.output_dir)
    # No raw URL strings or original dataset are saved into CI artifacts.
    print(json.dumps({"model_version": MODEL_VERSION, "counts": metrics["counts"],
        "auc": metrics["holdout_auc"], "fpr": metrics["holdout_fpr_at_threshold"],
        "recall": metrics["holdout_recall_at_threshold"],
        "csv_sha256": metrics["csv_sha256"]}, indent=2))

if __name__ == "__main__":
    main()
