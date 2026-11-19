#!/usr/bin/env python3
"""Offline evaluation of BOTH native rule formats on a SHA-pinned labelled corpus.

TSV columns: sha256, label, origin. Files: <sha256>.sample. Labels are benign,
malicious or fixture. Fixtures are excluded from efficacy rates. An origin
is mandatory; its truth and independent curation still need external review.
No malware downloads or sample execution. Missing engines/samples stay incomplete.
"""
import argparse
import csv
import hashlib
import json
import subprocess
from importlib.metadata import version
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024

def rates(groups):
    benign, malicious = groups["benign"], groups["malicious"]
    def fraction(a, b):
        return a / b if b else None
    return {
        "false_positive_rate_completed": fraction(benign["matched"], benign["matched"] + benign["unmatched"]),
        "recall_completed": fraction(malicious["matched"], malicious["matched"] + malicious["unmatched"]),
        "recall_including_incomplete": fraction(malicious["matched"], sum(malicious.values())),
        "both_labels_completed": all(groups[label]["matched"] + groups[label]["unmatched"] > 0 for label in ("benign", "malicious")),
    }

def evaluate(manifest, directory, yara_rules, clam_rules, clamscan=None):
    import yara_x
    if version("yara-x") != "0.13.0":
        raise ValueError("Must evaluate the app's pinned yara-x==0.13.0")
    scanner = yara_x.Scanner(yara_x.compile(yara_rules.read_text()))
    scanner.set_timeout(10)
    counts = {engine: {label: dict(matched=0, unmatched=0, incomplete=0)
                       for label in ("benign", "malicious", "fixture")}
              for engine in ("yara-x", "clamav")}
    digest = lambda data: hashlib.sha256(data).hexdigest()
    rows = csv.DictReader(manifest.open(), delimiter="\t", strict=True)
    if rows.fieldnames != ["sha256", "label", "origin"]:
        raise ValueError("Expected sha256, label, origin TSV columns")
    seen = set()
    matches = {}
    for row in rows:
        sha, label, origin = row["sha256"], row["label"], row["origin"]
        if (None in row or label not in counts["yara-x"] or not origin or
                len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha) or sha in seen):
            raise ValueError("Invalid, unlabelled or duplicate corpus entry")
        seen.add(sha)
        file = directory / f"{sha}.sample"
        try:
            with file.open("rb") as source:
                data = source.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES or digest(data) != sha:
                raise ValueError("size or digest mismatch")
        except (OSError, ValueError):
            for engine in counts:
                counts[engine][label]["incomplete"] += 1
            continue
        try:
            names = sorted(rule.identifier for rule in scanner.scan(data).matching_rules)
            counts["yara-x"][label]["matched" if names else "unmatched"] += 1
            if names:
                matches[sha] = names
        except (yara_x.ScanError, yara_x.TimeoutError):
            counts["yara-x"][label]["incomplete"] += 1
        outcome = "incomplete"
        if clamscan:
            try:
                run = subprocess.run([str(clamscan), "--no-summary", "--stdout",
                                      "--database", str(clam_rules.resolve()), str(file.resolve())],
                                     capture_output=True, timeout=25, check=False)
                outcome = {0: "unmatched", 1: "matched"}.get(run.returncode, "incomplete")
            except (OSError, subprocess.TimeoutExpired):
                pass
        counts["clamav"][label][outcome] += 1
    return {"manifest_sha256": digest(manifest.read_bytes()),
            "rules": {"yara-x": digest(yara_rules.read_bytes()), "clamav": digest(clam_rules.read_bytes())},
            "engine_versions": {"yara-x": "0.13.0", "clamav": "not measured" if not clamscan else
                subprocess.run([str(clamscan), "--version"], capture_output=True, text=True, check=True).stdout.strip()},
            "counts": counts, "metrics": {engine: rates(groups) for engine, groups in counts.items()},
            "yara_matches": matches,
            "independent_corpus_review_required": True,
            "production_certification": False}

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("manifest", "directory", "yara-rules", "clam-rules"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--clamscan", type=Path)
    args = p.parse_args()
    print(json.dumps(evaluate(args.manifest, args.directory, args.yara_rules, args.clam_rules, args.clamscan), indent=2))
