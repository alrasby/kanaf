#!/usr/bin/env python3
"""Measure reviewed YARA candidates on a local, labeled APK corpus."""
import argparse
import csv
import hashlib
import io
import json
import re
from importlib.metadata import version
from pathlib import Path

ENGINE_VERSION = "0.13.0"
MAX_APK_BYTES = 64 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def evaluate(rules, manifest, directory):
    import yara_x

    if version("yara-x") != ENGINE_VERSION:
        raise ValueError(f"Expected yara-x=={ENGINE_VERSION}")
    rule_bytes = rules.read_bytes()
    manifest_bytes = manifest.read_bytes()
    rows = csv.DictReader(io.StringIO(manifest_bytes.decode("utf-8")), delimiter="\t", strict=True)
    if rows.fieldnames != ["sha256", "label"]:
        raise ValueError("Expected TSV columns sha256 and label")
    scanner = yara_x.Scanner(yara_x.compile(rule_bytes.decode("utf-8")))
    scanner.set_timeout(10)
    counts = {label: dict(matched=0, unmatched=0, incomplete=0)
              for label in ("benign", "malicious")}
    matches = {}
    seen = set()
    for row in rows:
        digest, label = row["sha256"], row["label"]
        if (None in row or label not in counts or
                not re.fullmatch(r"[a-f0-9]{64}", digest or "") or digest in seen):
            raise ValueError(f"Invalid or duplicate sample at manifest line {rows.line_num}")
        seen.add(digest)
        group = counts[label]
        try:
            with (directory / f"{digest}.apk").open("rb") as sample:
                data = sample.read(MAX_APK_BYTES + 1)
            if len(data) > MAX_APK_BYTES or sha256(data) != digest:
                group["incomplete"] += 1
                continue
            result = scanner.scan(data)
        except (OSError, yara_x.ScanError, yara_x.TimeoutError):
            group["incomplete"] += 1
            continue
        identifiers = sorted({rule.identifier for rule in result.matching_rules})
        group["matched" if identifiers else "unmatched"] += 1
        if identifiers:
            matches[digest] = identifiers

    return {
        "engine": ENGINE_VERSION,
        "rules_sha256": sha256(rule_bytes),
        "manifest_sha256": sha256(manifest_bytes),
        "raw_apk_counts": counts,
        "matched_identifiers": matches,
        "both_labels_measured": all(group["matched"] + group["unmatched"] for group in counts.values()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("rules", "manifest", "directory"):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.rules, args.manifest, args.directory), indent=2))


if __name__ == "__main__":
    main()
