#!/usr/bin/env python3
"""Acquire a frozen external pilot corpus as non-executable private data.

Never install/run APKs. Never commit or upload sample bytes. Collector labels
and F-Droid publication are reference labels, not independent adjudication.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

def acquire(plan_path, destination, manifest_path):
    raw = plan_path.read_bytes()
    plan = json.loads(raw)
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(destination, 0o700)
    def download(index_row):
        index, row = index_row
        if row["source"] == "F-Droid":
            url = "https://f-droid.org/repo" + row["source_path"]
        elif row["source"] == "ashishb/android-malware":
            url = "https://raw.githubusercontent.com/ashishb/android-malware/" + row["source_commit"] + "/" + urllib.parse.quote(row["source_path"], safe="/")
        else:
            raise ValueError("Unapproved corpus source")
        size = row["size"]
        if not 0 < size <= plan["maximum_input_bytes"]:
            raise ValueError("Sample size outside frozen policy")
        temporary = destination / f"download-{index}.part"
        # A previous complete download can be re-verified without re-fetching.
        if not temporary.exists() or temporary.stat().st_size != size:
            with urllib.request.urlopen(url, timeout=45) as source, temporary.open("wb") as output:
                os.chmod(temporary, 0o600)
                total = 0
                started = time.monotonic()
                while True:
                    block = source.read(64 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > size or time.monotonic() - started > 120:
                        raise ValueError("Download size/deadline exceeded")
                    output.write(block)
        data = temporary.read_bytes()
        if len(data) != size:
            raise ValueError("Truncated sample")
        sha = hashlib.sha256(data).hexdigest()
        if row.get("sha256") and row["sha256"] != sha:
            raise ValueError("F-Droid catalogue SHA-256 mismatch")
        if row.get("git_blob_sha1"):
            blob = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest()
            if blob != row["git_blob_sha1"]:
                raise ValueError("Pinned Git source blob mismatch")
            name = Path(row["source_path"]).name.removesuffix(".apk")
            if re.fullmatch("[a-f0-9]{64}", name) and name != sha:
                raise ValueError("Collector hash filename mismatch")
        final = destination / f"{sha}.sample"
        temporary.replace(final)
        os.chmod(final, 0o600)
        try:
            with zipfile.ZipFile(final) as archive:
                apk_manifest = "AndroidManifest.xml" in archive.namelist()
        except zipfile.BadZipFile:
            apk_manifest = False
        return dict(row, sha256=sha, url=url, zip_has_android_manifest=apk_manifest)

    acquired = []
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(download, item): item for item in enumerate(plan["samples"])}
        for future in concurrent.futures.as_completed(futures):
            index, row = futures[future]
            try:
                acquired.append(future.result())
            except Exception as error:
                failures.append(dict(index=index, source_path=row["source_path"], reason=type(error).__name__ + ": " + str(error)[:200]))
            if (len(acquired) + len(failures)) % 10 == 0:
                print(f"Acquired={len(acquired)} failed={len(failures)}", flush=True)
    acquired.sort(key=lambda row: (row["label"], row["group"], row["sha256"]))
    unique = {}
    duplicates = []
    conflicts = set()
    for row in acquired:
        sha = row["sha256"]
        if sha in unique:
            duplicates.append(dict(sha256=sha, path=row["source_path"]))
            if unique[sha]["label"] != row["label"]:
                conflicts.add(sha)
        else:
            unique[sha] = row
    samples = [row for sha, row in unique.items() if sha not in conflicts]
    manifest = dict(format=1, plan_sha256=hashlib.sha256(raw).hexdigest(),
                    selection_seed=plan["selection_seed"], rules_frozen_at=plan["rules_frozen_at"],
                    qualification=plan["intended_claim"], sample_execution=False,
                    samples=samples, acquisition_failures=failures,
                    duplicate_records=duplicates, conflicting_labels=sorted(conflicts))
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Frozen manifest: {len(samples)} unique samples; failures={len(failures)}; conflicts={len(conflicts)}", flush=True)
    return manifest

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    acquire(args.plan, args.destination, args.manifest)
