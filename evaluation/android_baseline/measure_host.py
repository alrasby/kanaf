#!/usr/bin/env python3
"""Measure frozen app definitions on an external corpus; host baseline only.
Android builds are measured separately. Never train/tune on this holdout.
"""
import argparse
import hashlib
import json
import math
import resource
import subprocess
import tempfile
import time
from importlib.metadata import version
from pathlib import Path

def wilson(matches, total):
    if not total:
        return None
    z = 1.959963984540054
    p = matches / total
    denominator = 1 + z*z/total
    center = (p + z*z/(2*total))/denominator
    margin = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))/denominator
    return [max(0, center-margin), min(1, center+margin)]

def metrics(counts):
    output = {}
    for engine, groups in counts.items():
        result = {}
        for label, group in groups.items():
            completed = group["matched"] + group["unmatched"]
            total = completed + group["incomplete"]
            result[label] = dict(total=total, completed=completed,
                incomplete=group["incomplete"], matched=group["matched"],
                match_rate_completed=group["matched"]/completed if completed else None,
                wilson_95_completed=wilson(group["matched"], completed),
                all_input_match_rate_bounds=[group["matched"]/total,
                    (group["matched"]+group["incomplete"])/total] if total else None)
        output[engine] = result
    return output

def measure(manifest_path, samples, probe, library, root, output):
    import yara_x
    assert version("yara-x") == "0.13.0"
    manifest = json.loads(manifest_path.read_text())
    assets = root / "native-rebuild/app/src/main/assets"
    clam_rules = assets / "production_clamav.hsb"
    yara_rules = assets / "production_yara.yar"
    scanner = yara_x.Scanner(yara_x.compile(yara_rules.read_text()))
    scanner.set_timeout(20)
    exact_hashes = {row.split(":")[0] for row in clam_rules.read_text().splitlines()}
    overlap = sorted(exact_hashes & {row["sha256"] for row in manifest["samples"]})
    assert not overlap, "Holdout contains exact signatures already used to construct the rules"
    results = []
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_FSIZE, (128*1024**2, 128*1024**2))
    for row in manifest["samples"]:
        sha = row["sha256"]
        file = samples / f"{sha}.sample"
        data = file.read_bytes()
        assert len(data) == row["size"] and hashlib.sha256(data).hexdigest() == sha
        started = time.monotonic()
        try:
            names = sorted(rule.identifier for rule in scanner.scan(data).matching_rules)
            yara = dict(kind="matched" if names else "unmatched", names=names)
        except (yara_x.ScanError, yara_x.TimeoutError) as error:
            yara = dict(kind="incomplete", reason=type(error).__name__)
        with tempfile.TemporaryDirectory(prefix="kanaf-parser-") as temporary:
            command = ["bwrap", "--unshare-user", "--unshare-pid", "--die-with-parent",
                "--ro-bind", "/", "/", "--bind", temporary, temporary,
                "--proc", "/proc", "--dev", "/dev", "--clearenv",
                "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", temporary,
                "--setenv", "LD_LIBRARY_PATH", str(library.parent), "--",
                str(probe), str(library), str(clam_rules), str(file), temporary]
            try:
                run = subprocess.run(command, capture_output=True, text=True, timeout=30, preexec_fn=limits)
                raw = run.stdout.strip()
                if run.returncode != 0:
                    clam = dict(kind="incomplete", reason="process-failed", exit_code=run.returncode)
                elif raw == "NO_MATCH":
                    clam = dict(kind="unmatched")
                elif raw.startswith("DETECTED:"):
                    clam = dict(kind="matched", names=[raw.split(":", 1)[1]])
                else:
                    clam = dict(kind="incomplete", reason=raw[:200])
            except subprocess.TimeoutExpired:
                clam = dict(kind="incomplete", reason="host-process-deadline")
        results.append(dict(sha256=sha, label=row["label"], group=row["group"],
                            clamav=clam, yara_x=yara, duration_ms=round((time.monotonic()-started)*1000)))
        if len(results) % 10 == 0:
            print(f"Measured {len(results)}/{len(manifest['samples'])}", flush=True)
    counts = {engine: {label: dict(matched=0, unmatched=0, incomplete=0)
                       for label in ("benign", "malicious")} for engine in ("clamav", "yara_x")}
    for case in results:
        for engine in counts:
            counts[engine][case["label"]][case[engine]["kind"]] += 1
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    report = dict(format=1, platform="Linux x86_64 host baseline; not Android device results",
        engines={"clamav":"1.4.6", "yara_x":"0.13.0"},
        manifest_sha256=digest(manifest_path),
        rules_sha256={"clamav":digest(clam_rules),"yara_x":digest(yara_rules)},
        app_clam_policy_sha256=digest(root / "native-rebuild/app/src/main/cpp/clam_scan_policy.h"),
        exact_training_overlap=overlap, counts=counts, metrics=metrics(counts), cases=results,
        frozen_rule_revision=manifest["rules_frozen_at"], sample_execution=False,
        claim="External source-labelled pilot, not representative certification", production_certification=False)
    output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(counts, indent=2), flush=True)
    return report

if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("manifest", "samples", "probe", "library", "root", "output"):
        p.add_argument("--"+key, required=True, type=Path)
    args=p.parse_args()
    measure(args.manifest, args.samples, args.probe, args.library, args.root, args.output)
