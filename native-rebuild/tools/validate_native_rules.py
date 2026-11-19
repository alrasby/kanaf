#!/usr/bin/env python3
"""Validate licensed native pack provenance, formats and safe control semantics.

This does NOT measure real malware recall. Positive controls are plain,
non-executable fixture bytes and must never be reported as real malware.
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from importlib.metadata import version
from pathlib import Path
from build_native_rule_pack import ROOT

def validate(clamscan, output):
    import yara_x
    assert version("yara-x") == "0.13.0"
    assets = ROOT / "app/src/main/assets"
    provenance = json.loads((assets / "native_rules_provenance.json").read_text())
    for name, expected in provenance["assets"].items():
        assert hashlib.sha256((assets / name).read_bytes()).hexdigest() == expected
    rules = yara_x.compile((assets / "production_yara.yar").read_text())
    scanner = yara_x.Scanner(rules)
    positive = b"\x7fELF" + b"\0".join([b"Modules are loaded", b"--scrypt", b"processor ", b"cpu model ", b"Host: www.challpok.cn"])
    negative = b"ordinary non-executable control"
    assert [r.identifier for r in scanner.scan(positive).matching_rules] == ["moose_2"]
    assert not list(scanner.scan(negative).matching_rules)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        sample = root / "control.sample"
        sample.write_bytes(negative)
        def run(database):
            return subprocess.run([str(clamscan), "--no-summary", "--database", str(database), str(sample)],
                                  timeout=25, capture_output=True, text=True)
        real_result = run(assets / "production_clamav.hsb")
        assert real_result.returncode == 0, real_result.stdout + real_result.stderr
        control = root / "safe-control.hsb"
        sha = hashlib.sha256(negative).hexdigest()
        control.write_text(f"{sha}:*:Kanaf.Harmless.Format.Control:73\n")
        result = run(control)
        assert result.returncode == 1, result.stdout + result.stderr
        sample.write_bytes(negative + b" changed")
        assert run(control).returncode == 0
    report = {"provenance": provenance, "yara_x_version": version("yara-x"),
              "clamav_host_version": subprocess.run([str(clamscan), "--version"], check=True, text=True, capture_output=True).stdout.strip(),
              "pinned_assets_verified": True, "native_formats_and_safe_controls_passed": True,
              "real_malware_recall": None, "production_certification": False}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print("Native formats and harmless controls passed; malware recall NOT measured")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--clamscan", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    validate(args.clamscan, args.output)
