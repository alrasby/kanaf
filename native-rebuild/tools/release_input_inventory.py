#!/usr/bin/env python3
"""Offline *inventory* only; file presence never equals validated evidence."""
import argparse
import json
import os
from pathlib import Path

ASSETS = (
    "production_signatures.zip",
    "production_clamav.ndb",
    "production_yara.yar",
    "validated_model.txt",
    "validated_model.sig",
)
NATIVE = ("libclamav.so", "libclammspack.so", "libyara_x_capi.so")
FILE_ENV = (
    "KANAF_RELEASE_KEYSTORE_FILE",
    "KANAF_QA_ATTESTATION",
    "KANAF_QA_ATTESTATION_SIGNATURE",
    "KANAF_QA_PUBLIC_KEY_DER",
)
VALUE_ENV = (
    "KANAF_RELEASE_STORE_PASSWORD",
    "KANAF_RELEASE_KEY_ALIAS",
    "KANAF_RELEASE_KEY_PASSWORD",
    "ORG_GRADLE_PROJECT_kanafSignaturePublicKeyBase64",
    "ORG_GRADLE_PROJECT_kanafSignatureMinVersion",
    "ORG_GRADLE_PROJECT_kanafSignatureFeedHttpsUrl",
    "ORG_GRADLE_PROJECT_kanafModelPublicKeyBase64",
    "ORG_GRADLE_PROJECT_kanafNativeClamRuleSha256",
    "ORG_GRADLE_PROJECT_kanafNativeYaraRuleSha256",
)


def inventory(root: Path, distribution: str, environ=None):
    """Return only status bits, never key content, file contents or passwords."""
    environ = os.environ if environ is None else environ
    assets = root / "app/src/main/assets"
    native = root / "app/src/main/jniLibs/arm64-v8a"
    checks = {}
    for name in ASSETS:
        path = assets / name
        checks["asset:" + name] = path.is_file() and path.stat().st_size > 0
    for name in NATIVE:
        path = native / name
        checks["native:" + name] = path.is_file() and path.stat().st_size > 0
    for name in FILE_ENV:
        value = environ.get(name, "")
        path = Path(value) if value else None
        checks["external-file:" + name] = bool(
            path and path.is_file() and path.stat().st_size > 0)
    for name in VALUE_ENV:
        checks["configured:" + name] = bool(environ.get(name, "").strip())
    checks["distribution:explicit"] = distribution in ("play", "direct")
    blockers = sorted(name for name, passed in checks.items() if not passed)
    return {
        "schema": 1,
        "distribution": distribution,
        "phase": "pre-build-inventory",
        "checks": checks,
        "missing_prerequisites": blockers,
        "prebuild_inputs_present": not blockers,
        "production_certified": False,
        "note": "Presence only. Independent QA, crypto signatures, final signed bytes, "
                "physical ARM64 tests, malware efficacy and policy approval "
                "are validated by other mandatory release gates.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--distribution", default="play", choices=("play", "direct"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    result = inventory(args.root, args.distribution)
    raw = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(raw, encoding="utf-8")
    else:
        print(raw, end="")
    if args.strict and result["missing_prerequisites"]:
        raise SystemExit("KANAF_RELEASE_INPUTS_BLOCKED: " +
                         ", ".join(result["missing_prerequisites"]))


if __name__ == "__main__":
    main()
