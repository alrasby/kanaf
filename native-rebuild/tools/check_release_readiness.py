#!/usr/bin/env python3
"""Strict offline production release gate; does not mint security evidence.

A publisher-appointed independent QA signer must attest the complete evidence
using a key supplied OUTSIDE this repository and APK. This is a technical gate,
not a substitute for human evaluation or physical-device penetration testing.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess


def validate(report, *, today=None):
    today = today or dt.date.today()
    problems = []
    def required(condition, message):
        if not condition:
            problems.append(message)
    digest = re.compile(r"[a-f0-9]{64}\Z")
    is_digest = lambda s: isinstance(s, str) and bool(digest.fullmatch(s))
    if not isinstance(report, dict):
        return ["invalid-evidence-schema"]
    required(report.get("schema") == 1, "evidence-schema")
    required(is_digest(report.get("git_tree_sha256", "")), "source-tree-digest")
    native = report.get("native") if isinstance(report.get("native"), dict) else {}
    required(native.get("clamav") == "1.4.6", "patched-clamav-version")
    required(native.get("abi") == "arm64-v8a", "native-arm64-abi")
    required(native.get("physical_device") is True, "physical-arm64-device-test")
    required(native.get("page_size_bytes") == 16384 and
             type(native.get("page_size_bytes")) is int,
             "physical-arm64-16kb-page-test")
    required(native.get("production_rules_loaded") is True,
             "native-production-rules-actually-loaded")
    required(is_digest(native.get("production_clamav_rules_sha256")),
             "native-production-clamav-rules-hash")
    required(is_digest(native.get("production_yara_rules_sha256")),
             "native-production-yara-rules-hash")
    required(native.get("independent_non_eicar_threat_detection") is True,
             "native-independent-malware-detection")
    required(native.get("clamav_eicar_detected") is True, "real-clamav-positive")
    required(native.get("clamav_benign_no_match") is True, "real-clamav-negative")
    required(native.get("yara_eicar_detected") is True, "real-yarax-positive")
    required(native.get("yara_benign_no_match") is True, "real-yarax-negative")
    required(is_digest(native.get("tested_apk_sha256")), "tested-apk-digest")

    model = report.get("model") if isinstance(report.get("model"), dict) else {}
    required(is_digest(model.get("weights_sha256")), "ml-model-hash")
    required(is_digest(model.get("independent_test_corpus_sha256")), "ml-test-corpus-hash")
    required(model.get("validated_label_provenance") is True, "ml-ground-truth-provenance")
    required(model.get("synthetic_fixture_only") is False,
             "ml-not-synthetic-fixtures")
    required(model.get("independent_external_source_holdout") is True,
             "ml-independent-external-source")
    required(model.get("independent_test") is True, "ml-independent-holdout")
    sample_count = model.get("test_samples")
    benign_count = model.get("benign_samples")
    malicious_count = model.get("malicious_samples")
    required(all(type(x) is int and x >= 0 for x in
                 (sample_count, benign_count, malicious_count)) and
             sample_count == benign_count + malicious_count,
             "ml-test-counts-consistent")
    required(model.get("train_test_disjoint_by_hash_and_source") is True, "ml-split-leakage")
    for key, low, high in (("auc", 0.90, 1), ("fpr", 0, 0.005),
                           ("recall", 0.85, 1)):
        value = model.get(key)
        required(isinstance(value, (int, float)) and not isinstance(value, bool)
                 and low <= value <= high, "ml-" + key)
    required(isinstance(model.get("test_samples"), int) and
             model.get("test_samples", -1) >= 5000, "ml-min-test-samples")
    required(isinstance(model.get("benign_samples"), int) and
             model.get("benign_samples", -1) >= 2000, "ml-min-benign")
    required(isinstance(model.get("malicious_samples"), int) and
             model.get("malicious_samples", -1) >= 2000, "ml-min-malicious")
    required(bool(model.get("dataset_license_review_id")), "ml-dataset-license-review")

    feed = report.get("signatures") if isinstance(report.get("signatures"), dict) else {}
    required(is_digest(feed.get("db_sha256")), "threat-feed-hash")
    required(is_digest(feed.get("pinned_key_sha256")), "threat-feed-pinned-public-key")
    required(isinstance(feed.get("version"), int) and
             feed.get("version", -1) >= 1, "threat-feed-version")
    required(isinstance(feed.get("real_non_test_signatures"), int) and
             feed.get("real_non_test_signatures", 0) > 0, "threat-feed-real-coverage")
    required(feed.get("verified_signature") is True, "threat-feed-rsa-proof")
    required(feed.get("signed_antirollback_test") is True, "threat-feed-antirollback")
    required(feed.get("fresh_install_verified") is True,
             "threat-feed-signed-bootstrap-tested")
    required(feed.get("test_only_rules_excluded") is True,
             "threat-feed-not-test-only")
    required(bool(feed.get("license_and_source_review_id")), "threat-feed-provenance")
    try:
        when = dt.date.fromisoformat(feed.get("verified_date", ""))
        required(0 <= (today - when).days <= 30, "threat-feed-freshness")
    except (ValueError, TypeError):
        required(False, "threat-feed-freshness")

    release = report.get("release") if isinstance(report.get("release"), dict) else {}
    required(release.get("signed_apk") is True, "apk-release-signing")
    required(release.get("signed_aab") is True, "aab-release-signing")
    required(type(release.get("target_sdk")) is int and
             release.get("target_sdk", 0) >= 36, "play-target-api36")
    required(release.get("play_sensitive_permissions_approved") is True,
             "play-sensitive-permissions-approval")
    required(release.get("vpn_service_policy_review") is True,
             "play-vpnservice-policy-review")
    required(release.get("real_device_scan_and_dns_qa") is True,
             "physical-dns-and-scan-acceptance")
    required(is_digest(release.get("signed_apk_sha256")), "release-apk-digest")
    required(release.get("signed_apk_sha256") == native.get("tested_apk_sha256"),
             "tested-artifact-must-match-release-artifact")
    required(bool(release.get("independent_security_review_id")), "independent-security-review")
    required(bool(release.get("distribution_licenses_review_id")), "distribution-license-review")
    required(bool(release.get("android_permissions_review_id")), "android-permissions-review")
    return problems


def verify_attestation(evidence_path: Path, signature_path: Path, public_key_path: Path):
    completed = subprocess.run([
        "openssl", "dgst", "-sha256", "-verify", str(public_key_path),
        "-signature", str(signature_path), str(evidence_path)
    ], capture_output=True, check=False, timeout=10)
    if completed.returncode != 0:
        raise ValueError("evidence-signature-invalid")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--signature", type=Path, required=True)
    p.add_argument("--qa-public-key", type=Path, required=True)
    args = p.parse_args()
    verify_attestation(args.evidence, args.signature, args.qa_public_key)
    evidence = json.loads(args.evidence.read_text("utf-8"))
    failures = validate(evidence)
    if failures:
        raise SystemExit("RELEASE BLOCKED: " + ", ".join(failures))
    print("TECHNICAL RELEASE GATES PASSED ON SIGNED CLAIMS. Independent audit still required.")


if __name__ == "__main__":
    main()
