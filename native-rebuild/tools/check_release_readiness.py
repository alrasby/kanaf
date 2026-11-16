#!/usr/bin/env python3
"""Strict offline production release gate; does not mint security evidence.

A publisher-appointed independent QA signer must attest the complete evidence
using a key supplied OUTSIDE this repository and APK. This is a technical gate,
not a substitute for human evaluation or physical-device penetration testing.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


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
    distribution = release.get("distribution")
    required(distribution in ("play", "direct"), "release-distribution-missing")
    # The app's compiled DNS policy must correspond to the distribution
    # that independent QA actually tested. Never call ad-filter builds Play.
    required(type(release.get("dns_security_only")) is bool and
             release.get("dns_security_only") == (distribution == "play"),
             "release-dns-policy-distribution-mismatch")
    required(release.get("signed_apk") is True, "apk-release-signing")
    required(release.get("signed_aab") is True, "aab-release-signing")
    required(is_digest(release.get("signed_aab_sha256")), "aab-artifact-digest")
    required(is_digest(release.get("apk_signer_cert_sha256")), "apk-signer-certificate-digest")
    required(type(release.get("target_sdk")) is int and
             release.get("target_sdk", 0) >= 36, "play-target-api36")
    # Direct distribution must not invent Play Store approval. Play permission
    # checks remain mandatory for a Play release or an unspecified channel.
    if distribution != "direct":
            required(release.get("play_sensitive_permissions_approved") is True,
                 "play-sensitive-permissions-approval")
        required(release.get("vpn_service_policy_review") is True,
                 "play-vpnservice-policy-review")
        required(release.get("play_dns_cross_app_ad_policy_resolved") is True,
                 "play-cross-app-ad-blocking-policy")
        required(release.get("vpn_explicit_disclosure_device_qa") is True,
                 "play-vpn-prominent-disclosure")
        required(release.get("vpn_stop_and_dns_leak_device_qa") is True,
                 "physical-vpn-disconnect-and-dns-leak-qa")
        required(release.get("live_privacy_policy_approved") is True,
                 "play-live-app-privacy-policy")
        required(release.get("play_data_safety_verified") is True,
                 "play-data-safety-attestation")
        required(release.get("play_fgs_special_use_approved") is True,
                 "play-special-use-fgs-approval")
    required(release.get("real_device_scan_and_dns_qa") is True,
             "physical-dns-and-scan-acceptance")
    required(is_digest(release.get("signed_apk_sha256")), "release-apk-digest")
    required(release.get("signed_apk_sha256") == native.get("tested_apk_sha256"),
             "tested-artifact-must-match-release-artifact")
    required(bool(release.get("independent_security_review_id")), "independent-security-review")
    required(bool(release.get("distribution_licenses_review_id")), "distribution-license-review")
    required(bool(release.get("android_permissions_review_id")), "android-permissions-review")
    return problems


def verify_artifacts(report, apk_path: Path, aab_path: Path, *, run=subprocess.run):
    """Bind independently signed QA claims to actual files and signing certificates.

    Missing signers/tools, mismatched bytes or invalid signatures MUST block release.
    apksigner and jarsigner come from the publisher's trusted Android/JDK toolchain.
    """
    problems = []
    release = report.get("release") if isinstance(report.get("release"), dict) else {}

    def digest(path, label):
        try:
            if not path.is_file() or path.stat().st_size == 0:
                raise OSError("empty or missing artifact")
            value = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    value.update(chunk)
            return value.hexdigest()
        except OSError:
            problems.append(label + "-unreadable")
            return None

    apk_digest = digest(apk_path, "apk")
    aab_digest = digest(aab_path, "aab")
    if apk_digest is not None and apk_digest != release.get("signed_apk_sha256"):
        problems.append("apk-actual-bytes-mismatch")
    if aab_digest is not None and aab_digest != release.get("signed_aab_sha256"):
        problems.append("aab-actual-bytes-mismatch")

    def execute(command, label):
        try:
            result = run(command, capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired):
            problems.append(label + "-verification-unavailable")
            return None
        if result.returncode != 0:
            problems.append(label + "-signature-invalid")
            return None
        return result.stdout + "\n" + result.stderr

    if apk_digest is not None:
        output = execute(["apksigner", "verify", "--min-sdk-version", "26",
                          "--verbose", "--print-certs", str(apk_path)], "apk")
        if output is not None:
            # v2/v3 protect APK contents, unlike relying on a legacy JAR signature.
            if not re.search(r"Verified using v[23] scheme[^\n]*:\s*true", output, re.I):
                problems.append("apk-modern-signature-absent")
            certificates = re.findall(
                r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})",
                output, re.I)
            if (len(certificates) != 1 or
                    certificates[0].lower() != release.get("apk_signer_cert_sha256")):
                problems.append("apk-signer-certificate-mismatch")
    if aab_digest is not None:
        output = execute(["jarsigner", "-verify", "-strict", str(aab_path)], "aab")
        if output is not None and "jar verified." not in output.lower():
            problems.append("aab-signature-not-confirmed")
    return problems


def verify_attestation(evidence_path: Path, signature_path: Path,
                       public_key_path: Path, expected_key_sha256: str):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_key_sha256):
        raise ValueError("untrusted-qa-key-fingerprint-invalid")
    actual = hashlib.sha256(public_key_path.read_bytes()).hexdigest()
    if actual != expected_key_sha256:
        raise ValueError("untrusted-qa-key-fingerprint-mismatch")
    # Publisher QA stores its pinned public key as X.509 SPKI DER, while
    # 'openssl dgst -verify' expects a PEM public key. Convert only the
    # already fingerprint-verified PUBLIC bytes in a disposable directory.
    encoded = base64.b64encode(public_key_path.read_bytes()).decode("ascii")
    pem_lines = "\n".join(encoded[n:n + 64] for n in range(0, len(encoded), 64))
    with tempfile.TemporaryDirectory(prefix="kanaf-qa-pub-") as temporary:
        pem = Path(temporary) / "qa-public.pem"
        pem.write_text("-----BEGIN PUBLIC KEY-----\n" + pem_lines +
                       "\n-----END PUBLIC KEY-----\n", encoding="ascii")
        completed = subprocess.run([
            "openssl", "dgst", "-sha256", "-verify", str(pem),
            "-signature", str(signature_path), str(evidence_path)
        ], capture_output=True, check=False, timeout=10)
    if completed.returncode != 0:
        raise ValueError("evidence-signature-invalid")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--signature", type=Path, required=True)
    p.add_argument("--qa-public-key", type=Path, required=True)
    p.add_argument("--expected-qa-public-key-sha256", required=True,
                   help="Pinned SHA-256 fingerprint from an independent trusted channel")
    p.add_argument("--apk", type=Path, required=True)
    p.add_argument("--aab", type=Path, required=True)
    args = p.parse_args()
    verify_attestation(args.evidence, args.signature, args.qa_public_key,
                       args.expected_qa_public_key_sha256)
    evidence = json.loads(args.evidence.read_text("utf-8"))
    failures = validate(evidence)
    if not failures:
        if evidence["signatures"]["pinned_key_sha256"] == args.expected_qa_public_key_sha256:
            failures.append("qa-key-must-be-independent-of-threat-feed-key")
        failures.extend(verify_artifacts(evidence, args.apk, args.aab))
    if failures:
        raise SystemExit("RELEASE BLOCKED: " + ", ".join(failures))
    print("TECHNICAL RELEASE GATES PASSED ON SIGNED CLAIMS. Independent audit still required.")


if __name__ == "__main__":
    main()
