import datetime as dt
import hashlib
import re
import shutil
import zipfile
import subprocess
import tempfile
from pathlib import Path
import unittest
from check_release_readiness import (validate, verify_artifacts, verify_attestation,
                                     verify_expected_distribution)


class ReleaseReadinessTest(unittest.TestCase):
    def test_missing_real_production_evidence_blocks_release(self):
        reasons = validate({}, today=dt.date(2026, 11, 15))
        self.assertIn("real-clamav-positive", reasons)
        self.assertIn("ml-ground-truth-provenance", reasons)
        self.assertIn("threat-feed-rsa-proof", reasons)
        self.assertIn("apk-release-signing", reasons)

    def test_cannot_equate_emulator_or_fake_model_to_production(self):
        report = {
            "schema": 1, "git_tree_sha256": "a"*64,
            "native": {
                "clamav": "1.4.6", "abi": "arm64-v8a",
                "physical_device": False,
                "clamav_eicar_detected": False, "clamav_benign_no_match": True,
                "yara_eicar_detected": True, "yara_benign_no_match": True,
                "tested_apk_sha256": "b"*64,
            },
            "model": {
                "weights_sha256": "c"*64,
                "independent_test_corpus_sha256": "d"*64,
                "validated_label_provenance": False,
                "independent_test": True,
                "train_test_disjoint_by_hash_and_source": True,
                "auc": .99, "fpr": .001, "recall": .99,
                "test_samples": 6000, "benign_samples": 3000,
                "malicious_samples": 3000, "dataset_license_review_id": "audit-x",
            },
            "signatures": {
                "db_sha256": "e"*64, "pinned_key_sha256": "f"*64,
                "version": 1, "real_non_test_signatures": 0,
                "verified_signature": False, "signed_antirollback_test": True,
                "license_and_source_review_id": "audit-y",
                "verified_date": "2026-11-15",
            },
            "release": {
                "signed_apk": True, "signed_apk_sha256": "b"*64,
                "independent_security_review_id": "audit-z",
                "distribution_licenses_review_id": "audit-w",
                "android_permissions_review_id": "audit-a",
            }
        }
        problems = validate(report, today=dt.date(2026, 11, 15))
        for key in ("physical-arm64-device-test", "real-clamav-positive",
                    "ml-ground-truth-provenance", "threat-feed-real-coverage",
                    "threat-feed-rsa-proof"):
            self.assertIn(key, problems)

    def test_inconsistent_or_boolean_ai_sample_counts_block_release(self):
        report = {"model": {"test_samples": 6000,
                             "benign_samples": 3500, "malicious_samples": 3000}}
        self.assertIn("ml-test-counts-consistent",
                      validate(report, today=dt.date(2026, 11, 15)))
        report["model"]["test_samples"] = True
        self.assertIn("ml-test-counts-consistent",
                      validate(report, today=dt.date(2026, 11, 15)))

    def test_emulator_and_synthetic_pilot_do_not_count_as_full_release(self):
        report = {
            "native": {
                "physical_device": True, "page_size_bytes": 4096,
                "production_rules_loaded": False,
                "independent_non_eicar_threat_detection": False,
            },
            "model": {
                "synthetic_fixture_only": True,
                "independent_external_source_holdout": False,
            },
            "signatures": {
                "fresh_install_verified": False,
                "test_only_rules_excluded": False,
            },
            "release": {
                "signed_aab": False, "target_sdk": 35,
                "play_sensitive_permissions_approved": False,
                "vpn_service_policy_review": False,
                "real_device_scan_and_dns_qa": False,
            },
        }
        failures = validate(report, today=dt.date(2026, 11, 16))
        for expected in (
            "physical-arm64-16kb-page-test",
            "native-production-rules-actually-loaded",
            "native-independent-malware-detection",
            "ml-not-synthetic-fixtures",
            "ml-independent-external-source",
            "threat-feed-signed-bootstrap-tested",
            "threat-feed-not-test-only",
            "aab-release-signing",
            "play-target-api36",
            "play-sensitive-permissions-approval",
            "play-vpnservice-policy-review",
            "physical-dns-and-scan-acceptance",
            "play-cross-app-ad-blocking-policy",
            "play-vpn-prominent-disclosure",
            "physical-vpn-disconnect-and-dns-leak-qa",
            "play-live-app-privacy-policy",
            "play-data-safety-attestation",
            "play-special-use-fgs-approval",
        ):
            self.assertIn(expected, failures)

    def test_rejects_tested_artifact_different_from_release(self):
        report = {
            "native": {"tested_apk_sha256": "a"*64},
            "release": {"signed_apk_sha256": "b"*64},
        }
        self.assertIn("tested-artifact-must-match-release-artifact",
                      validate(report, today=dt.date(2026, 11, 15)))

    def test_release_artifact_bytes_and_signatures_must_be_real(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "signed.apk"
            aab = Path(directory) / "signed.aab"
            apk.write_bytes(b"actual release APK fixture")
            aab.write_bytes(b"actual signed AAB fixture")
            digest = lambda b: hashlib.sha256(b).hexdigest()
            cert = "c" * 64
            report = {"release": {
                "signed_apk_sha256": digest(apk.read_bytes()),
                "signed_aab_sha256": digest(aab.read_bytes()),
                "apk_signer_cert_sha256": cert,
                "aab_signer_cert_sha256": cert,
            }}

            def verified_runner(command, **kwargs):
                if command[0] == "apksigner":
                    output = ("Verified using v2 scheme (APK Signature Scheme v2): true\n"
                              "Signer #1 certificate SHA-256 digest: " + cert + "\n")
                elif command[0] == "jarsigner":
                    output = "jar verified.\n"
                else:
                    output = ("Signer #1:\nCertificate #1:\nSHA256: " +
                              ":".join(cert[i:i+2] for i in range(0, 64, 2)) + "\n")
                return subprocess.CompletedProcess(command, 0, output, "")

            self.assertEqual([], verify_artifacts(report, apk, aab, run=verified_runner))
            apk.write_bytes(b"mutated after physical-device test")
            self.assertIn("apk-actual-bytes-mismatch",
                          verify_artifacts(report, apk, aab, run=verified_runner))
            apk.write_bytes(b"actual release APK fixture")
            aab.write_bytes(b"other AAB")
            self.assertIn("aab-actual-bytes-mismatch",
                          verify_artifacts(report, apk, aab, run=verified_runner))

    def test_fake_signing_tools_and_wrong_certificate_block_release(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "app.apk"
            aab = Path(directory) / "app.aab"
            apk.write_bytes(b"apk bytes")
            aab.write_bytes(b"aab bytes")
            digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            report = {"release": {
                "signed_apk_sha256": digest(apk),
                "signed_aab_sha256": digest(aab),
                "apk_signer_cert_sha256": "a" * 64,
                "aab_signer_cert_sha256": "a" * 64,
            }}
            def legacy_signer(command, **kwargs):
                if command[0] == "apksigner":
                    output = ("Verified using v1 scheme (JAR signing): true\n"
                              "Signer #1 certificate SHA-256 digest: " + "b" * 64)
                elif command[0] == "jarsigner":
                    output = "jar is unsigned."
                else:
                    output = "Signer #1:\nSHA256: " + ":".join(["bb"] * 32) + "\n"
                return subprocess.CompletedProcess(command, 0, output, "")
            issues = verify_artifacts(report, apk, aab, run=legacy_signer)
            for expected in ("apk-modern-signature-absent",
                             "apk-signer-certificate-mismatch",
                             "aab-signature-not-confirmed"):
                self.assertIn(expected, issues)

            def missing_tool(command, **kwargs):
                raise FileNotFoundError(command[0])
            issues = verify_artifacts(report, apk, aab, run=missing_tool)
            self.assertIn("apk-verification-unavailable", issues)
            self.assertIn("aab-verification-unavailable", issues)
            self.assertIn("aab-cert-verification-unavailable", issues)

    def test_independent_qa_key_fingerprint_is_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "qa-key.der"
            key.write_bytes(b"substituted self-signed QA key")
            with self.assertRaisesRegex(ValueError, "untrusted-qa-key-fingerprint-mismatch"):
                verify_attestation(Path(directory) / "report",
                                   Path(directory) / "signature",
                                   key, "a" * 64)

    def test_real_der_rsa_attestation_round_trip_and_tamper_rejection(self):
        # Short-lived test identity only, never a Kanaf publisher or QA key.
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "temporary-private.pem"
            public = Path(directory) / "temporary-public.der"
            report = Path(directory) / "report.json"
            signature = Path(directory) / "report.sig"
            def openssl(*args):
                subprocess.run(["openssl", *map(str, args)],
                               check=True, capture_output=True, timeout=20)
            openssl("genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", key)
            openssl("pkey", "-in", key, "-pubout", "-outform", "DER", "-out", public)
            report.write_text('{"schema":1}', encoding="utf-8")
            openssl("dgst", "-sha256", "-sign", key, "-out", signature, report)
            pinned = hashlib.sha256(public.read_bytes()).hexdigest()
            verify_attestation(report, signature, public, pinned)
            report.write_text('{"schema":2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "evidence-signature-invalid"):
                verify_attestation(report, signature, public, pinned)

    def test_publisher_channel_cannot_substitute_signed_direct_report_for_play(self):
        self.assertEqual([], verify_expected_distribution(
            {"release": {"distribution": "play"}}, "play"))
        self.assertIn("independent-qa-distribution-mismatch",
                      verify_expected_distribution(
                          {"release": {"distribution": "direct"}}, "play"))
        with self.assertRaisesRegex(ValueError, "untrusted-expected-distribution"):
            verify_expected_distribution(
                {"release": {"distribution": "play"}}, "unknown")

    def test_release_distribution_requires_truthful_dns_compilation(self):
        base = {"release": {
            "signed_apk": True, "signed_aab": True,
            "distribution": "play", "dns_security_only": False,
        }}
        issues = validate(base, today=dt.date(2026, 11, 16))
        self.assertIn("release-dns-policy-distribution-mismatch", issues)
        self.assertIn("play-sensitive-permissions-approval", issues)
        base["release"]["distribution"] = "direct"
        base["release"]["dns_security_only"] = False
        direct_issues = validate(base, today=dt.date(2026, 11, 16))
        self.assertNotIn("release-dns-policy-distribution-mismatch", direct_issues)
        self.assertNotIn("play-sensitive-permissions-approval", direct_issues)
        # Direct releases still need exact signed binaries, physical QA, and
        # a legally sourced independent malware evaluation.
        self.assertIn("physical-arm64-device-test", direct_issues)
        self.assertIn("native-independent-malware-detection", direct_issues)
        base["release"]["distribution"] = "play"
        base["release"]["dns_security_only"] = True
        self.assertNotIn("release-dns-policy-distribution-mismatch",
                         validate(base, today=dt.date(2026, 11, 16)))
        base["release"]["distribution"] = "unknown"
        self.assertIn("release-distribution-missing",
                      validate(base, today=dt.date(2026, 11, 16)))

    def test_real_self_signed_aab_key_accepted_and_unsigned_append_rejected(self):
        if not shutil.which("keytool") or not shutil.which("jarsigner"):
            self.skipTest("JDK signer tools unavailable")
        # Ephemeral offline test identity only. No actual publisher secret.
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            aab = d / "fixture.aab"
            store = d / "test.jks"
            apk = d / "simulated.apk"
            apk.write_bytes(b"mocked APK signature fixture")
            with zipfile.ZipFile(aab, "w") as archive:
                archive.writestr("base/manifest/AndroidManifest.xml", b"test manifest")
            def jdk(*args):
                return subprocess.run(args, check=True, capture_output=True,
                                      text=True, timeout=40)
            pwd = "OnlyFixture123"
            jdk("keytool", "-genkeypair", "-alias", "test", "-keyalg", "RSA",
                "-keysize", "2048", "-validity", "365", "-keystore", str(store),
                "-storepass", pwd, "-keypass", pwd, "-dname",
                "CN=Temporary Kanaf Test", "-noprompt")
            jdk("jarsigner", "-keystore", str(store), "-storepass", pwd,
                "-keypass", pwd, str(aab), "test")
            key_output = jdk("keytool", "-printcert", "-jarfile", str(aab)).stdout
            match = re.search(r"SHA256:\s*((?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2})",
                              key_output)
            self.assertIsNotNone(match)
            thumb = match.group(1).replace(":", "").lower()
            cert = "b" * 64
            report = {"release": {
                "signed_apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                "signed_aab_sha256": hashlib.sha256(aab.read_bytes()).hexdigest(),
                "apk_signer_cert_sha256": cert,
                "aab_signer_cert_sha256": thumb,
            }}
            def real_jdk_mock_apksigner(command, **kwargs):
                if command[0] == "apksigner":
                    message = ("Verified using v2 scheme (APK Signature Scheme v2): true\n"
                               "Signer #1 certificate SHA-256 digest: " + cert + "\n")
                    return subprocess.CompletedProcess(command, 0, message, "")
                return subprocess.run(command, **kwargs)
            self.assertEqual([],
                verify_artifacts(report, apk, aab, run=real_jdk_mock_apksigner))
            with zipfile.ZipFile(aab, "a") as archive:
                archive.writestr("base/untrusted.bin", b"unsigned payload")
            self.assertIn("aab-unsigned-entries",
                verify_artifacts(report, apk, aab, run=real_jdk_mock_apksigner))


if __name__ == "__main__":
    unittest.main()
