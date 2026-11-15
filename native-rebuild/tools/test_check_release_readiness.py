import datetime as dt
import unittest
from check_release_readiness import validate


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

    def test_rejects_tested_artifact_different_from_release(self):
        report = {
            "native": {"tested_apk_sha256": "a"*64},
            "release": {"signed_apk_sha256": "b"*64},
        }
        self.assertIn("tested-artifact-must-match-release-artifact",
                      validate(report, today=dt.date(2026, 11, 15)))


if __name__ == "__main__":
    unittest.main()
