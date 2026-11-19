import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import build_native_rule_pack as pack
from evaluate_detection_pack import rates

class NativeRulePackTest(unittest.TestCase):
    def test_reviewed_source_and_generated_assets_are_reproducible(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(pack.ROOT / "rules", root / "rules")
            manifest = pack.build(root)
            for name, sha in manifest["assets"].items():
                self.assertEqual(hashlib.sha256((pack.ROOT / "app/src/main/assets" / name).read_bytes()).hexdigest(), sha)
            self.assertEqual(manifest["android_exact_hashes"], 30)
            seed = root / "rules/eset-android-seed/signatures.tsv"
            seed.write_bytes(seed.read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                pack.build(root)

    def test_absent_malware_samples_cannot_produce_recall_or_certification(self):
        groups = {label: dict(matched=0, unmatched=0, incomplete=0) for label in ("benign", "malicious", "fixture")}
        groups["benign"]["unmatched"] = 20
        groups["fixture"]["matched"] = 10
        result = rates(groups)
        self.assertEqual(result["false_positive_rate_completed"], 0)
        self.assertIsNone(result["recall_completed"])
        self.assertFalse(result["both_labels_completed"])
        groups["malicious"]["matched"] = 1
        groups["malicious"]["incomplete"] = 1
        self.assertEqual(rates(groups)["recall_including_incomplete"], .5)

    def test_real_content_rule_semantics_with_harmless_non_executable_fixtures(self):
        try:
            import yara_x
        except ImportError:
            self.skipTest("YARA-X runtime not installed in this job")
        rules = yara_x.compile((pack.ROOT / "app/src/main/assets/production_yara.yar").read_text())
        scanner = yara_x.Scanner(rules)
        strings = [b"Modules are loaded", b"--scrypt", b"processor ", b"cpu model ", b"Host: www.challpok.cn"]
        positive = b"\x7fELF" + b"\0".join(strings)
        self.assertEqual([r.identifier for r in scanner.scan(positive).matching_rules], ["moose_2"])
        self.assertFalse(list(scanner.scan(b"\0".join(strings)).matching_rules))
        self.assertFalse(list(scanner.scan(b"\x7fELF" + b"\0".join(strings[:4])).matching_rules))
        # These are rule-semantics tests, not samples for real malware recall.

if __name__ == "__main__":
    unittest.main()
