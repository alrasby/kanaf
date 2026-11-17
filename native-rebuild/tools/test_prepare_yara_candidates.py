import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from prepare_yara_candidates import intake, IntakeError

def sha(x):
    return hashlib.sha256(x).hexdigest()

class CandidateIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / "yara").mkdir()
        self.license = b"Detection Rule License (DRL) 1.1\n"
        self.source = (b'rule Example_Threat {\n meta:\n  author = "Example Author"\n'
                       b'  license = "Detection Rule License 1.1"\n'
                       b' strings:\n  $x = "harmless-fixture"\n condition:\n  $x\n}\n')
        (self.repo / "LICENSE").write_bytes(self.license)
        self.rule_path = self.repo / "yara" / "example.yar"
        self.rule_path.write_bytes(self.source)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid",
                        "commit", "-qm", "test"], check=True)
        commit = subprocess.check_output(["git", "-C", str(self.repo),
                                         "rev-parse", "HEAD"], text=True).strip()
        self.plan = {"schema": 1, "upstream": "Neo23x0/signature-base",
            "commit": commit, "license_sha256": sha(self.license),
            "rules": [{"path": "yara/example.yar", "sha256": sha(self.source),
                       "author": "Example Author"}]}

    def test_pinned_candidate_is_never_production_approved(self):
        rules, report = intake(self.repo, self.plan)
        self.assertIn(b"Example_Threat", rules)
        self.assertFalse(report["production_approved"])
        self.assertEqual("Example Author", report["rules"][0]["author"])

    def test_pin_and_license_fail_closed(self):
        self.plan["commit"] = "a" * 40
        with self.assertRaisesRegex(IntakeError, "not-pinned"):
            intake(self.repo, self.plan)
        self.plan["commit"] = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            text=True).strip()
        self.plan["license_sha256"] = "f" * 64
        with self.assertRaisesRegex(IntakeError, "license"):
            intake(self.repo, self.plan)

    def test_invalid_author_and_unsafe_path_fail_closed(self):
        self.plan["rules"][0]["author"] = "forged"
        with self.assertRaisesRegex(IntakeError, "attribution"):
            intake(self.repo, self.plan)
        self.plan["rules"][0]["path"] = "yara/../LICENSE"
        with self.assertRaisesRegex(IntakeError, "path"):
            intake(self.repo, self.plan)

    def test_modified_upstream_rejected(self):
        self.rule_path.write_bytes(self.source + b"// unreviewed")
        with self.assertRaisesRegex(IntakeError, "not-pinned"):
            intake(self.repo, self.plan)

    def test_unreviewed_import_rejected(self):
        self.source = b'import "pe"\n' + self.source
        self.rule_path.write_bytes(self.source)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "commit",
                        "-qm", "test2"], check=True)
        self.plan["commit"] = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            text=True).strip()
        self.plan["rules"][0]["sha256"] = sha(self.source)
        with self.assertRaisesRegex(IntakeError, "import"):
            intake(self.repo, self.plan)

if __name__ == "__main__":
    unittest.main()
