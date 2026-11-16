import io
import json
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main
from release_input_inventory import ASSETS, FILE_ENV, NATIVE, VALUE_ENV, inventory


class ReleaseInputInventoryTest(TestCase):
    def test_absent_inputs_never_mint_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = inventory(Path(tmp), "play", {})
        self.assertFalse(report["prebuild_inputs_present"])
        self.assertFalse(report["production_certified"])
        self.assertIn("asset:production_signatures.zip",
                      report["missing_prerequisites"])
        self.assertIn("native:libclamav.so", report["missing_prerequisites"])
        self.assertIn("external-file:KANAF_RELEASE_KEYSTORE_FILE",
                      report["missing_prerequisites"])

    def test_filled_fixture_inventory_is_not_external_qa_certification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            assetdir = root / "app/src/main/assets"
            native = root / "app/src/main/jniLibs/arm64-v8a"
            assetdir.mkdir(parents=True)
            native.mkdir(parents=True)
            for name in ASSETS:
                (assetdir / name).write_bytes(b"untrusted fixture data")
            for name in NATIVE:
                (native / name).write_bytes(b"synthetic test library")
            key = root / "not-a-real-keystore"
            key.write_bytes(b"test-only")
            env = {name: str(key) for name in FILE_ENV}
            env.update({name: "TEST_SECRET_MUST_NOT_LEAK" for name in VALUE_ENV})
            report = inventory(root, "direct", env)
        self.assertTrue(report["prebuild_inputs_present"])
        self.assertFalse(report["production_certified"])
        self.assertFalse(report["missing_prerequisites"])
        self.assertNotIn("TEST_SECRET_MUST_NOT_LEAK", json.dumps(report))
        self.assertNotIn("not-a-real-keystore", json.dumps(report))

    def test_distribution_not_derived_from_hidden_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = inventory(Path(tmp), "unknown", {})
        self.assertIn("distribution:explicit", report["missing_prerequisites"])


if __name__ == "__main__":
    main()
