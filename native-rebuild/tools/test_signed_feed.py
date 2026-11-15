import hashlib
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from signed_feed import check_database, create_feed, verify_feed


class SignedFeedPublisherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.private = cls.root / "ephemeral-private.pem"
        cls.public = cls.root / "ephemeral-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(cls.private)],
                       capture_output=True, check=True)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private),
                        "-pubout", "-out", str(cls.public)],
                       capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.db = self.root / "local-fixture.tsv"
        self.db.write_bytes(hashlib.sha256(b"EICAR harmless fixture").hexdigest().encode()
                            + b"\tEicar-Test-Signature\n")
        self.zip = self.root / "signed-fixture.zip"

    def test_offline_sign_and_verify_without_production_key(self):
        create_feed(self.db, self.private, 11, self.zip)
        version, digest = verify_feed(self.zip, self.public)
        self.assertEqual(version, 11)
        self.assertEqual(digest, hashlib.sha256(self.db.read_bytes()).hexdigest())

    def test_tampered_database_cannot_keep_valid_digest(self):
        create_feed(self.db, self.private, 12, self.zip)
        with zipfile.ZipFile(self.zip) as source:
            manifest = source.read("manifest.txt")
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("manifest.txt", manifest)
            archive.writestr("signatures.tsv",
                             hashlib.sha256(b"mutated").hexdigest() + "\tTEST\n")
        with self.assertRaises(ValueError):
            verify_feed(self.zip, self.public)

    def test_reject_unsigned_manifest_and_rogue_entries(self):
        create_feed(self.db, self.private, 13, self.zip)
        with zipfile.ZipFile(self.zip) as source:
            data = source.read("signatures.tsv")
            manifest = source.read("manifest.txt")
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("signatures.tsv", data)
            archive.writestr("manifest.txt", manifest)
            archive.writestr("unexpected.bin", b"xyz")
        with self.assertRaises(ValueError):
            verify_feed(self.zip, self.public)

    def test_bad_rows_and_duplicate_conflicting_digests_rejected(self):
        sha = b"a" * 64
        with self.assertRaises(ValueError):
            check_database(sha + b"\tlabel one\n")
        with self.assertRaises(ValueError):
            check_database(sha + b"\tGOOD\n" + sha + b"\tEVIL\n")

    def test_wrong_publisher_key_fails(self):
        create_feed(self.db, self.private, 14, self.zip)
        alt_private = self.root / "other-private.pem"
        alt_public = self.root / "other-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(alt_private)],
                       capture_output=True, check=True)
        subprocess.run(["openssl", "pkey", "-in", str(alt_private),
                        "-pubout", "-out", str(alt_public)],
                       capture_output=True, check=True)
        with self.assertRaises(ValueError):
            verify_feed(self.zip, alt_public)


if __name__ == "__main__":
    unittest.main()
