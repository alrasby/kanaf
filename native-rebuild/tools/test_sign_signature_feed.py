"""Publisher signing regression (ephemeral CI-only RSA key; no real key committed)."""
import base64
import hashlib
import subprocess
import tempfile
from pathlib import Path
import unittest
import zipfile
from sign_signature_feed import pack


class SignFeedTest(unittest.TestCase):
    def test_produces_manifest_accepted_by_pinned_rsa_verifier(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = root / "test-private.pem"
            public = root / "test-public.pem"
            release = root / "signed.zip"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                            "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                           capture_output=True, check=True)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout",
                            "-out", str(public)], capture_output=True, check=True)
            database = ("a"*64 + "\tKNOWN_TEST\n").encode("ascii")
            digest = pack(database, 8, key, release)
            self.assertEqual(digest, hashlib.sha256(database).hexdigest())
            with zipfile.ZipFile(release) as f:
                self.assertEqual(set(f.namelist()), {"manifest.txt", "signatures.tsv"})
                self.assertEqual(f.read("signatures.tsv"), database)
                version, sha, signature, empty = f.read("manifest.txt").decode().split("\n")
                self.assertEqual((version, sha, empty), ("8", digest, ""))
                sig_path = root / "sig.bin"
                message_path = root / "payload.txt"
                sig_path.write_bytes(base64.b64decode(signature, validate=True))
                message_path.write_bytes(f"Kanaf-DB-v1\n8\n{sha}\n".encode("ascii"))
                subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public),
                                "-signature", str(sig_path), str(message_path)],
                               capture_output=True, check=True)
            with self.assertRaises(ValueError):
                pack(database, 0, key, release)
            with self.assertRaises(ValueError):
                pack(b"not-a-valid-signature\n", 9, key, release)


if __name__ == "__main__":
    unittest.main()
