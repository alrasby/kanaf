#!/usr/bin/env python3
"""Prepare Kanaf offline SHA-256 feed for a release signer.

Private RSA key must be supplied externally by the publisher. NEVER store
private keys in repository, mobile APK, Actions artifact or log.
Public DER (SubjectPublicKeyInfo) should be embedded at build time via
-PkanafSignaturePublicKeyBase64=... and comes from the same trusted keypair.
"""
import argparse
import base64
import hashlib
from pathlib import Path
import re
import subprocess
import zipfile

MAX_FEED = 32 * 1024 * 1024


def pack(db: bytes, version: int, key_path: Path, output: Path) -> str:
    if not (0 < version <= 2**63 - 1):
        raise ValueError("Version must be a positive signed 64-bit integer")
    if not (0 < len(db) <= MAX_FEED):
        raise ValueError("Database is empty or too large")
    for row in db.decode("utf-8").splitlines():
        if not row or row.startswith("#"):
            continue
        if not re.fullmatch(r"[0-9a-fA-F]{64}\t[a-zA-Z0-9_.:+-]{1,128}", row):
            raise ValueError("Unexpected SHA-256 signature entry")
    sha = hashlib.sha256(db).hexdigest()
    manifest_payload = f"Kanaf-DB-v1\n{version}\n{sha}\n".encode("ascii")
    signed = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
        input=manifest_payload, capture_output=True, check=True
    ).stdout
    manifest = (f"{version}\n{sha}\n" +
                base64.b64encode(signed).decode("ascii") + "\n").encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zipfile_out:
        zipfile_out.writestr("manifest.txt", manifest)
        zipfile_out.writestr("signatures.tsv", db)
    return sha


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--version", type=int, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    digest = pack(args.database.read_bytes(), args.version,
                  args.private_key, args.output)
    print(f"Created signed feed: version={args.version}; sha256={digest}")
