#!/usr/bin/env python3
"""Offline signer/verifier for Kanaf v1 SHA-256 feed. Never commit private keys.

Accept only publisher-controlled, legally licensed signatures. No downloader
or key generation is performed here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

MAX_DB = 32 * 1024 * 1024
MAX_ARCHIVE = MAX_DB + 16384
ENTRY = re.compile(rb"[0-9a-fA-F]{64}\t[A-Za-z0-9_.:+-]{1,128}")
MANIFEST = re.compile(rb"([1-9][0-9]*)\n([0-9a-f]{64})\n([A-Za-z0-9+/]+={0,2})\n")


def check_database(data: bytes) -> None:
    if not 0 < len(data) <= MAX_DB:
        raise ValueError("signature database must be non-empty and <=32MiB")
    seen: dict[bytes, bytes] = {}
    for row in data.splitlines():
        if not row.strip() or row.startswith(b"#"):
            continue
        if not ENTRY.fullmatch(row):
            raise ValueError("invalid signature row: expected SHA256<TAB>label")
        digest, label = row.split(b"\t")
        digest = digest.lower()
        if digest in seen and seen[digest] != label:
            raise ValueError("conflicting signature labels for one SHA256")
        seen[digest] = label
        if len(seen) > 500_000:
            raise ValueError("signature record count exceeded")
    if not seen:
        raise ValueError("no usable signature rows")


def signed_payload(version: int, digest: str) -> bytes:
    if version < 1 or version > (2**63 - 1):
        raise ValueError("version must be a positive signed 64-bit integer")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid SHA256 hex")
    return f"Kanaf-DB-v1\n{version}\n{digest}\n".encode("ascii")


def openssl(*args: str, payload: bytes) -> bytes:
    p = subprocess.run(["openssl", "dgst", "-sha256", *args], input=payload,
                       capture_output=True, check=False)
    if p.returncode:
        raise ValueError("OpenSSL sign/verify failed: " + p.stderr.decode("utf8", "replace")[:200])
    return p.stdout


def create_feed(database: Path, key: Path, version: int, destination: Path) -> None:
    data = database.read_bytes()
    check_database(data)
    digest = hashlib.sha256(data).hexdigest()
    sig = openssl("-sign", str(key), payload=signed_payload(version, digest))
    metadata = f"{version}\n{digest}\n{base64.b64encode(sig).decode('ascii')}\n".encode("ascii")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, mode="w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, allowZip64=False) as archive:
        archive.writestr("signatures.tsv", data)
        archive.writestr("manifest.txt", metadata)
    if destination.stat().st_size > MAX_ARCHIVE:
        destination.unlink()
        raise ValueError("feed ZIP exceeds app download limit")


def verify_feed(source: Path, public_key: Path) -> tuple[int, str]:
    if source.stat().st_size > MAX_ARCHIVE:
        raise ValueError("feed ZIP exceeds download limit")
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if sorted(names) != ["manifest.txt", "signatures.tsv"]:
            raise ValueError("feed must contain exactly manifest.txt and signatures.tsv")
        if any(i.is_dir() for i in archive.infolist()):
            raise ValueError("directory entries are not permitted")
        if archive.getinfo("manifest.txt").file_size > 4096:
            raise ValueError("manifest exceeds 4096 bytes")
        if archive.getinfo("signatures.tsv").file_size > MAX_DB:
            raise ValueError("signature file exceeds app limit")
        metadata = archive.read("manifest.txt")
        data = archive.read("signatures.tsv")
    check_database(data)
    match = MANIFEST.fullmatch(metadata)
    if match is None:
        raise ValueError("invalid manifest format")
    version = int(match[1])
    digest = match[2].decode("ascii")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("signature file digest mismatch")
    signature = base64.b64decode(match[3], validate=True)
    with tempfile.TemporaryDirectory(prefix="kanaf-feed-verify-") as folder:
        sigpath = Path(folder) / "signature.bin"
        sigpath.write_bytes(signature)
        openssl("-verify", str(public_key), "-signature", str(sigpath),
                payload=signed_payload(version, digest))
    return version, digest


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="mode", required=True)
    sign = subs.add_parser("sign", help="Sign a locally licensed SHA256 database")
    sign.add_argument("--database", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--version", required=True, type=int)
    sign.add_argument("--output", required=True, type=Path)
    verify = subs.add_parser("verify", help="Validate a Kanaf v1 signed ZIP")
    verify.add_argument("--zip", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    args = p.parse_args()
    try:
        if args.mode == "sign":
            create_feed(args.database, args.private_key, args.version, args.output)
            print("Generated Kanaf v1 signed feed:", args.output)
        else:
            version, digest = verify_feed(args.zip, args.public_key)
            print(f"Verified signed feed version={version} sha256={digest}")
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
