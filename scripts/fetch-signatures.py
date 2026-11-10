#!/usr/bin/env python3
"""Download public signature feeds and write Kanaf's local index.

No user data is read. ClamAV CVD payloads are authenticated with the
legacy freshclam RSA key before any hash record is accepted.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "signatures"
CACHE = Path("/tmp/sigcheck")

N = int(
    "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037"
)
E = 100001027
ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

# main.cvd is large. Keep hash signatures whose names are in the families
# the product can act on without libclamav: Android, Java, scripts, archives,
# documents, and the EICAR test record. daily.cvd is small and kept whole.
MAIN_KEEP = re.compile(
    r"(eicar|andr|android|\.apk|java|js\.|script|html|phish|vbs|powershell|ps1|"
    r"archive|zip\.|rar\.|jar\.|dex|multios|unix\.|osx\.|email|macro|doc\.|pdf\.)",
    re.I,
)

UA = "Kanaf/1.0 (local signature prefetch; no user data)"


def versig(md5_hex: str, dsig: str) -> bool:
    if len(md5_hex) != 32:
        return False
    c = 0
    for i, ch in enumerate(dsig):
        dec = ALPH.find(ch)
        if dec < 0:
            return False
        c += dec << (6 * i)
    p = pow(c, E, N)
    length = max(1, (p.bit_length() + 7) // 8)
    raw = p.to_bytes(length, "big")
    if len(raw) > 16:
        return False
    return raw.rjust(16, b"\x00").hex() == md5_hex.lower()


def normalize_url(raw: str) -> str | None:
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlsplit(s)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https"):
        return None
    host = p.hostname or ""
    try:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return None
    if not host:
        return None
    port = p.port
    default = port is None or (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)
    netloc = host if default else f"{host}:{port}"
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return urlunsplit((p.scheme.lower(), netloc, path, p.query, ""))


def fetch(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        print(f"cache {dest.name} {dest.stat().st_size}")
        return
    print(f"get {url}")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=180) as res, dest.open("wb") as out:
        while True:
            chunk = res.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)


def parse_header(raw: bytes) -> dict:
    text = raw.split(b"\0", 1)[0].decode("ascii", "replace").strip()
    parts = text.split(":")
    if len(parts) < 9 or parts[0] != "ClamAV-VDB":
        raise SystemExit("CVD header is not ClamAV-VDB")
    return {
        "built": parts[1],
        "version": parts[2],
        "reported": int(parts[3]),
        "flevel": parts[4],
        "md5": parts[5],
        "dsig": parts[6],
        "builder": parts[7],
        "stime": parts[8],
    }


def iter_hash_lines(blob: str, keep_all: bool):
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        bits = line.split(":")
        if len(bits) < 3:
            continue
        digest, size_s, name = bits[0], bits[1], bits[2]
        if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", digest):
            continue
        if not keep_all and not MAIN_KEEP.search(name):
            continue
        size = size_s if re.fullmatch(r"\d+", size_s) else "*"
        kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(digest)]
        yield kind, digest.lower(), size, name


def read_cvd(path: Path, keep_all: bool):
    with path.open("rb") as fh:
        head = fh.read(512)
        body = fh.read()
    header = parse_header(head)
    digest = hashlib.md5(body).hexdigest()
    if digest != header["md5"]:
        raise SystemExit(f"{path.name}: MD5 mismatch")
    if not versig(header["md5"], header["dsig"]):
        raise SystemExit(f"{path.name}: digital signature rejected")
    print(f"verified {path.name} version {header['version']} bytes {len(body)}")
    raw = gzip.decompress(body)
    rows = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
        for member in tf.getmembers():
            base = member.name.rsplit("/", 1)[-1]
            if not member.isfile() or not (base.endswith(".hdb") or base.endswith(".hsb")):
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            text = extracted.read().decode("utf-8", "replace")
            rows.extend(iter_hash_lines(text, keep_all))
    print(f"  hash rows {len(rows)} keep_all={keep_all}")
    return header, rows


def main() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    fetch("https://urlhaus.abuse.ch/downloads/text/", CACHE / "urlhaus.txt")
    fetch("https://urlhaus.abuse.ch/downloads/hostfile/", CACHE / "hostfile.txt")
    fetch("https://bazaar.abuse.ch/export/txt/sha256/recent/", CACHE / "mb-sha256.txt")
    fetch("https://bazaar.abuse.ch/export/txt/md5/recent/", CACHE / "mb-md5.txt")
    fetch("https://bazaar.abuse.ch/export/csv/cscb/", CACHE / "cscb.csv")
    if not (CACHE / "daily.cvd").exists():
        fetch("https://packages.microsoft.com/clamav/daily.cvd", CACHE / "daily.cvd")

    daily_header, daily_rows = read_cvd(CACHE / "daily.cvd", keep_all=True)
    main_rows = []
    main_header = None
    main_path = CACHE / "main.cvd"
    if main_path.exists() and main_path.stat().st_size > 1_000_000:
        try:
            main_header, main_rows = read_cvd(main_path, keep_all=False)
        except SystemExit as exc:
            print("main.cvd skipped:", exc)
            main_rows = []
            main_header = None

    hashes: dict[tuple[str, str], tuple[str, str, str]] = {}

    def add(kind: str, digest: str, size: str, source: str, name: str) -> None:
        key = (kind, digest)
        prev = hashes.get(key)
        if prev is None:
            hashes[key] = (size, source, name)
            return
        prev_size, prev_source, prev_name = prev
        size_out = prev_size if prev_size != "*" else size
        if name not in prev_name.split(" | "):
            prev_name = f"{prev_name} | {name}"
        source_out = prev_source if source in prev_source.split("+") else f"{prev_source}+{source}"
        hashes[key] = (size_out, source_out, prev_name)

    for kind, digest, size, name in daily_rows:
        add(kind, digest, size, "clamav-daily", name)
    for kind, digest, size, name in main_rows:
        add(kind, digest, size, "clamav-main", name)

    mb_sha = 0
    for line in (CACHE / "mb-sha256.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", line):
            add("sha256", line, "*", "malwarebazaar", "MalwareBazaar-recent")
            mb_sha += 1
    mb_md5 = 0
    for line in (CACHE / "mb-md5.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().lower()
        if re.fullmatch(r"[0-9a-f]{32}", line):
            add("md5", line, "*", "malwarebazaar", "MalwareBazaar-recent")
            mb_md5 += 1

    hash_path = OUT / "hashes.tsv"
    counts = {"md5": 0, "sha1": 0, "sha256": 0, "clamav-daily": 0, "clamav-main": 0, "malwarebazaar": 0}
    with hash_path.open("w", encoding="utf-8") as out:
        for (kind, digest), (size, source, name) in hashes.items():
            safe_name = name.replace("\t", " ").replace("\n", " ")
            out.write(f"{kind}\t{digest}\t{size}\t{source}\t{safe_name}\n")
            counts[kind] += 1
            for part in source.split("+"):
                if part in counts:
                    counts[part] += 1

    urls = []
    hosts = set()
    url_seen = set()
    for line in (CACHE / "urlhaus.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        norm = normalize_url(line)
        if not norm or norm in url_seen:
            continue
        url_seen.add(norm)
        urls.append(norm)
        host = urlsplit(norm).hostname
        if host:
            hosts.add(host)
    for line in (CACHE / "hostfile.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        bits = line.split()
        if len(bits) >= 2:
            hosts.add(bits[1].strip(".").lower())

    (OUT / "urls.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    (OUT / "hosts.txt").write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")

    certs = []
    text = (CACHE / "cscb.csv").read_text(encoding="utf-8", errors="replace")
    body = "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))
    reader = csv.DictReader(io.StringIO(body))
    for row in reader:
        thumb = (row.get("thumbprint") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", thumb):
            reason = (row.get("Reason") or row.get("subject_cn") or "CSCB").replace("\t", " ")
            certs.append(f"{thumb}\t{reason}")
    (OUT / "certs.txt").write_text("\n".join(certs) + ("\n" if certs else ""), encoding="utf-8")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sources = [
        {
            "id": "clamav-daily",
            "version": daily_header["version"],
            "updatedAt": daily_header["built"],
            "publishedAt": int(daily_header["stime"]),
            "count": counts["clamav-daily"],
            "reportedSignatures": daily_header["reported"],
            "license": "ClamAV CVD, hash records only (hdb/hsb). Digital signature verified. libclamav is not included.",
            "terms": "https://www.clamav.net/",
        },
        {
            "id": "urlhaus",
            "version": now[:10],
            "updatedAt": now,
            "count": len(urls),
            "license": "abuse.ch URLhaus — free for non-commercial and commercial use with attribution.",
            "terms": "https://urlhaus.abuse.ch/api/",
        },
        {
            "id": "malwarebazaar",
            "version": now[:10],
            "updatedAt": now,
            "count": mb_sha + mb_md5,
            "license": "abuse.ch MalwareBazaar recent hash export.",
            "terms": "https://bazaar.abuse.ch/faq/#tos",
        },
        {
            "id": "cscb",
            "version": now[:10],
            "updatedAt": now,
            "count": len(certs),
            "license": "MalwareBazaar code-signing certificate blocklist.",
            "terms": "https://bazaar.abuse.ch/faq/#cscb",
        },
    ]
    if main_header:
        sources.insert(
            1,
            {
                "id": "clamav-main",
                "version": main_header["version"],
                "updatedAt": main_header["built"],
                "publishedAt": int(main_header["stime"]),
                "count": counts["clamav-main"],
                "reportedSignatures": main_header["reported"],
                "license": "ClamAV main.cvd, filtered hash families. Signature verified.",
                "terms": "https://www.clamav.net/",
                "filtered": True,
            },
        )
    manifest = {
        "builtAt": now,
        "hashRecords": len(hashes),
        "md5": counts["md5"],
        "sha1": counts["sha1"],
        "sha256": counts["sha256"],
        "urls": len(urls),
        "hosts": len(hosts),
        "certs": len(certs),
        "sources": sources,
        "notes": [
            "ndb, ldb and bytecode signatures are not loaded because they require libclamav (GPLv2), which Kanaf does not ship.",
            "main.cvd hash records are filtered to Android, Java, script, archive and document families when that file is present.",
            "MalwareBazaar recent exports do not include file size, so those hashes match on the digest alone.",
        ],
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("hashRecords", "md5", "sha256", "urls", "hosts", "certs")}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"signature build failed: {exc}", file=sys.stderr)
        sys.exit(1)
