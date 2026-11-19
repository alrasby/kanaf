#!/usr/bin/env python3
"""Reproducible native rules from pinned BSD-2-Clause ESET and MIT ReversingLabs inputs.

No executable malware is downloaded. Exact Android IOCs are NOT family-wide
detection; the Linux/Moose content rules target ELF files, not APK internals.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "8921a81d245cce3f9b7a199b123d221ed8f1fe33"
SEED_SHA256 = "f9e2e00f5f8f442a60be9002b0a7fc11230bb0764f1948649680bd161b35f882"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def build(root=ROOT):
    seed = (root / "rules/eset-android-seed/signatures.tsv").read_bytes()
    if digest(seed) != SEED_SHA256:
        raise ValueError("Pinned ESET seed changed; review provenance before updating")
    content = (root / "rules/native-v1/linux-moose.yar").read_bytes()
    # This hash pins the original upstream file, including its licence and author.
    if digest(content) != "600beb24cb82f01d145f7353f5eb081153dffcd7c31adcf940a66094fa19b28a":
        raise ValueError("Pinned upstream YARA rule changed")
    rl = (root / "rules/native-v1/reversinglabs-acidrain.yara").read_bytes()
    if digest(rl) != "33416451fa8920e3a17f9844843dfb5173732c040a139f875558a0e8ab27024c":
        raise ValueError("Pinned ReversingLabs source changed")
    rl_notice = (root / "app/src/main/assets/ReversingLabs-MIT.txt").read_text()
    if digest(rl_notice.encode()) != "8ac378a5a6716e1aef984c2ea50cbeb28d9a2f0a871846875245f71a02d023fc":
        raise ValueError("Pinned ReversingLabs licence notice changed")
    rows = [line.split("\t") for line in seed.decode().splitlines() if line and not line.startswith("#")]
    clam = "".join(f"{sha}:*:{name}:73\n" for sha, name in rows).encode()
    yara = ('import "hash"\n' + content.decode() + "\n/*\n" + rl_notice + "\n" +
        "Source: https://github.com/reversinglabs/reversinglabs-yara-rules/blob/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84/yara/trojan/Linux.Trojan.AcidRain.yara\n*/\n" + rl.decode() + "\n// KANAF_EXACT_HASH_RULES\n")
    for i, (sha, name) in enumerate(rows):
        yara += (f'\nrule Kanaf_Android_Exact_{i} {{\n meta:\n'
                 f'  author = "ESET Research; Kanaf format conversion"\n'
                 f'  license = "BSD-2-Clause"\n  description = "{name}; exact file only"\n'
                 f'  source = "https://github.com/eset/malware-ioc/tree/{SOURCE_COMMIT}"\n'
                 f' condition:\n  hash.sha256(0, filesize) == "{sha}"\n}}\n')
    assets = root / "app/src/main/assets"
    assets.mkdir(parents=True, exist_ok=True)
    files = {"production_clamav.hsb": clam, "production_yara.yar": yara.encode()}
    for name, data in files.items():
        (assets / name).write_bytes(data)
    manifest = dict(format=1, source_commit=SOURCE_COMMIT, license=["BSD-2-Clause", "MIT"],
                    author=["ESET Research", "ReversingLabs"], android_exact_hashes=len(rows),
                    linux_elf_content_rules=3, independent_detection_sources=2,
                    reversinglabs_source_commit="e0a0be54aa1e11ccfd6854e4f19e9476f328fd84",
                    source_files={"signatures.tsv": digest(seed), "linux-moose.yar": digest(content), "reversinglabs-acidrain.yara": digest(rl)},
                    assets={name: digest(data) for name, data in files.items()})
    (assets / "native_rules_provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest

if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
