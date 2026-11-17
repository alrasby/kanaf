#!/usr/bin/env python3
"""Offline YARA candidate intake. NEVER labels a rule production-approved."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

class IntakeError(ValueError):
    pass

def sha(value):
    return hashlib.sha256(value).hexdigest()

def intake(repo, plan):
    if plan.get("schema") != 1 or plan.get("upstream") != "Neo23x0/signature-base":
        raise IntakeError("unexpected-upstream")
    commit = plan.get("commit", "")
    if not re.fullmatch("[a-f0-9]{40}", commit):
        raise IntakeError("invalid-source-commit")
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args],
            check=True, capture_output=True, text=True, timeout=15).stdout.strip()
    if git("rev-parse", "HEAD") != commit or git("status", "--porcelain"):
        raise IntakeError("source-not-pinned-and-clean")
    def tracked_bytes(path):
        entry = git("ls-tree", commit, "--", path)
        if not entry.startswith(("100644 blob ", "100755 blob ")):
            raise IntakeError("source-file-not-tracked-regular:" + path)
        return subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{path}"],
            check=True, capture_output=True, timeout=15
        ).stdout

    license_file = tracked_bytes("LICENSE")
    if (b"Detection Rule License (DRL) 1.1" not in license_file or
            sha(license_file) != plan.get("license_sha256")):
        raise IntakeError("source-license-unverified")
    selected = plan.get("rules")
    if not isinstance(selected, list) or not 1 <= len(selected) <= 32:
        raise IntakeError("rule-selection-invalid")
    compiled = []
    audit = []
    unique = set()
    for entry in selected:
        if not isinstance(entry, dict):
            raise IntakeError("rule-record-invalid")
        path = entry.get("path", "")
        if not isinstance(path, str):
            raise IntakeError("rule-path-invalid")
        relative = PurePosixPath(path)
        if (relative.is_absolute() or len(relative.parts) != 2 or
                ".." in relative.parts or relative.parts[0] != "yara" or
                relative.suffix not in (".yar", ".yara") or path in unique):
            raise IntakeError("rule-path-invalid")
        unique.add(path)
        file = repo.joinpath(*relative.parts)
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 256 * 1024:
            raise IntakeError("rule-unavailable-or-oversize")
        raw = tracked_bytes(relative.as_posix())
        if not raw or b"\x00" in raw or sha(raw) != entry.get("sha256"):
            raise IntakeError("rule-hash-unverified")
        try:
            source = raw.decode("utf-8")
        except UnicodeError as exc:
            raise IntakeError("rule-not-utf8") from exc
        # No automatic imports, includes, custom externals, or multi-rule files.
        if re.search(r'(?m)^\s*(?:import|include)\s+"', source):
            raise IntakeError("rule-import-requires-review")
        rules = re.findall(r"(?m)^\s*(?:(?:private|global)\s+)?rule\s+([A-Za-z_]\w*)\b", source)
        if len(rules) != 1 or "meta:" not in source or "condition:" not in source:
            raise IntakeError("ambiguous-rule-metadata")
        name = rules[0]
        header = source.split("condition:", 1)[0].split("meta:", 1)[1]
        author = re.findall(r'(?m)^\s*author\s*=\s*"([^"\n]{1,160})"\s*$', header)
        if len(author) != 1 or author[0] != entry.get("author"):
            raise IntakeError("attribution-not-verified")
        declared = re.findall(r'(?m)^\s*license\s*=\s*"([^"\n]+)"', header)
        if any(value not in {"Detection Rule License 1.1", "Detection Rule License (DRL) 1.1"}
               for value in declared):
            raise IntakeError("rule-license-override")
        if "EICAR" in source.upper():
            raise IntakeError("test-rule-not-production")
        audit.append({"rule": name, "author": author[0], "source_sha256": sha(raw),
                      "url": "https://github.com/Neo23x0/signature-base/blob/" +
                             commit + "/" + path})
        compiled.append(raw.rstrip() + b"\n")
    candidates = b"\n".join(compiled)
    if len(candidates) > 4 * 1024 * 1024:
        raise IntakeError("native-rule-size-limit")
    return candidates, {"status": "UNREVIEWED_CANDIDATE_ONLY",
                        "production_approved": False, "commit": commit,
                        "candidate_sha256": sha(candidates), "rules": audit}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    if "assets" in args.out.resolve().parts:
        raise SystemExit("REFUSED: candidate cannot be packaged in app assets")
    candidate, report = intake(args.source.resolve(),
        json.loads(args.plan.read_text(encoding="utf-8")))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "candidate.yar").write_bytes(candidate)
    (args.out / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Candidate staged, NOT APPROVED. Review YARA-X, test corpus, attribution and licensing.")

if __name__ == "__main__":
    main()
