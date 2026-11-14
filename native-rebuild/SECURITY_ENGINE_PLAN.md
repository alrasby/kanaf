# Kanaf antivirus integration decision (2026-11-13)

## Decision
- **ClamAV** is the candidate on-device antivirus engine, NOT yet integrated. GPLv2 obligations, Android arm64-v8a cross-compilation, memory use, and CVD update distribution terms require review before release.
- **YARA-X** is a candidate for advanced binary pattern analysis, NOT yet integrated. BSD-3-Clause license; Rust/native Android integration and ruleset licensing must be verified.
- **VirusTotal public API** must NOT be embedded as a replacement antivirus scanner: its public terms prohibit antivirus-product substitution and commercial integration.
- **Play Integrity / Play Protect verdicts** may be evaluated only as optional platform signals, not as a reusable malware scanning engine.

## Required architecture
1. Keep current SHA-256, APK, ZIP and DEX checks as independent evidence sources; never label an incomplete scan as safe.
2. Build a bounded, isolated native scanning adapter with cancellation, byte/time/memory limits, clear error states and no untrusted file execution.
3. Pin engine and database provenance. Use upstream-approved signed update formats and authenticated HTTPS. Never silently substitute unsigned feeds.
4. Publish database version, engine version, last successful update and source in settings. Handle offline and stale databases explicitly.
5. Obtain explicit user consent before sending any hash, URL or file to an external service. Default is entirely local.
6. Separate confirmed signature matches, suspicious heuristics, and unknown/incomplete results. Never delete or quarantine solely on an ML score.
7. Validate with clean Android APKs, known safe test signatures (EICAR), malformed archives, ZIP bombs, oversized files and independent malware test corpora handled safely.
8. Measure false-positive rate, recall, latency, memory and battery on representative Android devices before enabling by default.

## Release blockers
- Native engine binary and ABI tests
- Licensing/legal review for redistribution and database updates
- Signed and rollback-resistant update pipeline
- Real-world independent detection evaluation
- Play policy and user privacy review

Sources:
- https://docs.clamav.net/
- https://www.clamav.net/downloads
- https://github.com/VirusTotal/yara-x
- https://docs.virustotal.com/reference/public-vs-premium-api
- https://support.google.com/googleplay/android-developer/answer/11395166
