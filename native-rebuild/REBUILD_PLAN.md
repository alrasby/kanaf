# Kanaf native rebuild — implementation and acceptance plan

## Architectural boundary
The native Android app under `native-rebuild/` is the replacement. Legacy web code is reference-only. Do not merge into the old scanner or present the bootstrap app as full protection.

## Gates (in order)
1. **Build reproducibility:** CI Gradle/JDK/SDK unit tests, lint, assembleDebug, APK install and launch. No release before this gate passes.
2. **Core scanning:** bounded streaming I/O; cancellation; SHA-256 and MD5 where required; content-type identification; transparent incomplete verdicts; fuzzing on hostile streams.
3. **Signatures:** authenticated, versioned update manifest; hash verification; rollback and atomic activation; offline bootstrap; tested stale/invalid updates. Current asset is EICAR only.
4. **Formats:** robust ZIP/APK parsing with limits on cumulative actual output, nested depth, and CPU; DEX/manifest heuristics with false-positive tests; never treat skipped content as safe.
5. **Quarantine:** encrypted storage with Android Keystore; crash-safe transactions; integrity checks; SAF-mediated restore; no silent deletion; restore and recovery tests.
6. **Android integration:** SAF and app visibility rules, lifecycle-safe background work, explicit user permissions, scheduled scans, installation-event handling within Android limitations.
7. **Product parity:** Arabic/English, accessibility, user-controlled alerts, results with reasons, scan history and privacy controls.
8. **Release:** instrumented tests across supported Android versions, security review, measured memory/battery, signed APK/AAB, documented limitations.

## Known current gaps
- CI workflow was added but no run has been confirmed.
- No production signatures, updates, APK analysis, quarantine, scheduled scanning, device tests, or release build.
- EICAR bootstrap demonstrates signature matching only, not malware detection coverage.
- The scanner currently has a per-file byte cap but not a wall-clock deadline.
- Compatibility is not yet validated on Android 8–current.

## Merge policy
Keep PR as draft until CI and core feature gates pass. No claims of comprehensive protection.

## Update security status (November 2026)
- RSA SHA256withRSA manifest verification and negative tampering tests have been added.
- `SignatureRepository.installVerified` requires an authenticated manifest and checks a locally persisted version floor.
- No production public key has been pinned and no trusted release pipeline has been implemented. Network updating MUST remain disabled until that exists.
- Database activation and version-floor persistence are not one crash-atomic transaction. Recovery/rollback hardening is required before shipping updates.
- Archive inspection enforces actual expanded byte limits, but still needs time budgets, nested inspection, and complete APK/DEX analysis.
- CI execution, Android build, device install, and all tests remain unverified.
