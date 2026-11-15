# Kanaf release readiness — production approval gate

Current decision: **BLOCKED (development preview)**. No release approval or PR
merge until the following independently grounded evidence is attached.

| Gate | Required independently verifiable evidence | Current status |
| --- | --- | --- |
| ClamAV 1.4.6 + YARA-X 0.13.0 native ARM64 | Real ARM64 hardware, EICAR/benign and representative licensed malware/cleanware fixtures, 0 crashes; per-engine positive/negative outcomes | Translated ARM64 emulator EICAR passed; hardware and real corpus pending |
| Production threat signatures | Legal redistribution/provenance per record; actual non-EICAR signatures; independent signed RSA publisher key, secure storage, HTTPS feed and rollback/tamper/revocation tests | Offline publisher tool and test-only signed fixtures pass; **no production database/key** |
| Device scan coverage | APK base/splits; Android 8–latest with different permissions, accessible shared storage, large files, archives, timeouts, cancellation, race/snapshot changes, no file deletion | Bounded app scan and consensus code covered in CI; physical devices and real coverage evaluation pending |
| False-positive/false-negative calibration | Independent labeled threat+benign datasets with privacy-safe sourcing; measure specificity, sensitivity, precision and broken/unknown rates; document non-overlap | No licensed independent corpus/benchmarks |
| Kanaf AI | Signed real on-device model, independent labeled Android corpus, train/test split and leakage prevention, per-device latency/battery/accuracy evidence | Signed loader and manual APK inference wired to UI; **unavailable** without externally validated signed weights and independent corpus |
| DNS VPN | Samsung/Pixel hardware: strict/auto Private DNS, one VPN coexistence, Android 8+, Wi-Fi ↔ mobile, IPv6, DNS over TLS/HTTPS, 24-hour battery/idle and app termination | Packet policy and API35 emulator tests only |
| Permissions and user disclosures | Play Console approval for QUERY_ALL_PACKAGES + MANAGE_EXTERNAL_STORAGE; VpnService declaration; accurately described scanning, uninstall and accessibility | Permission declaration implementation only; no Play approvals |
| Security/privacy/licensing | Current license obligations for ClamAV, YARA-X and each signature feed; secure native dependencies; data minimization, threat feed key rotation, secure updates and rollback | Pending legal/security reviews |
| Android 16 KiB page compatibility | PT_LOAD 16 KiB ELF segments for every packaged ARM64 .so, 16 KiB ZIP alignment, device runtime | New ClamAV/YARA-X/CMake linker flags and APK validation gate; final artifact CI and 16 KiB device run pending |
| Google Play API targeting | New/updated Android phone apps must target API 36; verify edge-to-edge, permissions and window sizing | API 36 configured, CI and physical-device acceptance pending |
| Release signing | Owner-controlled production keystore (never committed), reproducible vetted signed AAB/APK, manifest assertions and artifact digest/attestation | Debug APK CI only; no production approval |
| Visual/device acceptance | RTL and LTR, fonts, TalkBack, dynamic scaling, 48dp targets, dark/light, weak/medium devices, one-tap scan/DNS onboarding | Emulator UI tests pass; physical visual sign-off pending |

Hard rules:
1. **Do not equate successful APK CI with antivirus effectiveness.**
2. **No test EICAR-only signatures in a publicly advertised production malware database.**
3. **Do not claim an Android third-party app reads all private app data or system files.**
4. **Do not embed private signing keys in code, release artifacts, CI job outputs or remote servers.**
5. **Do not declare this PR ready to merge until every gate is backed by external evidence.**

References:
- Google Play: https://support.google.com/googleplay/android-developer/answer/10467955
- Google Play: https://support.google.com/googleplay/android-developer/answer/10158779
- ClamAV: https://docs.clamav.net/manual/Signatures.html
- YARA-X licensing: https://github.com/VirusTotal/yara-x/blob/main/LICENSE
- Kanaf signature publishing procedure: THREAT_FEED_PUBLISHING.md
