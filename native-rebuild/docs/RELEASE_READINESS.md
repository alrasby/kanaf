# Kanaf release readiness — production approval gate

Current decision: **BLOCKED (development preview)**. No release approval or PR
merge until the following independently grounded evidence is attached.

| Gate | Required independently verifiable evidence | Current status |
| --- | --- | --- |
| ClamAV 1.4.6 + YARA-X 0.13.0 native ARM64 | Real ARM64 hardware, EICAR/benign and representative licensed malware/cleanware fixtures, 0 crashes; per-engine positive/negative outcomes | Translated ARM64 emulator EICAR passed; hardware and real corpus pending |
| Publisher-signed native production rules | Independently sourced and audited ClamAV NDB + YARA-X YAR, pinned SHA-256 in APK; no EICAR-only verdicts | Release scanner now demands pinned production assets and fails INCOMPLETE if missing; real rules not provided |
| First-run signed threat feed | Publisher-signed ZIP containing curated SHA-256 rules included at build, pinned RSA public key and anti-rollback, verified AtomicFile installation | Bootstrapping implemented and Android signing/tamper tests added; no production feed/key provided |
| Fail-closed release preflight | Independently signed QA asset attestation, fully signed malware model, audited native rules, publisher threat feed, owner keystore; final signed-APK digest and physical QA | Gradle release now refuses missing inputs; signing and QA keys must be provisioned externally |
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

### Production deployment gate — never use CI test credentials

`./gradlew :app:verifyKanafProductionInputs` is a **negative test** without
external publisher materials; the task must fail with
`KANAF_PRODUCTION_RELEASE_BLOCKED`. `preReleaseBuild` depends on this task.
The normal debug/emulator route remains available without production secrets.

Release publisher inputs must be provided outside source control:
- `-PkanafSignaturePublicKeyBase64=<publisher RSA SPKI DER Base64>`,
  `-PkanafSignatureMinVersion=<positive monotonically increasing version>`,
  `-PkanafSignatureFeedHttpsUrl=https://<publisher>/...zip`;
  `src/main/assets/production_signatures.zip` must be signed and contain
  **real independently audited** non-EICAR signatures.
- `src/main/assets/production_clamav.ndb`,
  `src/main/assets/production_yara.yar`, and
  `-PkanafNativeClamRuleSha256=<lowercase SHA256>`,
  `-PkanafNativeYaraRuleSha256=<lowercase SHA256>`.
  The release worker verifies both rule digests and **never substitutes
  EICAR test fixtures** for normal file scans.
- `src/main/assets/validated_model.txt` + `validated_model.sig` and
  `-PkanafModelPublicKeyBase64=<publisher key DER Base64>`.
  Generated structural-fixture model weights do not qualify.
- An **independent** QA signing key (not equal to either publisher key),
  with env paths `KANAF_QA_ATTESTATION`,
  `KANAF_QA_ATTESTATION_SIGNATURE` (raw SHA256withRSA binary signature),
  `KANAF_QA_PUBLIC_KEY_DER` (SPKI DER).
  Attested ASCII file (LF newlines), in order:
  `Kanaf-Production-Assets-v1`; SHA256 model bytes; SHA256 signed feed's
  uncompressed `signatures.tsv`; SHA256 ClamAV rules; SHA256 YARA-X
  rules; independently audited dataset-license review ID; security review
  ID. **QA independence and truthfulness require external human verification**;
  a valid signature does not certify factual claims by itself.
- `KANAF_RELEASE_KEYSTORE_FILE`,
  `KANAF_RELEASE_STORE_PASSWORD`, `KANAF_RELEASE_KEY_ALIAS`,
  `KANAF_RELEASE_KEY_PASSWORD`. All kept exclusively in protected local
  signing infrastructure, never committed or printed.

Even with valid asset preflight, require a separately signed final artifact
report via `tools/check_release_readiness.py`, real Android ARM64
hardware/16-KiB kernel verification, representative independent malware
and benign evaluations, policy declarations and publication approval.

### Final artifact identity and independent trust pin (added 16 Nov 2026)

The signed QA report is **not** a substitute for examining the actual shipped
artifacts. `tools/check_release_readiness.py` now requires:

- `--apk` and `--aab` pointing to the actual final release artifacts;
  the script hashes both files (streaming SHA-256), compares their hashes to
  `release.signed_apk_sha256` and `release.signed_aab_sha256`, and requires
  the APK digest to match `native.tested_apk_sha256`.
- `apksigner verify --min-sdk-version 26 --verbose --print-certs`, with a
  modern v2/v3 APK signature and exactly one certificate whose actual digest
  matches `release.apk_signer_cert_sha256`. Install trusted Android SDK
  Build Tools on the release-signing host.
- `jarsigner -verify -strict` must affirm the uploaded AAB is signed, using
  the trusted JDK toolchain. The AAB upload key can differ from the APK
  distribution signing certificate under Play App Signing.
- `--expected-qa-public-key-sha256` pins the **DER bytes** of the independent
  QA public key via an external, publisher/QA-controlled trusted channel.
  Signing evidence using an attacker-provided substitute key cannot satisfy
  that independently pinned fingerprint. It must not equal the threat-feed key.
- Missing artifacts, missing sign-tool executables, invalid signing, altered
  bytes, unpinned QA keys, or evidence lacking the new signed AAB/certificate
  fields block release. Debug APKs cannot satisfy this production gate.

Usage (paths and trusted fingerprint supplied by the independent publisher):
```bash
python3 tools/check_release_readiness.py \
  --evidence /secure/qa/release.json \
  --signature /secure/qa/release.sig \
  --qa-public-key /secure/qa/qa-public.der \
  --expected-qa-public-key-sha256 "$TRUSTED_QA_PUBLIC_KEY_DER_SHA256" \
  --expected-distribution play \
  --apk /secure/release/kanaf-release.apk \
  --aab /secure/release/kanaf-release.aab
```

These checks establish **artifact/signing consistency**, not physical hardware
testing, malware detection rates, legal permission approvals or independent
security certification. Those still require evidence produced outside CI.

### Release operator workflow — exact distributions (16 November 2026)

Only the publisher's **protected local/signing environment** can run this.
`tools/build_approved_release.sh` has three modes:

- `status`: show the presence/absence of signed production inputs, trusted
  publisher keys, offline QA attestation and packaged ARM64 libraries; never
  prints key content or passwords. File presence **does not certify** a signature.
- `build`: after the external real inputs are provisioned, run the strict
  Gradle production gate, build a fully **signed** Release APK **and** AAB,
  confirm APK v2/v3 and AAB JAR signatures, and print both SHA-256 hashes.
  Output is still **only a release candidate**, not a certified product.
- `verify`: only after the **same signed APK bytes** have passed real ARM64
  hardware QA and independent dataset/effectiveness review, verify the
  separate independently signed QA JSON, signature, out-of-band pinned QA
  key, artifact SHA-256 hashes and Android signatures. Any mismatch blocks.

Choose the channel **explicitly** using `KANAF_RELEASE_DISTRIBUTION`:
`play` builds with security-only Cloudflare DoH and no local ad-blocking;
`direct` retains existing community ad/tracker filtering. Gradle release
preflight now insists on matching
`-PkanafReleaseDistribution=<play|direct>` with
`-PkanafPlayDnsSecurityOnly=<true|false>` and refuses ambiguous releases.
The Android foreground-service subtype is automatically generated from the
same build policy; the Play variant can no longer advertise ad filtering.

Example:
```bash
cd native-rebuild
export KANAF_RELEASE_DISTRIBUTION=play
bash tools/build_approved_release.sh status
# Provision offline-validated production assets, ARM64 native libraries,
# owner-controlled signing env and independent QA attestation outside Git.
bash tools/build_approved_release.sh build
# Following physical-device QA on the exact signed APK and independent
# signing of the final QA evidence JSON:
bash tools/build_approved_release.sh verify
```

For the second stage set
`KANAF_QA_RELEASE_EVIDENCE`, `KANAF_QA_RELEASE_SIGNATURE`,
`KANAF_QA_PUBLIC_KEY_DER`, and the trusted out-of-band
`KANAF_TRUSTED_QA_PUBLIC_KEY_DER_SHA256`.
The report must include `release.distribution` and
`release.dns_security_only` matching the compiled variant. A direct release
does not require approval by a store where it is not distributed, but **still**
requires real malware/benign validation, physical-device QA, signed assets,
security review and licensed signatures. A direct APK must never be presented
as a Play-compatible binary.

No release is currently approved: these external inputs and production
signatures have not been supplied or demonstrated in the repository.
