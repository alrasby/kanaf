# Kanaf native Android rebuild (engineering preview)

Kanaf is a Kotlin / Jetpack Compose Android app (min SDK 26). This directory is
separate from the earlier web/React prototype. Do not merge/release as a full
antivirus until native detection, update trust, and on-device tests are complete.

## Present capabilities

- SAF user-selected file scanning, bounded streaming SHA-256, local bootstrap hashes.
- ZIP, APK and DEX structural inspection with explicit incomplete verdicts.
- Fail-closed multi-engine consensus and evidence-based decision guidance. If all completed SHA-256 hashes do not match (e.g. SAF content changes between reads), the aggregate result is explicitly inconclusive rather than a falsely confirmed detection; the individual matches remain available for review. Bad digests, empty labels and missing engines also fail closed.
- ClamAV 1.4.3 and YARA-X 0.13.0 Android ARM64 libraries built in isolated CI jobs.
- JNI bridge with a 16 MiB staging ceiling and 30-second cooperative copy deadline. Native calls are delegated to the separate `:scanner` process; the parent process never calls the JNI scan symbols.
- The JNI bridge also verifies the runtime's exact ClamAV 1.4.3 version before using its pinned C ABI. Missing symbols or a different version fail closed. Native detections without a bounded, valid rule identifier, and contradictory CL_CLEAN + rule name results, are incomplete rather than reported as clean or confirmed malware.
- ClamAV 1.4.3 native engine now sets decompressed scan budget (32 MiB), contained-file limit (16 MiB), recursion depth (8), file-count cap (512), and engine scan time (20 seconds). Limit-exceeded heuristic alerts are deliberately reported as **incomplete**, not malware or clean; missing/failed limit configuration aborts that engine. ABI ordinals are pinned to ClamAV 1.4.3 and host C++ regression-tested.
- YARA-X 0.13.0 now requires a 20-second per-scan timeout; an unsupported/failed timeout or scanner error yields **incomplete**. A received matching-rule callback with an unreadable, oversized or invalid identifier also yields **incomplete**, never a false `NO_MATCH`. Host C++ regression tests cover the callback policy.
- Private native scan copies are sealed read-only and SHA-256 verified before and after engine execution; changed or truncated snapshots fail closed. YARA-X also reads a bounded, stable regular-file snapshot (no symlinks/FIFOs), checks EOF and before/after metadata to prevent false negatives if a file changes while being read. JVM and native C++ regressions cover this policy.
- **EICAR-only** ClamAV NDB **body-based** rule and YARA-X rule, with pinned SHA-256 digests. The ClamAV test originally used an HDB hash signature, which the ClamAV docs warn is unsuitable for text or other internally normalized data; a full-byte NDB body signature avoids relying on raw-file MD5 matching. This remains a harmless test vector, NOT a production malware database.
- Both engines must pass a positive EICAR and a negative benign-sample self-test
  before their file-scan results are accepted. No match is NOT proof of safety.
- User-initiated offline URL/text structure inspection (paste or Android Share > Kanaf). Explicitly NOT a malware, reputation, phishing database, or URL safety verdict.
- Home, session-only scan history (10 bounded non-persistent summaries), Engines and About sections, using the existing Kanaf color and glass style.
- **Encrypted-copy vault (manual; not full quarantine):** users explicitly confirm and pick a SAF file, then Kanaf stores an authenticated AES-256-GCM encrypted copy under `noBackupFilesDir` with an Android Keystore key, a random per-item IV and item-ID-bound AAD. The original is never moved, removed or restricted. Maximum 16 MiB per copy, 32 stored items and 128 MiB of ciphertext. No original filenames or URIs are persisted. Copies can be restored only into a user-chosen SAF document; GCM authentication completes in bounded memory before any plaintext is written to that provider. Corrupt/missing keys or content fail closed. Restoring to a failing document provider may leave a partial document; the UI warns the user to delete it.
- A separate bilingual glass-style **Vault / الخزنة** screen provides explicit confirmation before saving and deletion, displays anonymous copy identifiers, and supports manual restore. Clearing application data or losing the device Keystore key makes saved copies unrecoverable; there is intentionally no unencrypted automatic backup. This is a copy vault, not security isolation of the source file.
- Explicit user-initiated sharing of the current text scan report through Android Sharesheet (may disclose SHA-256 to the chosen recipient), and a shortcut to official Android application/permission settings. Kanaf does not silently monitor applications or grant itself special privileges.
- **Opt-in launchable-app review** enumerates only apps Android exposes through the scoped MAIN/LAUNCHER `<queries>` declaration, displays their labels, package IDs and counts of requested manifest permissions, and links to each app's official Android settings. It does **not** claim APK signature analysis, enumerate hidden packages, silently restrict permissions or require `QUERY_ALL_PACKAGES`. A separate Android instrumentation test verifies the visible own app and settings intent.
- VaultCrypto JVM tests check round-trip, corruption, missing authentication tag, wrong item-ID AAD, oversized sources, and malformed headers; a scoped Android API35 integration test validates real Android Keystore AES-GCM.
- ZIP structure inspection has a cooperative 20-second deadline and a stalled-read guard; blocked I/O and native parsing still require process isolation.
- An offline **Test both engines** action within Engines. It runs native code, not a
  mock, and only reports success after a real EICAR signature match.
- Signature updates (not yet network-enabled) now stage the previously signature-verified version, digest and database in **one AtomicFile**, rejecting damaged/truncated bundles and version rollback against legacy state. The old split-file format fails closed until an authenticated update replaces it.
- Android emulator integration tests cover private `:scanner` service declaration, bound worker IPC self-test, unavailable providers, and debuggable-only worker process crash/restart. Crash injection is unreachable in non-debuggable releases; x86_64 does not validate native ARM64 detection. The emulator uses x86_64, so native ARM64 engine detection is still a separate device test.
- Opt-in package installation/replacement event **review prompts** via a protected Android package broadcast receiver and WorkManager. The app does NOT inspect new APK bytes automatically or provide continuous malware prevention; Android 13+ notification permission may be needed.
- User-chosen SAF directory (limited to up to **32 direct child files per check**) can be checked approximately every 24 hours, or on request, with WorkManager and the installed local SHA-256 index. Missing permissions/oversized files/provider errors are **incomplete**, never clean. This does not traverse the device filesystem or all subdirectories. Android may postpone jobs during Doze/battery restrictions.
- Explicit manual **visible installed APK audit** reads at most 20 launchable apps' base APKs when Android allows access and file size is 16 MiB or less. Runs SHA-256 signature matching and APK/DEX/ZIP structure inspections. Splits, inaccessible packages, insufficient signatures and partial reads are reported as incomplete. Structural warnings are not malware proof.
- **User-approved SAF document quarantine:** makes an authenticated encrypted copy, confirms its plaintext SHA-256 matches the selected original before/after copying, and requests `DocumentsContract.deleteDocument` ONLY when the provider advertises delete support. If deletion fails or the source changes, the report says **encrypted copy only**, never isolated. The feature cannot contain other apps' private files or intercept access, and SAF providers offer no transactional guarantee against changes between the last check and deletion.
- **Offline production signature feed import** uses an explicitly build-pinned RSA PUBLIC key, a strict ZIP containing `manifest.txt` and `signatures.tsv`, a signed version/SHA-256 manifest, AtomicFile persistence and anti-rollback checks. The importer remains DISABLED when the release key is unprovisioned (default builds), and no production feed or automatic network update is asserted. Production release signing, source provenance, threat-feed operational QA and model data remain outstanding.
- JUnit regression tests and CI build, lint and APK native-library assertions.

## Validated local ML model pipeline (integration, NOT a bundled detector)

- A small, deterministic on-device logistic model with the existing `ThreatFeatureVector` schema (7 structure/count features) is now wired into scan evidence as an **advisory risk score only**. The scan is never marked safe or malware-confirmed based on this model. Missing features yield `Unavailable`, not zero or a safe score.
- The default APK has **no trained model weights** and **no model signing public key**. `VerifiedLinearThreatModel.load()` consequently returns `UnavailableThreatModel`. This is deliberate: a real, independently audited APK malware dataset and evaluated trained weights have not been provided.
- To train a candidate off-device on legally licensed, independently labeled APK feature records: use `tools/train_apk_risk_model.py`, with disjoint `--train-csv`, `--validation-csv`, `--test-csv`, publisher-held `--private-key`, a substantive `--audit-report`, model `--version` and `--output-dir`. Requires NumPy and scikit-learn (pinned versions documented in the script). Distinct APK hashes AND collection provenance IDs between all splits are enforced.
- The script selects a decision threshold from the *validation* split ONLY, then rejects the model unless an untouched independent test set has >=5000 APKs, >=2000 verified benign, >=2000 verified malicious, ROC-AUC >=0.90, FPR <=0.005 and recall >=0.85. The released model format contains publisher-attested evaluation numbers; **independent examination of the audit report, labels, and any distribution shift is still mandatory**, as signed numbers alone are not proof of quality.
- Only an explicitly supplied release `-PkanafModelPublicKeyBase64=<SPKI_DER_BASE64>` AND publisher-signed `app/src/main/assets/validated_model.txt` and `validated_model.sig` permit inference. The model bytes are RSA SHA-256 authenticated with the pinned key, parsing, numeric ranges, sample-count and declared metrics are checked. No model files or signing keys are bundled now; production features are gated off.
- The current 7 structural features may be too weak for real-world Android malware classification. Any failure to meet quality criteria means **do not ship an ML verdict**; expand audited features and repeat independent evaluation rather than fabricate risk estimates. Privacy: no cloud upload, no automatic message collection.

## ARM64 ClamAV experimental diagnostics

The published ClamAV 1.4.3 API counts `scanned` in units of 4096 bytes. A 68-byte EICAR file legitimately logs `scannedUnits=0`; that counter does **not** establish a skipped scan. The actual `CL_CLEAN` result on EICAR still fails the engine's strict positive/negative readiness gate. For debug builds with the NDB matcher failing, an additional **diagnostic-only** comparison now probes a valid MD5 `.hdb` EICAR signature and an NDB sample padded beyond 4 KiB. Neither observation can override failed content-based EICAR readiness. The generated debug log will help distinguish a general ClamAV runtime problem from Android matcher issues; native ARM64 physical-device confirmation is still mandatory.

## Publisher-owned signed signature feed (not yet provisioned)

1. Hold the RSA private signing key outside this repository and outside the APK; set the corresponding SPKI DER public key Base64 for a trusted release build using `-PkanafSignaturePublicKeyBase64=<PUBLIC_DER_BASE64>`. Never inject a private key into CI artifacts or upload it to ChatGPT.
2. Validate candidate SHA-256 threat labels and their licensing/attribution with the publisher. Sign a monotonically increasing version using `python3 tools/sign_signature_feed.py --database signed-signatures.tsv --version 1 --private-key /private/publisher.pem --output signed-feed.zip`.
3. The **Engines / المحركات** screen enables manual local import only in builds with the pinned public key. The import rejects invalid ZIP layout, wrong RSA signature, mismatched digest, corrupt database, or rollback. No network updater is present.
4. A release cannot claim production malware coverage until feed acquisition, false-positive testing, legal review, rollback policies and on-device detector validation have independently passed.

## New opt-in protection QA

- **Protection / الحماية**: install event alerts start disabled. On Android 13+, enable notification permission explicitly. Test install/replacement notifications on a physical device; package broadcast delivery is best-effort under Android power/background limits.
- Select a directory through Android's document-tree picker for the 24-hour WorkManager SHA-256 checks; grant persists only while this feature is enabled and is revoked on opt-out. The run examines at most 32 direct-child files. Status says `incomplete` for unreadable/oversized files. The check is not a device-wide scan.
- **Apps / التطبيقات**: the on-demand APK audit checks up to 20 visible base APKs, and reports inaccessible, split or oversized APKs as incomplete. Do not infer safety from missing SHA-256 matches.
- **Vault / الخزنة**: explicitly consent to quarantine a selected SAF document. Verify the original disappears only if its document provider supports deletion and after a fully authenticated encrypted copy has been created; failures must be labelled copy-only. Restore to a new user-selected SAF file, verify it, and test reboot/reinstall key-loss behavior. This does not isolate files inside other apps.
- Physical-device and emulator tests for the new Android WorkManager/broadcast/Keystore/SAF flows remain mandatory before calling them release-ready.

## On-device validation

1. Install a recent ARM64 *debug* APK from the `kanaf-android-native-engine-apk`
   artifact of a **successful** ClamAV workflow; the diagnostics artifact is not an app.
2. Open **Engines / المحركات**, select **Test both engines / اختبار المحركين الآن**.
3. Verify that both ClamAV and YARA-X report an EICAR test detection. If a library
   cannot load or its rules fail validation, expect **incomplete**, never clean.
4. In **Scan / الفحص**, select a harmless file. Confirm that the results identify
   each scanner separately, plus SHA-256 and any structure-analysis findings.
5. Repeat after app restart and test dark/light system themes and both UI locales.

## Explicit limitations

- The bundled database only recognizes the harmless EICAR test string, not general malware.
- Native scanning is limited to explicitly selected files up to 16 MiB.
- **No comprehensive full-device malware protection** is provided. Opt-in package-install review prompts, user-granted scheduled SHA-256 checks, manual visible-APK inspection and explicit provider-approved single-file removal are limited by Android permissions and available rules. No unrestricted filesystem access, general all-app realtime inspection, automatic original-file containment, or network threat feed is enabled by default.
- Native ClamAV and YARA-X parsing now runs in a **separate, non-exported app-private Android process** (`:scanner`) via Messenger IPC. The UI process receives an explicit incomplete verdict if the worker disconnects or times out. A worker watchdog terminates only the scanner process after 90 seconds, with a 100-second client deadline. Stale scanner cache copies are purged when the worker restarts.
- Process separation provides **crash containment only**, NOT a restricted/isolated Android UID, sandbox, or guaranteed interruption of a maliciously blocked input provider. Real-device IPC, native-loader, timeout and memory tests remain release blockers.
- Only Android ARM64 has the ClamAV/YARA-X libraries; other ABIs are unavailable.
- The official ClamAV libclamav is GPLv2 licensed. Review source distribution and
  application license compatibility **before redistributing a production build**.
  No automatic licensing decision has been made.
- Instrumentation/on-device detection tests and production release signing remain pending.

## CI

`kanaf-clamav-arm64.yml` compiles ClamAV and builds a debug APK with both native
libraries and the JNI bridge. The APK is published only after Gradle tests,
lint, native ELF and APK-content checks succeed.

The separate `kanaf-package-native-engines.yml` may reuse pinned successful
native build artifacts to reduce repetitive native compilation.

Local prerequisites: JDK 17, Android SDK 35, NDK 27.2.12479018, CMake 3.22.1,
Gradle 8.9. Run from `native-rebuild`:

```bash
gradle --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

Debug APKs and EICAR checks are engineering test artifacts, **not security
certification or a consumer release**.

## Experimental ARM64 runtime CI

The scoped `kanaf-arm64-runtime.yml` workflow tries to execute the **real ARM64** ClamAV and YARA-X libraries on an Android 35 Google APIs x86_64 emulator that explicitly advertises ARM64 translation. A special `-PkanafArm64Runtime=true` test build restricts its bundled ABI to ARM64; ordinary APK builds are unchanged. The workflow downloads pinned successful engine artifacts, runs the real `:scanner` IPC EICAR positive and benign negative checks, and **fails**, rather than skipping, when the emulator cannot execute ARM64 or an engine returns incomplete. The result is experimental translated ARM64 runtime evidence only, **not** a physical device test, real malware detection, or release certification.

## ClamAV ARM64 memory-map diagnostic

ARM64 probe #7 verified that disabling ClamAV's clean cache **did not** resolve the native EICAR `NO_MATCH`; therefore that experimental option was reverted. The debug-only native self-test now compares the same harmless built-in EICAR bytes via ClamAV's `cl_scanfile` and `cl_fmap_open_memory` + `cl_scanmap_callback`. Both comparisons use the same compiled signature database and **neither changes any verdict or readiness gate**. A memory-only detection would indicate a disk/file-map path issue; two no-matches point to signature-matcher/library integration. This test must not be used to claim production antivirus coverage.

## Strict ARM64 runtime #10 outcome (15 Nov 2026)

The translated Android ARM64 run #10 FAILED the actual engine detection gate: ClamAV loaded one test rule but returned CL_CLEAN for EICAR via normal, raw and memory-backed scans, even with AC-only matching; YARA-X passed its EICAR and benign checks. The APK #58 packaging and native CI #301 passed, but do not establish ClamAV functionality. This unresolved platform-specific result must not be bypassed with fake detections, a fallback clean verdict, or a production claim. Verify an actual Android ARM64 device or independently reproduce the Android target binary on a native ARM64 Android environment before accepting the engine.

## ClamAV Android matcher controlled experiment (15 Nov 2026)

The ClamAV 1.4.3 source places simple NDB signatures in Boyer–Moore by default; `CL_ENGINE_AC_ONLY` switches to a supported Aho–Corasick matcher. For Kanaf's EICAR-only prototype, the bridge now enables the AC-only option (ABI ordinal 10) **before `cl_load` initializes the matcher roots**, rejecting a failed option rather than continuing insecurely. Host C++ regression cases cover the setting and failure handling. This remains an experiment until strict ARM64 EICAR-positive/benign-negative checks pass, and performance must be re-evaluated before any full production database.
