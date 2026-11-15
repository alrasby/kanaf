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
- ZIP structure inspection has a cooperative 20-second deadline and a stalled-read guard; blocked I/O and native parsing still require process isolation.
- An offline **Test both engines** action within Engines. It runs native code, not a
  mock, and only reports success after a real EICAR signature match.
- Signature updates (not yet network-enabled) now stage the previously signature-verified version, digest and database in **one AtomicFile**, rejecting damaged/truncated bundles and version rollback against legacy state. The old split-file format fails closed until an authenticated update replaces it.
- Android emulator integration tests cover private `:scanner` service declaration, bound worker IPC self-test, unavailable providers, and debuggable-only worker process crash/restart. Crash injection is unreachable in non-debuggable releases; x86_64 does not validate native ARM64 detection. The emulator uses x86_64, so native ARM64 engine detection is still a separate device test.
- JUnit regression tests and CI build, lint and APK native-library assertions.

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
- No protection of the entire device, on-install verification, realtime monitoring,
  quarantine, safe remote threat updates or background scanning is provided.
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
