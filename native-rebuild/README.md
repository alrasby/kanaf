# Kanaf native Android rebuild (engineering preview)

Kanaf is a Kotlin / Jetpack Compose Android app (min SDK 26). This directory is
separate from the earlier web/React prototype. Do not merge/release as a full
antivirus until native detection, update trust, and on-device tests are complete.

## Present capabilities

- SAF user-selected file scanning, bounded streaming SHA-256, local bootstrap hashes.
- ZIP, APK and DEX structural inspection with explicit incomplete verdicts.
- Fail-closed multi-engine consensus and evidence-based decision guidance.
- ClamAV 1.4.3 and YARA-X 0.13.0 Android ARM64 libraries built in isolated CI jobs.
- Experimental JNI bridge with 16 MiB ceiling, temporary private-cache copies and cleanup.
- **EICAR-only** ClamAV HDB and YARA-X rule, with pinned SHA-256 digests.
- Both engines must pass a positive EICAR and a negative benign-sample self-test
  before their file-scan results are accepted. No match is NOT proof of safety.
- Home, Engines and About sections, using the existing Kanaf color and glass style.
- An offline **Test both engines** action within Engines. It runs native code, not a
  mock, and only reports success after a real EICAR signature match.
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
- Native engines currently parse inside the app process. For an actual production
  threat scanner, move untrusted native parsing to an isolated process and validate
  limits, cancellation and crash recovery on real devices.
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
