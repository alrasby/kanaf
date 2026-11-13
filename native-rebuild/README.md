# Kanaf native rebuild (in progress)

This is a new Android application, not a patch to the existing React/TypeScript application. The old code remains untouched for reference and feature parity.

## Implemented
- Kotlin / Jetpack Compose Android app, minimum SDK 26.
- System file picker (SAF) and streaming SHA-256 calculation on a background dispatcher.
- Explicit incomplete/unknown result when no signature database is available; never falsely claims a clean file.
- Scan byte ceiling and cancellation hook in the scanner primitive.
- JUnit tests for hashing, signature lookup, cancellation, and size limits.

## Not yet implemented
Production threat-feed ingestion and cryptographic verification, persistent signature index, APK/DEX inspection, ZIP streaming limits, encrypted quarantine, scheduled/installation scans, Android background service, UI parity, localization, instrumentation tests, release signing.

## Verification
No build or tests have been run for this new module yet. CI is not configured for this module. Do not release or merge as a complete security app.

## Local checks
From native-rebuild, use an installed compatible JDK 17, Android SDK 35, and Gradle 8.9:
`gradle :app:testDebugUnitTest :app:assembleDebug`

Do not treat an unsigned/debug APK as a release.
