# Kanaf / كنف

Local threat scanner. Files, links, and message text are examined on the device. The only network use is downloading public signature databases. Nothing is deleted, quarantined, or blocked unless the person using Kanaf chooses that.

## What runs here

The interface in this workspace is the working product: a browser app with the Kanaf engine.

- ClamAV `daily.cvd` **28157** (18 Oct 2026), digital signature checked, **54,705** hash records (`hdb`/`hsb` only).
- ClamAV `main.cvd` **63** (16 Dec 2025), signature checked, **207,432** hash records after the Android / Java / script / archive / document filter. The CVD itself reports 3,287,027 signatures of every type.
- abuse.ch URLhaus snapshot: **73,351** URLs and **18,054** hosts (19 Oct 2026).
- MalwareBazaar recent MD5 and SHA-256: **1,747** hashes. The public export has no file size, so those match on the digest alone.
- MalwareBazaar code-signing blocklist: **408** certificate thumbprints.
- Unique hash index: **263,882**.

`ndb`, `ldb`, and bytecode signatures are not loaded. They need libclamav (GPLv2), which is not shipped.

## Android package

Signed sideload APK `Kanaf.apk`, package `com.kanaf.alrasby`, `versionName` `1.0`. It installs on Android 7 or newer. The shell loads the same scanner UI and the bundled signature files. Folder and file scans use the system document picker. Installed-package scanning is still not available. Signature refresh over the network still depends on the server route, so a phone with only the APK keeps the bundled database.

## Checks that were run

Unit tests in `src/lib/kanaf/engine/engine.test.ts` cover MD5/SHA-256, the published ClamAV CVD signature (accept and reject), the size secondary key, EICAR end to end, allow-listing, nested archives, zip-bomb limits, URL and trusted-sender analysis, and heuristic weights.

Not run: instrumented UI tests, screenshot diffs, WorkManager, and any test on a physical phone.
