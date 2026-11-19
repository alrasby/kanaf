# Kanaf practical protection implementation — 2026-11-19

Base: `rebuild/kanaf-native-v1` at `9c171ed1ac83878b01898605de888501c84345a8`.
Work branch: `feature/verified-protection`, PR #3. No changes to the old web app.

## Detection and trust

- Normal native scans use digest-pinned real research assets in debug and release.
- ClamAV `.hsb`: 30 exact Android file hashes from ESET Research (SpyLoan,
  VajraSpy), BSD-2-Clause. Exact hashes do not detect all members of a family.
- YARA-X: the same 30 Android file hashes plus the original ESET Linux/Moose
  ELF content rules and ReversingLabs Linux/Trojan/AcidRain (MIT), pinned
  to source commit `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84`. Original
  source is unchanged and its MIT notice is reproduced in the generated pack
  and app assets. These add Linux/ELF coverage, not new Android family claims.
  ELF rules do not establish Android-family detection and
  are not recursively applied to compressed APK members by YARA-X.
- Three matches for the same ESET file hash are one evidence source.
- EICAR remains an explicitly labelled, harmless diagnostic alongside real
  rules. Readiness checks require positive AND negative NDB, HSB and YARA tests.
- Source commit, author, licence, original file hashes and generated asset
  hashes are in `assets/native_rules_provenance.json`. Original source and
  licence notices are retained. `tools/build_native_rule_pack.py` reproduces
  the generated assets and refuses changed pinned inputs.
- The existing publisher key is unchanged. No private keys were requested,
  generated or accessed. The real HTTPS feed was downloaded and verified as
  version 1, SHA-256
  `f9e2e00f5f8f442a60be9002b0a7fc11230bb0764f1948649680bd161b35f882`.
- The packaging workflow configures this HTTPS URL:
  `https://raw.githubusercontent.com/alrasby/kanaf/rebuild/kanaf-native-v1/native-rebuild/rules/eset-android-seed/kanaf-feed-v1.zip`.
  An identical authenticated version is reported as up-to-date. Older feeds,
  altered same-version data, invalid signatures and digest mismatches fail.
- Signed SHA-256 updates replace exact-file rows in BOTH native engines.
  Content-rule and engine updates ship through reviewed application builds.
  Future feed versions must still be signed by the owner's existing key.

## Practical features

1. Opt-in dynamic install/update broadcasts enqueue unique package-specific workers.
   Android 8+ does not reliably deliver these implicit broadcasts to manifest
   receivers, so a 15-minute-or-later WorkManager delta inventory provides a
   background fallback after process death. It seeds a baseline once and queues
   changed packages in bounded batches; it never rescans unchanged APKs each cycle.
   Workers check the available base/split APKs, report partial coverage, and
   inspect permission and signing-certificate changes. Android controls timing.
2. Local certificate/permission baselines recognise Android-verified signing
   rotation. Unverified changed signers do not overwrite the trusted baseline.
3. App privacy review separates requested and granted sensitive permissions;
   special access is referred to Android Settings, not guessed to be active.
4. Android share sheet accepts a single `content://` file for local scanning,
   or text for link inspection. Incoming `file://` paths are not accepted.
5. Reports expose known matches, structural warnings, partial checks and
   reasons. Export adds app version, rule version, health and export time.
6. Process-local incremental verdict cache keys immutable full-file hashes,
   BOTH rule digests, engine versions and resource policy. No incomplete
   results are cached. File paths and timestamps never prove unchanged content.
7. Protection health shows actual DNS state, last scan/update check, installed
   signed database version, opt-in monitoring and scheduled work settings.
8. Optional daily signed updates use WorkManager network/battery constraints.
9. DNS diagnostics are OFF by default, RAM-only, capped at 64 events and
   cleared on stop/disable. Exact-domain exceptions affect local ad rules only;
   they do not override security rules or upstream filtering. NXDOMAIN is not
   falsely classified as confirmed malicious-domain blocking.
10. Optional HTTPS redirect inspection sends HEAD requests only, without cookies
    or page bodies. It rejects credentials, non-443 ports, HTTP downgrades,
    private/reserved addresses and loops. TLS connections use the validated IP
    plus hostname verification, avoiding DNS rebinding between check/connect.

## Validation and remaining acceptance gates

- Local Python suite: 55 tests, one pre-existing skip; YARA-X 0.13.0 installed.
- Real YARA rules compile; harmless ELF positive/near-miss controls pass. These
  are rule semantics tests, not malware recall measurements.
- CI adds host ClamAV format validation, safe HSB controls and an Android ARM64
  translated runtime job covering real-content controls, near misses, EICAR,
  20 MiB files and over-limit rejection.
- `tools/evaluate_detection_pack.py` measures both formats on SHA-pinned labelled
  corpora and reports missing samples/engines separately. Fixture matches never
  enter malware recall rates; absent malicious samples yield null recall.
- Independent, representative benign APK and real-malware corpora remain
  necessary before declaring efficacy or production approval. The present
  limited rules are not comparable in coverage to a full commercial database.
- Device battery/RAM measurements, OEM background behaviour, VPN/DNS bypass
  tests, expanded UI/device tests, publisher-signed release and store review
  remain required. Production gates are retained and must not be bypassed.

## Resume

Read this file and PR #3 checks before repeating work. Latest local changes
include source-pinned native assets, protection workers, privacy/certificate
review, DNS diagnostics, redirects, share/report flows, tests and CI wiring.
First CI caught a permission-flag constant referenced on PackageManager;
corrected to PackageInfo. Android runtime executed both real rule formats and
content positive/near-miss controls. Its 20 MiB test exposed a remaining 16 MiB
snapshot-integrity default from the previous build; corrected to 64 MiB and
covered by a JVM regression. Packaging also exposed an old test assuming the
HTTPS feed was always unconfigured; it now checks the actual build inputs.
A preliminary YARA-X check of the prior self-owned APK found 0 matches in 1
benign APK. This is not a representative false-positive estimate; real-malware
recall remains unmeasured. Continue from the latest PR head, inspect failed job
logs once, fix the cause, then fetch the exact successful APK and evidence.

Additional checkpoint: PR head `4529c9c` passed packaging and all JVM/lint
checks. Android instrumentation compilation rejected a test's direct protected
onNewIntent call; the test now exercises the real singleTop Activity entry
through startActivity. Android 8+ broadcast delivery restrictions prompted the
addition of dynamic registration and an opt-in periodic delta-inventory
fallback. Final Android checks must be read from the latest PR head.

Android checkpoint at `41d06af`: 11/12 Android tests passed, including actual
ARM64 rule controls, large files, signed HTTPS updates, privacy, DNS controls
and package scanning. The shared-file test exposed a stale page number (4,
while scan tools are page 10); fixed using a shared SCAN_TOOLS_PAGE constant.
Its harness now delivers onNewIntent through Instrumentation to the owned
Activity instead of opening another task. Packaging at this checkpoint failed
on transient Maven dependency lookup, while JVM/lint checks passed. Recheck
all results on the final PR head; do not treat this checkpoint as acceptance.

Final share-test harness diagnosis: AndroidX ActivityScenario filters lifecycle
callbacks by the Activity's launch Intent. Kanaf's correct onNewIntent/setIntent
handling changes that identity, hiding teardown transitions. The test now
restores the original launch Intent in finally, keeping all share/report
assertions and exposing any actual failure instead of masking it at teardown.
Source verified in android/android-test ActivityScenario.activityMatchesIntent.
Export diagnostics also include engine versions, signed feed digest and pinned
native rule digests; the health panel keeps the large digests out of normal UI.
