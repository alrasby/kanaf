# Frozen external Android detection pilot — 19 November 2026

Status: host baseline completed; Android runtime evidence is recorded separately.
This is **not production certification**. No production source, rules, or keys
were changed to improve this test set.

## Why the definitions are narrow

At application revision `4cb2ea8366a6a39def42a33c0104dc144d905d46`,
ClamAV receives 30 ESET Android exact-file SHA-256 signatures (17 SpyLoan,
13 VajraSpy), not the full ClamAV distribution database. YARA-X has the same
30 exact hashes and three Linux ELF content rules (ESET Moose 1/2 and
ReversingLabs AcidRain). YARA-X scans raw input bytes, not decompressed APK
members. Consequently these are real, licensed research definitions with
extremely limited Android coverage. Engine readiness and signed updates prove
execution/authenticity; they do not prove broad detection effectiveness.

## Frozen external corpus

- 60 collector-labelled malware files, selected across 30 directories from
  [ashishb/android-malware](https://github.com/ashishb/android-malware), pinned
  commit `3097faef00fb38afaf4bb90e25167907047ec607`.
- 60 reference-benign APKs, 4 each across 15 F-Droid categories. Original
  catalogue SHA-256 and length checked; ARM64/universal versions within 64 MiB.
  F-Droid catalogue index SHA-256:
  `a5cc6e3426041cdb1f488997b2726e2b236b83169c398aa65ac299478fc919a8`.
- 120 unique files, 921,580,412 bytes; no acquisition failures, duplicate files,
  conflicting reference labels, or exact-hash overlap with bundled definitions.
- Selection plan saved before detection, including seed, source versions,
  category choices and file-size ceiling. No thresholds/rules changed after
  reading test outcomes. The exact list, hashes and URLs are committed in
  `corpus-manifest.json`; **no sample bytes are committed or uploaded**.
- Labels come from the external collector/catalogue; we did **not** independently
  adjudicate them. F-Droid publication is not proof of harmlessness. The malware
  is largely historical, category and source proportions are chosen rather than
  population-derived, and files over 64 MiB are excluded. Independence from rule
  construction does not make this representative of current Android threats.

Structural audit (not outcome-based filtering): only 114/120 files are APK ZIPs
containing AndroidManifest.xml. Three collector files are raw DEX and three
`farseer/*.apk` files actually have valid Windows PE headers. They remain in
the frozen 120-file experiment, but **must be excluded from Android APK recall**.
The primary APK subset is therefore **54 collector-labelled malware APKs from
28 directories and 60 reference-benign APKs**. The other 6 are auxiliary file
tests. `file-type-audit.json` and `host-apk-summary.json` document this correction;
no replacement samples were chosen after viewing results.

## Completed host results

Linux x86_64 ClamAV **1.4.6**, YARA-X **0.13.0**; frozen shipped rule assets.
The C API helper reuses the app's policy header: 64 MiB per file, 128 MiB
aggregate, 512 contained files, depth 8, 20-second native timeout, identical
archive flags and AC-only configuration. C parser network/exec syscalls denied,
filesystem read-only except private per-scan temporary directory. There is an
additional 1 GiB host process cap. YARA scans the raw input with a 20-second
limit. The app's harmless EICAR diagnostics are not included as malware evidence.
The host helper uses the bundled production HSB/YARA assets; app-side signed-feed
bootstrap, JNI/IPC, diagnostic rules and ARM64 execution are tested separately.

| Engine | Reference label | Matched | No known match | Incomplete |
|---|---|---:|---:|---:|
| clamav | malicious | 0 | 47 | 13 |
| clamav | benign | 0 | 17 | 43 |
| yara_x | malicious | 0 | 60 | 0 |
| yara_x | benign | 0 | 60 | 0 |

ClamAV: 0/47 completed malware inputs detected; 13 malware scans incomplete.
0 false alarms among 17 completed reference-benign inputs; 43 benign scans
incomplete. All 56 incomplete results reported `clamav-resource-limit`, never
malware or clean. APK archive complexity is material: e.g. a 3.94 MB-unpacked
reference app has 911 ZIP entries, exceeding the 512-file envelope. The generic
native error does not identify which specific configured limit fired in every
case. Do not equate resource failures with either false positives or true
negatives.

YARA-X: 0/60 malware detected, 0/60 reference-benign alarms; all inputs complete.
On the primary **APK-only** subset: ClamAV detected **0/41** completed malware
APKs, with **13/54 incomplete**; YARA-X detected **0/54**, all complete. Both
engines had zero observed reference-benign alerts, with the ClamAV completion
limitations above. The 6 auxiliary DEX/PE files had no matches in either engine.
These are rates for this corpus, not universal accuracy. Zero false alarms
here does not establish production specificity: the illustrative Wilson 95%
upper bound is 6.02% for 0/60 and 18.43% for 0/17. Nonrandom/reference labels
limit population interpretation of these intervals.

Positive/negative harmless SHA controls verify that the host ClamAV matcher
actually detects a known matching definition and rejects a changed input.
Six evaluation integrity tests cover incomplete denominators, undefined rates,
uncertainty, hash disjointness and rejection of duplicate/partial reports.

## Reproduction and evidence

`host-results.json` contains per-file SHA-256 outcomes and definition/policy
hashes; `host-controls.json` records control outcomes. `measure_host.py` and
`clam_probe.cpp` reproduce the Linux baseline (requires yara-x==0.13.0,
Bubblewrap, g++ and official ClamAV 1.4.6 shared libraries). Official release:
https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6

Official Linux .deb SHA-256, checked against GitHub release metadata:
`d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2`.

The dedicated `kanaf-independent-benchmark.yml` workflow builds the trusted app
and instrumentation APK only, transfers samples as non-executable `.sample`
data into app-private storage, disables emulator Wi-Fi/data, requires the real
ARM64 engine self-test, and scans all 120 with `NativeScannerBridge` plus the
signed hash engine. A passing instrumentation run denotes a complete valid
measurement, **not** a minimum detection score. Only JSON/log evidence is
uploaded. The raw corpus never becomes an APK asset or artifact.

## Release decision and next gates

**Do not approve the current malware detection as comprehensive protection.**
The immediate gaps are Android content/family coverage and bounded APK parsing
coverage, not cosmetic polish. Expand rules on a separate development set with
file provenance, redistribution licence, independently reviewed predicates and
positive/near-miss controls. Add bounded APK member analysis and tune parser
limits from measured RAM/time evidence. Preserve this baseline, then select a
new untouched holdout with independently adjudicated labels, newer malware,
multiple benign channels (including signed commercial/system apps), separate
riskware/PUA classes, and family/temporal/source diversity. Measure cold/warm
scans, memory, time, power and failure coverage on physical ARM64 devices.

[AndroZoo](https://androzoo.uni.lu/access) requires an institutional research
application/personal API key and restricts commercial use; access was not
available or assumed. [CICMalDroid2020](https://www.unb.ca/cic/datasets/maldroid-2020.html)
is historical 2017–2018 data and its download path requires registration;
no fabricated identity or unauthorised registration was submitted. Public
availability of corpus bytes is not a redistribution licence or permission to
ship those bytes in an app. Full ClamAV standard databases require separate
mobile resource/licensing testing; official documentation recommends at least
3 GiB RAM for their standard deployment, not a measured Kanaf device requirement.
