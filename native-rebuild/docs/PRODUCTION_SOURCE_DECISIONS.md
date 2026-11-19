# Kanaf production-source and physical-device acceptance decisions

Prepared 16 November 2026. None of these sources are pre-approved as an
effective production antivirus feed merely because they can be downloaded.

## 1. Rights-cleared YARA subset

Candidate: https://github.com/Neo23x0/signature-base
Upstream default license is Detection Rule License (DRL) 1.1:
https://github.com/Neo23x0/signature-base/blob/master/LICENSE
It permits modification and redistribution, but mandates rule author
attribution both in distributed rules AND detection outputs; individual
rule metadata may specify stricter or different terms.

Publisher acceptance checklist:
- Pin the exact upstream Git commit and record the raw rule SHA-256.
- Review each selected rule license and its author/source metadata.
- Exclude any rule without sufficient permission or whose dependencies
  cannot be built by the pinned YARA-X runtime.
- Compile against the actual YARA-X 0.13.0 ARM64 engine and validate
  independent benign/APK test sets. An EICAR match is NOT a malware
  effectiveness result.
- Implement author attribution in the app result display before enabling
  rules subject to DRL.
- Sign the published rule bundle, review false positives, version and
  rollback-protect it. Do NOT silently label every ad domain as malware.

## 2. ClamAV and mobile memory

Official engine: https://github.com/Cisco-Talos/clamav (GPLv2 software;
publisher must review source-distribution obligations for its Android app).
Official databases and freshclam:
https://docs.clamav.net/manual/Signatures.html
Private mirrors: https://docs.clamav.net/appendix/CvdPrivateMirror.html

The currently bundled Android bridge accepts a limited pinned
production_clamav.hsb, NOT a full standard CVD database. The complete
CVD format can include many rule types and ClamAV's full-size standard
database commonly requires multiple GiB of memory. Never replace the
bridge with a full database or unpack random unsigned bytecode on device
without first proving license, resource and security viability.
Confirm official signature redistribution rights separately from the
engine's GPLv2 license; do not assume one automatically governs the other.

## 3. APK threat AI: training is not sufficient

University of New Brunswick's CCCS-CIC-AndMal-2020 source:
https://www.unb.ca/cic/datasets/andmal2020.html
The dataset states redistribution is permitted with required citations.
However, many features are dynamic observations (API/network/battery/logcat)
requiring a running app. Kanaf's present on-device Android APK scanner
primarily extracts ZIP/DEX/manifest structure. Training on unavailable
features would make the reported accuracy meaningless at inference time.

Before adopting weights, align the training and inference feature schemas,
obtain a legally usable independent external holdout (not synthetic tests),
deduplicate package-family and near-identical variants, split by time and
publisher to reduce leakage, report per-family recall, false positives,
ROC-AUC and calibration, and measure model latency/RAM/battery on ARM64.
Document corpus dates, sample hashes, labels, licenses and provenance.
No weights may pass release validation without independent evidence.

## 4. Physical-device acceptance: preserve exact signed bytes

Firebase Test Lab: https://firebase.google.com/docs/test-lab
Supports real physical Android devices, gcloud/CI integration and
instrumentation. Current documented physical instrumentation cap is
45 minutes: https://firebase.google.com/docs/test-lab/android/instrumentation-test
It cannot alone replace a real 24-hour sustained battery test.

AWS Device Farm: https://docs.aws.amazon.com/devicefarm/latest/developerguide/
Offers real devices but AWS docs say it re-signs Android apps and devices
do not have cellular carriers. If a provider changes the APK signing
certificate or bytes, its result MUST NOT claim validation of the original
release SHA-256. Hardware QA of the original signed APK and real
Wi-Fi-to-cellular handoff remains necessary.

## 5. Owner-controlled private signing key (not stored in Git)

Run exclusively on a trusted publisher-controlled Linux/macOS terminal:
```sh
cd native-rebuild
KANAF_SIGNER_PRIVATE_DIR=/absolute/path/outside/repository \
  bash tools/create_owner_signing_key.sh play-upload
```
The script prompts for a password (no command-line or repository secrets),
will not overwrite a key or generate one in CI, and outputs only a local
PKCS12 file. A separate `direct-app` purpose may be selected, but beware:
if Play App Signing uses a different app-signing certificate from direct
distribution under the SAME package name, users cannot install one APK
over the other as a normal update. Set a cross-store identity strategy
BEFORE publishing. Never disclose the private key or password in chat.

Google documentation:
https://developer.android.com/studio/publish/app-signing

## 6. Final gates that cannot be self-certified

- No source rule admission until licensing, false positives, compat,
  upstream hash and output attribution have been reviewed.
- No AI claims until the independent holdout and matching runtime feature
  extractor can be reproduced; do not rely on in-sample accuracy.
- No signed Release without publisher key and independent QA.
- No 24-hour battery or exact signed-byte VPN claim from a short cloud test.
- A retained Draft PR and successful CI are NOT product certification.
