# Kanaf — Google Play policy review / مراجعة النشر (16 November 2026)

**Decision: NOT READY FOR PLAY SUBMISSION OR PUBLIC CLAIMS OF COMPLETE ANTIVIRUS.**
This document records evidence requirements; it is **not a Play approval**.

## Findings (from actual Android manifest/code)

- `targetSdk=36`, `minSdk=26`: satisfies Play's phone target API threshold
  effective 31 Aug 2026. Device compatibility and 16 KiB physical runtime
  still require final signed artifacts and hardware tests.
- `QUERY_ALL_PACKAGES`: broad installed-app access, a potentially permitted
  antivirus use case but subject to the *Permissions Declaration Form*,
  necessity demonstration, user-data transparency and Play review. Do not
  re-use installed-app inventory for analytics, ads, profiling or resale.
- `MANAGE_EXTERNAL_STORAGE`: potentially permitted for an actual antivirus
  whose **core** purpose requires all-files access. Kanaf already offers
  SAF-selected files/folders. Prove with a filmed device test why those
  privacy-friendly alternatives cannot serve the specific full-storage scan,
  and exactly which shared files Android allows. Otherwise remove the broad
  permission in the Play build **only after product approval**. It cannot read
  protected apps' private storage.
- `VpnService` + `specialUse` foreground service: needs Play Console
  declarations, user-facing disclosure **before** Android VPN consent (also
  through Quick Settings), affirmative opt-in, a short functionality video,
  and correct explanation of the actual DNS-only local VPN. DNS queries
  forwarded to selected AdGuard DNS over TLS/HTTPS are received by that
  **independent provider**, which may see domains and connecting IP addresses.
  The app cannot promise the provider logs nothing.
- **HIGH BLOCKER: cross-app ad blocking**. The current local DNS blocklist
  and AdGuard DNS upstream can interfere with ads served by OTHER applications.
  Google's Device and Network Abuse rules explicitly list this kind of
  behavior as a violation example. VPN eligibility for device-security apps
  does **not** automatically override this restriction. Do NOT assert Play
  compliance while that behavior remains. Resolution requires review of
  actual traffic/filter semantics and a compliant product decision (e.g.
  change the Play-distributed implementation to security-only DNS filtering),
  with written reviewer/legal/Play confirmation as appropriate. Keep all
  existing features in the development/non-Play build until product approval;
  do not silently remove them or mislabel ads as malware.
- `POST_NOTIFICATIONS` and user-initiated 24h-scoped scans: check Android 13+
  notification consent, opt-out, cancellation, and foreground-service
  usage on physical devices.
- AI: offline URL and structural APK models are **advisory**. No claim of
  continuous surveillance, comprehensive malware protection or independent
  model accuracy without signed weights, original validated data, and external
  QA. Do not call unresolved scans "safe."
- ClamAV libclamav uses **GPLv2**; linking, source availability, notices and
  any redistribution obligations require specialist review. YARA-X
  BSD-3-Clause notice/redistribution obligations also apply. ClamAV
  Talos CVD mirrors/feeds have separate operational and licensing questions;
  neither CVD nor unaudited third-party signatures should be repackaged as an
  approved Kanaf Android feed.

## Mandatory submission work (publisher and independent QA)

1. Resolve the cross-app ad-blocking policy blocker; record the decision and
   examine the **final exact compiled variant** (not only UI strings).
2. Produce a real, licensed, signed, versioned malware feed plus audited
   ClamAV/YARA-X rules; document dataset provenance and false positives.
3. Obtain independently labeled actual APK/benign test data with exact
   7-feature Android extraction parity; train, sign and evaluate a model on
   an untouched external test set. Do not count synthetic fixtures as evidence.
4. Test the **same final SHA-256 signed APK** on ARM64 hardware: engine
   detection, file permissions, app inventory, Android 8–16, background
   workload, reboots, memory and battery, plus 16 KiB page support on hardware.
5. Perform live DNS consent tests from **in-app and Quick Settings**, refusal,
   switching providers, DNS failure/recovery, stop/disconnect as observed from
   Android's VPN state, strict/automatic system DNS, IPv4/IPv6 and 24h battery.
6. Submit QUERY_ALL_PACKAGES / All files / VpnService / foreground specialUse
   declarations with **accurate screenshots and short reviewer-accessible
   demo**, submit Data safety and a publicly accessible privacy-policy URL.
   The in-app text is **not** a substitute for the public policy URL.
7. Sign final APK and AAB with owner-controlled signing keys outside source;
   verify actual bytes, signatures, SHA-256 identity and independent QA
   attestation using `check_release_readiness.py`.
8. For a new **Personal** Play developer account created after 13 Nov 2023,
   complete at least 12 continuously opted-in closed testers for at least
   14 days, then apply for production access. Google may request more testing.
9. Obtain Google Play review outcome. App acceptance cannot be simulated
   through GitHub Actions or signed by an assistant.

### Possible permission declaration wording (requires factual device proof)

- Broad package visibility: "On demand, Kanaf inventories installed
  application packages to identify packages accessible through Android's
  package APIs, then analyzes their APK files locally. No installed-app
  inventory is sold or used for advertising."
- All-files access: "After explicit Android Settings approval, users can
  request a shared-storage security scan. This access does not cover
  protected private app data. We also support scoped SAF file/folder scans."
  Explain why SAF alone does not deliver the declared core full-storage
  use case, using an actual screen recording.
- VPN: "An optional local DNS-only VPN filters DNS queries sent to Kanaf's
  resolver and forwards permitted queries via encrypted HTTPS to the
  user's chosen AdGuard DNS provider. The provider may receive domains
  and connection IP data. The user can stop it and it cannot coexist
  with other VPNs." **Current ad-blocking implementation must be resolved
  before claiming Play eligibility.**

### Required public app privacy policy (NOT YET PUBLISHED)

A publisher-controlled HTTPS webpage, worldwide accessible without login,
must name Kanaf and the publisher, privacy contact, data types accessed,
local processing, third-party DNS forwarding, update-server requests,
retention/deletion, permissions, and any telemetry/SDKs actually enabled.
The Data safety answers must match the **built binary**, not a proposed policy.

## Primary official sources (verified 16 Nov 2026)

- https://support.google.com/googleplay/android-developer/answer/11926878
- https://support.google.com/googleplay/android-developer/answer/10158779
- https://support.google.com/googleplay/android-developer/answer/10467955
- https://support.google.com/googleplay/android-developer/answer/12564964
- https://support.google.com/googleplay/android-developer/answer/16559646
- https://support.google.com/googleplay/android-developer/answer/10144311
- https://support.google.com/googleplay/android-developer/answer/9859455
- https://support.google.com/googleplay/android-developer/answer/14151465
- https://docs.clamav.net/manual/Signatures.html
- https://docs.clamav.net/appendix/CvdPrivateMirror.html
- https://github.com/Cisco-Talos/clamav
- https://github.com/VirusTotal/yara-x/blob/main/LICENSE

**This checklist is not legal advice, does not grant Google Play approval,
and does not substitute for physical-device QA or publisher signatures.**
