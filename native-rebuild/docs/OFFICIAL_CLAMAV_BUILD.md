# Building the full ClamAV edition

Prepare the official database using Cisco Talos FreshClam 1.4.6 or a compatible current updater, with `sigtool` on the same path. Use a directory outside the checkout. The audited Android engine version remains 1.4.6.

```sh
tools/prepare_official_clamav.sh /absolute/path/to/clamav-assets
gradle :app:assembleDebug :app:testDebugUnitTest \
  -PkanafOfficialClamAssets=/absolute/path/to/clamav-assets \
  -PkanafArm64Runtime=true
```

Provide the project's verified ARM64 ClamAV, supporting library, and YARA-X binaries as described in the native packaging workflow. The Gradle property adds all three unmodified Cisco files. The resulting test app has package ID `com.kanaf.alrasby.fulltest` and can be installed alongside the previous build. An ordinary build that omits this property continues to package the local research rules. Updating the bundled official database requires a new build. The independent publisher-signed exact-file feed continues to work. Native rules use the expanded binary baseline with feed version 1 and honor a trusted version 2 or newer as the current exact-file set.

The scanner verifies the packaged digests and the upstream CVD signatures before compiling the database in the separate scanner process. Source and distribution terms for ClamAV are available from Cisco Talos at https://github.com/Cisco-Talos/clamav/tree/clamav-1.4.6 and https://docs.clamav.net/faq/faq-cvd.html. The full edition accepts inputs up to 256 MiB and keeps a separate 384 MiB aggregate ClamAV scan budget. Files above 64 MiB get up to 90 seconds of ClamAV scan time, with a separate process deadline. YARA-X reports its own 64 MiB input limit. A match from another engine remains actionable, while a partial scan without any match remains incomplete. Exact-file Android indicators cover only the identified file bytes. Sources and licenses are recorded in `app/src/main/assets/native_rules_provenance.json`.

The full engine requires at least 3 GiB total RAM and 1,200 MiB available when first initialized. Low-memory and worker-exit outcomes remain incomplete when local signatures do not match. A whole-device run continues with local rules after a scanner crash or timeout. The checkpoint stores only the attempted count. It supports reporting an interrupted session after process exit, and the next manual start begins a new scan.

Hardware acceptance should cover the original APK, a large accessible shared folder, navigation and Activity recreation, screen-off behavior, cold and warm ClamAV memory and latency, and an independent Android corpus. The bundled harmless EICAR sample verifies execution.
