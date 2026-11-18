# Real Android 16 KiB memory-page integration

This workflow uses Google's experimental Android 15 `google_apis_ps16k`
**x86_64** emulator image and fails unless `adb shell getconf PAGE_SIZE`
returns **16384**. It runs actual app package APK/ZIP/DEX inspection,
fixture-only structural Kanaf AI, Android Keystore GCM, and IPv4/IPv6 DNS
packet tests; also validates APK ZIP alignment via `zipalign -c -P 16`.

This is **not** evidence of native ClamAV/YARA-X on an ARM64 kernel with
16 KiB pages: the tested image is x86_64, and those libraries remain ARM64.
The distinct ARM64 translated runtime CI covers actual scanners but on the
host emulator's page size. Physical ARM64/16 KiB validation is still required
for release readiness. No real network DNS/VPN consent is tested here.
