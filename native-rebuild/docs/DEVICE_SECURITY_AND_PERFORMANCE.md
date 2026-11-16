# Kanaf — device security, memory and battery test evidence

Static review on 2026-11-16: MainActivity uses Compose rememberCoroutineScope
and an Activity LifecycleEventObserver removed in DisposableEffect.onDispose.
The native scanner IPC client unbinds its ServiceConnection in finally.
KanafDnsVpnService unregisters its ContentObserver and closes its VPN interface,
reader and bounded worker executor in onDestroy. These are lifecycle safeguards,
NOT proof that the app has no retained objects or native memory leaks.

**PlaybackService is not present in the Kanaf repository branch.** A
PlaybackService leak can only be inspected in the app containing that class.
ScopedDeviceScan previously continued after ON_STOP. It now receives a
session-aware cancellation callback and does not start further work after
cancellation. An already-active native IPC can still finish or time out.

## Run a private physical-device performance session

Install the **same signed APK** under review on an actual ARM64 phone.
Record its SHA-256 and Android version separately before measurement.

1. Connect owner-controlled Android phone with ADB enabled.
2. Run: KANAF_ADB_SERIAL=DEVICE bash tools/capture_android_perf.sh start
3. Open/close the app 20 times, scan apps and permitted Downloads, run DNS on/off,
   try Wi-Fi and cellular, and repeat in Arabic and English.
4. Run: KANAF_ADB_SERIAL=DEVICE bash tools/capture_android_perf.sh snapshot
5. After an ordinary 24-hour use period including idle, run:
   KANAF_ADB_SERIAL=DEVICE bash tools/capture_android_perf.sh finish

Each command records process PSS, native and Java heap, procstats, CPU use,
app battery estimates and frame stats under private local-only output folders.
No global battery statistics are reset; no report is uploaded. Retest on at
least two different ARM64 phones, including a device with 16KiB pages if
possible. Use Android Studio Memory Profiler and Perfetto for heap retaining
paths and thread leaks; one meminfo sample cannot prove no leak.
Review DoH-only VPN route/packet leakage separately with physical capture.

Current source manifest requests Internet, network state, package visibility,
optional broad storage, legacy read <= API32, notification and foreground
service permissions. It does NOT request camera, microphone, contacts,
geolocation, accessibility, overlay, SMS or device administration. Broad
package/storage permissions implement core scanning; removing them without
changing approved features would silently disable requested coverage.
Source manifest permission/export/backup/cleartext checks run in CI; a merged
signed manifest still needs final verification.

On-device detection remains incomplete without independently audited signed
production signatures and externally evaluated Kanaf AI weights. SHA-256 on a
photo or document is a REAL hash, but by itself is not deep visual or document
malware detection. Android inaccessible/private data is out of reach.

Android references:
https://developer.android.com/topic/performance/measuring-performance
https://developer.android.com/tools/dumpsys
https://developer.android.com/topic/performance/memory/guide/service-bindings
