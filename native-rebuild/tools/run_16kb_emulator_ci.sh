#!/usr/bin/env bash
set -euo pipefail

# This fails if the runner silently uses a normal 4 KiB Android image.
pages="$(adb shell getconf PAGE_SIZE | tr -d '\r\n')"
echo "Emulator kernel memory page size = $pages"
if [[ "$pages" != "16384" ]]; then
  echo "::error::Not running on a real 16 KiB-page Android system image"
  exit 1
fi

sdkmanager "platforms;android-36" "build-tools;35.0.0" "ndk;27.2.12479018" "cmake;3.22.1"
gradle --no-daemon :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kanaf.alrasby.RealApkPipelineAndroidTest,com.kanaf.alrasby.VaultAndroidKeyStoreTest,com.kanaf.alrasby.KanafAiIntegrationAndroidTest,com.kanaf.alrasby.DnsFilterAndroidTest \
  --stacktrace

apk=app/build/outputs/apk/debug/app-debug.apk
test -s "$apk"
"$ANDROID_HOME/build-tools/35.0.0/zipalign" -c -P 16 -v 4 "$apk"
test "$(adb shell getconf PAGE_SIZE | tr -d '\r\n')" = 16384
echo "Passed real 16 KiB page-size emulator integration; native ClamAV ARM64 requires a separate ARM64 runtime test."
