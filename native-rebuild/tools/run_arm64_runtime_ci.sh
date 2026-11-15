#!/usr/bin/env bash
set -euo pipefail

# Emulator runner executes its script via /bin/sh. Invoke this file through bash.
# Never mark an ARM64 test as passing when this emulator lacks ARM translation.
abi="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
echo "Android emulator advertised ABIs: $abi"
if ! [[ ",$abi," == *",arm64-v8a,"* ]]; then
  echo "::error::ARM64 translation unavailable; no runtime detection evidence"
  exit 1
fi

adb logcat -c || true
report_worker_diagnostics() {
  result=$?
  echo "=== ARM64 native engine debug-only self-test diagnostics ==="
  adb logcat -d -s KanafNativeSelfTest:I KanafClamNative:I | tail -n 100 || true
  exit "$result"
}
trap report_worker_diagnostics EXIT

# Retry only external dependency rate limiting, never detection or test failures.
# Keep the same emulator and worktree; Gradle caches successfully fetched modules.
# Each attempt has its own log so an older 429 cannot hide a real later failure.
for attempt in 1 2 3; do
  log="/tmp/kanaf-arm64-gradle-attempt-${attempt}.log"
  if gradle --no-daemon :app:connectedDebugAndroidTest \
    -PkanafArm64Runtime=true \
    -Pandroid.testInstrumentationRunnerArguments.class=com.kanaf.alrasby.NativeArm64EngineRuntimeTest \
    --stacktrace 2>&1 | tee "$log"; then
    exit 0
  fi
  if [[ "$attempt" -ge 3 ]] ||
      ! grep -Eq 'Received status code 429|Too Many Requests' "$log"; then
    echo "::error::Android ARM64 runtime build/test failed for a non-rate-limit reason, or retry budget exhausted"
    exit 1
  fi
  delay=$((attempt * 25))
  echo "::warning::Transient Maven/Gradle HTTP 429; one bounded retry after ${delay}s (attempt ${attempt}/3)"
  sleep "$delay"
done
exit 1
