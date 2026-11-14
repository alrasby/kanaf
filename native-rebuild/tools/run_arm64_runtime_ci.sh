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

gradle --no-daemon :app:connectedDebugAndroidTest \
  -PkanafArm64Runtime=true \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kanaf.alrasby.NativeArm64EngineRuntimeTest \
  --stacktrace
