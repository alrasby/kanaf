#!/usr/bin/env bash
set -euo pipefail

abis="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
[[ ",$abis," == *",arm64-v8a,"* ]]
adb install -t native-rebuild/app/build/outputs/apk/debug/app-debug.apk
adb install -t native-rebuild/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
engine=com.kanaf.alrasby.NativeArm64EngineRuntimeTest
ipc=com.kanaf.alrasby.NativeScannerProcessIntegrationTest
scan=com.kanaf.alrasby.AutomaticDeviceScanAndroidTest
test_app_id="${KANAF_TEST_APP_ID:-com.kanaf.alrasby.fulltest}"
tests="$engine#bothActualArm64EnginesPassEicarSelfTestThroughWorkerIpc,$engine#officialClamAvCompletesSeventyMiBAndYaraReportsItsOwnLimit,$engine#officialClamAvScansCompressedEntriesInApkShapedArchive,$engine#realYaraContentRuleRunsOnHarmlessControlAndRejectsNearMiss,$ipc#workerDeathFailsClosedAndNextScanRecovers,$scan#activeDeviceScanKeepsItsOwnerAfterActivityRecreation,$scan#interruptionReportRestoresLastPhaseCounterAndOriginalBuild"
adb shell am instrument -w -r -e class "$tests" \
  "${test_app_id}.test/androidx.test.runner.AndroidJUnitRunner" | tee android-runtime.txt
grep -Eq 'OK \(7 tests\)' android-runtime.txt
! grep -Eq 'FAILURES|INSTRUMENTATION_FAILED' android-runtime.txt
