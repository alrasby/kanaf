#!/usr/bin/env bash
set -euo pipefail
abi=$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')
[[ ",$abi," == *",arm64-v8a,"* ]] || { echo 'ARM64 translation unavailable'; exit 1; }
cd native-rebuild
feed=rules/eset-android-seed
python3 tools/signed_feed.py verify --zip "$feed/kanaf-feed-v1.zip" --public-key "$feed/feed-public.pem"
public_key=$(openssl pkey -pubin -in "$feed/feed-public.pem" -outform DER | openssl base64 -A)
install -m 644 "$feed/kanaf-feed-v1.zip" app/src/main/assets/production_signatures.zip
gradle --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest -PkanafArm64Runtime=true \
  "-PkanafSignaturePublicKeyBase64=$public_key" -PkanafSignatureMinVersion=1 \
  -PkanafSignatureFeedHttpsUrl=https://raw.githubusercontent.com/alrasby/kanaf/rebuild/kanaf-native-v1/native-rebuild/rules/eset-android-seed/kanaf-feed-v1.zip
adb install -r -t app/build/outputs/apk/debug/app-debug.apk
adb install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
cd ..
adb shell run-as com.kanaf.alrasby mkdir -p files/independent-evaluation
for file in /tmp/kanaf-evaluation-samples/*.sample; do
  adb exec-in run-as com.kanaf.alrasby tee "files/independent-evaluation/$(basename "$file")" < "$file" > /dev/null
done
adb exec-in run-as com.kanaf.alrasby tee files/independent-evaluation/corpus-manifest.json < evaluation/android_baseline/corpus-manifest.json > /dev/null
adb shell svc wifi disable
adb shell svc data disable
mkdir -p /tmp/kanaf-evaluation-reports
# Even a failed test must preserve partial results. No sample data are exported.
set +e
adb shell am instrument -w -r -e class com.kanaf.alrasby.IndependentCorpusAndroidTest \
  -e timeout_msec 1800000 com.kanaf.alrasby.test/androidx.test.runner.AndroidJUnitRunner \
  | tee /tmp/kanaf-evaluation-reports/instrumentation.log
adb exec-out run-as com.kanaf.alrasby cat files/independent-evaluation/android-results.json > /tmp/kanaf-evaluation-reports/android-results.json
set -e
grep -F 'OK (1 test)' /tmp/kanaf-evaluation-reports/instrumentation.log
python3 - <<'PY'
import json
p=json.load(open('/tmp/kanaf-evaluation-reports/android-results.json'))
assert p['complete'] and len(p['cases'])==120 and p['self_test_passed']
assert not p['sample_execution']
PY
python3 evaluation/android_baseline/summarize_results.py /tmp/kanaf-evaluation-reports/android-results.json evaluation/android_baseline/corpus-manifest.json /tmp/kanaf-evaluation-reports/android-summary.json
