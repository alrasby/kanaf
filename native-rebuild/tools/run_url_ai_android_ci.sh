#!/usr/bin/env bash
set -euo pipefail
test -n "${KANAF_URL_KEY:-}" || { echo "missing signed URL-model public key"; exit 1; }
gradle --no-daemon :app:connectedDebugAndroidTest \
  -PkanafUrlModelPublicKeyBase64="$KANAF_URL_KEY" \
  -Pandroid.testInstrumentationRunnerArguments.class=com.kanaf.alrasby.KanafUrlAiAndroidTest,com.kanaf.alrasby.KanafUiNavigationTest,com.kanaf.alrasby.KanafAiIntegrationAndroidTest,com.kanaf.alrasby.RealApkPipelineAndroidTest \
  --stacktrace
