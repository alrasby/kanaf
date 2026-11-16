#!/usr/bin/env bash
# Owner-operated release signing; NEVER runs on untrusted public PR builds.
# Stage 1 builds signed *candidates*. Stage 2 verifies independently tested
# exact artifact bytes against a separate signed QA report.
set -euo pipefail
umask 077

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

action="${1:-status}"
channel="${KANAF_RELEASE_DISTRIBUTION:-play}"
if [[ "$channel" != play && "$channel" != direct ]]; then
  echo "KANAF_RELEASE_BLOCKED: distribution must be play or direct" >&2
  exit 2
fi

case "$action" in
  status)
    python3 tools/release_input_inventory.py --distribution "$channel"
    ;;
  build)
    # Do not allow Gradle or signing to run at all if key materials and
    # independently audited production input files are not present.
    python3 tools/release_input_inventory.py --distribution "$channel" --strict
    export ORG_GRADLE_PROJECT_kanafReleaseDistribution="$channel"
    if [[ "$channel" == play ]]; then
      export ORG_GRADLE_PROJECT_kanafPlayDnsSecurityOnly=true
    else
      export ORG_GRADLE_PROJECT_kanafPlayDnsSecurityOnly=false
    fi
    if [[ -z "${ANDROID_HOME:-}" || ! -x "$ANDROID_HOME/build-tools/35.0.0/apksigner" ]]; then
      echo "KANAF_RELEASE_BLOCKED: trusted Android SDK apksigner 35.0.0 is required" >&2
      exit 2
    fi
    command -v jarsigner >/dev/null ||
      { echo "KANAF_RELEASE_BLOCKED: jarsigner unavailable" >&2; exit 2; }
    export PATH="$ANDROID_HOME/build-tools/35.0.0:$PATH"
    for so in libclamav.so libclammspack.so libyara_x_capi.so; do
      python3 tools/verify_arm64_elf.py --require-16kb \
        "app/src/main/jniLibs/arm64-v8a/$so"
    done
    bash tools/gradle_retry_429.sh --no-daemon \
      :app:verifyKanafProductionInputs :app:assembleRelease :app:bundleRelease
    apk="app/build/outputs/apk/release/app-release.apk"
    aab="app/build/outputs/bundle/release/app-release.aab"
    [[ -s "$apk" && -s "$aab" ]] ||
      { echo "KANAF_RELEASE_BLOCKED: missing signed APK/AAB" >&2; exit 2; }
    apksigner verify --min-sdk-version 26 --verbose --print-certs "$apk" >/dev/null
    jarsigner -verify -strict "$aab" >/dev/null
    sha256sum "$apk" "$aab"
    echo "SIGNED CANDIDATES ONLY: conduct real ARM64 hardware QA and obtain a separately signed final evidence report."
    ;;
  verify)
    : "${KANAF_QA_RELEASE_EVIDENCE:?independent hardware/model/Play evidence JSON required}"
    : "${KANAF_QA_RELEASE_SIGNATURE:?independent final QA signature required}"
    : "${KANAF_QA_PUBLIC_KEY_DER:?independently pinned QA public DER key required}"
    : "${KANAF_TRUSTED_QA_PUBLIC_KEY_DER_SHA256:?out-of-band QA key SHA-256 required}"
    if [[ -z "${ANDROID_HOME:-}" || ! -x "$ANDROID_HOME/build-tools/35.0.0/apksigner" ]]; then
      echo "KANAF_RELEASE_BLOCKED: apksigner 35.0.0 unavailable" >&2
      exit 2
    fi
    export PATH="$ANDROID_HOME/build-tools/35.0.0:$PATH"
    python3 tools/check_release_readiness.py \
      --evidence "$KANAF_QA_RELEASE_EVIDENCE" \
      --signature "$KANAF_QA_RELEASE_SIGNATURE" \
      --qa-public-key "$KANAF_QA_PUBLIC_KEY_DER" \
      --expected-qa-public-key-sha256 "$KANAF_TRUSTED_QA_PUBLIC_KEY_DER_SHA256" \
      --apk "app/build/outputs/apk/release/app-release.apk" \
      --aab "app/build/outputs/bundle/release/app-release.aab"
    ;;
  *)
    echo "Usage: tools/build_approved_release.sh [status|build|verify]" >&2
    exit 2
    ;;
esac
