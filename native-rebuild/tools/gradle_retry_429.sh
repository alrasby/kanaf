#!/usr/bin/env bash
set -euo pipefail

# Bounded retry ONLY for remote Maven HTTP 429, not failed Kotlin/tests.
# Per-attempt logs prevent an old 429 from hiding a new actual failure.
if [[ "$#" -lt 1 ]]; then
  echo "Usage: gradle_retry_429.sh <gradle arguments>" >&2
  exit 2
fi
for attempt in 1 2 3; do
  log="$(mktemp "${TMPDIR:-/tmp}/kanaf-gradle-429.XXXXXX")"
  if gradle "$@" 2>&1 | tee "$log"; then
    rm -f "$log"
    exit 0
  fi
  if [[ "$attempt" -ge 3 ]] ||
    ! grep -Eq 'Received status code 429|Too Many Requests' "$log"; then
    rm -f "$log"
    echo "::error::Gradle failed for a non-rate-limit reason or the retry budget expired" >&2
    exit 1
  fi
  rm -f "$log"
  delay=$((attempt * 20))
  echo "::warning::Transient Maven HTTP 429; bounded retry ${attempt}/2 after ${delay}s" >&2
  sleep "$delay"
done
exit 1
