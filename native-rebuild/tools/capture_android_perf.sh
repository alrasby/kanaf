#!/usr/bin/env bash
# On-device performance evidence only; no upload, no global battery reset.
set -euo pipefail
umask 077
mode="snapshot"
if [[ $# -gt 0 ]]; then mode="$1"; fi
if [[ "$mode" != start && "$mode" != snapshot && "$mode" != finish ]]; then
  echo "Usage: capture_android_perf.sh start|snapshot|finish" >&2
  exit 2
fi
command -v adb >/dev/null || { echo "Android adb unavailable" >&2; exit 2; }
adb_kanaf() {
  if [[ -v KANAF_ADB_SERIAL && -n "$KANAF_ADB_SERIAL" ]]; then
    adb -s "$KANAF_ADB_SERIAL" "$@"
  else
    adb "$@"
  fi
}
package_name="com.kanaf.alrasby"
adb_kanaf wait-for-device
if ! adb_kanaf shell pm list packages "$package_name" |
    grep -Fx "package:$package_name" >/dev/null; then
  echo "Kanaf is not installed on this Android device" >&2
  exit 2
fi
output="$PWD/kanaf-device-perf"
if [[ -v KANAF_PROFILE_DIR && -n "$KANAF_PROFILE_DIR" ]]; then
  output="$KANAF_PROFILE_DIR"
fi
dir="$output/$(date -u +%Y%m%dT%H%M%SZ)-$mode"
mkdir -p "$dir"
printf 'utc=%s\nmode=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$mode" > "$dir/metadata.txt"
adb_kanaf shell getprop ro.product.model >> "$dir/metadata.txt"
adb_kanaf shell getprop ro.product.cpu.abi >> "$dir/metadata.txt"
adb_kanaf shell getconf PAGESIZE >> "$dir/metadata.txt"
adb_kanaf shell dumpsys meminfo "$package_name" > "$dir/meminfo-main.txt"
adb_kanaf shell dumpsys meminfo "$package_name:scanner" > "$dir/meminfo-scanner.txt"
adb_kanaf shell dumpsys procstats --hours 1 "$package_name" > "$dir/procstats.txt"
adb_kanaf shell dumpsys cpuinfo | grep -F "$package_name" > "$dir/cpu-kanaf.txt" || true
adb_kanaf shell dumpsys batterystats --charged "$package_name" > "$dir/batterystats.txt"
adb_kanaf shell dumpsys gfxinfo "$package_name" > "$dir/gfxinfo.txt"
echo "Saved private device measurements locally at: $dir"
echo "Do not upload raw system diagnostics. Compare matched workloads, devices and time windows."
