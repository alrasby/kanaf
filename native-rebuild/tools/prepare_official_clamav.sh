#!/usr/bin/env bash
# Prepare a Gradle assets root from the official FreshClam updater.
set -euo pipefail
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 /absolute/path/to/clamav-assets" >&2
    exit 2
fi

mkdir -p "$1/official-clamav"
assets_root="$(cd "$1" && pwd)"
config="$(mktemp)"
updater_dir="$(mktemp -d)"
trap 'rm -f "$config"; rm -rf "$updater_dir"' EXIT

# Preserve only original signed CVD archives. A local CLD is a different format.
printf 'DatabaseDirectory "%s"\nDatabaseMirror database.clamav.net\nScriptedUpdates no\n' "$updater_dir" > "$config"
freshclam --config-file="$config"
for name in main daily bytecode; do
    info="$(LC_ALL=C sigtool --info "$updater_dir/$name.cvd")"
    printf '%s\n' "$info"
    grep -Fxq 'Verification OK.' <<< "$info"
    cp "$updater_dir/$name.cvd" "$assets_root/official-clamav/$name.cvd"
done
