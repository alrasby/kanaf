#!/usr/bin/env bash
# Run ONLY on the publisher's own trusted interactive machine.
# The private signing key must never be created by public CI, uploaded to
# ChatGPT, or committed to source control.
set -euo pipefail
umask 077

purpose="${1:-}"
case "$purpose" in
  play-upload|direct-app) ;;
  *) echo "Usage: KANAF_SIGNER_PRIVATE_DIR=/absolute/off-repo/path bash tools/create_owner_signing_key.sh play-upload|direct-app" >&2; exit 2 ;;
esac
if [[ ! -t 0 || ! -t 1 ]]; then
  echo "KANAF_KEY_CREATION_BLOCKED: requires owner's interactive terminal" >&2
  exit 2
fi
command -v keytool >/dev/null || { echo "JDK keytool unavailable" >&2; exit 2; }
owner_dir="${KANAF_SIGNER_PRIVATE_DIR:-}"
if [[ "$owner_dir" != /* ]]; then
  echo "KANAF_KEY_CREATION_BLOCKED: set absolute KANAF_SIGNER_PRIVATE_DIR outside repository" >&2
  exit 2
fi
mkdir -p -- "$owner_dir"
owner_dir="$(cd -- "$owner_dir" && pwd -P)"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
if [[ "$owner_dir" == "$root" || "$owner_dir" == "$root/"* ]]; then
  echo "KANAF_KEY_CREATION_BLOCKED: private keys must be outside Git checkout" >&2
  exit 2
fi
chmod 700 "$owner_dir"
key_path="$owner_dir/kanaf-$purpose.p12"
if [[ -e "$key_path" || -L "$key_path" ]]; then
  echo "KANAF_KEY_CREATION_BLOCKED: refusing to overwrite any existing key" >&2
  exit 2
fi
alias_name="kanaf-$purpose"
echo "Creating owner-controlled $purpose identity. Enter a STRONG password interactively."
echo "The password and private key will not appear in logs or command-line arguments."
keytool -genkeypair \
  -storetype PKCS12 \
  -keystore "$key_path" \
  -alias "$alias_name" \
  -keyalg RSA -keysize 3072 -validity 12000 \
  -dname "CN=Kanaf Publisher" -noprompt
chmod 600 "$key_path"
echo "KEY CREATED LOCALLY (NOT AN APPROVED RELEASE): $key_path"
echo "Alias: $alias_name"
echo "Store an encrypted offline backup and its password separately."
echo "For Play App Signing, this play-upload identity is NOT the Google app-signing identity."
echo "To inspect the PUBLIC SHA-256 certificate locally:"
echo "keytool -list -v -keystore '$key_path' -alias '$alias_name'"
