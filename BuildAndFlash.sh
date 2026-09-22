#!/bin/bash
# Build, authenticate, install, and read-back verify one local M5Stack release.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly ESP_ENV_FILE="/tmp/export-esp-kassigner.sh"
readonly KEY_PATH_FILE="$SCRIPT_DIR/.release-signing-key-path"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

[ -f "$ESP_ENV_FILE" ] || die "ESP environment is missing: $ESP_ENV_FILE"
[ -f "$KEY_PATH_FILE" ] || die "signing-key path config is missing: $KEY_PATH_FILE"

printf '[setup] Checking the local firmware-signing key...\n'
IFS= read -r SIGNING_KEY < "$KEY_PATH_FILE"
[ -n "$SIGNING_KEY" ] || die "signing-key path config is empty"
[ -f "$SIGNING_KEY" ] || die "configured signing key does not exist"
[ "$(wc -c < "$SIGNING_KEY" | tr -d '[:space:]')" = "32" ] \
    || die "configured signing key must be exactly 32 bytes"

# shellcheck source=/dev/null
source "$ESP_ENV_FILE"
cd "$SCRIPT_DIR"

# Dirty builds are permitted only for local device testing while a scoped fix
# is awaiting its commit. The signed manifest records the source as dirty.
printf '[build] Compiling and signing the current test branch...\n'
KASSIGNER_ALLOW_DIRTY_BUILD=1 \
    ./tools/build_with_hash.sh production --board m5stack --key "$SIGNING_KEY"

# Install.sh independently verifies the signed release before device access,
# immediately before erase, and immediately before flashing, then reads it back.
printf '[install] Authenticating, flashing, and reading back the M5...\n'
./Install.sh dist
