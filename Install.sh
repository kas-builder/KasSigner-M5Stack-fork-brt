#!/bin/bash
# Verified M5Stack CoreS3 release installer.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly RELEASE_DIR="${1:-$SCRIPT_DIR/dist}"
readonly ARTIFACT="$RELEASE_DIR/kassigner-m5stack.bin"
readonly MANIFEST="$RELEASE_DIR/kassigner-m5stack.manifest"
readonly SIGNATURE="$RELEASE_DIR/kassigner-m5stack.manifest.sig"
readonly PUBLIC_KEY="$SCRIPT_DIR/release/release_pubkey.hex"
PORT="${2:-}"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

verify_release() {
    cargo run --quiet --manifest-path "$SCRIPT_DIR/tools/Cargo.toml" \
        --bin release-manifest -- verify \
        "$ARTIFACT" "$MANIFEST" "$SIGNATURE" "$PUBLIC_KEY"
}

printf 'KasSigner M5Stack CoreS3 verified installer\n'
printf 'Release directory: %s\n\n' "$RELEASE_DIR"

# Verification is deliberately the first operation. Do not detect, erase, or
# communicate with a device until every local release input has authenticated.
verify_release
printf '\nRelease authentication passed before device access.\n'

command -v espflash >/dev/null 2>&1 || die "espflash is required; this installer never downloads or installs tools"

if [ -z "$PORT" ]; then
    shopt -s nullglob
    ports=(/dev/cu.usbmodem*)
    shopt -u nullglob
    [ "${#ports[@]}" -eq 1 ] || die "connect exactly one M5Stack CoreS3 or pass its serial port as the second argument"
    PORT="${ports[0]}"
fi
[ -e "$PORT" ] || die "serial port does not exist: $PORT"

printf 'Device: %s\n' "$PORT"

# Read and report the hardware state before asking for confirmation or erasing.
# This release is authenticated by the signed manifest and mandatory firmware
# signature. ESP Secure Boot provisioning is a separate hardware procedure and
# this installer never burns eFuses.
BOARD_INFO="$(espflash board-info --chip esp32s3 --port "$PORT" --non-interactive 2>&1)" \
    || die "could not read M5Stack security state"
printf '%s\n' "$BOARD_INFO"
printf '%s\n' "$BOARD_INFO" | grep -Eq '^Chip type:[[:space:]]+esp32s3' \
    || die "connected device is not an ESP32-S3"
printf '%s\n' "$BOARD_INFO" | grep -Eq '^Flash size:[[:space:]]+16MB$' \
    || die "connected device does not report the expected 16MB flash"
if ! printf '%s\n' "$BOARD_INFO" | grep -Eq '^Secure Boot:[[:space:]]+Enabled$'; then
    printf 'NOTICE: ESP Secure Boot is not provisioned; signed KasSigner firmware verification remains mandatory.\n'
fi
if ! printf '%s\n' "$BOARD_INFO" | grep -Eq '^Flash Encryption:[[:space:]]+Enabled$'; then
    printf 'NOTICE: ESP flash encryption is not provisioned; this installer will not modify eFuses.\n'
fi

printf 'This will erase that device and install the authenticated M5Stack image.\n'
read -r -p "Type ERASE-M5STACK to continue: " confirmation </dev/tty
[ "$confirmation" = "ERASE-M5STACK" ] || die "installation cancelled"

# Re-authenticate immediately before the first destructive command. This
# catches replacement between the initial check and user confirmation.
verify_release
espflash erase-flash --chip esp32s3 --port "$PORT" --non-interactive

# Re-authenticate again after erase and immediately before flashing. The exact
# file verified here is the exact path passed to espflash.
verify_release
espflash write-bin --chip esp32s3 --port "$PORT" --non-interactive 0x0 "$ARTIFACT"

# Read back exactly the authenticated artifact length and compare every byte.
# A successful write alone is not accepted as proof of installation.
READBACK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kassigner-readback.XXXXXX")" \
    || die "could not create read-back directory"
trap 'rm -rf "$READBACK_DIR"' EXIT
READBACK="$READBACK_DIR/kassigner-m5stack.readback.bin"
ARTIFACT_SIZE="$(wc -c < "$ARTIFACT" | tr -d '[:space:]')"
case "$ARTIFACT_SIZE" in
    ''|*[!0-9]*) die "authenticated artifact size is invalid" ;;
esac
espflash read-flash --chip esp32s3 --port "$PORT" --non-interactive \
    0x0 "$ARTIFACT_SIZE" "$READBACK"
cmp -s "$ARTIFACT" "$READBACK" \
    || die "post-flash read-back does not match the authenticated release"

printf '\nVerified M5Stack CoreS3 firmware installed and read back successfully.\n'
