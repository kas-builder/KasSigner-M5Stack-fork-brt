#!/bin/bash
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
set -euo pipefail

echo "╔════════════════════════════════════════════════╗"
echo "║  KasSigner — Signed Build with Hash             ║"
echo "║  Iterative convergence + Schnorr signing        ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")/.."

ELF="bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader"
BIN="bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader.bin"

# Usage: build_with_hash.sh [development|production]
#        [--board waveshare|m5stack] [--key path/to/signing_key.bin]
MODE="development"
BOARD=""
SIGNING_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        production)
            MODE="production"
            shift
            ;;
        development)
            MODE="development"
            shift
            ;;
        --board)
            if [ $# -lt 2 ]; then
                echo "ERROR: --board requires waveshare or m5stack" >&2
                exit 2
            fi
            BOARD="$2"
            shift 2
            ;;
        --key)
            if [ $# -lt 2 ]; then
                echo "ERROR: --key requires a file path" >&2
                exit 2
            fi
            SIGNING_KEY="$2"
            shift 2
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            echo "Usage: $0 [development|production] [--board waveshare|m5stack] [--key path]" >&2
            exit 2
            ;;
    esac
done

if [ -z "$BOARD" ]; then
    echo "ERROR: --board is required; choose waveshare or m5stack explicitly" >&2
    exit 2
fi

case "$BOARD" in
    waveshare)
        if [ "$MODE" = "production" ]; then
            BUILD_ARGS=(--release --features production)
        else
            BUILD_ARGS=(--release)
        fi
        ;;
    m5stack)
        if [ "$MODE" = "production" ]; then
            BUILD_ARGS=(--release --no-default-features --features m5stack,production)
        else
            BUILD_ARGS=(--release --no-default-features --features m5stack)
        fi
        ;;
    *)
        echo "ERROR: Unsupported board '$BOARD'; expected waveshare or m5stack" >&2
        exit 2
        ;;
esac

echo "  Mode: $MODE"
echo "  Board: $BOARD"

SIGN_ARG=""
if [ -n "$SIGNING_KEY" ]; then
    if [ ! -f "$SIGNING_KEY" ]; then
        echo "ERROR: Signing key does not exist: $SIGNING_KEY" >&2
        exit 1
    fi
    KEY_SIZE=$(wc -c < "$SIGNING_KEY" | tr -d ' ')
    if [ "$KEY_SIZE" -ne 32 ]; then
        echo "ERROR: Signing key must be exactly 32 bytes; got $KEY_SIZE" >&2
        exit 1
    fi
    SIGN_ARG="$SIGNING_KEY"
fi

if [ "$MODE" = "production" ] && [ -z "$SIGN_ARG" ]; then
    echo "ERROR: Production builds require a valid 32-byte signing key" >&2
    exit 1
fi

if [ "$MODE" = "development" ] && [ -n "$SIGN_ARG" ]; then
    echo "ERROR: --key is accepted only for production builds" >&2
    exit 2
fi

if [ "$MODE" = "production" ]; then
    cargo run --manifest-path tools/Cargo.toml --bin release-manifest -- \
        check-key "$SIGN_ARG"

    COMMIT="$(git rev-parse --verify HEAD)"
    if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
        if [ "${KASSIGNER_ALLOW_DIRTY_BUILD:-0}" != "1" ]; then
            echo "ERROR: Production builds require a clean Git tree" >&2
            echo "For a local test build only, set KASSIGNER_ALLOW_DIRTY_BUILD=1" >&2
            exit 1
        fi
        COMMIT="${COMMIT}-dirty"
        echo "  Source: DIRTY local test build (not releasable)"
    else
        echo "  Source: clean commit $COMMIT"
    fi
fi

if [ -n "$SIGN_ARG" ]; then
    echo "  Signing: enabled"
else
    echo "  Signing: disabled (development only)"
fi
echo ""

build_firmware() {
    (
        cd bootloader
        cargo build "${BUILD_ARGS[@]}"
    )
}

run_hash_tool() {
    if [ -n "$SIGN_ARG" ]; then
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash -- "$BIN" "$SIGN_ARG"
    else
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash -- "$BIN"
    fi
}

echo "[1] Compiling bootloader (first pass)..."
build_firmware

MAX_ITERATIONS=5
PREV_HASH=""
CURRENT_HASH=""
CONVERGED=false

for i in $(seq 1 $MAX_ITERATIONS); do
    echo ""
    echo "── Iteration $i/$MAX_ITERATIONS ──────────────────────────"

    espflash save-image --chip esp32s3 "$ELF" "$BIN"
    if ! HASH_OUTPUT=$(run_hash_tool 2>&1 | tee /dev/tty); then
        printf '%s\n' "$HASH_OUTPUT" >&2
        exit 1
    fi
    CURRENT_HASH=$(echo "$HASH_OUTPUT" | grep "SHA256:" | awk '{print $2}')
    SEG_SIZE=$(echo "$HASH_OUTPUT" | grep "Segment size:" | awk '{print $3}')
    SIGNED=$(echo "$HASH_OUTPUT" | grep "Status:" | head -1)

    if [ -z "$CURRENT_HASH" ] || [ -z "$SEG_SIZE" ]; then
        echo "ERROR: Hash tool did not return complete firmware metadata" >&2
        echo "$HASH_OUTPUT" >&2
        exit 1
    fi

    echo "   Hash: ${CURRENT_HASH:0:16}..."
    echo "   Segment: $SEG_SIZE bytes"
    [ -n "$SIGNED" ] && echo "   $SIGNED"

    if [ "$CURRENT_HASH" = "$PREV_HASH" ]; then
        echo ""
        echo "   CONVERGED at iteration $i"
        echo "   Stable hash: $CURRENT_HASH"
        CONVERGED=true
        break
    fi

    PREV_HASH="$CURRENT_HASH"
    echo "   Recompiling with embedded hash..."
    build_firmware
done

if [ "$CONVERGED" != true ]; then
    echo "ERROR: Firmware hash did not converge after $MAX_ITERATIONS iterations" >&2
    exit 1
fi

echo ""
echo "[Final] Generating and verifying final .bin..."
espflash save-image --chip esp32s3 "$ELF" "$BIN"
if ! FINAL_OUTPUT=$(run_hash_tool 2>&1 | tee /dev/tty); then
    printf '%s\n' "$FINAL_OUTPUT" >&2
    exit 1
fi
FINAL_HASH=$(echo "$FINAL_OUTPUT" | grep "SHA256:" | awk '{print $2}')
FINAL_STATUS=$(echo "$FINAL_OUTPUT" | grep "Status:" | head -1)

if [ -z "$FINAL_HASH" ] || [ "$FINAL_HASH" != "$CURRENT_HASH" ]; then
    echo "ERROR: Final binary hash does not match the converged hash" >&2
    exit 1
fi

if [ "$MODE" = "production" ] && ! echo "$FINAL_STATUS" | grep -q "SIGNED (production-ready)"; then
    echo "ERROR: Final production binary is not signed" >&2
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "════════════════════════════════════════════════"
echo ""
echo "  Board: $BOARD"
echo "  Hash: ${FINAL_HASH:0:16}..."
if [ "$MODE" = "production" ]; then
    echo "  Status: SIGNED (production)"
elif [ -n "$SIGN_ARG" ]; then
    echo "  Status: SIGNED (development)"
else
    echo "  Status: UNSIGNED (development)"
fi

if [ "$MODE" = "production" ]; then
    RELEASE_DIR="dist"
    RELEASE_ARTIFACT="$RELEASE_DIR/kassigner-m5stack.bin"
    RELEASE_MANIFEST="$RELEASE_DIR/kassigner-m5stack.manifest"
    RELEASE_SIGNATURE="$RELEASE_DIR/kassigner-m5stack.manifest.sig"
    VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' bootloader/Cargo.toml | head -1)"
    [ -n "$VERSION" ] || { echo "ERROR: Could not determine bootloader version" >&2; exit 1; }
    mkdir -p "$RELEASE_DIR"
    # The convergence hash is computed from the application image above, but a
    # release artifact must contain the bootloader, partition table, and app.
    # --skip-padding avoids shipping a 16 MiB file while --flash-size records
    # the actual CoreS3 flash geometry in the image metadata.
    espflash save-image --chip esp32s3 --merge --skip-padding --flash-size 16mb \
        "$ELF" "$RELEASE_ARTIFACT"
    cargo run --quiet --manifest-path tools/Cargo.toml --bin release-manifest -- create \
        "$RELEASE_ARTIFACT" "$RELEASE_MANIFEST" "$RELEASE_SIGNATURE" \
        "$SIGN_ARG" "$COMMIT" "$VERSION"
    cargo run --quiet --manifest-path tools/Cargo.toml --bin release-manifest -- verify \
        "$RELEASE_ARTIFACT" "$RELEASE_MANIFEST" "$RELEASE_SIGNATURE" \
        release/release_pubkey.hex
    echo "  Release: $RELEASE_DIR (artifact + signed manifest)"
fi
echo ""
if [ "$MODE" = "production" ]; then
    echo "  To install the authenticated release:"
    echo "    ./Install.sh dist"
else
    echo "  Development flash (not a release):"
    echo "    espflash flash --monitor $ELF"
fi
