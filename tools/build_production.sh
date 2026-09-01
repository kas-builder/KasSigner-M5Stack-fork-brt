#!/bin/bash
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
# Production build: delegates to the unified build script with "production" flag
set -euo pipefail

# This fork targets M5Stack CoreS3. Keep the board choice explicit here so a
# production release can never silently fall back to the Waveshare default.
exec "$(dirname "$0")/build_with_hash.sh" production --board m5stack "$@"
