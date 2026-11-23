#!/usr/bin/env bash
# ==============================================================================
# start-codex.sh -- 1-Touch Launcher for Codex Dual-Lane Control Center
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0
# ==============================================================================
set -euo pipefail
KIT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec bash "${KIT_DIR}/scripts/codex-manager.sh" "$@"
