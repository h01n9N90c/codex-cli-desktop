#!/usr/bin/env bash
# Deterministic rollback & recovery tool for Codex Dual-Lane & Security Kit on macOS / Linux / WSL.
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
set -euo pipefail

LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"
REMOVE_LANE2=0
DRY_RUN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --remove-lane2-home) REMOVE_LANE2=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      echo "Usage: ./scripts/restore-original.sh [--remove-lane2-home] [--dry-run]"
      exit 0
      ;;
    *) echo "[FAIL] Unknown argument: $1" >&2; exit 1 ;;
  esac
done

echo "=== Codex Dual-Lane Deterministic Rollback & Recovery (Unix / macOS / WSL) ==="
[ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files will be modified."

# 1. Safely unlink symlinks in Lane 2 first (never rm -rf through a symlink target)
echo "[+] Step 1: Unlinking shared symlinks in ${LANE2_HOME}..."
for d in memories memories_v2 sessions archived_sessions skills plugins; do
  target="${LANE2_HOME}/${d}"
  if [ -L "${target}" ]; then
    [ "${DRY_RUN}" -eq 0 ] && rm "${target}"
    echo "    Unlinked symlink: ${target} (Lane 1 data untouched)"
  fi
  latest_dir_bkp="$(ls -1dt "${LANE2_HOME}/${d}.backup-"* 2>/dev/null | head -n 1 || true)"
  if [ -n "${latest_dir_bkp}" ] && [ ! -e "${target}" ]; then
    [ "${DRY_RUN}" -eq 0 ] && mv "${latest_dir_bkp}" "${target}"
    echo "    Restored pre-existing directory: ${latest_dir_bkp} -> ${target}"
  fi
done

# 2. Restore latest timestamped backups for config.toml, AGENTS.md, rules/default.rules
echo "[+] Step 2: Restoring backed-up configuration and rule files..."
restore_latest() {
  local file="$1"
  local bkp
  bkp="$(ls -1t "${file}.backup-"* 2>/dev/null | head -n 1 || true)"
  if [ -n "${bkp}" ]; then
    if [ "${DRY_RUN}" -eq 0 ]; then
      cp "${bkp}" "${file}"
      rm -f "${bkp}"
    fi
    echo "    Restored: ${bkp} -> ${file}"
  fi
}

for home_dir in "${LANE1_HOME}" "${LANE2_HOME}"; do
  restore_latest "${home_dir}/config.toml"
  restore_latest "${home_dir}/AGENTS.md"
  restore_latest "${home_dir}/rules/default.rules"
done

# 3. Remove CLI wrappers
echo "[+] Step 3: Removing CLI wrappers from ${LOCAL_BIN}..."
for w in codex codex-official codex-t3; do
  if [ -f "${LOCAL_BIN}/${w}" ]; then
    [ "${DRY_RUN}" -eq 0 ] && rm -f "${LOCAL_BIN}/${w}"
    echo "    Removed wrapper: ${LOCAL_BIN}/${w}"
  fi
done

# 4. Optional: remove Lane 2 home directory after confirming zero symlinks remain
if [ "${REMOVE_LANE2}" -eq 1 ] && [ -d "${LANE2_HOME}" ]; then
  echo "[+] Step 4: Removing ${LANE2_HOME} (--remove-lane2-home)..."
  if [ "${DRY_RUN}" -eq 0 ]; then
    for d in memories memories_v2 sessions archived_sessions skills plugins; do
      if [ -L "${LANE2_HOME}/${d}" ]; then
        echo "[FAIL] Symlink still present at ${LANE2_HOME}/${d}; aborting removal." >&2
        exit 1
      fi
    done
    rm -rf "${LANE2_HOME}"
  fi
  echo "    Removed directory: ${LANE2_HOME}"
fi

echo "[OK] Deterministic rollback completed!"
