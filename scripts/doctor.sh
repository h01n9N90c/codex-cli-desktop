#!/usr/bin/env bash
# Real-time compatibility, health & behavioral security diagnostic for Codex Dual-Lane & Security Kit on macOS / Linux / WSL.
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Read-only; modifies zero files and uses zero mock data.
set -uo pipefail

LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"

PASS=0
WARN=0
FAIL=0

report() {
  local status="$1"
  local label="$2"
  local detail="$3"
  case "${status}" in
    PASS) PASS=$((PASS + 1)) ;;
    WARN) WARN=$((WARN + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
  esac
  printf '[%s] %-30s : %s\n' "${status}" "${label}" "${detail}"
}

echo "=== Codex Dual-Lane System Doctor (Unix / macOS / WSL Diagnostics) ==="

# 1. OS & Shell
report "PASS" "Operating System" "$(uname -srm) | bash ${BASH_VERSION:-unknown}"

# 2. Free disk space on HOME
HOME_FREE="$(df -h "${HOME}" 2>/dev/null | awk 'NR==2 {print $4 " free on " $1}' || echo "unknown")"
report "PASS" "Home Filesystem" "${HOME_FREE}"

# 3. Codex CLI launcher resolution & PATH precedence
CODEX_FOUND="$(command -v codex 2>/dev/null || true)"
if [ -n "${CODEX_FOUND}" ]; then
  VER="$("${CODEX_FOUND}" --version 2>/dev/null | head -n 1 || echo "unknown")"
  if [ "${CODEX_FOUND}" = "${LOCAL_BIN}/codex" ]; then
    report "PASS" "codex CLI in PATH" "${CODEX_FOUND} (${VER})"
  else
    report "WARN" "codex CLI in PATH" "Resolved to ${CODEX_FOUND} instead of ${LOCAL_BIN}/codex (put ${LOCAL_BIN} first in PATH)"
  fi
else
  report "WARN" "codex CLI in PATH" "Not found in PATH. Run ./scripts/setup-dual-lane.sh and add ${LOCAL_BIN} to PATH"
fi

CODEX_T3="$(command -v codex-t3 2>/dev/null || true)"
if [ -n "${CODEX_T3}" ]; then
  report "PASS" "codex-t3 CLI in PATH" "${CODEX_T3}"
else
  report "WARN" "codex-t3 CLI in PATH" "Not found in PATH"
fi

# 4. Shared symlinks
LINKED_OK=0
BROKEN=""
for d in memories memories_v2 sessions archived_sessions skills plugins; do
  if [ -L "${LANE2_HOME}/${d}" ]; then
    LINKED_OK=$((LINKED_OK + 1))
  else
    BROKEN="${BROKEN}${d} "
  fi
done
if [ -z "${BROKEN}" ]; then
  report "PASS" "Shared Brain Symlinks" "${LINKED_OK}/6 symlinks healthy"
else
  report "WARN" "Shared Brain Symlinks" "${LINKED_OK}/6 healthy; missing/non-symlink: ${BROKEN}"
fi

# 5. Security guardrails (config + default.rules + AGENTS.md + behavioral execpolicy probe)
check_lane() {
  local label="$1"
  local dir="$2"
  local cfg="${dir}/config.toml"
  local rules="${dir}/rules/default.rules"
  local agents="${dir}/AGENTS.md"
  if [ -f "${cfg}" ] && [ -f "${rules}" ] && [ -s "${agents}" ]; then
    local static_ok=0
    if grep -q 'pattern=\["php"\]' "${rules}" && grep -q 'pattern=\["mshta"\]' "${rules}" && grep -q 'Static-Analysis-Only' "${agents}"; then
      static_ok=1
    fi
    local net_label="sandbox_net=enabled"
    if grep -Eq '^network_access[[:space:]]*=[[:space:]]*false' "${cfg}"; then
      net_label="sandbox_net=restricted"
    fi
    local probe_note="static_rules=OK"
    if [ -n "${CODEX_FOUND}" ]; then
      local p_ok=0
      if "${CODEX_FOUND}" execpolicy check --rules "${rules}" -- php -r "echo 1;" 2>/dev/null | grep -q '"decision":"forbidden"'; then p_ok=$((p_ok + 1)); fi
      if "${CODEX_FOUND}" execpolicy check --rules "${rules}" -- vssadmin delete shadows 2>/dev/null | grep -q '"decision":"forbidden"'; then p_ok=$((p_ok + 1)); fi
      if "${CODEX_FOUND}" execpolicy check --rules "${rules}" -- Start-Process calc.exe 2>/dev/null | grep -q '"decision":"forbidden"'; then p_ok=$((p_ok + 1)); fi
      probe_note="engine_probe=${p_ok}/3 forbidden"
    fi
    if [ "${static_ok}" -eq 1 ]; then
      report "PASS" "${label} Guardrails" "config + AGENTS.md | ${probe_note} | ${net_label}"
    else
      report "WARN" "${label} Guardrails" "config + rules + AGENTS.md present, but static-only isolation rules incomplete (${net_label})"
    fi
  else
    report "WARN" "${label} Guardrails" "Missing one or more of config.toml, rules/default.rules, AGENTS.md"
  fi
}

check_lane "Lane 1" "${LANE1_HOME}"
check_lane "Lane 2" "${LANE2_HOME}"

# 6. Auth isolation (read auth_mode only, never print tokens/keys)
read_auth_mode() {
  local file="$1"
  [ ! -f "${file}" ] && echo "not-logged-in" && return
  grep -oE '"auth_mode"[[:space:]]*:[[:space:]]*"[^"]+"' "${file}" 2>/dev/null | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/' || echo "present"
}
M1="$(read_auth_mode "${LANE1_HOME}/auth.json")"
M2="$(read_auth_mode "${LANE2_HOME}/auth.json")"
if [ "${M2}" != "not-logged-in" ]; then
  report "PASS" "Auth Isolation" "Lane 1=${M1} | Lane 2=${M2} (isolated auth.json files)"
else
  report "WARN" "Auth Isolation" "Lane 1=${M1} | Lane 2=${M2} (run 'codex login' for Lane 2)"
fi

# 7. Python 3 availability (optional; verify real Python 3.x and ignore Windows Store alias stub)
PY_FOUND=""
for cand in python3 python; do
  if command -v "${cand}" >/dev/null 2>&1; then
    PY_VER="$("${cand}" --version 2>&1 | head -n 1 || true)"
    if printf '%s' "${PY_VER}" | grep -Eq '^Python 3\.'; then
      PY_FOUND="${PY_VER} ($(command -v "${cand}"))"
      break
    fi
  fi
done
if [ -n "${PY_FOUND}" ]; then
  report "PASS" "Python 3 (Optional Sync)" "${PY_FOUND}"
else
  report "WARN" "Python 3 (Optional Sync)" "Not installed (only needed for scripts/sync-sessions.py)"
fi

printf '\nSummary: %d PASS | %d WARN | %d FAIL\n' "${PASS}" "${WARN}" "${FAIL}"
[ "${FAIL}" -gt 0 ] && exit 1 || exit 0
