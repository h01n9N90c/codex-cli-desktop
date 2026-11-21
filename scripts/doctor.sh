#!/usr/bin/env bash
# ==============================================================================
# Real-time compatibility, health & behavioral security doctor (macOS/Linux/WSL)
# ==============================================================================
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Project   : Codex Dual-Lane & Security Kit
#
# Security & Read-Only Guarantees:
#   - Strictly READ-ONLY: creates, modifies, and deletes ZERO files on disk.
#   - Uses strict Bash safety mode (`set -euo pipefail`) and `umask 077` while
#     explicitly guarding probe commands so diagnostics always complete and
#     print a full summary before exiting.
#   - Zero secret leakage: reads only the sanitized `auth_mode` field from
#     `auth.json` (allowlisted to `[A-Za-z0-9_.-]`), never prints tokens, API
#     keys, or raw `config.toml` lines.
#   - Audits POSIX permissions (`0600` owner-only) on sensitive `auth.json` and
#     `config.toml` files, detects plaintext `api_key =` assignments, checks
#     shared symlinks (including dangling/misdirected links), and executes live
#     behavioral `codex execpolicy check` probes against `default.rules`.
# ==============================================================================
set -euo pipefail

# Defensive owner-only mask even though this diagnostic never writes to disk.
umask 077

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

usage() {
  cat <<'EOF'
Usage: ./scripts/doctor.sh [OPTIONS]

Read-only compatibility, health, and behavioral security diagnostic.

Options:
  --lane1 PATH        Primary CODEX_HOME to inspect (default: $CODEX_LANE1_HOME or ~/.codex)
  --lane2 PATH        Secondary CODEX_HOME to inspect (default: $CODEX_LANE2_HOME or ~/.codex-official)
  --local-bin PATH    CLI wrapper directory to inspect (default: $CODEX_LOCAL_BIN or ~/.local/bin)
  -h, --help          Show this help message
EOF
}

require_arg() {
  local opt_name="$1"
  local arg_count="$2"
  if [ "${arg_count}" -lt 2 ]; then
    echo "[FAIL] Option '${opt_name}' requires a value." >&2
    usage >&2
    exit 1
  fi
}

# Strip trailing slashes (except '/') so directory path equality checks match reliably.
strip_trailing_slashes() {
  local p="$1"
  while [ "${#p}" -gt 1 ] && [ "${p%/}" != "${p}" ]; do
    p="${p%/}"
  done
  printf '%s' "${p}"
}

# Resolve a directory to its physical path portably (handles macOS /var -> /private/var).
canonicalize_dir_if_exists() {
  local p="$1"
  if [ -d "${p}" ]; then
    (cd -P -- "${p}" 2>/dev/null && pwd -P) || printf '%s' "${p}"
  else
    printf '%s' "${p}"
  fi
}

# Safely read the first line of a string without triggering SIGPIPE under `pipefail`.
first_line_or_default() {
  local text="$1"
  local fallback="$2"
  printf '%s\n' "${text}" | awk -v fb="${fallback}" 'NR==1 { line=$0 } END { if (line != "") print line; else print fb }'
}

# Portably read POSIX octal file permission bits (GNU `stat -c %a` / BSD `stat -f %Lp`).
get_octal_mode() {
  local path="$1"
  local mode=""
  if mode="$(stat -c '%a' -- "${path}" 2>/dev/null)"; then
    printf '%s' "${mode}"
  elif mode="$(stat -f '%Lp' "${path}" 2>/dev/null)"; then
    printf '%s' "${mode}"
  else
    printf ''
  fi
}

# Return 0 (true) if an octal mode exposes any group or other permission bits
# (i.e. last two digits are not `00`, such as 644 or 640).
mode_has_group_or_other_bits() {
  local mode="$1"
  if ! printf '%s' "${mode}" | grep -Eq '^[0-7]{3,4}$'; then
    return 1
  fi
  local go_bits="${mode: -2}"
  [ "${go_bits}" != "00" ]
}

# Format and tally [PASS], [WARN], and [FAIL] diagnostic entries.
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

# ------------------------------------------------------------------------------
# CLI Argument Parsing
# ------------------------------------------------------------------------------
LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --lane1)
      require_arg "$1" "$#"
      LANE1_HOME="$2"
      shift 2
      ;;
    --lane2)
      require_arg "$1" "$#"
      LANE2_HOME="$2"
      shift 2
      ;;
    --local-bin)
      require_arg "$1" "$#"
      LOCAL_BIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

LANE1_HOME="$(strip_trailing_slashes "${LANE1_HOME}")"
LANE2_HOME="$(strip_trailing_slashes "${LANE2_HOME}")"
LOCAL_BIN="$(strip_trailing_slashes "${LOCAL_BIN}")"

LANE1_CANON="$(canonicalize_dir_if_exists "${LANE1_HOME}")"
LOCAL_BIN_CANON="$(canonicalize_dir_if_exists "${LOCAL_BIN}")"

echo "=== Codex Dual-Lane System Doctor (Unix / macOS / WSL Diagnostics) ==="

# ------------------------------------------------------------------------------
# 1. Operating System & Shell Version
# ------------------------------------------------------------------------------
OS_INFO="$(uname -srm 2>/dev/null || echo "unknown")"
report "PASS" "Operating System" "${OS_INFO} | bash ${BASH_VERSION:-unknown}"

# ------------------------------------------------------------------------------
# 2. Free Disk Space on HOME (POSIX `df -Pk` Prevents Wrapped Device Lines)
# ------------------------------------------------------------------------------
HOME_FREE="$(df -Pk "${HOME}" 2>/dev/null | awk 'NR==2 { printf "%.1f GB free on %s", ($4 / 1048576.0), $1 }' || true)"
[ -z "${HOME_FREE}" ] && HOME_FREE="unknown"
report "PASS" "Home Filesystem" "${HOME_FREE}"

# ------------------------------------------------------------------------------
# 3. Codex CLI Launcher Resolution & PATH Precedence
# ------------------------------------------------------------------------------
CODEX_FOUND="$(command -v codex 2>/dev/null || true)"
if [ -n "${CODEX_FOUND}" ]; then
  VER_RAW="$("${CODEX_FOUND}" --version 2>/dev/null || true)"
  VER="$(first_line_or_default "${VER_RAW}" "unknown")"
  CODEX_DIR_CANON="$(canonicalize_dir_if_exists "$(dirname -- "${CODEX_FOUND}")")"
  if [ "${CODEX_DIR_CANON}" = "${LOCAL_BIN_CANON}" ]; then
    report "PASS" "codex CLI in PATH" "${CODEX_FOUND} (${VER})"
  else
    report "WARN" "codex CLI in PATH" "Resolved to ${CODEX_FOUND} instead of ${LOCAL_BIN}/codex (put ${LOCAL_BIN} first in PATH)"
  fi
else
  report "WARN" "codex CLI in PATH" "Not found in PATH. Run ./scripts/setup-dual-lane.sh and add ${LOCAL_BIN} to PATH"
fi

CODEX_T3="$(command -v codex-t3 2>/dev/null || true)"
if [ -n "${CODEX_T3}" ]; then
  T3_DIR_CANON="$(canonicalize_dir_if_exists "$(dirname -- "${CODEX_T3}")")"
  if [ "${T3_DIR_CANON}" = "${LOCAL_BIN_CANON}" ]; then
    report "PASS" "codex-t3 CLI in PATH" "${CODEX_T3}"
  else
    report "WARN" "codex-t3 CLI in PATH" "Resolved to ${CODEX_T3} instead of ${LOCAL_BIN}/codex-t3"
  fi
else
  report "WARN" "codex-t3 CLI in PATH" "Not found in PATH"
fi

# ------------------------------------------------------------------------------
# 4. Shared Brain Symlinks (Verify Presence, Target Existence & Lane 1 Target)
# ------------------------------------------------------------------------------
LINKED_OK=0
ISSUES=""
SHARED_DIRS=(memories memories_v2 sessions archived_sessions skills plugins)
for d in "${SHARED_DIRS[@]}"; do
  link_path="${LANE2_HOME}/${d}"
  expected_dir="${LANE1_CANON}/${d}"
  if [ -L "${link_path}" ]; then
    if [ -d "${link_path}" ]; then
      resolved_target="$(canonicalize_dir_if_exists "${link_path}")"
      if [ "${resolved_target}" = "${expected_dir}" ]; then
        LINKED_OK=$((LINKED_OK + 1))
      else
        ISSUES="${ISSUES}${d}(unexpected-target) "
      fi
    else
      ISSUES="${ISSUES}${d}(dangling) "
    fi
  else
    ISSUES="${ISSUES}${d}(missing/non-symlink) "
  fi
done
if [ -z "${ISSUES}" ]; then
  report "PASS" "Shared Brain Symlinks" "${LINKED_OK}/${#SHARED_DIRS[@]} symlinks healthy"
else
  report "WARN" "Shared Brain Symlinks" "${LINKED_OK}/${#SHARED_DIRS[@]} healthy; issues: ${ISSUES% }"
fi

# ------------------------------------------------------------------------------
# 5. Security Guardrails (config.toml + default.rules + AGENTS.md + Live Probe)
# ------------------------------------------------------------------------------
# Checks that `network_access = false` is set specifically inside the
# `[sandbox_workspace_write]` TOML table (tolerating CRLF line endings and
# trailing `#` comments on section headers while preserving `#` inside quotes).
is_sandbox_network_restricted() {
  local cfg_file="$1"
  awk '
    function strip_comment(s,    i, c, in_dq, in_sq, esc, out) {
      in_dq = 0; in_sq = 0; esc = 0; out = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (esc) { out = out c; esc = 0; continue }
        if (in_dq) {
          out = out c
          if (c == "\\") esc = 1
          else if (c == "\"") in_dq = 0
        } else if (in_sq) {
          out = out c
          if (c == "\047") in_sq = 0
        } else {
          if (c == "#") break
          if (c == "\"") in_dq = 1
          else if (c == "\047") in_sq = 1
          out = out c
        }
      }
      return out
    }
    {
      sub(/\r$/, "", $0)
      clean = strip_comment($0)
    }
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ {
      sec = clean
      sub(/^[[:space:]]*\[/, "", sec)
      sub(/\][[:space:]]*$/, "", sec)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
      in_sw = (sec == "sandbox_workspace_write")
      next
    }
    in_sw && clean ~ /^[[:space:]]*network_access[[:space:]]*=[[:space:]]*false[[:space:]]*$/ {
      found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "${cfg_file}" 2>/dev/null
}

# Detect hardcoded plaintext `api_key =` assignments without ever printing them.
has_plaintext_api_key() {
  local cfg_file="$1"
  awk '
    { sub(/\r$/, "", $0) }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*api_key[[:space:]]*=/ { found = 1; exit }
    END { exit(found ? 0 : 1) }
  ' "${cfg_file}" 2>/dev/null
}

check_lane() {
  local label="$1"
  local dir="$2"
  local cfg="${dir}/config.toml"
  local rules="${dir}/rules/default.rules"
  local agents="${dir}/AGENTS.md"

  if [ -f "${cfg}" ] && [ -f "${rules}" ] && [ -s "${agents}" ]; then
    local symlink_warn=""
    if [ -L "${cfg}" ] || [ -L "${rules}" ] || [ -L "${agents}" ]; then
      symlink_warn=" | symlink-detected"
    fi

    local static_ok=0
    if grep -Fq -e 'pattern=["php"]' "${rules}" \
      && grep -Fq -e 'pattern=["mshta"]' "${rules}" \
      && grep -Fq -e 'Static-Analysis-Only' "${agents}"; then
      static_ok=1
    fi

    local net_label="sandbox_net=enabled"
    if is_sandbox_network_restricted "${cfg}"; then
      net_label="sandbox_net=restricted"
    fi

    local secret_warn=0
    if has_plaintext_api_key "${cfg}"; then
      secret_warn=1
    fi

    local probe_note="engine_probe=skipped(no-codex)"
    local probe_ok=0
    local probe_total=5
    if [ -n "${CODEX_FOUND}" ]; then
      local out=""
      out="$("${CODEX_FOUND}" execpolicy check --rules "${rules}" -- php -r "echo 1;" 2>/dev/null || true)"
      if printf '%s' "${out}" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"forbidden"'; then probe_ok=$((probe_ok + 1)); fi

      out="$("${CODEX_FOUND}" execpolicy check --rules "${rules}" -- mshta http://example.invalid 2>/dev/null || true)"
      if printf '%s' "${out}" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"forbidden"'; then probe_ok=$((probe_ok + 1)); fi

      out="$("${CODEX_FOUND}" execpolicy check --rules "${rules}" -- vssadmin delete shadows /all 2>/dev/null || true)"
      if printf '%s' "${out}" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"forbidden"'; then probe_ok=$((probe_ok + 1)); fi

      out="$("${CODEX_FOUND}" execpolicy check --rules "${rules}" -- Start-Process calc.exe 2>/dev/null || true)"
      if printf '%s' "${out}" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"forbidden"'; then probe_ok=$((probe_ok + 1)); fi

      out="$("${CODEX_FOUND}" execpolicy check --rules "${rules}" -- iex dir 2>/dev/null || true)"
      if printf '%s' "${out}" | grep -Eq '"decision"[[:space:]]*:[[:space:]]*"forbidden"'; then probe_ok=$((probe_ok + 1)); fi

      probe_note="engine_probe=${probe_ok}/${probe_total} forbidden"
    fi

    if [ "${secret_warn}" -eq 1 ]; then
      report "WARN" "${label} Guardrails" "Plaintext api_key found in config.toml (switch to env_key/OAuth) | ${probe_note} | ${net_label}${symlink_warn}"
    elif [ "${static_ok}" -eq 1 ] && [ -n "${CODEX_FOUND}" ] && [ "${probe_ok}" -eq "${probe_total}" ] && [ -z "${symlink_warn}" ]; then
      report "PASS" "${label} Guardrails" "config + AGENTS.md | ${probe_note} | ${net_label}"
    elif [ "${static_ok}" -eq 1 ]; then
      report "WARN" "${label} Guardrails" "config + AGENTS.md present | ${probe_note} | ${net_label}${symlink_warn}"
    else
      report "WARN" "${label} Guardrails" "config + rules + AGENTS.md present, but static-only isolation rules incomplete (${net_label}${symlink_warn})"
    fi
  else
    report "WARN" "${label} Guardrails" "Missing one or more of config.toml, rules/default.rules, AGENTS.md"
  fi
}

check_lane "Lane 1" "${LANE1_HOME}"
check_lane "Lane 2" "${LANE2_HOME}"

# ------------------------------------------------------------------------------
# 6. Auth Isolation & POSIX Permission Hygiene (NEVER Echoes Secrets/Tokens)
# ------------------------------------------------------------------------------
# Extract ONLY the `auth_mode` metadata field using a single awk pass and
# allowlist its characters so malformed files can never leak token contents.
read_auth_mode() {
  local file="$1"
  if [ -L "${file}" ]; then
    echo "symlink-warning"
    return 0
  fi
  if [ ! -f "${file}" ]; then
    echo "not-logged-in"
    return 0
  fi
  local raw_mode=""
  raw_mode="$(awk '
    match($0, /"auth_mode"[[:space:]]*:[[:space:]]*"[^"]+"/) {
      seg = substr($0, RSTART, RLENGTH)
      sub(/^"auth_mode"[[:space:]]*:[[:space:]]*"/, "", seg)
      sub(/"$/, "", seg)
      print seg
      exit
    }
  ' "${file}" 2>/dev/null || true)"
  if printf '%s' "${raw_mode}" | grep -Eq '^[A-Za-z0-9_.-]{1,32}$'; then
    printf '%s' "${raw_mode}"
  else
    printf 'present'
  fi
}

M1="$(read_auth_mode "${LANE1_HOME}/auth.json")"
M2="$(read_auth_mode "${LANE2_HOME}/auth.json")"

# Audit POSIX permission bits on sensitive files across both lanes (expect 0600).
PERM_EXPOSED=0
for sf in \
  "${LANE1_HOME}/auth.json" \
  "${LANE1_HOME}/config.toml" \
  "${LANE2_HOME}/auth.json" \
  "${LANE2_HOME}/config.toml"; do
  if [ -f "${sf}" ] && [ ! -L "${sf}" ]; then
    fmode="$(get_octal_mode "${sf}")"
    if [ -n "${fmode}" ] && mode_has_group_or_other_bits "${fmode}"; then
      PERM_EXPOSED=$((PERM_EXPOSED + 1))
    fi
  fi
done

if [ "${PERM_EXPOSED}" -eq 0 ]; then
  PERM_LABEL="perms=0600-locked"
else
  PERM_LABEL="perms=exposed(${PERM_EXPOSED}; run chmod 600)"
fi

if [ "${M2}" != "not-logged-in" ] && [ "${M2}" != "symlink-warning" ] && [ "${M1}" != "symlink-warning" ] && [ "${PERM_EXPOSED}" -eq 0 ]; then
  report "PASS" "Auth & Perm Isolation" "Lane 1=${M1} | Lane 2=${M2} | ${PERM_LABEL}"
else
  report "WARN" "Auth & Perm Isolation" "Lane 1=${M1} | Lane 2=${M2} | ${PERM_LABEL}"
fi

# ------------------------------------------------------------------------------
# 7. Python 3 Availability (Optional; Used Only by scripts/sync-sessions.py)
# ------------------------------------------------------------------------------
PY_FOUND=""
for cand in python3 python; do
  if command -v "${cand}" >/dev/null 2>&1; then
    PY_RAW="$("${cand}" --version 2>&1 || true)"
    PY_VER="$(first_line_or_default "${PY_RAW}" "")"
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
if [ "${FAIL}" -gt 0 ]; then
  exit 1
fi
exit 0
