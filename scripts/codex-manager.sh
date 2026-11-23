#!/usr/bin/env bash
# ==============================================================================
# Interactive & Scriptable Sandbox 2 Control Center (macOS / Linux / WSL / Git Bash)
# ==============================================================================
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Project   : Codex Dual-Lane & Security Kit
#
# Security & End-User Safety Guarantees:
#   - Strict Bash error handling (`set -euo pipefail`) and owner-only default
#     file creation mask (`umask 077`).
#   - Bash 3.2 (macOS default), GNU Linux, WSL, and Git Bash compatible.
#   - Zero plaintext secret exposure:
#       * NEVER accepts plaintext API keys via CLI flags (refuses `--api-key`,
#         `--key`, `--token`, `--secret`).
#       * Prompts interactively with masked input (`read -r -s`) or reads from
#         stdin (`--api-key-from-stdin`) and pipes directly via Bash builtin
#         `printf` (never appearing in `ps` / argv or on disk).
#       * Online `/models` probe sends the key strictly via stdin pipe to
#         Python `urllib` (never in `curl` / process argv or error logs).
#       * Redacts secret patterns before displaying any subcommand output.
#   - Strict read-only `check-accounts` and `check-api-key` (zero mutations to
#     GPT 1 or Sandbox 2).
#   - Fail-closed history-preserving Sandbox 2 removal (`remove-sandbox2`):
#     MANDATORILY rescues & syncs 100% of Sandbox 2 chats, Pinned threads,
#     Goals, and any non-symlink local rollout/memory files back into GPT 1
#     BEFORE unlinking shared symlinks and removing Sandbox 2.
#   - Atomic file writes (`mktemp` + `chmod 600` + `mv -f`) with signal-safe
#     cleanup traps and symlink-clobber guards.
# ==============================================================================
set -euo pipefail

# Enforce owner-only permissions on every artifact created during management ops.
umask 077

# ------------------------------------------------------------------------------
# Temporary Artifact Tracking & Signal-Safe Cleanup
# ------------------------------------------------------------------------------
TEMP_ARTIFACTS=()
cleanup_temp_artifacts() {
  # Guard array length so Bash 3.2 (macOS default) does not fail under `set -u`.
  if [ "${#TEMP_ARTIFACTS[@]}" -gt 0 ]; then
    rm -rf -- "${TEMP_ARTIFACTS[@]}" 2>/dev/null || true
  fi
}
handle_signal_exit() {
  local sig="$1"
  cleanup_temp_artifacts
  trap - "${sig}" EXIT
  kill -"${sig}" "$$" 2>/dev/null || exit 130
}
trap cleanup_temp_artifacts EXIT
trap 'handle_signal_exit INT' INT
trap 'handle_signal_exit TERM' TERM

# ------------------------------------------------------------------------------
# Usage & CLI Help
# ------------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: ./scripts/codex-manager.sh [OPTIONS]

Interactive & scriptable Control Center for Sandbox 2 (Codex CLI: ~/.codex-official)
while keeping GPT 1 (Codex Desktop: ~/.codex) and 100% of chat history safe.

Options:
  --action ACTION        Action to execute (default: menu):
                           menu            Interactive Control Center menu
                           api-gpt         Configure OpenAI / GPT API Key for Sandbox 2
                           api-other       Configure Third-Party / Custom Provider (opens config.toml)
                           login           Official OpenAI / ChatGPT login for Sandbox 2
                           check-api-key   Inspect Sandbox 2 API key sources (masked) + optional live probe
                           check-accounts  Read-only inspection of GPT 1 & Sandbox 2 accounts/health
                           sync-history    Bidirectional chat history sync (GPT 1 <-> Sandbox 2)
                           remove-sandbox2 Safe uninstall Sandbox 2 WITHOUT deleting chat history
                           set-cli-mode    Configure Sandbox 2 CLI permission mode (ask | config | full-access)
  --lane1-home PATH      GPT 1 / Desktop CODEX_HOME (default: $CODEX_LANE1_HOME or ~/.codex)
  --lane2-home PATH      Sandbox 2 / CLI CODEX_HOME (default: $CODEX_LANE2_HOME or ~/.codex-official)
  --local-bin PATH       CLI wrapper directory (default: $CODEX_LOCAL_BIN or ~/.local/bin)
  --codex-path PATH      Explicit path to real `codex` binary (auto-detected if omitted)
  --cli-mode MODE        With set-cli-mode: 'ask', 'config', or 'full-access'
  --confirm-full-access  Explicitly confirm --cli-mode full-access (required when --non-interactive)
  --online-check         With check-api-key, perform live GET <base_url>/models probe
  --device-auth          With login, pass --device-auth to `codex login`
  --editor CMD           Editor command for api-other (default: $VISUAL, $EDITOR, or vi)
  --dry-run              Preview every operation without mutating any files on disk
  --force                Skip confirmation prompts (for login provider reset / remove-sandbox2)
  --non-interactive      Disable interactive prompts (fail closed if required input is missing)
  --api-key-from-stdin   Read API key from stdin for --action api-gpt (NEVER pass keys as CLI args!)
  -h, --help             Show this help message

Environment overrides:
  CODEX_LANE1_HOME       Default for --lane1-home
  CODEX_LANE2_HOME       Default for --lane2-home
  CODEX_LOCAL_BIN        Default for --local-bin
  CODEX_REAL_BIN         Optional default for --codex-path
EOF
}

# ------------------------------------------------------------------------------
# Portable Core Helpers (Bash 3.2 / macOS BSD / GNU Linux / WSL / Git Bash)
# ------------------------------------------------------------------------------

require_arg() {
  local opt_name="$1"
  local arg_count="$2"
  if [ "${arg_count}" -lt 2 ]; then
    echo "[FAIL] Option '${opt_name}' requires a value." >&2
    usage >&2
    exit 1
  fi
}

to_lower() {
  printf '%s' "$1" | awk '{print tolower($0)}'
}

is_windows_msys() {
  case "$(uname -s 2>/dev/null || echo '')" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

validate_path_value() {
  local label="$1"
  local raw="$2"
  if [ -z "${raw}" ]; then
    echo "[FAIL] ${label} must not be empty." >&2
    exit 1
  fi
  if printf '%s' "${raw}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "[FAIL] ${label} contains unsupported control characters (newline/tab/CR)." >&2
    exit 1
  fi
  local trimmed="${raw}"
  while [ "${#trimmed}" -gt 1 ] && [ "${trimmed%/}" != "${trimmed}" ]; do
    trimmed="${trimmed%/}"
  done
  if [ "${trimmed}" = "/" ]; then
    echo "[FAIL] Refusing filesystem root '/' for ${label}." >&2
    exit 1
  fi
  printf '%s' "${trimmed}"
}

canonicalize_dir() {
  local p="$1"
  local suffix=""
  local cur="${p}"
  while [ ! -d "${cur}" ]; do
    local parent base
    parent="$(dirname -- "${cur}")"
    base="$(basename -- "${cur}")"
    if [ "${parent}" = "${cur}" ]; then
      break
    fi
    if [ -n "${suffix}" ]; then
      suffix="${base}/${suffix}"
    else
      suffix="${base}"
    fi
    cur="${parent}"
  done
  local resolved=""
  if [ -d "${cur}" ]; then
    resolved="$(cd -P -- "${cur}" && pwd -P)"
  else
    resolved="${cur}"
  fi
  if [ -n "${suffix}" ]; then
    if [ "${resolved}" = "/" ]; then
      printf '/%s' "${suffix}"
    else
      printf '%s/%s' "${resolved}" "${suffix}"
    fi
  else
    printf '%s' "${resolved}"
  fi
}

get_octal_mode() {
  local path="$1"
  local mode=""
  if mode="$(stat -c '%a' "${path}" 2>/dev/null)"; then
    :
  elif mode="$(stat -f '%Lp' "${path}" 2>/dev/null)"; then
    :
  else
    printf ''
    return 0
  fi
  if printf '%s' "${mode}" | grep -Eq '^[0-7]{4}$'; then
    mode="${mode#?}"
  fi
  if printf '%s' "${mode}" | grep -Eq '^[0-7]{1,2}$'; then
    while [ "${#mode}" -lt 3 ]; do
      mode="0${mode}"
    done
  fi
  if printf '%s' "${mode}" | grep -Eq '^[0-7]{3}$'; then
    printf '%s' "${mode}"
  else
    printf ''
  fi
}

# Bash 3.2-safe check for any group/other permission bits (last 2 digits of 3-digit mode).
mode_has_group_or_other_bits() {
  local mode="$1"
  if ! printf '%s' "${mode}" | grep -Eq '^[0-7]{3}$'; then
    return 1
  fi
  local go_bits="${mode:1:2}"
  [ "${go_bits}" != "00" ]
}

sha256_file() {
  local file="$1"
  local digest=""
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum < "${file}" | awk '{print tolower($1)}')"
  elif command -v shasum >/dev/null 2>&1; then
    digest="$(shasum -a 256 < "${file}" | awk '{print tolower($1)}')"
  elif command -v openssl >/dev/null 2>&1; then
    digest="$(openssl dgst -sha256 < "${file}" | awk '{print tolower($NF)}')"
  else
    echo "[FAIL] No SHA-256 utility found (need sha256sum, shasum, or openssl)." >&2
    exit 1
  fi
  if ! printf '%s' "${digest}" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "[FAIL] Unexpected SHA-256 output while hashing ${file}." >&2
    exit 1
  fi
  printf '%s' "${digest}"
}

atomic_write_from_stdin() {
  local dst="$1"
  local mode="$2"
  if [ -L "${dst}" ]; then
    echo "[FAIL] Security refusal: destination '${dst}' is a symlink; refusing to overwrite." >&2
    exit 1
  fi
  if [ -d "${dst}" ]; then
    echo "[FAIL] Refusing to overwrite directory '${dst}' with a regular file." >&2
    exit 1
  fi
  local parent tmp
  parent="$(dirname -- "${dst}")"
  mkdir -p -- "${parent}"
  tmp="$(mktemp "${parent}/.codex-mgr-tmp.XXXXXX")"
  TEMP_ARTIFACTS+=("${tmp}")
  cat > "${tmp}"
  chmod "${mode}" "${tmp}"
  mv -f -- "${tmp}" "${dst}"
}

unique_backup_path() {
  local base="$1"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local cand="${base}.backup-${ts}"
  local idx=1
  while [ -e "${cand}" ] || [ -L "${cand}" ]; do
    cand="${base}.backup-${ts}-${idx}"
    idx=$((idx + 1))
  done
  printf '%s' "${cand}"
}

backup_file_0600() {
  local src="$1"
  if [ -L "${src}" ]; then
    echo "[FAIL] Security refusal: '${src}' is a symlink; refusing to back up or modify." >&2
    exit 1
  fi
  if [ -d "${src}" ]; then
    echo "[FAIL] Refusing to treat directory '${src}' as a regular file." >&2
    exit 1
  fi
  if [ ! -f "${src}" ]; then
    return 0
  fi
  local orig_hash bkp bkp_hash
  orig_hash="$(sha256_file "${src}")"
  bkp="$(unique_backup_path "${src}")"
  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${bkp}" 600 < "${src}"
    bkp_hash="$(sha256_file "${bkp}")"
    if [ "${bkp_hash}" != "${orig_hash}" ]; then
      echo "[FAIL] Backup integrity verification failed for ${bkp}." >&2
      exit 1
    fi
    echo "    Backup saved: ${bkp} (SHA256=${orig_hash:0:12}...)"
  else
    echo "    [DRY-RUN] Would save backup: ${bkp} (SHA256=${orig_hash:0:12}...)"
  fi
}

lock_file_0600() {
  local f="$1"
  if [ -L "${f}" ]; then
    echo "[WARN] Skipping chmod 600 on symlink: ${f}" >&2
    return 0
  fi
  if [ -f "${f}" ]; then
    if [ "${DRY_RUN}" -eq 0 ]; then
      chmod 600 "${f}"
      echo "    Locked permissions (0600): ${f}"
    else
      echo "    [DRY-RUN] Would enforce chmod 600: ${f}"
    fi
  fi
}

# Safe secret masker — Bash 3.2 compatible (avoids negative offset syntax).
# NEVER echoes plaintext keys.
mask_secret() {
  local raw="$1"
  local len="${#raw}"
  if [ "${len}" -eq 0 ]; then
    printf 'NOT_SET'
    return 0
  fi
  if [ "${len}" -le 8 ]; then
    printf '*** (len=%d)' "${len}"
    return 0
  fi
  if [ "${len}" -lt 12 ]; then
    local s2="${raw:$((len - 2)):2}"
    printf '***...%s (len=%d)' "${s2}" "${len}"
    return 0
  fi
  local s4="${raw:$((len - 4)):4}"
  case "${raw}" in
    sk-*)
      printf 'sk-...%s (len=%d)' "${s4}" "${len}"
      ;;
    *)
      printf '%s...%s (len=%d)' "${raw:0:3}" "${s4}" "${len}"
      ;;
  esac
}

# Redact common token/API-key patterns from command outputs before printing.
redact_secrets_stream() {
  sed -E \
    -e 's/sk-[A-Za-z0-9_-]{8,}/sk-***REDACTED***/g' \
    -e 's/Bearer[[:space:]]+[A-Za-z0-9._~+\/=-]{8,}/Bearer ***REDACTED***/g' \
    -e 's/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/jwt.***REDACTED***/g' \
    -e 's/gh[po]_[A-Za-z0-9]{12,}/gh_***REDACTED***/g' \
    -e 's/xox[baprs]-[A-Za-z0-9-]{10,}/xox-***REDACTED***/g'
}

resolve_python3() {
  local cand py_ver
  for cand in python3 python; do
    if command -v "${cand}" >/dev/null 2>&1; then
      if py_ver="$("${cand}" --version </dev/null 2>&1)" && printf '%s\n' "${py_ver}" | grep -Eq '^Python 3\.'; then
        command -v "${cand}"
        return 0
      fi
    fi
  done
  printf ''
}

resolve_codex_bin() {
  if [ -n "${CODEX_PATH}" ]; then
    if [ -L "${CODEX_PATH}" ] && [ ! -f "${CODEX_PATH}" ]; then
      echo "[FAIL] Specified --codex-path is a broken symlink: ${CODEX_PATH}" >&2
      return 1
    fi
    if [ ! -f "${CODEX_PATH}" ] || [ ! -x "${CODEX_PATH}" ]; then
      echo "[FAIL] Specified --codex-path is missing or not executable: ${CODEX_PATH}" >&2
      return 1
    fi
    printf '%s' "${CODEX_PATH}"
    return 0
  fi

  local candidate cand_dir
  while IFS= read -r candidate; do
    [ -z "${candidate}" ] && continue
    cand_dir="$(canonicalize_dir "$(dirname -- "${candidate}")")"
    if [ "${cand_dir}" = "${LOCAL_BIN}" ]; then
      continue
    fi
    if [ -f "${candidate}" ] && [ -x "${candidate}" ]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done < <(type -ap codex 2>/dev/null || true)

  printf ''
  return 0
}

# ------------------------------------------------------------------------------
# Safe TOML & auth.json Inspection / Mutation Helpers (Zero Secret Leakage)
# ------------------------------------------------------------------------------

# Return 0 if non-comment plaintext `api_key =` or `experimental_bearer_token =` exists.
has_plaintext_secret_in_toml() {
  local cfg="$1"
  [ -f "${cfg}" ] && [ ! -L "${cfg}" ] || return 1
  awk '
    { sub(/\r$/, "", $0) }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*experimental_bearer_token[[:space:]]*=/ { found = 1; exit }
    /^[[:space:]]*api_key[[:space:]]*=/ { found = 1; exit }
    END { exit(found ? 0 : 1) }
  ' "${cfg}" 2>/dev/null
}

# Detect if Lane 2 config.toml has a custom/third-party top-level `model_provider` override.
# Prints the provider name if overridden, or empty string if using built-in OpenAI.
detect_custom_model_provider() {
  local cfg="$1"
  [ -f "${cfg}" ] && [ ! -L "${cfg}" ] || return 0
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
    BEGIN { in_sec = 0; prov = ""; has_custom_table = 0 }
    {
      sub(/\r$/, "", $0)
      clean = strip_comment($0)
    }
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ {
      in_sec = 1
      sec = clean
      sub(/^[[:space:]]*\[/, "", sec)
      sub(/\][[:space:]]*$/, "", sec)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
      lsec = tolower(sec)
      if (lsec ~ /^model_providers\./) {
        sub(/^model_providers\.[[:space:]]*/, "", lsec)
        gsub(/^["\047]|["\047]$/, "", lsec)
        tables[lsec] = 1
      }
      next
    }
    !in_sec && clean ~ /^[[:space:]]*(model_provider|"model_provider"|\047model_provider\047)[[:space:]]*=/ {
      val = clean
      sub(/^[[:space:]]*(model_provider|"model_provider"|\047model_provider\047)[[:space:]]*=[[:space:]]*/, "", val)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
      gsub(/^["\047]|["\047]$/, "", val)
      prov = val
    }
    END {
      if (prov != "") {
        lprov = tolower(prov)
        if (prov != "openai" || (lprov in tables)) {
          print prov
        }
      }
    }
  ' "${cfg}" 2>/dev/null || true
}

# Atomically strip top-level `model_provider = ...` from config.toml while preserving
# ALL `[projects.*]` trust levels, comments, `[features]`, `[mcp_servers.*]`, etc.
strip_top_level_model_provider() {
  local cfg="$1"
  if [ -L "${cfg}" ]; then
    echo "[FAIL] Security refusal: '${cfg}' is a symlink; refusing to modify." >&2
    exit 1
  fi
  [ -f "${cfg}" ] || return 0

  local stripped
  stripped="$(awk '
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
    BEGIN { in_sec = 0 }
    {
      raw = $0
      sub(/\r$/, "", raw)
      clean = strip_comment(raw)
      if (!in_sec) {
        if (clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/) {
          in_sec = 1
        } else if (clean ~ /^[[:space:]]*(model_provider|"model_provider"|\047model_provider\047)[[:space:]]*=/) {
          next
        }
      }
      print raw
    }
  ' "${cfg}")"

  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${cfg}" 600 < <(printf '%s\n' "${stripped}")
  fi
}

# Validate TOML syntax strictly via Python tomllib (if available).
validate_toml_file() {
  local cfg="$1"
  if [ ! -f "${cfg}" ] || [ -L "${cfg}" ]; then
    echo "[FAIL] Target config.toml missing or symlink: ${cfg}" >&2
    return 1
  fi
  if [ -z "${PY_BIN}" ]; then
    echo "[WARN] Python 3 not available; skipping strict TOML syntax validation." >&2
    return 0
  fi
  local py_out="" py_rc=0
  set +e
  py_out="$("${PY_BIN}" -B - "${cfg}" 2>&1 <<'PY'
import pathlib, sys
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print("NO_TOMLLIB")
        sys.exit(0)
try:
    tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    print("TOML_OK")
except Exception as exc:
    print(f"TOML_ERR:{type(exc).__name__}: {exc}")
    sys.exit(2)
PY
)"
  py_rc=$?
  set -e
  if [ "${py_rc}" -ne 0 ]; then
    local safe_err
    safe_err="$(printf '%s' "${py_out}" | redact_secrets_stream)"
    echo "[FAIL] Invalid TOML syntax in ${cfg}: ${safe_err}" >&2
    return 1
  fi
  case "${py_out}" in
    *NO_TOMLLIB*)
      echo "[WARN] Python tomllib/tomli not available (Python < 3.11); skipped strict TOML parse." >&2
      ;;
    *)
      echo "    [OK] TOML syntax validated cleanly: ${cfg}"
      ;;
  esac
  return 0
}

# Read ONLY safe non-secret metadata from a config.toml into CFG_* globals.
CFG_MODEL_PROVIDER=""
CFG_ENV_KEY=""
CFG_BASE_URL=""
CFG_MODELS_URL=""
CFG_SANDBOX_MODE=""
CFG_APPROVAL_POLICY=""
CFG_HAS_PLAINTEXT=0

read_config_meta() {
  local cfg="$1"
  CFG_MODEL_PROVIDER=""
  CFG_ENV_KEY=""
  CFG_BASE_URL=""
  CFG_MODELS_URL=""
  CFG_SANDBOX_MODE=""
  CFG_APPROVAL_POLICY=""
  CFG_HAS_PLAINTEXT=0

  if [ ! -f "${cfg}" ] || [ -L "${cfg}" ]; then
    return 0
  fi
  if has_plaintext_secret_in_toml "${cfg}"; then
    CFG_HAS_PLAINTEXT=1
  fi

  local parsed=""
  if [ -n "${PY_BIN}" ]; then
    parsed="$("${PY_BIN}" -B - "${cfg}" 2>/dev/null <<'PY' || true
import pathlib, re, sys
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        sys.exit(1)

try:
    data = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
except Exception:
    sys.exit(1)

def clean_val(v, pat, max_len=128):
    if not isinstance(v, str):
        return ""
    v = v.strip()
    if len(v) > max_len or not re.fullmatch(pat, v):
        return ""
    return v

mp = clean_val(data.get("model_provider", ""), r"[A-Za-z0-9_.-]+", 64)
sb = clean_val(data.get("sandbox_mode", ""), r"[A-Za-z0-9_.-]+", 64)
ap_raw = data.get("approval_policy", "")
if isinstance(ap_raw, dict):
    ap = "granular"
else:
    ap = clean_val(ap_raw, r"[A-Za-z0-9_.-]+", 64)

env_key = ""
base_url = ""
models_url = ""
providers = data.get("model_providers")
if mp and isinstance(providers, dict):
    selected = None
    if mp in providers and isinstance(providers[mp], dict):
        selected = providers[mp]
    else:
        for k, v in providers.items():
            if isinstance(k, str) and k.lower() == mp.lower() and isinstance(v, dict):
                selected = v
                break
    if selected is not None:
        ek = selected.get("env_key", "")
        if isinstance(ek, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", ek) and not re.match(r"^(sk-|eyJ|Bearer|ghp_|gho_|xox)", ek):
            env_key = ek
        bu = selected.get("base_url", "")
        if isinstance(bu, str) and re.fullmatch(r"https?://[^\s\"'<>]{1,256}", bu.strip()):
            base_url = bu.strip()
        mu = selected.get("model_catalog_url", "")
        if isinstance(mu, str) and re.fullmatch(r"https?://[^\s\"'<>]{1,256}", mu.strip()):
            models_url = mu.strip()

print(f"MP={mp}")
print(f"EK={env_key}")
print(f"BU={base_url}")
print(f"MU={models_url}")
print(f"SB={sb}")
print(f"AP={ap}")
PY
)"
  fi

  if [ -n "${parsed}" ]; then
    local line
    while IFS= read -r line; do
      line="${line%$'\r'}"
      case "${line}" in
        MP=*) CFG_MODEL_PROVIDER="${line#MP=}" ;;
        EK=*) CFG_ENV_KEY="${line#EK=}" ;;
        BU=*) CFG_BASE_URL="${line#BU=}" ;;
        MU=*) CFG_MODELS_URL="${line#MU=}" ;;
        SB=*) CFG_SANDBOX_MODE="${line#SB=}" ;;
        AP=*) CFG_APPROVAL_POLICY="${line#AP=}" ;;
      esac
    done <<< "${parsed}"
    return 0
  fi

  # Pure-awk fallback when Python tomllib is unavailable.
  parsed="$(awk '
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
    function unquote(v) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      gsub(/^["\047]|["\047]$/, "", v)
      return v
    }
    BEGIN { sec = ""; mp = ""; sb = ""; ap = ""; ek = ""; bu = ""; mu = "" }
    {
      sub(/\r$/, "", $0)
      clean = strip_comment($0)
    }
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ {
      sec = clean
      sub(/^[[:space:]]*\[/, "", sec)
      sub(/\][[:space:]]*$/, "", sec)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
      if (ap == "" && (tolower(sec) == "approval_policy" || index(tolower(sec), "approval_policy.") == 1)) {
        ap = "granular"
      }
      next
    }
    sec == "" && clean ~ /^[[:space:]]*["\047]?model_provider["\047]?[[:space:]]*=/ {
      v = clean; sub(/^[^=]*=/, "", v); mp = unquote(v)
    }
    sec == "" && clean ~ /^[[:space:]]*["\047]?sandbox_mode["\047]?[[:space:]]*=/ {
      v = clean; sub(/^[^=]*=/, "", v); sb = unquote(v)
    }
    sec == "" && clean ~ /^[[:space:]]*["\047]?approval_policy["\047]?[[:space:]]*=/ {
      v = clean; sub(/^[^=]*=/, "", v)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (substr(v, 1, 1) == "{") ap = "granular"
      else ap = unquote(v)
    }
    tolower(sec) ~ /^model_providers\./ {
      pname = tolower(sec)
      sub(/^model_providers\.[[:space:]]*/, "", pname)
      gsub(/^["\047]|["\047]$/, "", pname)
      if (mp != "" && pname == tolower(mp)) {
        if (ek == "" && clean ~ /^[[:space:]]*env_key[[:space:]]*=/) {
          v = clean; sub(/^[^=]*=/, "", v); ek = unquote(v)
        }
        if (bu == "" && clean ~ /^[[:space:]]*base_url[[:space:]]*=/) {
          v = clean; sub(/^[^=]*=/, "", v); bu = unquote(v)
        }
        if (mu == "" && clean ~ /^[[:space:]]*model_catalog_url[[:space:]]*=/) {
          v = clean; sub(/^[^=]*=/, "", v); mu = unquote(v)
        }
      }
    }
    END {
      if (mp ~ /^[A-Za-z0-9_.-]+$/) print "MP=" mp
      if (ek ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && ek !~ /^(sk-|eyJ|Bearer|ghp_|gho_|xox)/) print "EK=" ek
      if (bu ~ /^https?:\/\/[^[:space:]"\047<>]+$/) print "BU=" bu
      if (mu ~ /^https?:\/\/[^[:space:]"\047<>]+$/) print "MU=" mu
      if (sb ~ /^[A-Za-z0-9_.-]+$/) print "SB=" sb
      if (ap ~ /^[A-Za-z0-9_.-]+$/) print "AP=" ap
    }
  ' "${cfg}" 2>/dev/null || true)"
  if [ -n "${parsed}" ]; then
    local line
    while IFS= read -r line; do
      line="${line%$'\r'}"
      case "${line}" in
        MP=*) CFG_MODEL_PROVIDER="${line#MP=}" ;;
        EK=*) CFG_ENV_KEY="${line#EK=}" ;;
        BU=*) CFG_BASE_URL="${line#BU=}" ;;
        MU=*) CFG_MODELS_URL="${line#MU=}" ;;
        SB=*) CFG_SANDBOX_MODE="${line#SB=}" ;;
        AP=*) CFG_APPROVAL_POLICY="${line#AP=}" ;;
      esac
    done <<< "${parsed}"
  fi
}

# Classify active Sandbox 2 CLI permission mode from (sandbox_mode, approval_policy).
classify_cli_mode() {
  local sb="${1:-}"
  local ap="${2:-}"
  if [ "${sb}" = "danger-full-access" ] && [ "${ap}" = "never" ]; then
    printf 'Full Access (Toan quyen — DANGER)'
  elif [ "${sb}" = "workspace-write" ] && [ "${ap}" = "on-request" ]; then
    printf 'Ask (Xin yeu cau)'
  else
    printf 'Config (config.toml: approval=%s, sandbox=%s)' "${ap:-unset}" "${sb:-unset}"
  fi
}

# Print high-visibility ANSI RED/YELLOW danger warning banner modeled on Codex CLI's
# --dangerously-bypass-approvals-and-sandbox warning whenever Full Access is requested.
print_full_access_danger_warning() {
  local c_red="" c_yel="" c_rst=""
  if [ -z "${NO_COLOR:-}" ]; then
    c_red=$'\033[1;31m'
    c_yel=$'\033[1;33m'
    c_rst=$'\033[0m'
  fi
  printf '%s\n' "${c_red}========================================================================${c_rst}"
  printf '%s\n' "${c_red}[!!!] CANH BAO NGUY HIEM — EXTREMELY DANGEROUS (FULL ACCESS MODE) [!!!]${c_rst}"
  printf '%s\n' "${c_red}========================================================================${c_rst}"
  printf '%s\n' "${c_yel}Che do duoc yeu cau: Toan quyen (Full Access) cho Sandbox 2 (Codex CLI)${c_rst}"
  printf '%s\n' "${c_yel}  - sandbox_mode    = \"danger-full-access\"  (TAT HOAN TOAN OS SANDBOX)${c_rst}"
  printf '%s\n' "${c_yel}  - approval_policy = \"never\"               (TAT HOAN TOAN HOI DUYET)${c_rst}"
  printf '\n'
  printf '%s\n' "${c_yel}Rui ro truc tiep tren toan bo may tinh (Host-Wide Risk):${c_rst}"
  printf '%s\n' "${c_yel}  * Codex CLI co the DOC / GHI / XOA bat ky tep nao ben ngoai thu muc${c_rst}"
  printf '%s\n' "${c_yel}    du an va CHAY LENH + TRUY CAP MANG voi toan bo quyen OS user hien tai.${c_rst}"
  printf '%s\n' "${c_yel}  * default.rules chi kiem tra prefix argv truc tiep (KHONG chan duoc${c_rst}"
  printf '%s\n' "${c_yel}    lenh long ben trong bash -c / sh -c / python -c / script).${c_rst}"
  printf '%s\n' "${c_yel}  * KHUYEN NGHI BAT BUOC: Tao Git commit checkpoint (git commit) hoac${c_rst}"
  printf '%s\n' "${c_yel}    chay trong --use-git-worktree / container truoc khi bat che do nay!${c_rst}"
  printf '%s\n' "${c_red}========================================================================${c_rst}"
}

# Atomically upsert ONLY top-level `sandbox_mode` and `approval_policy` in config.toml,
# stripping any conflicting `[approval_policy]` granular table while preserving 100% of
# `[projects.*]` trust levels, `[features]`, `[mcp_servers.*]`, `[plugins.*]`, `[tui]`,
# `[model_providers.*]`, comments, and all other user keys.
upsert_cli_mode_in_toml() {
  local cfg="$1"
  local target_sb="$2"
  local target_ap="$3"
  if [ -L "${cfg}" ]; then
    echo "[FAIL] Security refusal: '${cfg}' is a symlink; refusing to modify." >&2
    exit 1
  fi
  if [ -d "${cfg}" ]; then
    echo "[FAIL] Refusing to modify directory '${cfg}' as config.toml." >&2
    exit 1
  fi
  [ -f "${cfg}" ] || return 1

  local updated
  updated="$(awk -v sb="${target_sb}" -v ap="${target_ap}" '
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
    function emit_missing() {
      if (!wrote_sb) {
        printf "sandbox_mode = \"%s\"\n", sb
        wrote_sb = 1
      }
      if (!wrote_ap) {
        printf "approval_policy = \"%s\"\n", ap
        wrote_ap = 1
      }
    }
    BEGIN { in_sec = 0; skip_sec = 0; wrote_sb = 0; wrote_ap = 0 }
    {
      raw = $0
      sub(/\r$/, "", raw)
      clean = strip_comment(raw)
      if (clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/) {
        if (!in_sec) {
          emit_missing()
          in_sec = 1
        }
        sec = clean
        sub(/^[[:space:]]*\[/, "", sec)
        sub(/\][[:space:]]*$/, "", sec)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
        lsec = tolower(sec)
        if (lsec == "approval_policy" || index(lsec, "approval_policy.") == 1) {
          skip_sec = 1
          next
        }
        skip_sec = 0
        print raw
        next
      }
      if (!in_sec) {
        if (clean ~ /^[[:space:]]*(sandbox_mode|"sandbox_mode"|\047sandbox_mode\047)[[:space:]]*=/) {
          if (!wrote_sb) {
            printf "sandbox_mode = \"%s\"\n", sb
            wrote_sb = 1
          }
          next
        }
        if (clean ~ /^[[:space:]]*(approval_policy|"approval_policy"|\047approval_policy\047)[[:space:]]*=/) {
          if (!wrote_ap) {
            printf "approval_policy = \"%s\"\n", ap
            wrote_ap = 1
          }
          next
        }
        print raw
        next
      }
      if (!skip_sec) {
        print raw
      }
    }
    END {
      if (!in_sec) {
        emit_missing()
      }
    }
  ' "${cfg}")"

  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${cfg}" 600 < <(printf '%s\n' "${updated}")
  fi
}

# Read ONLY safe metadata from auth.json into AUTH_* globals (NEVER raw tokens/keys!).
AUTH_STATUS="missing"
AUTH_MODE="not-logged-in"
AUTH_HAS_API_KEY=0
AUTH_API_KEY_MASKED="NOT_SET"
AUTH_HAS_OAUTH=0

read_auth_meta_safe() {
  local file="$1"
  AUTH_STATUS="missing"
  AUTH_MODE="not-logged-in"
  AUTH_HAS_API_KEY=0
  AUTH_API_KEY_MASKED="NOT_SET"
  AUTH_HAS_OAUTH=0

  if [ -L "${file}" ]; then
    AUTH_STATUS="symlink-warning"
    AUTH_MODE="symlink-warning"
    return 0
  fi
  if [ ! -f "${file}" ]; then
    return 0
  fi
  AUTH_STATUS="ok"

  if [ -n "${PY_BIN}" ]; then
    local py_meta=""
    py_meta="$("${PY_BIN}" -B - "${file}" 2>/dev/null <<'PY' || true
import json, pathlib, re, sys

def mask_key(raw):
    n = len(raw)
    if n == 0:
        return "NOT_SET"
    if n <= 8:
        return f"*** (len={n})"
    if n < 12:
        return f"***...{raw[-2:]} (len={n})"
    if raw.startswith("sk-"):
        return f"sk-...{raw[-4:]} (len={n})"
    return f"{raw[:3]}...{raw[-4:]} (len={n})"

try:
    obj = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
except Exception:
    print("STATUS=unreadable")
    sys.exit(0)

if not isinstance(obj, dict):
    print("STATUS=unreadable")
    sys.exit(0)

raw_mode = obj.get("auth_mode")
if isinstance(raw_mode, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", raw_mode):
    mode = raw_mode
else:
    mode = "present"

api_key = ""
for k in ("OPENAI_API_KEY", "api_key"):
    val = obj.get(k)
    if isinstance(val, str) and val.strip():
        api_key = val.strip()
        break

tokens = obj.get("tokens")
has_oauth = 0
if isinstance(tokens, dict) and any(isinstance(tokens.get(k), str) and tokens.get(k) for k in ("access_token", "refresh_token", "id_token")):
    has_oauth = 1
elif any(isinstance(obj.get(k), str) and obj.get(k) for k in ("access_token", "refresh_token", "token")):
    has_oauth = 1

print("STATUS=ok")
print(f"MODE={mode}")
print(f"HAS_KEY={1 if api_key else 0}")
print(f"MASK={mask_key(api_key)}")
print(f"HAS_OAUTH={has_oauth}")
PY
)"
    if [ -n "${py_meta}" ]; then
      local line
      while IFS= read -r line; do
        line="${line%$'\r'}"
        case "${line}" in
          STATUS=*) AUTH_STATUS="${line#STATUS=}" ;;
          MODE=*) AUTH_MODE="${line#MODE=}" ;;
          HAS_KEY=*) AUTH_HAS_API_KEY="${line#HAS_KEY=}" ;;
          MASK=*) AUTH_API_KEY_MASKED="${line#MASK=}" ;;
          HAS_OAUTH=*) AUTH_HAS_OAUTH="${line#HAS_OAUTH=}" ;;
        esac
      done <<< "${py_meta}"
      return 0
    fi
  fi

  # Pure-awk fallback when Python is unavailable (never prints raw tokens).
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
    AUTH_MODE="${raw_mode}"
  else
    AUTH_MODE="present"
  fi
  if grep -Eq '"(OPENAI_API_KEY|api_key)"[[:space:]]*:[[:space:]]*"[^"]+"' "${file}" 2>/dev/null; then
    AUTH_HAS_API_KEY=1
    AUTH_API_KEY_MASKED="present (masked)"
  fi
  if grep -Eq '"(access_token|refresh_token|id_token|token)"[[:space:]]*:[[:space:]]*"[^"]+"' "${file}" 2>/dev/null; then
    AUTH_HAS_OAUTH=1
  fi
}

# Extract API key from auth.json into memory ONLY for internal stdin piping during --online-check.
# NEVER echoed to stdout/stderr.
extract_auth_api_key_silent() {
  local file="$1"
  if [ -L "${file}" ] || [ ! -f "${file}" ] || [ -z "${PY_BIN}" ]; then
    printf ''
    return 0
  fi
  "${PY_BIN}" -B - "${file}" 2>/dev/null <<'PY' || true
import json, pathlib, sys
try:
    obj = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
except Exception:
    sys.exit(0)
if isinstance(obj, dict):
    for k in ("OPENAI_API_KEY", "api_key"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            sys.stdout.write(v.strip())
            break
PY
}

format_perm_status() {
  local f="$1"
  if [ -L "${f}" ]; then
    printf 'SYMLINK-WARN'
    return 0
  fi
  if [ ! -f "${f}" ]; then
    printf 'N/A'
    return 0
  fi
  if is_windows_msys; then
    printf 'NTFS/MSYS'
    return 0
  fi
  local m
  m="$(get_octal_mode "${f}")"
  if [ -z "${m}" ]; then
    printf 'unknown'
  elif mode_has_group_or_other_bits "${m}"; then
    printf 'EXPOSED(%s; run chmod 600)' "${m}"
  else
    printf '0%s-locked' "${m}"
  fi
}

count_session_index_entries() {
  local home_dir="$1"
  local idx="${home_dir}/session_index.jsonl"
  if [ ! -f "${idx}" ] || [ -L "${idx}" ]; then
    printf '0'
    return 0
  fi
  awk 'NF > 0 { n++ } END { printf "%d", n + 0 }' "${idx}" 2>/dev/null || printf '0'
}

count_session_rollout_files() {
  local home_dir="$1"
  local sdir="${home_dir}/sessions"
  if [ ! -d "${sdir}" ]; then
    printf '0'
    return 0
  fi
  find "${sdir}" -type f -name '*.jsonl' 2>/dev/null | awk 'END { printf "%d", NR + 0 }'
}

# Shared brain symlink health check (6 directories).
check_shared_symlinks_summary() {
  local linked_ok=0
  local issues=""
  local d link_path expected_dir resolved_target
  local shared_dirs=(memories memories_v2 sessions archived_sessions skills plugins)
  for d in "${shared_dirs[@]}"; do
    link_path="${LANE2_HOME}/${d}"
    expected_dir="${LANE1_HOME}/${d}"
    if [ -L "${link_path}" ]; then
      if [ -d "${link_path}" ]; then
        resolved_target="$(canonicalize_dir "${link_path}")"
        if [ "${resolved_target}" = "${expected_dir}" ]; then
          linked_ok=$((linked_ok + 1))
        else
          issues="${issues}${d}(unexpected-target) "
        fi
      else
        issues="${issues}${d}(dangling) "
      fi
    elif [ -d "${link_path}" ]; then
      issues="${issues}${d}(local-dir) "
    else
      issues="${issues}${d}(missing) "
    fi
  done
  if [ -z "${issues}" ]; then
    printf '%d/6 healthy' "${linked_ok}"
  else
    printf '%d/6 healthy; issues: %s' "${linked_ok}" "${issues% }"
  fi
}

# Run bidirectional chat history sync between GPT 1 and Sandbox 2.
# Arg 1: strict_mode ("1" = fail closed if Python/script missing or fails; "0" = best-effort after auth).
run_bidirectional_sync() {
  local strict_mode="${1:-0}"
  local sync_script="${KIT_ROOT}/scripts/sync-sessions.py"

  if [ ! -f "${sync_script}" ]; then
    if [ "${strict_mode}" -eq 1 ]; then
      echo "[FAIL] Missing required sync script: ${sync_script}" >&2
      return 1
    fi
    echo "[WARN] Sync script not found (${sync_script}); skipping automatic chat sync." >&2
    return 0
  fi
  if [ -z "${PY_BIN}" ]; then
    if [ "${strict_mode}" -eq 1 ]; then
      echo "[FAIL] Python 3 is required for scripts/sync-sessions.py." >&2
      return 1
    fi
    echo "[WARN] Python 3 not found; skipping automatic bidirectional chat history sync." >&2
    return 0
  fi
  if [ ! -d "${LANE1_HOME}" ] || [ ! -d "${LANE2_HOME}" ]; then
    if [ "${strict_mode}" -eq 1 ] && [ "${DRY_RUN}" -eq 0 ]; then
      echo "[WARN] Both GPT 1 (${LANE1_HOME}) and Sandbox 2 (${LANE2_HOME}) should exist before syncing." >&2
    fi
    if [ "${strict_mode}" -eq 0 ]; then
      echo "    [INFO] Skipping automatic chat sync until both lanes exist."
      return 0
    fi
  fi

  local sync_args=("${sync_script}" --source "${LANE1_HOME}" --target "${LANE2_HOME}" --bidirectional --backup-target)
  [ "${DRY_RUN}" -eq 1 ] && sync_args+=(--dry-run)
  echo "[+] Running bidirectional chat history sync (GPT 1 <-> Sandbox 2)..."
  "${PY_BIN}" -B "${sync_args[@]}"
}

# ------------------------------------------------------------------------------
# Actions
# ------------------------------------------------------------------------------

# [1a] OpenAI / GPT API Key for Sandbox 2
action_api_gpt() {
  echo "=== [1a] Configure OpenAI / GPT API Key for Sandbox 2 (${LANE2_HOME}) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files on disk will be modified."

  local codex_bin
  codex_bin="$(resolve_codex_bin)"
  if [ -z "${codex_bin}" ]; then
    echo "[FAIL] No 'codex' binary found in PATH (or via --codex-path). Install '@openai/codex' first." >&2
    return 1
  fi

  if [ -L "${LANE2_HOME}" ]; then
    echo "[FAIL] Security refusal: LANE2_HOME '${LANE2_HOME}' is a symlink." >&2
    return 1
  fi

  local api_key=""
  if [ "${API_KEY_FROM_STDIN}" -eq 1 ]; then
    IFS= read -r api_key || true
  elif [ "${NON_INTERACTIVE}" -eq 1 ]; then
    echo "[FAIL] --action api-gpt in --non-interactive mode requires --api-key-from-stdin (plaintext CLI args are forbidden)." >&2
    return 1
  else
    printf 'Nhap OpenAI / GPT API Key cho Sandbox 2 (input an / masked): ' >&2
    IFS= read -r -s api_key || true
    printf '\n' >&2
  fi

  # Trim CR and leading/trailing whitespace.
  api_key="${api_key%$'\r'}"
  api_key="$(printf '%s' "${api_key}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  if [ -z "${api_key}" ]; then
    echo "[FAIL] Empty API key provided; aborting." >&2
    return 1
  fi
  if printf '%s' "${api_key}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    api_key=""
    echo "[FAIL] API key contains invalid control characters; aborting." >&2
    return 1
  fi

  local masked_preview
  masked_preview="$(mask_secret "${api_key}")"
  echo "[+] API key received safely: ${masked_preview}"

  if [ "${DRY_RUN}" -eq 0 ]; then
    mkdir -p -- "${LANE2_HOME}"
    chmod 700 "${LANE2_HOME}" 2>/dev/null || true
  fi

  local cfg2="${LANE2_HOME}/config.toml"
  if [ -L "${cfg2}" ]; then
    api_key=""
    echo "[FAIL] Security refusal: '${cfg2}' is a symlink." >&2
    return 1
  fi
  if [ -f "${cfg2}" ]; then
    backup_file_0600 "${cfg2}"
    local custom_prov=""
    custom_prov="$(detect_custom_model_provider "${cfg2}")"
    if [ -n "${custom_prov}" ]; then
      if [ "${DRY_RUN}" -eq 0 ]; then
        strip_top_level_model_provider "${cfg2}"
        echo "    Cleared conflicting third-party model_provider ('${custom_prov}') from ${cfg2} (preserved [projects.*] & user sections)."
      else
        echo "    [DRY-RUN] Would clear third-party model_provider ('${custom_prov}') from ${cfg2} while preserving [projects.*]."
      fi
    fi
  fi

  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "    [DRY-RUN] Would pipe masked key (${masked_preview}) via stdin to: CODEX_HOME=\"${LANE2_HOME}\" \"${codex_bin}\" login --with-api-key"
    api_key=""
  else
    echo "[+] Authenticating Sandbox 2 via 'codex login --with-api-key' (stdin pipe)..."
    local login_out="" login_rc=0
    set +e
    login_out="$(printf '%s\n' "${api_key}" | CODEX_HOME="${LANE2_HOME}" "${codex_bin}" login --with-api-key 2>&1)"
    login_rc=$?
    set -e

    # Pure-Bash check ensures arbitrary key canaries can NEVER leak in output.
    case "${login_out}" in
      *"${api_key}"*)
        login_out="[output redacted to prevent secret exposure]"
        ;;
    esac
    api_key=""
    unset api_key

    if [ -n "${login_out}" ]; then
      printf '%s\n' "${login_out}" | redact_secrets_stream
    fi
    if [ "${login_rc}" -ne 0 ]; then
      echo "[FAIL] 'codex login --with-api-key' failed with exit code ${login_rc}." >&2
      return "${login_rc}"
    fi
  fi

  lock_file_0600 "${LANE2_HOME}/auth.json"
  lock_file_0600 "${cfg2}"

  run_bidirectional_sync 0
  echo "[OK] Sandbox 2 OpenAI / GPT API Key configured cleanly."
}

# [1b] Other Provider / Custom Gateway -> Edit Lane 2 config.toml directly
action_api_other() {
  echo "=== [1b] Configure Other Provider / Custom Gateway (${LANE2_HOME}/config.toml) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files on disk will be modified."

  if [ -L "${LANE2_HOME}" ]; then
    echo "[FAIL] Security refusal: LANE2_HOME '${LANE2_HOME}' is a symlink." >&2
    return 1
  fi
  if [ "${DRY_RUN}" -eq 0 ]; then
    mkdir -p -- "${LANE2_HOME}"
    chmod 700 "${LANE2_HOME}" 2>/dev/null || true
  fi

  local cfg2="${LANE2_HOME}/config.toml"
  if [ -L "${cfg2}" ]; then
    echo "[FAIL] Security refusal: '${cfg2}' is a symlink; refusing to edit." >&2
    return 1
  fi
  if [ -d "${cfg2}" ]; then
    echo "[FAIL] Refusing to edit directory '${cfg2}' as config.toml." >&2
    return 1
  fi

  if [ -f "${cfg2}" ]; then
    backup_file_0600 "${cfg2}"
  elif [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${cfg2}" 600 <<'EOF'
# Sandbox 2 (Codex CLI) configuration
# Use env_key (NEVER hardcode plaintext api_key) for third-party / custom gateways:
#
# model_provider = "CustomGateway"
# model = "gpt-5"
#
# [model_providers."CustomGateway"]
# name = "CustomGateway"
# base_url = "https://your-gateway.example/v1"
# wire_api = "responses"
# env_key = "CODEX_GATEWAY_API_KEY"
sandbox_mode = "workspace-write"
approval_policy = "on-request"
EOF
    echo "    Initialized starter config: ${cfg2}"
  else
    echo "    [DRY-RUN] Would initialize starter config: ${cfg2}"
  fi

  cat <<EOF

Target config file:
  ${cfg2}

Recommended safe custom-provider template (uses env_key — ZERO plaintext secrets):
  model_provider = "CustomGateway"
  model = "gpt-5"

  [model_providers."CustomGateway"]
  name = "CustomGateway"
  base_url = "https://your-gateway.example/v1"
  wire_api = "responses"
  env_key = "CODEX_GATEWAY_API_KEY"

Then export the key in your shell profile (outside config.toml):
  export CODEX_GATEWAY_API_KEY="<your-key>"

EOF

  local chosen_editor=""
  if [ -n "${EDITOR_CMD}" ]; then
    chosen_editor="${EDITOR_CMD}"
  elif [ "${NON_INTERACTIVE}" -eq 0 ]; then
    chosen_editor="${VISUAL:-${EDITOR:-vi}}"
    if ! command -v "${chosen_editor%% *}" >/dev/null 2>&1 && command -v nano >/dev/null 2>&1; then
      chosen_editor="nano"
    fi
  fi

  if [ -n "${chosen_editor}" ]; then
    if [ "${DRY_RUN}" -eq 1 ]; then
      echo "    [DRY-RUN] Would open ${cfg2} with editor: ${chosen_editor}"
    else
      echo "[+] Opening ${cfg2} with editor: ${chosen_editor}"
      if [ -f "${chosen_editor}" ] && [ -x "${chosen_editor}" ]; then
        "${chosen_editor}" "${cfg2}"
      else
        local editor_parts=()
        read -r -a editor_parts <<< "${chosen_editor}"
        if [ "${#editor_parts[@]}" -eq 0 ]; then
          echo "[FAIL] Invalid --editor command." >&2
          return 1
        fi
        "${editor_parts[@]}" "${cfg2}"
      fi
    fi
  else
    echo "    [INFO] Non-interactive mode without --editor: running post-edit validation directly."
  fi

  if [ -f "${cfg2}" ]; then
    validate_toml_file "${cfg2}"
    if has_plaintext_secret_in_toml "${cfg2}"; then
      echo "[WARN] SECURITY WARNING: Plaintext 'api_key' or 'experimental_bearer_token' detected in ${cfg2}!" >&2
      echo "[WARN] Strongly recommend replacing plaintext keys with env_key = \"YOUR_ENV_VAR\" so secrets stay out of config.toml." >&2
    fi
    lock_file_0600 "${cfg2}"
  fi

  run_bidirectional_sync 0
  echo "[OK] Sandbox 2 custom provider configuration verified."
}

# [2] Official OpenAI / ChatGPT Login for Sandbox 2
action_login() {
  echo "=== [2] Official OpenAI / ChatGPT Login for Sandbox 2 (${LANE2_HOME}) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files on disk will be modified."

  local codex_bin
  codex_bin="$(resolve_codex_bin)"
  if [ -z "${codex_bin}" ]; then
    echo "[FAIL] No 'codex' binary found in PATH (or via --codex-path). Install '@openai/codex' first." >&2
    return 1
  fi

  if [ -L "${LANE2_HOME}" ]; then
    echo "[FAIL] Security refusal: LANE2_HOME '${LANE2_HOME}' is a symlink." >&2
    return 1
  fi
  if [ "${DRY_RUN}" -eq 0 ]; then
    mkdir -p -- "${LANE2_HOME}"
    chmod 700 "${LANE2_HOME}" 2>/dev/null || true
  fi

  local cfg2="${LANE2_HOME}/config.toml"
  if [ -f "${cfg2}" ] && [ ! -L "${cfg2}" ]; then
    local custom_prov=""
    custom_prov="$(detect_custom_model_provider "${cfg2}")"
    if [ -n "${custom_prov}" ]; then
      local should_clear=0
      if [ "${FORCE}" -eq 1 ]; then
        should_clear=1
      elif [ "${NON_INTERACTIVE}" -eq 1 ]; then
        echo "[WARN] Third-party model_provider ('${custom_prov}') found in ${cfg2}; pass --force to clear it automatically before login." >&2
      else
        local ans=""
        printf "Phat hien model_provider = '%s' trong %s (co the xung dot voi login chinh thuc). Xoa truoc khi login? [Y/n]: " "${custom_prov}" "${cfg2}" >&2
        IFS= read -r ans || true
        case "$(to_lower "${ans}")" in
          ""|y|yes) should_clear=1 ;;
          *) should_clear=0 ;;
        esac
      fi

      if [ "${should_clear}" -eq 1 ]; then
        backup_file_0600 "${cfg2}"
        if [ "${DRY_RUN}" -eq 0 ]; then
          strip_top_level_model_provider "${cfg2}"
          echo "    Cleared conflicting model_provider ('${custom_prov}') from ${cfg2} (preserved [projects.*] & user sections)."
        else
          echo "    [DRY-RUN] Would clear model_provider ('${custom_prov}') from ${cfg2}."
        fi
      fi
    fi
  fi

  local login_args=(login)
  if [ "${DEVICE_AUTH}" -eq 1 ]; then
    login_args+=(--device-auth)
  fi

  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "    [DRY-RUN] Would run: CODEX_HOME=\"${LANE2_HOME}\" \"${codex_bin}\" ${login_args[*]}"
  else
    echo "[+] Launching official login: CODEX_HOME=\"${LANE2_HOME}\" codex ${login_args[*]}"
    if [ "${NON_INTERACTIVE}" -eq 1 ]; then
      local out="" rc=0
      set +e
      out="$(CODEX_HOME="${LANE2_HOME}" "${codex_bin}" "${login_args[@]}" 2>&1)"
      rc=$?
      set -e
      if [ -n "${out}" ]; then
        printf '%s\n' "${out}" | redact_secrets_stream
      fi
      if [ "${rc}" -ne 0 ]; then
        echo "[FAIL] 'codex ${login_args[*]}' failed with exit code ${rc}." >&2
        return "${rc}"
      fi
    else
      CODEX_HOME="${LANE2_HOME}" "${codex_bin}" "${login_args[@]}"
    fi
  fi

  lock_file_0600 "${LANE2_HOME}/auth.json"
  lock_file_0600 "${cfg2}"

  run_bidirectional_sync 0
  echo "[OK] Official OpenAI / ChatGPT login flow completed for Sandbox 2."
}

# [3] Check API Key (Read-Only Local Inspection + Optional Online /models Probe)
action_check_api_key() {
  echo "=== [3] Check Sandbox 2 API Key (${LANE2_HOME}) — Read-Only ==="

  local cfg2="${LANE2_HOME}/config.toml"
  local auth2="${LANE2_HOME}/auth.json"

  read_config_meta "${cfg2}"
  read_auth_meta_safe "${auth2}"

  local active_provider="${CFG_MODEL_PROVIDER:-openai (built-in)}"
  local base_url="${CFG_BASE_URL:-https://api.openai.com/v1}"
  local probe_url=""
  if [ -n "${CFG_MODELS_URL}" ]; then
    probe_url="${CFG_MODELS_URL}"
  else
    probe_url="${base_url%/}/models"
  fi

  echo "  Active Provider    : ${active_provider}"
  echo "  Target Base URL    : ${base_url}"
  echo "  Models Probe URL   : ${probe_url}"

  local env_key_val=""
  if [ -n "${CFG_ENV_KEY}" ] && printf '%s' "${CFG_ENV_KEY}" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
    # CFG_ENV_KEY is strictly validated as ^[A-Za-z_][A-Za-z0-9_]*$.
    env_key_val="${!CFG_ENV_KEY:-}"
    echo "  config.toml env_key: ${CFG_ENV_KEY} -> $(mask_secret "${env_key_val}")"
  else
    echo "  config.toml env_key: (none configured)"
  fi

  local openai_env_val="${OPENAI_API_KEY:-}"
  echo "  OPENAI_API_KEY env : $(mask_secret "${openai_env_val}")"

  if [ "${AUTH_STATUS}" = "missing" ]; then
    echo "  auth.json          : missing"
  elif [ "${AUTH_STATUS}" = "symlink-warning" ]; then
    echo "  auth.json          : [WARN] SYMLINK detected!"
  else
    echo "  auth.json          : auth_mode=${AUTH_MODE} | api_key=${AUTH_API_KEY_MASKED} | oauth_tokens=$([ "${AUTH_HAS_OAUTH}" -eq 1 ] && echo yes || echo no)"
  fi

  echo "  Permissions        : config.toml=$(format_perm_status "${cfg2}") | auth.json=$(format_perm_status "${auth2}")"

  if [ "${CFG_HAS_PLAINTEXT}" -eq 1 ]; then
    echo "  [WARN] SECURITY WARNING: Plaintext 'api_key' or 'experimental_bearer_token' detected in ${cfg2}! Switch to env_key." >&2
  else
    echo "  Plaintext Check    : clean (no hardcoded api_key/bearer_token in config.toml)"
  fi

  # Select effective key for optional live /models probe (in memory only, never echoed).
  local probe_source=""
  local probe_key=""
  if [ -n "${CFG_MODEL_PROVIDER}" ] && [ -n "${CFG_ENV_KEY}" ]; then
    probe_source="env_key(${CFG_ENV_KEY})"
    probe_key="${env_key_val}"
  elif [ -n "${CFG_ENV_KEY}" ] && [ -n "${env_key_val}" ]; then
    probe_source="env_key(${CFG_ENV_KEY})"
    probe_key="${env_key_val}"
  elif [ "${AUTH_HAS_API_KEY}" -eq 1 ]; then
    probe_source="auth.json"
    probe_key="$(extract_auth_api_key_silent "${auth2}")"
  elif [ -n "${openai_env_val}" ]; then
    probe_source="OPENAI_API_KEY"
    probe_key="${openai_env_val}"
  fi

  local do_online="${ONLINE_CHECK}"
  if [ "${do_online}" -eq 0 ] && [ "${NON_INTERACTIVE}" -eq 0 ]; then
    local ans=""
    printf 'Thu kiem tra ket noi truc tuyen (GET %s)? [y/N]: ' "${probe_url}" >&2
    IFS= read -r ans || true
    case "$(to_lower "${ans}")" in
      y|yes) do_online=1 ;;
    esac
  fi

  if [ "${do_online}" -eq 1 ]; then
    if [ -z "${probe_key}" ]; then
      echo "  Online Probe       : SKIPPED (no active API key configured)"
    elif [ -z "${PY_BIN}" ]; then
      probe_key=""
      echo "  Online Probe       : SKIPPED (Python 3 required for argv-safe urllib probe)"
    else
      local probe_result=""
      # Pass API key strictly via Bash builtin printf -> stdin pipe (ZERO exposure in ps / argv / env!).
      probe_result="$(printf '%s\n' "${probe_key}" | "${PY_BIN}" -B -c '
import json, sys, urllib.error, urllib.parse, urllib.request
url = sys.argv[1]
key = sys.stdin.read().strip()
try:
    parsed_url = urllib.parse.urlsplit(url)
    scheme = parsed_url.scheme.lower()
    host = (parsed_url.hostname or "").lower()
except Exception:
    print("NETWORK_ERROR (invalid_url)")
    sys.exit(0)
# SECURITY: the Bearer key is only ever sent over HTTPS. Plain HTTP is allowed solely for loopback
# hosts (local mock servers / tests); any other http:// URL is refused BEFORE a request is built.
if scheme == "https" and host:
    pass
elif scheme == "http" and host in ("127.0.0.1", "localhost", "::1"):
    pass
else:
    print("REFUSED (https_required: API key is never sent over plain HTTP to non-loopback hosts)")
    sys.exit(0)
if parsed_url.username or parsed_url.password:
    print("REFUSED (credentials_in_url_not_allowed)")
    sys.exit(0)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # SECURITY: never follow redirects while carrying the Authorization header.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(_NoRedirect())
req = urllib.request.Request(
    url,
    headers={"Authorization": f"Bearer {key}", "Accept": "application/json", "User-Agent": "codex-dual-lane-manager/1.4"},
    method="GET",
)
try:
    with opener.open(req, timeout=10) as resp:
        code = resp.getcode()
        # RESOURCE GUARD: cap response body read at 2 MiB so an oversized/streaming endpoint cannot OOM Python.
        max_bytes = 2 * 1024 * 1024
        raw = resp.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        if truncated:
            print(f"VALID (HTTP {code}, response >2 MiB truncated)")
        else:
            body = raw.decode("utf-8", errors="replace")
            n_models = None
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict) and isinstance(parsed.get("data"), list):
                    n_models = len(parsed["data"])
                elif isinstance(parsed, list):
                    n_models = len(parsed)
            except Exception:
                pass
            if n_models is not None:
                print(f"VALID (HTTP {code}, {n_models} models)")
            else:
                print(f"VALID (HTTP {code})")
except urllib.error.HTTPError as e:
    if e.code in (401, 403):
        print(f"INVALID/EXPIRED (HTTP {e.code})")
    elif e.code == 429:
        print(f"QUOTA/RATE_LIMITED (HTTP {e.code})")
    elif 300 <= e.code < 400:
        print(f"REDIRECT_BLOCKED (HTTP {e.code}: redirects are never followed with an API key)")
    else:
        print(f"HTTP_ERROR (HTTP {e.code})")
except Exception as e:
    print(f"NETWORK_ERROR ({type(e).__name__})")
' "${probe_url}" 2>/dev/null || echo "NETWORK_ERROR (probe_failed)")"
      probe_result="${probe_result%$'\r'}"
      # Pure-Bash defense-in-depth ensuring probe_key never appears in output.
      case "${probe_result}" in
        *"${probe_key}"*) probe_result="NETWORK_ERROR (redacted)" ;;
      esac
      probe_key=""
      echo "  Online Probe       : ${probe_result} [source=${probe_source}]"
    fi
  fi

  probe_key=""
  env_key_val=""
  openai_env_val=""
  return 0
}

# Helper for [4] Check Accounts (strictly read-only for one lane)
inspect_lane_readonly() {
  local title="$1"
  local lane_dir="$2"
  local codex_bin="$3"

  echo "--- ${title} (${lane_dir}) ---"
  if [ -L "${lane_dir}" ]; then
    echo "  Directory       : [WARN] SYMLINK detected!"
    return 0
  fi
  if [ ! -d "${lane_dir}" ]; then
    echo "  Directory       : NOT_FOUND"
    return 0
  fi

  local cfg="${lane_dir}/config.toml"
  local auth="${lane_dir}/auth.json"
  read_config_meta "${cfg}"
  read_auth_meta_safe "${auth}"

  local login_status="codex-not-found"
  if [ -n "${codex_bin}" ]; then
    local raw_st=""
    raw_st="$(CODEX_HOME="${lane_dir}" "${codex_bin}" login status 2>&1 || true)"
    raw_st="$(printf '%s\n' "${raw_st}" | redact_secrets_stream | tr '\r\n' ' ' | sed -e 's/[[:space:]]\{2,\}/ /g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -n "${raw_st}" ]; then
      login_status="${raw_st}"
    else
      login_status="(no output)"
    fi
  fi

  local env_state="none"
  if [ -n "${CFG_ENV_KEY}" ] && printf '%s' "${CFG_ENV_KEY}" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
    if [ -n "${!CFG_ENV_KEY:-}" ]; then
      env_state="${CFG_ENV_KEY} (SET)"
    else
      env_state="${CFG_ENV_KEY} (NOT_SET)"
    fi
  fi

  local idx_count file_count
  idx_count="$(count_session_index_entries "${lane_dir}")"
  file_count="$(count_session_rollout_files "${lane_dir}")"

  echo "  codex status    : ${login_status}"
  echo "  auth.json       : status=${AUTH_STATUS} | auth_mode=${AUTH_MODE} | api_key=${AUTH_API_KEY_MASKED} | oauth=$([ "${AUTH_HAS_OAUTH}" -eq 1 ] && echo yes || echo no)"
  echo "  config.toml     : model_provider=${CFG_MODEL_PROVIDER:-openai(default)} | env_key=${env_state} | sandbox=${CFG_SANDBOX_MODE:-default} | approval=${CFG_APPROVAL_POLICY:-default}"
  case "${title}" in
    "Sandbox 2"*)
      echo "  CLI Mode        : $(classify_cli_mode "${CFG_SANDBOX_MODE}" "${CFG_APPROVAL_POLICY}")"
      ;;
  esac
  if [ "${CFG_HAS_PLAINTEXT}" -eq 1 ]; then
    echo "  Secret Hygiene  : [WARN] Plaintext api_key/bearer_token present in config.toml!"
  else
    echo "  Secret Hygiene  : clean"
  fi
  echo "  Permissions     : config.toml=$(format_perm_status "${cfg}") | auth.json=$(format_perm_status "${auth}")"
  echo "  Chat Sessions   : session_index=${idx_count} entries | rollout_files=${file_count}"
}

# [4] Check Existing Accounts (Strictly Read-Only on BOTH GPT 1 and Sandbox 2)
action_check_accounts() {
  echo "=== [4] Check Accounts & Health (Read-Only: GPT 1 & Sandbox 2) ==="
  local codex_bin=""
  codex_bin="$(resolve_codex_bin || true)"

  inspect_lane_readonly "GPT 1 (Codex Desktop)" "${LANE1_HOME}" "${codex_bin}"
  echo ""
  inspect_lane_readonly "Sandbox 2 (Codex CLI)" "${LANE2_HOME}" "${codex_bin}"
  echo ""
  echo "--- Shared Brain Symlinks (Sandbox 2 -> GPT 1) ---"
  echo "  Shared Symlinks : $(check_shared_symlinks_summary)"
  return 0
}

# [5] Bidirectional Chat History Sync
action_sync_history() {
  echo "=== [5] Bidirectional Chat History Sync (GPT 1 <-> Sandbox 2) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] Inspecting sync without mutating disk."
  run_bidirectional_sync 1
  echo "[OK] Bidirectional chat history sync completed."
}

# [6] Safe Uninstall Sandbox 2 WITHOUT Deleting Chat History
action_remove_sandbox2() {
  echo "=== [6] Safe Remove Sandbox 2 (History-Preserving -> GPT 1) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] Previewing rescue & uninstall without mutating disk."

  local sync_script="${KIT_ROOT}/scripts/sync-sessions.py"
  local restore_script="${KIT_ROOT}/scripts/restore-original.sh"

  if [ ! -f "${sync_script}" ]; then
    echo "[FAIL] Missing required sync script: ${sync_script}. Refusing to delete Sandbox 2 without rescuing chat history." >&2
    return 1
  fi
  if [ ! -f "${restore_script}" ]; then
    echo "[FAIL] Missing required restore script: ${restore_script}." >&2
    return 1
  fi
  if [ -z "${PY_BIN}" ]; then
    echo "[FAIL] Python 3 is required to rescue Sandbox 2 chat history into GPT 1 before removal. Aborting fail-closed." >&2
    return 1
  fi

  if [ "${FORCE}" -eq 0 ] && [ "${DRY_RUN}" -eq 0 ]; then
    if [ "${NON_INTERACTIVE}" -eq 1 ]; then
      echo "[FAIL] --action remove-sandbox2 requires --force in --non-interactive mode (or use --dry-run to preview)." >&2
      return 1
    fi
    cat <<EOF
Thao tac nay se:
  1. CUU & DONG BO 100% lich su chat, Pinned, Goals va cac file rollout/memory cuc bo tu Sandbox 2 (${LANE2_HOME}) ve GPT 1 (${LANE1_HOME}).
  2. Thao an toan toan bo symlink dung chung (xac minh 0 symlink con lai) va go wrapper CLI trong ${LOCAL_BIN}.
  3. Xoa thu muc Sandbox 2 (${LANE2_HOME}) — GIU NGUYEN 100% du lieu GPT 1 (${LANE1_HOME}).

EOF
    local confirm=""
    printf "Nhap 'YES' de xac nhan xoa Sandbox 2: " >&2
    IFS= read -r confirm || true
    if [ "${confirm}" != "YES" ] && [ "${confirm}" != "yes" ]; then
      echo "[INFO] Cancelled by user; no changes made."
      return 0
    fi
  fi

  # Step 1 (Mandatory, fail-closed): Rescue 100% of Sandbox 2 chat history back into GPT 1 BEFORE removing Sandbox 2!
  echo "[+] Step 1/3: Rescuing Sandbox 2 chat history & local shared files into GPT 1 (${LANE1_HOME})..."
  if [ -d "${LANE2_HOME}" ]; then
    if [ "${DRY_RUN}" -eq 0 ] && [ ! -d "${LANE1_HOME}" ]; then
      mkdir -p -- "${LANE1_HOME}"
      chmod 700 "${LANE1_HOME}" 2>/dev/null || true
    fi
    local rescue_args=("${sync_script}" --source "${LANE2_HOME}" --target "${LANE1_HOME}" --rescue-shared-files --backup-target --strict)
    [ "${DRY_RUN}" -eq 1 ] && rescue_args+=(--dry-run)
    local rescue_out=""
    local rescue_rc=0
    rescue_out="$("${PY_BIN}" -B "${rescue_args[@]}" 2>&1)" || rescue_rc=$?
    if [ -n "${rescue_out}" ]; then
      printf '%s\n' "${rescue_out}"
    fi
    if [ "${rescue_rc}" -ne 0 ] || printf '%s\n' "${rescue_out}" | grep -Eq 'status=(FAILED|PARTIAL)|reconcile=MISMATCH'; then
      echo "[FAIL] Chat history rescue failed or returned PARTIAL/FAILED (source SQLite DB unreadable/locked/corrupt or reconciliation mismatch). Aborting Sandbox 2 removal to protect your chat history!" >&2
      return 1
    fi
  else
    echo "    Sandbox 2 directory (${LANE2_HOME}) does not exist; skipping rescue step."
  fi

  # Step 2: Unlink all symlinks safely & remove Sandbox 2 via restore-original.sh --remove-lane2-home
  echo "[+] Step 2/3: Unlinking shared symlinks & removing Sandbox 2 via restore-original.sh..."
  local restore_args=(--remove-lane2-home)
  [ "${DRY_RUN}" -eq 1 ] && restore_args+=(--dry-run)
  CODEX_LANE1_HOME="${LANE1_HOME}" \
  CODEX_LANE2_HOME="${LANE2_HOME}" \
  CODEX_LOCAL_BIN="${LOCAL_BIN}" \
    bash "${restore_script}" "${restore_args[@]}"

  # Step 3: Verify GPT 1 chat history remains intact!
  echo "[+] Step 3/3: Verifying GPT 1 (${LANE1_HOME}) chat history remains intact..."
  if [ ! -d "${LANE1_HOME}" ]; then
    echo "[FAIL] GPT 1 directory '${LANE1_HOME}' is missing after uninstall!" >&2
    return 1
  fi
  if [ "${DRY_RUN}" -eq 0 ] && [ -e "${LANE2_HOME}" ]; then
    echo "[FAIL] Expected Sandbox 2 directory '${LANE2_HOME}' to be removed, but it still exists." >&2
    return 1
  fi

  local l1_idx l1_files
  l1_idx="$(count_session_index_entries "${LANE1_HOME}")"
  l1_files="$(count_session_rollout_files "${LANE1_HOME}")"
  echo "    Verified GPT 1 intact: ${LANE1_HOME} (session_index=${l1_idx} entries, rollout_files=${l1_files})"
  if [ "${DRY_RUN}" -eq 0 ]; then
    echo "[OK] Sandbox 2 removed safely; 100% of chat history preserved in GPT 1!"
  else
    echo "[OK] [DRY-RUN] Preview complete; zero files modified."
  fi
}

# [7] Configure Sandbox 2 Permission Mode (Ask / Config / Full Access)
action_set_cli_mode() {
  echo "=== [7] Chon Che do Quyen Sandbox 2 (Codex CLI: ${LANE2_HOME}/config.toml) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files on disk will be modified."

  if [ -L "${LANE2_HOME}" ]; then
    echo "[FAIL] Security refusal: LANE2_HOME '${LANE2_HOME}' is a symlink." >&2
    return 1
  fi
  local cfg2="${LANE2_HOME}/config.toml"
  if [ -L "${cfg2}" ]; then
    echo "[FAIL] Security refusal: '${cfg2}' is a symlink; refusing to modify." >&2
    return 1
  fi
  if [ -d "${cfg2}" ]; then
    echo "[FAIL] Refusing to treat directory '${cfg2}' as config.toml." >&2
    return 1
  fi

  read_config_meta "${cfg2}"
  echo "  Current CLI Mode : $(classify_cli_mode "${CFG_SANDBOX_MODE}" "${CFG_APPROVAL_POLICY}")"

  local chosen_mode="${CLI_MODE}"
  if [ -z "${chosen_mode}" ]; then
    if [ "${NON_INTERACTIVE}" -eq 1 ]; then
      echo "[FAIL] --action set-cli-mode in --non-interactive mode requires --cli-mode <ask|config|full-access>." >&2
      return 1
    fi
    cat <<EOF

Chon che do quyen cho Sandbox 2 (Codex CLI):
  [1] Xin yeu cau (Ask)
      approval_policy = "on-request", sandbox_mode = "workspace-write"
      (nam gon trong thu muc du an, chi tham khao thuat toan ben ngoai o che do chi-doc)
  [2] Thuoc cau hinh config.toml (Config)
      Giu nguyen approval_policy / sandbox_mode trong ${cfg2}
      (tuy chon mo chinh truc tiep + kiem tra TOML + khoa 0600)
  [3] Toan quyen (Full Access — DANGER)
      approval_policy = "never", sandbox_mode = "danger-full-access"
      (CANH BAO NGUY HIEM — tat sandbox & tat hoi duyet; yeu cau xac nhan 'TOAN QUYEN')
  [0] Huy (Cancel)

EOF
    local sel=""
    printf 'Chon che do [1/2/3/0]: ' >&2
    IFS= read -r sel || true
    sel="$(to_lower "$(printf '%s' "${sel%$'\r'}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')")"
    case "${sel}" in
      1|ask) chosen_mode="ask" ;;
      2|config) chosen_mode="config" ;;
      3|full-access|fullaccess) chosen_mode="full-access" ;;
      0|q|quit|cancel|"")
        echo "[INFO] Cancelled by user; no changes made."
        return 0
        ;;
      *)
        echo "[FAIL] Lua chon khong hop le: '${sel}' (chon 1, 2, 3, hoac 0)." >&2
        return 1
        ;;
    esac
  fi

  case "${chosen_mode}" in
    ask)
      if [ "${DRY_RUN}" -eq 0 ]; then
        mkdir -p -- "${LANE2_HOME}"
        chmod 700 "${LANE2_HOME}" 2>/dev/null || true
      fi
      if [ -f "${cfg2}" ]; then
        backup_file_0600 "${cfg2}"
        if [ "${DRY_RUN}" -eq 0 ]; then
          upsert_cli_mode_in_toml "${cfg2}" "workspace-write" "on-request"
          echo "    Updated ${cfg2}: approval_policy=\"on-request\", sandbox_mode=\"workspace-write\" (preserved [projects.*] & user sections)."
        else
          echo "    [DRY-RUN] Would set approval_policy=\"on-request\" and sandbox_mode=\"workspace-write\" in ${cfg2}."
        fi
      elif [ "${DRY_RUN}" -eq 0 ]; then
        atomic_write_from_stdin "${cfg2}" 600 <<'EOF'
# Sandbox 2 (Codex CLI) configuration — Ask mode (Xin yeu cau)
sandbox_mode = "workspace-write"
approval_policy = "on-request"
EOF
        echo "    Initialized ${cfg2} in Ask mode."
      else
        echo "    [DRY-RUN] Would initialize ${cfg2} in Ask mode."
      fi
      if [ "${DRY_RUN}" -eq 0 ] && [ -f "${cfg2}" ]; then
        validate_toml_file "${cfg2}"
        lock_file_0600 "${cfg2}"
      fi
      run_bidirectional_sync 0
      echo "[OK] Sandbox 2 CLI mode set to Ask (Xin yeu cau: approval_policy=on-request, sandbox_mode=workspace-write)."
      ;;

    config)
      if [ ! -f "${cfg2}" ]; then
        if [ "${DRY_RUN}" -eq 0 ]; then
          mkdir -p -- "${LANE2_HOME}"
          chmod 700 "${LANE2_HOME}" 2>/dev/null || true
          atomic_write_from_stdin "${cfg2}" 600 <<'EOF'
# Sandbox 2 (Codex CLI) configuration — Config mode (config.toml is source of truth)
sandbox_mode = "workspace-write"
approval_policy = "on-request"
EOF
          echo "    Initialized starter config: ${cfg2}"
        else
          echo "    [DRY-RUN] Would initialize starter config: ${cfg2}"
        fi
      else
        echo "    Preserving existing approval_policy & sandbox_mode in ${cfg2} untouched."
      fi

      local chosen_editor=""
      if [ -n "${EDITOR_CMD}" ]; then
        chosen_editor="${EDITOR_CMD}"
      elif [ "${NON_INTERACTIVE}" -eq 0 ]; then
        local edit_ans=""
        printf 'Ban co muon mo %s de chinh sua truc tiep? [y/N]: ' "${cfg2}" >&2
        IFS= read -r edit_ans || true
        case "$(to_lower "${edit_ans%$'\r'}")" in
          y|yes)
            chosen_editor="${VISUAL:-${EDITOR:-vi}}"
            if ! command -v "${chosen_editor%% *}" >/dev/null 2>&1 && command -v nano >/dev/null 2>&1; then
              chosen_editor="nano"
            fi
            ;;
        esac
      fi

      if [ -n "${chosen_editor}" ]; then
        if [ -f "${cfg2}" ]; then
          backup_file_0600 "${cfg2}"
        fi
        if [ "${DRY_RUN}" -eq 1 ]; then
          echo "    [DRY-RUN] Would open ${cfg2} with editor: ${chosen_editor}"
        else
          echo "[+] Opening ${cfg2} with editor: ${chosen_editor}"
          if [ -f "${chosen_editor}" ] && [ -x "${chosen_editor}" ]; then
            "${chosen_editor}" "${cfg2}"
          else
            local editor_parts=()
            read -r -a editor_parts <<< "${chosen_editor}"
            if [ "${#editor_parts[@]}" -eq 0 ]; then
              echo "[FAIL] Invalid --editor command." >&2
              return 1
            fi
            "${editor_parts[@]}" "${cfg2}"
          fi
        fi
      fi

      if [ -f "${cfg2}" ]; then
        validate_toml_file "${cfg2}"
        if has_plaintext_secret_in_toml "${cfg2}"; then
          echo "[WARN] SECURITY WARNING: Plaintext 'api_key' or 'experimental_bearer_token' detected in ${cfg2}! Switch to env_key." >&2
        fi
        lock_file_0600 "${cfg2}"
        read_config_meta "${cfg2}"
        echo "    Active config.toml mode: $(classify_cli_mode "${CFG_SANDBOX_MODE}" "${CFG_APPROVAL_POLICY}")"
      fi
      run_bidirectional_sync 0
      echo "[OK] Sandbox 2 CLI mode: Config (Thuoc cau hinh config.toml) verified & preserved."
      ;;

    full-access)
      # Print realistic Codex-style ANSI RED/YELLOW danger warning BEFORE any mutation!
      print_full_access_danger_warning

      # Mandatory fail-closed confirmation gate (--force alone MUST NOT bypass this!).
      if [ "${CONFIRM_FULL_ACCESS}" -eq 1 ]; then
        echo "[WARN] Explicit --confirm-full-access received. Enabling Full Access (danger-full-access / approval_policy=never)..." >&2
      elif [ "${NON_INTERACTIVE}" -eq 1 ]; then
        echo "[FAIL] Refused Full Access (danger-full-access / approval_policy=never) in --non-interactive mode without explicit --confirm-full-access (--force alone is NOT accepted). Zero changes made to ${cfg2}." >&2
        return 1
      else
        local confirm_phrase=""
        printf "De xac nhan bat TOAN QUYEN (Full Access), go chinh xac 'TOAN QUYEN' (hoac 'I UNDERSTAND'): " >&2
        IFS= read -r confirm_phrase || true
        confirm_phrase="${confirm_phrase%$'\r'}"
        if [ "${confirm_phrase}" != "TOAN QUYEN" ] && [ "${confirm_phrase}" != "I UNDERSTAND" ]; then
          echo "[FAIL] Refused Full Access (danger-full-access / approval_policy=never): confirmation phrase did not match exact 'TOAN QUYEN' or 'I UNDERSTAND'. Zero changes made to ${cfg2}." >&2
          return 1
        fi
      fi

      if [ "${DRY_RUN}" -eq 0 ]; then
        mkdir -p -- "${LANE2_HOME}"
        chmod 700 "${LANE2_HOME}" 2>/dev/null || true
      fi
      if [ -f "${cfg2}" ]; then
        backup_file_0600 "${cfg2}"
        if [ "${DRY_RUN}" -eq 0 ]; then
          upsert_cli_mode_in_toml "${cfg2}" "danger-full-access" "never"
          echo "    Updated ${cfg2}: approval_policy=\"never\", sandbox_mode=\"danger-full-access\" (preserved [projects.*] & user sections)."
        else
          echo "    [DRY-RUN] Would set approval_policy=\"never\" and sandbox_mode=\"danger-full-access\" in ${cfg2}."
        fi
      elif [ "${DRY_RUN}" -eq 0 ]; then
        atomic_write_from_stdin "${cfg2}" 600 <<'EOF'
# Sandbox 2 (Codex CLI) configuration — FULL ACCESS (DANGER)
sandbox_mode = "danger-full-access"
approval_policy = "never"
EOF
        echo "    Initialized ${cfg2} in Full Access mode (DANGER)."
      else
        echo "    [DRY-RUN] Would initialize ${cfg2} in Full Access mode (DANGER)."
      fi
      if [ "${DRY_RUN}" -eq 0 ] && [ -f "${cfg2}" ]; then
        validate_toml_file "${cfg2}"
        lock_file_0600 "${cfg2}"
      fi
      run_bidirectional_sync 0
      echo "[OK] Sandbox 2 CLI mode set to Full Access (Toan quyen: approval_policy=never, sandbox_mode=danger-full-access)."
      ;;

    *)
      echo "[FAIL] Invalid --cli-mode '${chosen_mode}'. Allowed values: 'ask', 'config', 'full-access'." >&2
      return 1
      ;;
  esac
}

# [8] RAM / ROM Storage Compaction & Backup Rotation
select_mandatory_project_dir() {
  local initial="${1:-}"
  if [ -n "${initial}" ]; then
    if [ -L "${initial}" ]; then
      echo "[FAIL] Security refusal: Project path '${initial}' must not be a symlink." >&2
      return 1
    fi
    if [ ! -d "${initial}" ]; then
      echo "[FAIL] Project directory does not exist: '${initial}'." >&2
      return 1
    fi
    (cd -P -- "${initial}" && pwd -P)
    return 0
  fi

  if [ "${NON_INTERACTIVE}" -eq 1 ]; then
    echo "[FAIL] Mandatory project directory is required in --non-interactive mode: pass --repo-path <dir>." >&2
    return 1
  fi

  local cwd_p=""
  cwd_p="$(pwd -P 2>/dev/null || pwd)"
  while true; do
    echo "" >&2
    echo "=== BUOC BAT BUOC: CHON THU MUC DU AN (PROJECT DIRECTORY) ===" >&2
    echo "  [1] ${cwd_p} (Thu muc hien tai)" >&2
    echo "  [N] Nhap duong dan thu muc du an moi" >&2
    echo "  [0] Huy (Cancel)" >&2
    local pick=""
    printf 'Chon du an [Enter=1 / N / duong dan / 0]: ' >&2
    IFS= read -r pick || return 1
    pick="${pick%$'\r'}"
    case "${pick}" in
      ""|1)
        if [ -L "${cwd_p}" ] || [ ! -d "${cwd_p}" ]; then
          echo "[WARN] Thu muc hien tai khong hop le." >&2
          continue
        fi
        printf '%s\n' "${cwd_p}"
        return 0
        ;;
      0|q|quit|cancel)
        return 1
        ;;
      n|N)
        printf 'Nhap duong dan thu muc du an: ' >&2
        IFS= read -r pick || return 1
        pick="${pick%$'\r'}"
        ;;
    esac
    if [ -n "${pick}" ] && [ ! -L "${pick}" ] && [ -d "${pick}" ]; then
      (cd -P -- "${pick}" && pwd -P)
      return 0
    fi
    echo "[WARN] Thu muc khong ton tai hoac la symlink: '${pick}'" >&2
  done
}

action_cleanup_storage() {
  echo "=== [8] Quan Ly & Toi Uu Dung Luong RAM / ROM (cleanup-storage) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] Inspecting storage without mutating disk."

  if [ -n "${PY_BIN}" ] && [ -f "${KIT_ROOT}/scripts/sync-sessions.py" ] && [ -d "${LANE1_HOME}" ] && [ -d "${LANE2_HOME}" ]; then
    local c_args=("${KIT_ROOT}/scripts/sync-sessions.py" --source "${LANE1_HOME}" --target "${LANE2_HOME}" --compact-storage --max-backups "${MAX_BACKUPS}")
    [ "${DRY_RUN}" -eq 1 ] && c_args+=(--dry-run)
    "${PY_BIN}" -B "${c_args[@]}" >/dev/null 2>&1 || true
  fi

  if [ -d "${LANE2_HOME}/.sandbox" ] && [ ! -L "${LANE2_HOME}/.sandbox" ] && [ "${DRY_RUN}" -eq 0 ]; then
    find "${LANE2_HOME}/.sandbox" -maxdepth 1 -type f \( -name '*.tmp' -o -size +5M \) -exec rm -f -- {} + 2>/dev/null || true
  fi
  echo "[OK] Storage compaction & backup rotation completed (max_backups=${MAX_BACKUPS})."
  return 0
}

action_quick_third_party() {
  echo "=== [1c] Wizard 1 Cham: Cau Hinh API Ben Thu 3 (Tu Dong A-Z, Khong Mo Editor) ==="
  [ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files on disk will be modified."

  local chosen_repo=""
  if ! chosen_repo="$(select_mandatory_project_dir "${REPO_PATH}")"; then
    return 1
  fi
  echo "  Project Directory : ${chosen_repo}"

  local eff_url="${GATEWAY_BASE_URL}"
  if [ -z "${eff_url}" ] && [ "${NON_INTERACTIVE}" -eq 0 ]; then
    printf '1/3. Nhap Base URL cong API (vd: https://api.xingchiapi.com/v1): ' >&2
    IFS= read -r eff_url || true
    eff_url="${eff_url%$'\r'}"
  fi
  eff_url="${eff_url%/}"
  case "${eff_url}" in
    https://*|http://127.0.0.1*|http://localhost*|http://\[::1\]*) ;;
    *)
      echo "[FAIL] Invalid --base-url '${eff_url}'. Must start with https:// (or loopback http:// for local tests)." >&2
      return 1
      ;;
  esac

  local eff_model="${GATEWAY_MODEL}"
  if [ -z "${eff_model}" ] && [ "${NON_INTERACTIVE}" -eq 0 ]; then
    printf '2/3. Nhap ten Model [Enter = gpt-5.4]: ' >&2
    IFS= read -r eff_model || true
    eff_model="${eff_model%$'\r'}"
  fi
  [ -z "${eff_model}" ] && eff_model="gpt-5.4"

  local eff_effort="${REASONING_EFFORT:-high}"
  local eff_prov="${PROVIDER_NAME:-custom_gw}"
  if [ "$(to_lower "${eff_prov}")" = "openai" ]; then
    eff_prov="custom_gw"
  fi
  local eff_env="${ENV_KEY_NAME:-CODEX_CLI_API_KEY}"

  local api_key=""
  if [ "${API_KEY_FROM_STDIN}" -eq 1 ]; then
    IFS= read -r api_key || true
    api_key="${api_key#$'\xef\xbb\xbf'}"
    api_key="${api_key%$'\r'}"
  elif [ "${NON_INTERACTIVE}" -eq 0 ] && [ "${DRY_RUN}" -eq 0 ]; then
    printf '3/3. Dan API Key ben thu 3 (an ky tu): ' >&2
    IFS= read -r -s api_key || true
    printf '\n' >&2
    api_key="${api_key%$'\r'}"
  elif [ "${DRY_RUN}" -eq 0 ]; then
    echo "[FAIL] --action quick-third-party in --non-interactive mode requires --api-key-from-stdin." >&2
    return 1
  fi

  api_key="$(printf '%s' "${api_key}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [ "${DRY_RUN}" -eq 0 ]; then
    if [ "${#api_key}" -lt 8 ] || printf '%s' "${api_key}" | grep -q '[[:space:]]'; then
      echo "[FAIL] Invalid API key (must be >= 8 chars with no whitespace)." >&2
      api_key=""
      return 1
    fi
  fi

  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "  [DRY-RUN] Would configure provider=${eff_prov}, base_url=${eff_url}, model=${eff_model} (${eff_effort}), env_key=${eff_env}, remove stale Lane2/auth.json, and lock 0600."
    api_key=""
    return 0
  fi

  mkdir -p -- "${LANE2_HOME}"
  chmod 700 "${LANE2_HOME}" 2>/dev/null || true
  export "${eff_env}=${api_key}"
  api_key=""

  if [ -f "${LANE2_HOME}/auth.json" ] && [ ! -L "${LANE2_HOME}/auth.json" ]; then
    backup_file_0600 "${LANE2_HOME}/auth.json"
    rm -f -- "${LANE2_HOME}/auth.json"
    echo "  Removed stale Sandbox 2 auth.json (backed up) to prevent ChatGPT OAuth quota collision."
  fi

  local cfg2="${LANE2_HOME}/config.toml"
  [ -f "${cfg2}" ] && backup_file_0600 "${cfg2}"

  "${PY_BIN}" -B - "${cfg2}" "${eff_prov}" "${eff_url}" "${eff_env}" "${eff_model}" "${eff_effort}" <<'PY'
import os, re, sys
cfg_path, prov, base_url, env_key, model_id, effort = sys.argv[1:7]
raw = open(cfg_path, "r", encoding="utf-8").read() if os.path.isfile(cfg_path) else ""
lines = raw.splitlines()
top, sections, cur_h, cur_b = [], [], "", []
for ln in lines:
    m = re.match(r"^\s*\[([^\[\]]+)\]\s*$", ln)
    if m:
        if cur_h:
            sections.append((cur_h, cur_b))
        cur_h, cur_b = m.group(1).strip(), []
    elif not cur_h:
        top.append(ln)
    else:
        cur_b.append(ln)
if cur_h:
    sections.append((cur_h, cur_b))

out = [
    f'model_provider = "{prov}"',
    f'model = "{model_id}"',
    f'model_reasoning_effort = "{effort}"',
]
has_sb = any(re.match(r'^\s*sandbox_mode\s*=', l) for l in top)
has_ap = any(re.match(r'^\s*approval_policy\s*=', l) for l in top)
if not has_sb:
    out.append('sandbox_mode = "workspace-write"')
if not has_ap:
    out.append('approval_policy = "on-request"')
for l in top:
    if re.match(r'^\s*(model_provider|model|model_reasoning_effort)\s*=', l):
        continue
    out.append(l)
out.append("")

wrote_prov = False
wrote_feat = False
cat_url = base_url.rstrip("/") + "/models"
for h, b in sections:
    if h.lower() == f"model_providers.{prov.lower()}":
        out.extend([
            f"[model_providers.{prov}]",
            f'name = "{prov}"',
            f'base_url = "{base_url}"',
            f'model_catalog_url = "{cat_url}"',
            'wire_api = "responses"',
            "requires_openai_auth = false",
            f'env_key = "{env_key}"',
            "",
        ])
        wrote_prov = True
    elif h.lower() == "features":
        out.append("[features]")
        out.append("daemon_auto_start = false")
        for bl in b:
            if not re.match(r"^\s*daemon_auto_start\s*=", bl):
                out.append(bl)
        if not any(re.match(r"^\s*api_key_model_discovery\s*=", bl) for bl in b):
            out.append("api_key_model_discovery = true")
        if not any(re.match(r"^\s*goals\s*=", bl) for bl in b):
            out.append("goals = true")
        out.append("")
        wrote_feat = True
    else:
        out.append(f"[{h}]")
        out.extend(b)
        out.append("")

if not wrote_prov:
    out.extend([
        f"[model_providers.{prov}]",
        f'name = "{prov}"',
        f'base_url = "{base_url}"',
        f'model_catalog_url = "{cat_url}"',
        'wire_api = "responses"',
        "requires_openai_auth = false",
        f'env_key = "{env_key}"',
        "",
    ])
if not wrote_feat:
    out.extend([
        "[features]",
        "daemon_auto_start = false",
        "api_key_model_discovery = true",
        "goals = true",
        "memories = true",
        "",
    ])

tmp = cfg_path + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out).rstrip() + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, cfg_path)
PY

  validate_toml_file "${cfg2}"
  lock_file_0600 "${cfg2}"
  run_bidirectional_sync 0
  action_cleanup_storage >/dev/null 2>&1 || true
  echo "[OK] Quick 3rd-party gateway configured cleanly for Sandbox 2 (provider=${eff_prov}, model=${eff_model})."
}

action_launch() {
  echo "=== [00] Chon Du An (Bat Buoc) & Khoi Chay Codex CLI (Sandbox 2) ==="
  local chosen_repo=""
  if ! chosen_repo="$(select_mandatory_project_dir "${REPO_PATH}")"; then
    return 1
  fi
  echo "  Project Directory : ${chosen_repo}"

  local safe_jobs=2
  export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-${safe_jobs}}"

  if [ ! -x "${LOCAL_BIN}/codex" ] || [ ! -f "${LANE2_HOME}/config.toml" ]; then
    if [ -f "${KIT_ROOT}/scripts/setup-dual-lane.sh" ]; then
      local s_args=(--repo "${chosen_repo}")
      [ -n "${CODEX_PATH}" ] && s_args+=(--codex-path "${CODEX_PATH}")
      [ "${DRY_RUN}" -eq 1 ] && s_args+=(--dry-run)
      CODEX_LANE1_HOME="${LANE1_HOME}" CODEX_LANE2_HOME="${LANE2_HOME}" CODEX_LOCAL_BIN="${LOCAL_BIN}" \
        bash "${KIT_ROOT}/scripts/setup-dual-lane.sh" "${s_args[@]}"
    fi
  fi

  if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[OK] [DRY-RUN] Would cd to '${chosen_repo}' (CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}) and launch '${LOCAL_BIN}/codex'."
    return 0
  fi

  action_cleanup_storage >/dev/null 2>&1 || true
  cd -P -- "${chosen_repo}"
  exec "${LOCAL_BIN}/codex"
}

# Interactive Menu
action_menu() {
  if [ "${NON_INTERACTIVE}" -eq 1 ]; then
    echo "[FAIL] --action menu cannot run with --non-interactive. Pass an explicit --action <api-gpt|api-other|quick-third-party|login|check-api-key|check-accounts|sync-history|remove-sandbox2|set-cli-mode|launch|cleanup-storage>." >&2
    return 1
  fi

  if [ -z "${REPO_PATH}" ]; then
    if ! REPO_PATH="$(select_mandatory_project_dir "")"; then
      echo "[INFO] Chua chon thu muc du an; da thoat Control Center."
      return 0
    fi
  else
    REPO_PATH="$(select_mandatory_project_dir "${REPO_PATH}")"
  fi
  cd -P -- "${REPO_PATH}" 2>/dev/null || true
  echo "[OK] Da khoa thu muc du an lam viec (Active Project CWD): ${REPO_PATH}"

  while true; do
    read_config_meta "${LANE2_HOME}/config.toml"
    local active_cli_mode=""
    active_cli_mode="$(classify_cli_mode "${CFG_SANDBOX_MODE}" "${CFG_APPROVAL_POLICY}")"
    cat <<EOF

========================================================================
  Codex Dual-Lane Control Center — 1-Touch Sandbox 2 CLI (v1.5)
========================================================================
  Du an dang chon  : ${REPO_PATH}
  GPT 1 (Desktop)  : ${LANE1_HOME}
  Sandbox 2 (CLI)  : ${LANE2_HOME}
  Che do quyen CLI : ${active_cli_mode}
------------------------------------------------------------------------
  [00] CHAY CODEX CLI NGAY TAI DU AN TREN (1 Cham) [Enter]
  [p]  Doi thu muc du an khac (Switch Project Directory)
  [1]  Xac thuc API Key cho Sandbox 2 (Codex CLI)
       [1a] OpenAI / GPT API Key (masked -> codex login --with-api-key)
       [1b] Ben thu 3 / Custom Provider (mo thang config.toml)
       [1c] Wizard 1 Cham API Ben thu 3 (Hoi 3 dong -> Tu dong A-Z)
  [2]  Dang nhap chinh thuc OpenAI / ChatGPT (codex login)
  [3]  Check API Key (masked offline + optional live /models probe)
  [4]  Check Tai khoan Hien co (GPT 1 & Sandbox 2 — chi doc)
  [5]  Dong bo Lich su Chat 2 chieu (GPT 1 <-> Sandbox 2)
  [6]  Xoa Sandbox 2 An toan (GIU NGUYEN 100% lich su chat ve GPT 1)
  [7]  Chon che do quyen Sandbox 2 (Codex CLI)
  [8]  Don dep & Toi uu Dung luong RAM / ROM (cleanup-storage)
  [0]  Thoat (Exit)
------------------------------------------------------------------------
EOF
    local choice=""
    printf 'Chon chuc nang [Enter/00/p/1c/1a/1b/2..8/0]: ' >&2
    if ! IFS= read -r choice; then
      printf '\n' >&2
      break
    fi
    choice="$(to_lower "$(printf '%s' "${choice}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')")"
    [ -z "${choice}" ] && choice="00"
    case "${choice}" in
      00|launch) action_launch || true ;;
      p)
        local np=""
        if np="$(select_mandatory_project_dir "")"; then
          REPO_PATH="${np}"
          cd -P -- "${REPO_PATH}" 2>/dev/null || true
          echo "[OK] Da chuyen sang thu muc du an: ${REPO_PATH}"
        fi
        ;;
      1c) action_quick_third_party || true ;;
      8) action_cleanup_storage || true ;;
      1)
        local sub=""
        printf 'Chon loai API Key: [a] OpenAI / GPT chinh chu | [b] Ben thu 3 / Custom (config.toml): ' >&2
        IFS= read -r sub || true
        case "$(to_lower "${sub}")" in
          a|1a) action_api_gpt || true ;;
          b|1b) action_api_other || true ;;
          *) echo "[INFO] Lua chon khong hop le." >&2 ;;
        esac
        ;;
      1a) action_api_gpt || true ;;
      1b) action_api_other || true ;;
      2)
        if [ "${DEVICE_AUTH}" -eq 0 ]; then
          local dchoice=""
          printf 'Chon kieu dang nhap: [1] Trinh duyet chinh thuc (mac dinh) | [2] Device Auth (--device-auth): ' >&2
          IFS= read -r dchoice || true
          if [ "${dchoice}" = "2" ]; then
            local prev_da="${DEVICE_AUTH}"
            DEVICE_AUTH=1
            action_login || true
            DEVICE_AUTH="${prev_da}"
          else
            action_login || true
          fi
        else
          action_login || true
        fi
        ;;
      3) action_check_api_key || true ;;
      4) action_check_accounts || true ;;
      5) action_sync_history || true ;;
      6) action_remove_sandbox2 || true ;;
      7)
        local prev_cm="${CLI_MODE}" prev_cfa="${CONFIRM_FULL_ACCESS}"
        CLI_MODE=""
        CONFIRM_FULL_ACCESS=0
        action_set_cli_mode || true
        CLI_MODE="${prev_cm}"
        CONFIRM_FULL_ACCESS="${prev_cfa}"
        ;;
      0|q|quit|exit)
        echo "Tam biet!"
        break
        ;;
      *)
        echo "[WARN] Lua chon khong hop le: '${choice}'" >&2
        ;;
    esac
  done
}

# ------------------------------------------------------------------------------
# Defaults & CLI Argument Parsing
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
KIT_ROOT="$(cd -P -- "${SCRIPT_DIR}/.." && pwd -P)"

ACTION="menu"
LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"
CODEX_PATH="${CODEX_REAL_BIN:-}"
CLI_MODE=""
CONFIRM_FULL_ACCESS=0
ONLINE_CHECK=0
DEVICE_AUTH=0
EDITOR_CMD=""
DRY_RUN=0
FORCE=0
NON_INTERACTIVE=0
API_KEY_FROM_STDIN=0
REPO_PATH=""
GATEWAY_BASE_URL=""
GATEWAY_MODEL=""
REASONING_EFFORT="high"
PROVIDER_NAME="custom_gw"
ENV_KEY_NAME="CODEX_CLI_API_KEY"
MAX_BACKUPS=5

while [ "$#" -gt 0 ]; do
  case "$1" in
    --action)
      require_arg "$1" "$#"
      ACTION="$2"
      shift 2
      ;;
    --repo-path|--repo)
      require_arg "$1" "$#"
      REPO_PATH="$2"
      shift 2
      ;;
    --base-url)
      require_arg "$1" "$#"
      GATEWAY_BASE_URL="$2"
      shift 2
      ;;
    --model)
      require_arg "$1" "$#"
      GATEWAY_MODEL="$2"
      shift 2
      ;;
    --reasoning-effort)
      require_arg "$1" "$#"
      REASONING_EFFORT="$2"
      shift 2
      ;;
    --provider-name)
      require_arg "$1" "$#"
      PROVIDER_NAME="$2"
      shift 2
      ;;
    --env-key)
      require_arg "$1" "$#"
      ENV_KEY_NAME="$2"
      shift 2
      ;;
    --max-backups)
      require_arg "$1" "$#"
      MAX_BACKUPS="$2"
      shift 2
      ;;
    --lane1-home|--lane1)
      require_arg "$1" "$#"
      LANE1_HOME="$2"
      shift 2
      ;;
    --lane2-home|--lane2)
      require_arg "$1" "$#"
      LANE2_HOME="$2"
      shift 2
      ;;
    --local-bin)
      require_arg "$1" "$#"
      LOCAL_BIN="$2"
      shift 2
      ;;
    --codex-path)
      require_arg "$1" "$#"
      CODEX_PATH="$2"
      shift 2
      ;;
    --cli-mode)
      require_arg "$1" "$#"
      CLI_MODE="$2"
      shift 2
      ;;
    --confirm-full-access)
      CONFIRM_FULL_ACCESS=1
      shift
      ;;
    --online-check)
      ONLINE_CHECK=1
      shift
      ;;
    --device-auth)
      DEVICE_AUTH=1
      shift
      ;;
    --editor)
      require_arg "$1" "$#"
      EDITOR_CMD="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --api-key-from-stdin)
      API_KEY_FROM_STDIN=1
      shift
      ;;
    --api-key|--api-key=*|--key|--key=*|--token|--token=*|--secret|--secret=*)
      echo "[FAIL] Security refusal: plaintext API keys/tokens are NEVER accepted as CLI flags! Use masked interactive prompt or --api-key-from-stdin." >&2
      exit 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# ------------------------------------------------------------------------------
# Strict Input & Precondition Validation
# ------------------------------------------------------------------------------
LANE1_HOME="$(validate_path_value "LANE1_HOME" "${LANE1_HOME}")"
LANE2_HOME="$(validate_path_value "LANE2_HOME" "${LANE2_HOME}")"
LOCAL_BIN="$(validate_path_value "LOCAL_BIN" "${LOCAL_BIN}")"
if [ -n "${CODEX_PATH}" ]; then
  CODEX_PATH="$(validate_path_value "CODEX_PATH" "${CODEX_PATH}")"
fi

for home_root in "${LANE1_HOME}" "${LANE2_HOME}"; do
  if [ -L "${home_root}" ]; then
    echo "[FAIL] Security refusal: CODEX_HOME '${home_root}' must not be a symlink." >&2
    exit 1
  fi
done

LANE1_HOME="$(canonicalize_dir "${LANE1_HOME}")"
LANE2_HOME="$(canonicalize_dir "${LANE2_HOME}")"
LOCAL_BIN="$(canonicalize_dir "${LOCAL_BIN}")"

if [ "${LANE1_HOME}" = "${LANE2_HOME}" ]; then
  echo "[FAIL] LANE1_HOME and LANE2_HOME must be distinct directories (both resolved to '${LANE1_HOME}')." >&2
  exit 1
fi

if [ -n "${CLI_MODE}" ]; then
  CLI_MODE="$(to_lower "${CLI_MODE}")"
  case "${CLI_MODE}" in
    ask|config|full-access) ;;
    fullaccess) CLI_MODE="full-access" ;;
    *)
      echo "[FAIL] Invalid --cli-mode '${CLI_MODE}'. Allowed values: 'ask', 'config', 'full-access'." >&2
      exit 1
      ;;
  esac
fi

PY_BIN="$(resolve_python3)"

ACTION_LOWER="$(to_lower "${ACTION}")"
case "${ACTION_LOWER}" in
  menu)
    action_menu
    ;;
  api-gpt|apigpt)
    action_api_gpt
    ;;
  api-other|apiother)
    action_api_other
    ;;
  login)
    action_login
    ;;
  check-api-key|checkapikey)
    action_check_api_key
    ;;
  check-accounts|checkaccounts)
    action_check_accounts
    ;;
  sync-history|synchistory)
    action_sync_history
    ;;
  remove-sandbox2|removesandbox2)
    action_remove_sandbox2
    ;;
  set-cli-mode|setclimode)
    action_set_cli_mode
    ;;
  quick-third-party|quickthirdparty)
    action_quick_third_party
    ;;
  launch)
    action_launch
    ;;
  cleanup-storage|cleanupstorage)
    action_cleanup_storage
    ;;
  *)
    echo "[FAIL] Unknown --action '${ACTION}'. Allowed: menu, api-gpt, api-other, quick-third-party, login, check-api-key, check-accounts, sync-history, remove-sandbox2, set-cli-mode, launch, cleanup-storage." >&2
    exit 1
    ;;
esac
