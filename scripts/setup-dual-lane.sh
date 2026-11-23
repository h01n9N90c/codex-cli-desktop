#!/usr/bin/env bash
# ==============================================================================
# Cross-platform installer for Codex Dual-Lane & Security Kit (macOS/Linux/WSL)
# ==============================================================================
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Project   : Codex Dual-Lane & Security Kit
#
# Security & End-User Safety Guarantees:
#   - Strict Bash error handling (`set -euo pipefail`) and owner-only default
#     file creation mask (`umask 077`) so sensitive configs, backups, and temp
#     files are never created group- or world-readable.
#   - Zero hardcoded secrets, zero plaintext API keys ever written or echoed.
#   - Atomic file writes (same-directory `mktemp` + `chmod` + `mv`) with `trap`
#     cleanup on EXIT/INT/TERM so interrupted runs never leave truncated configs
#     or stray temporary artifacts.
#   - Refuses to overwrite symlinks on sensitive targets (symlink-clobber guard).
#   - Non-destructive `config.toml` merge: preserves user top-level settings and
#     custom sections (e.g. `[mcp_servers.*]`, `[tui]`, `[plugins.*]`).
#   - Portable SHA-256 rollback manifest (`.rollback/latest.tsv`) enabling
#     byte-exact verified recovery via `./scripts/restore-original.sh`.
#   - Shell-safe single-quoted launcher generation (prevents metacharacter
#     injection from paths containing spaces, `$`, backticks, quotes, or `&`).
#   - Full `--dry-run` preview mode that mutates zero user files on disk.
# ==============================================================================
set -euo pipefail

# Enforce owner-only permissions (0700 dirs, 0600 files) for every artifact
# created during installation, preventing TOCTOU exposure on multi-user hosts.
umask 077

# ------------------------------------------------------------------------------
# Temporary Artifact Tracking & Signal-Safe Cleanup
# ------------------------------------------------------------------------------
# Every mktemp directory or staging file created by this script is appended to
# TEMP_ARTIFACTS and removed automatically on normal exit or signal interruption.
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

# Track every managed file written so we can flush a crash-safe, deterministic
# SHA-256 rollback manifest incrementally for `./scripts/restore-original.sh`.
MANIFEST_ROWS=()
LINKED_SHARED_DIRS=()
LINK_MANIFEST_ROWS=()
ROLLBACK_READY=0
ROLLBACK_STATUS="in-progress"
ROLLBACK_DIR=""
SNAP_FILE=""
LATEST_FILE=""
UTC_NOW=""
stamp=""

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

# Print CLI usage, options, and supported environment variable overrides.
usage() {
  cat <<'EOF'
Usage: ./scripts/setup-dual-lane.sh [REPO_PATH] [OPTIONS]

Options:
  --repo, --repo-path PATH    Target repository directory (default: current directory; accepts relative paths like .)
  --cli-mode MODE             Lane 2 CLI permission mode: 'ask' (default: on-request + workspace-write),
                              'config' (preserve existing config.toml approval_policy & sandbox_mode),
                              or 'full-access' (DANGER: never + danger-full-access; requires confirmation)
  --confirm-full-access       Explicitly confirm --cli-mode full-access (required when non-interactive)
  --approval-policy MODE      'on-request' (default, secure) or 'never' (unattended; used with --cli-mode ask)
  --allow-sandbox-network     Enable network_access=true inside [sandbox_workspace_write]
  --use-git-worktree          Create an isolated Git worktree (<repo>-lane2) for OS-level file isolation
  --worktree-path PATH        Custom worktree path when using --use-git-worktree
  --configure-gateway         Configure custom API key / gateway provider via env_key (zero plaintext secrets)
  --configure-cli-gateway     Configure custom API key / gateway on Lane 2 CLI only (leaves Lane 1 Desktop config.toml untouched)
  --gateway-target-lane LANE  Target lane for gateway/API key config: 'lane1' (default), 'lane2' (CLI), or 'both'
  --gateway-provider NAME     Provider identifier for [model_providers."<NAME>"] (default: OpenAI)
  --gateway-base-url URL      Absolute http(s) base URL for the gateway (required with --configure-gateway)
  --gateway-model SLUG        Optional default model and review_model slug for the gateway lane
  --gateway-api-key-env VAR   Environment variable referenced by env_key (default: CODEX_GATEWAY_API_KEY)
  --cli-api-key-env VAR       Alias for --gateway-api-key-env
  --trust-repo-path           Explicit opt-in: write REPO_PATH (and Lane 2 worktree) as trust_level = "trusted"; default OFF (trust is never raised implicitly)
--share-auth-to-lane2       Opt-in: read-only copy Lane 1 Desktop auth.json to Lane 2 CLI (0600, tracked; avoid mixing with third-party gateways) (alias: --share-official-auth)
  --install-bridge            Copy templates/DUAL_LANE_BRIDGE.md into <repo>/artifacts/dual-lane/
  --sync-sessions             Run scripts/sync-sessions.py after install (requires python3)
  --pinned-only               With --sync-sessions, only sync pinned threads
  --dry-run                   Preview every step without writing any user files
  -h, --help                  Show this help message

Environment overrides:
  CODEX_LANE1_HOME            Primary CODEX_HOME (Desktop / Primary Account, default: ~/.codex)
  CODEX_LANE2_HOME            Secondary CODEX_HOME (CLI: Login + API Key, default: ~/.codex-official)
  CODEX_LOCAL_BIN             Launcher install directory (default: ~/.local/bin)
  CODEX_CARGO_TARGET_DIR      Isolated Rust Cargo target dir for Lane 2
  CODEX_CLI_MODE              Default Lane 2 CLI mode ('ask', 'config', or 'full-access')
  CODEX_APPROVAL_POLICY       Default approval policy ('on-request' or 'never')
  CODEX_SANDBOX_NETWORK       Default sandbox network flag ('false' or 'true')
  CODEX_LANE2_BRANCH          Git branch name when --use-git-worktree is enabled (default: dual-lane-2)
  CODEX_GATEWAY_TARGET_LANE   Target lane for gateway config ('lane1', 'lane2', or 'both')
  CODEX_GATEWAY_PROVIDER      Gateway provider name (default: OpenAI)
  CODEX_GATEWAY_BASE_URL      Gateway http(s) base URL
  CODEX_GATEWAY_MODEL         Optional gateway default model slug
  CODEX_GATEWAY_API_KEY_ENV   Environment variable name for gateway env_key (default: CODEX_GATEWAY_API_KEY)
EOF
}

# Validate that an option requiring a value actually received one before
# dereferencing $2 (avoids cryptic `unbound variable` crashes under `set -u`).
require_arg() {
  local opt_name="$1"
  local arg_count="$2"
  if [ "${arg_count}" -lt 2 ]; then
    echo "[FAIL] Option '${opt_name}' requires a value." >&2
    usage >&2
    exit 1
  fi
}

# Reject empty paths, filesystem root '/', or control characters (newline, CR,
# tab) that could break TOML strings or TSV rollback manifests. Strips trailing
# slashes so path comparisons remain canonical.
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
  # Strip trailing slashes while preserving '/' detection.
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

# Resolve a directory path to its canonical physical path (portable across
# macOS BSD, Linux GNU, WSL, and Git Bash without requiring `realpath`).
# Works even if the leaf directory does not exist yet by resolving the nearest
# existing ancestor and reattaching the remaining components.
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

# Single-quote a string safely for POSIX/Bash scripts (`'` -> `'\''`).
# Uses an explicit loop instead of `${var//pat/rep}` so behavior is identical
# from Bash 3.2 (macOS) through Bash 5.2+ (where `patsub_replacement` alters `&`/`\`).
shell_quote() {
  local s="$1"
  local sq="'"
  local out="'"
  while [[ "${s}" == *"${sq}"* ]]; do
    out+="${s%%"${sq}"*}'\\''"
    s="${s#*"${sq}"}"
  done
  out+="${s}'"
  printf '%s' "${out}"
}

# Escape backslashes and double quotes for TOML basic strings ("...").
escape_toml() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Portably read standard POSIX owner/group/other octal permission bits (3 digits:
# 000..777, stripping any special SUID/SGID/sticky leading digit) across GNU `stat -c %a`
# and BSD/macOS `stat -f %Lp`. Returns empty string if unavailable.
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

# Compute a lowercase 64-hex SHA-256 digest portably across Linux (`sha256sum`),
# macOS (`shasum -a 256`), and minimal Unix (`openssl dgst -sha256`).
# Reading via stdin (`< "$file"`) prevents leading-dash option injection and
# suppresses GNU `sha256sum`'s backslash-escaping prefix on unusual filenames.
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

# Atomically write stdin to a target path with explicit file mode.
# Security invariants:
#   - Refuses to overwrite symlinks or directories (blocks symlink-clobbering).
#   - Creates a temporary staging file in the destination's own directory so
#     `mv -f` performs an atomic same-filesystem rename(2).
#   - Registers the temp file in TEMP_ARTIFACTS before writing so interruption
#     never leaves orphaned staging files behind.
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
  tmp="$(mktemp "${parent}/.codex-tmp.XXXXXX")"
  TEMP_ARTIFACTS+=("${tmp}")
  cat > "${tmp}"
  chmod "${mode}" "${tmp}"
  mv -f -- "${tmp}" "${dst}"
}

# Generate a unique timestamped backup path that never overwrites an existing
# backup file, directory, or symlink created in the same second.
unique_backup_path() {
  local base="$1"
  local cand="${base}.backup-${stamp}"
  local idx=1
  while [ -e "${cand}" ] || [ -L "${cand}" ]; do
    cand="${base}.backup-${stamp}-${idx}"
    idx=$((idx + 1))
  done
  printf '%s' "${cand}"
}

# Emit the current rollback manifest (5-column TSV with metadata headers).
# Comment lines record schema_version=2, completion status (`in-progress` during
# incremental checkpoints vs `complete` at finish), timestamp, and kit-created
# shared links. Structured `L` rows record every shared link's initial state
# (`absent`, `preexisting_link`, `preexisting_dir`), ownership (`created_by_kit`
# 1/0), and exact `backup_dir_path` so rollback preserves pre-existing links and
# never guesses directory backups by wildcard sorting.
emit_manifest() {
  printf '# schema_version=2\n'
  printf '# status=%s\n' "${ROLLBACK_STATUS}"
  printf '# timestamp=%s\n' "${stamp}"
  printf '# created_at_utc=%s\n' "${UTC_NOW}"
  if [ "${#LINKED_SHARED_DIRS[@]}" -gt 0 ]; then
    local joined_links="" d_item
    for d_item in "${LINKED_SHARED_DIRS[@]}"; do
      if [ -n "${joined_links}" ]; then
        joined_links="${joined_links},${d_item}"
      else
        joined_links="${d_item}"
      fi
    done
    printf '# shared_links=%s\n' "${joined_links}"
  fi
  printf '# columns: record_type(0|1|L)<TAB>sha256_or_created<TAB>target_path<TAB>backup_path<TAB>mode_or_prior_state\n'
  if [ "${#LINK_MANIFEST_ROWS[@]}" -gt 0 ]; then
    local lrow
    for lrow in "${LINK_MANIFEST_ROWS[@]}"; do
      printf '%s\n' "${lrow}"
    done
  fi
  if [ "${#MANIFEST_ROWS[@]}" -gt 0 ]; then
    local row
    for row in "${MANIFEST_ROWS[@]}"; do
      printf '%s\n' "${row}"
    done
  fi
}

# Atomically persist both the timestamped rollback snapshot and latest.tsv
# (mode 0600) incrementally after every tracked backup/mutation when DRY_RUN=0.
# Uses process substitution so atomic_write_from_stdin runs in the main shell
# and registers staging files in TEMP_ARTIFACTS for signal-safe cleanup.
flush_rollback_manifest() {
  if [ "${DRY_RUN}" -ne 0 ] || [ "${ROLLBACK_READY}" -ne 1 ]; then
    return 0
  fi
  if [ -L "${ROLLBACK_DIR}" ]; then
    echo "[FAIL] Security refusal: rollback directory '${ROLLBACK_DIR}' is a symlink." >&2
    exit 1
  fi
  atomic_write_from_stdin "${SNAP_FILE}" 600 < <(emit_manifest)
  atomic_write_from_stdin "${LATEST_FILE}" 600 < <(emit_manifest)
}

# Back up a pre-existing target file (such as a CLI launcher in LOCAL_BIN)
# before overwriting it, recording its SHA-256, backup path, and original POSIX
# mode (column 5) in MANIFEST_ROWS and flushing the manifest incrementally so
# interrupted installs remain fully recoverable with exact mode restoration.
record_target_for_rollback() {
  local dst="$1"
  local bkp_mode="${2:-600}"
  if [ -L "${dst}" ]; then
    echo "[FAIL] Security refusal: destination '${dst}' is a symlink; refusing to overwrite." >&2
    exit 1
  fi
  if [ -d "${dst}" ]; then
    echo "[FAIL] Refusing to overwrite directory '${dst}' with a regular file." >&2
    exit 1
  fi
  if [ -f "${dst}" ]; then
    local orig_hash orig_mode effective_bkp_mode bkp bkp_hash
    orig_hash="$(sha256_file "${dst}")"
    orig_mode="$(get_octal_mode "${dst}")"
    [ -z "${orig_mode}" ] && orig_mode="-"
    effective_bkp_mode="${bkp_mode}"
    if [ "${bkp_mode}" = "preserve" ]; then
      if [ "${orig_mode}" != "-" ]; then
        effective_bkp_mode="${orig_mode}"
      else
        effective_bkp_mode="700"
      fi
    fi
    bkp="${dst}.backup-${stamp}"
    if [ "${DRY_RUN}" -eq 0 ]; then
      atomic_write_from_stdin "${bkp}" "${effective_bkp_mode}" < "${dst}"
      bkp_hash="$(sha256_file "${bkp}")"
      if [ "${bkp_hash}" != "${orig_hash}" ]; then
        echo "[FAIL] Backup integrity verification failed for ${bkp}." >&2
        exit 1
      fi
      echo "    Backup saved: ${bkp} (SHA256=${orig_hash:0:12}..., mode=${orig_mode})"
    else
      echo "    [DRY-RUN] Would save backup: ${bkp} (SHA256=${orig_hash:0:12}..., mode=${orig_mode})"
    fi
    MANIFEST_ROWS+=("$(printf '1\t%s\t%s\t%s\t%s' "${orig_hash}" "${dst}" "${bkp}" "${orig_mode}")")
  else
    MANIFEST_ROWS+=("$(printf '0\t-\t%s\t-\t-' "${dst}")")
  fi
  flush_rollback_manifest
}

# Back up an existing file with SHA-256 verification, flush the rollback
# manifest BEFORE overwriting the live target (write-ahead journal), and
# atomically install the replacement template.
backup_and_copy() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  if [ -L "${dst}" ]; then
    echo "[FAIL] Security refusal: destination '${dst}' is a symlink; refusing to overwrite." >&2
    exit 1
  fi
  if [ -d "${dst}" ]; then
    echo "[FAIL] Refusing to overwrite directory '${dst}' with a regular file." >&2
    exit 1
  fi
  if [ -f "${dst}" ]; then
    local orig_hash orig_mode bkp bkp_hash
    orig_hash="$(sha256_file "${dst}")"
    orig_mode="$(get_octal_mode "${dst}")"
    [ -z "${orig_mode}" ] && orig_mode="-"
    bkp="${dst}.backup-${stamp}"
    if [ "${DRY_RUN}" -eq 0 ]; then
      atomic_write_from_stdin "${bkp}" 600 < "${dst}"
      bkp_hash="$(sha256_file "${bkp}")"
      if [ "${bkp_hash}" != "${orig_hash}" ]; then
        echo "[FAIL] Backup integrity verification failed for ${bkp}." >&2
        exit 1
      fi
      echo "    Backup saved: ${bkp} (SHA256=${orig_hash:0:12}...)"
    else
      echo "    [DRY-RUN] Would save backup: ${bkp} (SHA256=${orig_hash:0:12}...)"
    fi
    MANIFEST_ROWS+=("$(printf '1\t%s\t%s\t%s\t%s' "${orig_hash}" "${dst}" "${bkp}" "${orig_mode}")")
  else
    MANIFEST_ROWS+=("$(printf '0\t-\t%s\t-\t-' "${dst}")")
  fi
  flush_rollback_manifest
  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${dst}" "${mode}" < "${src}"
    echo "    Installed: ${dst}"
  else
    echo "    [DRY-RUN] Would install: ${dst}"
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

# ------------------------------------------------------------------------------
# Defaults & CLI Argument Parsing
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
KIT_ROOT="$(cd -P -- "${SCRIPT_DIR}/.." && pwd -P)"

SAFE_TMPDIR="${TMPDIR:-/tmp}"
SAFE_TMPDIR="${SAFE_TMPDIR%/}"
[ -z "${SAFE_TMPDIR}" ] && SAFE_TMPDIR="/tmp"

REPO_PATH="$(pwd -P)"
LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"
CARGO_TARGET_LANE2="${CODEX_CARGO_TARGET_DIR:-${SAFE_TMPDIR}/codex-lane2-target}"
CLI_MODE="${CODEX_CLI_MODE:-ask}"
CONFIRM_FULL_ACCESS=0
APPROVAL_POLICY="${CODEX_APPROVAL_POLICY:-on-request}"
SANDBOX_NETWORK="${CODEX_SANDBOX_NETWORK:-false}"
ALLOW_SANDBOX_NETWORK_EXPLICIT=0
USE_GIT_WORKTREE=0
LANE2_WORKTREE_PATH=""
LANE2_BRANCH="${CODEX_LANE2_BRANCH:-dual-lane-2}"
CONFIGURE_GATEWAY=0
CONFIGURE_CLI_GATEWAY=0
GATEWAY_TARGET_LANE="${CODEX_GATEWAY_TARGET_LANE:-lane1}"
GATEWAY_PROVIDER="${CODEX_GATEWAY_PROVIDER:-OpenAI}"
GATEWAY_BASE_URL="${CODEX_GATEWAY_BASE_URL:-}"
GATEWAY_MODEL="${CODEX_GATEWAY_MODEL:-}"
GATEWAY_API_KEY_ENV="${CODEX_GATEWAY_API_KEY_ENV:-CODEX_GATEWAY_API_KEY}"
SHARE_AUTH_TO_LANE2=0
TRUST_REPO_PATH=0
INSTALL_BRIDGE=0
SYNC_SESSIONS=0
PINNED_ONLY=0
DRY_RUN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo|--repo-path)
      require_arg "$1" "$#"
      REPO_PATH="$2"
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
    --approval-policy)
      require_arg "$1" "$#"
      APPROVAL_POLICY="$2"
      shift 2
      ;;
    --allow-sandbox-network)
      SANDBOX_NETWORK="true"
      ALLOW_SANDBOX_NETWORK_EXPLICIT=1
      shift
      ;;
    --use-git-worktree)
      USE_GIT_WORKTREE=1
      shift
      ;;
    --worktree-path)
      require_arg "$1" "$#"
      LANE2_WORKTREE_PATH="$2"
      shift 2
      ;;
    --configure-gateway)
      CONFIGURE_GATEWAY=1
      shift
      ;;
    --configure-cli-gateway)
      CONFIGURE_GATEWAY=1
      CONFIGURE_CLI_GATEWAY=1
      shift
      ;;
    --gateway-target-lane)
      require_arg "$1" "$#"
      GATEWAY_TARGET_LANE="$2"
      shift 2
      ;;
    --gateway-provider|--gateway-provider-name)
      require_arg "$1" "$#"
      GATEWAY_PROVIDER="$2"
      shift 2
      ;;
    --gateway-base-url)
      require_arg "$1" "$#"
      GATEWAY_BASE_URL="$2"
      CONFIGURE_GATEWAY=1
      shift 2
      ;;
    --gateway-model)
      require_arg "$1" "$#"
      GATEWAY_MODEL="$2"
      shift 2
      ;;
    --gateway-api-key-env|--cli-api-key-env)
      require_arg "$1" "$#"
      GATEWAY_API_KEY_ENV="$2"
      shift 2
      ;;
    --share-auth-to-lane2|--share-official-auth)
      SHARE_AUTH_TO_LANE2=1
      shift
      ;;
    --trust-repo-path)
      TRUST_REPO_PATH=1
      shift
      ;;
    --install-bridge)
      INSTALL_BRIDGE=1
      shift
      ;;
    --sync-sessions)
      SYNC_SESSIONS=1
      shift
      ;;
    --pinned-only)
      PINNED_ONLY=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      if [ "$#" -gt 0 ]; then
        REPO_PATH="$1"
        shift
      fi
      ;;
    -*)
      echo "[FAIL] Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      REPO_PATH="$1"
      shift
      ;;
  esac
done

# ------------------------------------------------------------------------------
# Strict Input & Precondition Validation (Fail Closed Before Any Disk Writes)
# ------------------------------------------------------------------------------
# Allowlist TOML enum/boolean values to prevent config.toml structure injection.
CLI_MODE="$(printf '%s' "${CLI_MODE}" | awk '{print tolower($0)}')"
case "${CLI_MODE}" in
  ask|config|full-access) ;;
  *)
    echo "[FAIL] Invalid --cli-mode '${CLI_MODE}'. Allowed values: 'ask', 'config', 'full-access'." >&2
    exit 1
    ;;
esac

case "${APPROVAL_POLICY}" in
  on-request|never) ;;
  *)
    echo "[FAIL] Invalid --approval-policy '${APPROVAL_POLICY}'. Allowed values: 'on-request', 'never'." >&2
    exit 1
    ;;
esac

case "${SANDBOX_NETWORK}" in
  true|false) ;;
  *)
    echo "[FAIL] Invalid CODEX_SANDBOX_NETWORK '${SANDBOX_NETWORK}'. Allowed values: 'false', 'true'." >&2
    exit 1
    ;;
esac

# Fail-closed Full Access confirmation gate (runs BEFORE any worktree, backup, or disk writes).
if [ "${CLI_MODE}" = "full-access" ]; then
  print_full_access_danger_warning
  if [ "${CONFIRM_FULL_ACCESS}" -eq 1 ]; then
    echo "[WARN] Explicit --confirm-full-access received. Proceeding with Full Access (danger-full-access / approval_policy=never)..." >&2
  elif [ -t 0 ]; then
    full_access_confirm=""
    printf "De xac nhan bat TOAN QUYEN (Full Access), go chinh xac 'TOAN QUYEN' (hoac 'I UNDERSTAND'): " >&2
    IFS= read -r full_access_confirm || true
    full_access_confirm="${full_access_confirm%$'\r'}"
    if [ "${full_access_confirm}" != "TOAN QUYEN" ] && [ "${full_access_confirm}" != "I UNDERSTAND" ]; then
      echo "[FAIL] Refused Full Access (danger-full-access / approval_policy=never): exact confirmation phrase 'TOAN QUYEN' or 'I UNDERSTAND' not provided. Zero files modified." >&2
      exit 1
    fi
  else
    echo "[FAIL] Refused Full Access (danger-full-access / approval_policy=never): explicit confirmation required (pass --confirm-full-access, or run interactively and type 'TOAN QUYEN' / 'I UNDERSTAND'). Zero files modified." >&2
    exit 1
  fi
fi

# Validate gateway target lane and gateway parameters when gateway mode is active.
if [ "${CONFIGURE_CLI_GATEWAY}" -eq 1 ]; then
  CONFIGURE_GATEWAY=1
  if [ "$(printf '%s' "${GATEWAY_TARGET_LANE}" | awk '{print tolower($0)}')" != "both" ]; then
    GATEWAY_TARGET_LANE="lane2"
  fi
fi
GATEWAY_TARGET_LOWER="$(printf '%s' "${GATEWAY_TARGET_LANE}" | awk '{print tolower($0)}')"
GATEWAY_ON_LANE1=0
GATEWAY_ON_LANE2=0
case "${GATEWAY_TARGET_LOWER}" in
  lane1)
    [ "${CONFIGURE_GATEWAY}" -eq 1 ] && GATEWAY_ON_LANE1=1
    ;;
  lane2)
    [ "${CONFIGURE_GATEWAY}" -eq 1 ] && GATEWAY_ON_LANE2=1
    ;;
  both)
    if [ "${CONFIGURE_GATEWAY}" -eq 1 ]; then
      GATEWAY_ON_LANE1=1
      GATEWAY_ON_LANE2=1
    fi
    ;;
  *)
    echo "[FAIL] Invalid --gateway-target-lane '${GATEWAY_TARGET_LANE}'. Allowed values: 'lane1', 'lane2', 'both'." >&2
    exit 1
    ;;
esac

GATEWAY_MODELS_URL=""
if [ "${CONFIGURE_GATEWAY}" -eq 1 ]; then
  if [ -z "${GATEWAY_BASE_URL}" ]; then
    echo "[FAIL] --configure-gateway requires --gateway-base-url <https://...>." >&2
    exit 1
  fi
  if printf '%s' "${GATEWAY_BASE_URL}" | LC_ALL=C grep -q '[[:cntrl:][:space:]"'\'']'; then
    echo "[FAIL] Invalid --gateway-base-url '${GATEWAY_BASE_URL}': whitespace, quotes, and control characters are not allowed." >&2
    exit 1
  fi
  if ! printf '%s' "${GATEWAY_BASE_URL}" | grep -Eq '^https?://[^/]+'; then
    echo "[FAIL] Invalid --gateway-base-url '${GATEWAY_BASE_URL}': must start with https:// or http://." >&2
    exit 1
  fi
  GATEWAY_MODELS_URL="${GATEWAY_BASE_URL%/}/models"

  if [ -z "${GATEWAY_PROVIDER}" ] || printf '%s' "${GATEWAY_PROVIDER}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "[FAIL] Invalid --gateway-provider '${GATEWAY_PROVIDER}': must be non-empty without control characters." >&2
    exit 1
  fi
  if ! printf '%s' "${GATEWAY_API_KEY_ENV}" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
    echo "[FAIL] Invalid --gateway-api-key-env '${GATEWAY_API_KEY_ENV}': must be a valid POSIX environment variable identifier." >&2
    exit 1
  fi
  if [ -n "${GATEWAY_MODEL}" ] && printf '%s' "${GATEWAY_MODEL}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "[FAIL] Invalid --gateway-model: control characters are not allowed." >&2
    exit 1
  fi
fi

REPO_PATH="$(validate_path_value "REPO_PATH" "${REPO_PATH}")"
if [ ! -d "${REPO_PATH}" ]; then
  echo "[FAIL] Target repository directory does not exist: ${REPO_PATH}" >&2
  exit 1
fi
REPO_PATH="$(cd -P -- "${REPO_PATH}" && pwd -P)"
if [[ "${REPO_PATH}" != /* ]]; then
  echo "[FAIL] REPO_PATH must resolve to an absolute path: ${REPO_PATH}" >&2
  exit 1
fi
REPO_PATH="$(validate_path_value "REPO_PATH" "${REPO_PATH}")"

LANE1_HOME="$(validate_path_value "LANE1_HOME" "${LANE1_HOME}")"
LANE2_HOME="$(validate_path_value "LANE2_HOME" "${LANE2_HOME}")"
LOCAL_BIN="$(validate_path_value "LOCAL_BIN" "${LOCAL_BIN}")"
CARGO_TARGET_LANE2="$(validate_path_value "CARGO_TARGET_LANE2" "${CARGO_TARGET_LANE2}")"

# Reject symlinked CODEX_HOME roots BEFORE canonicalize_dir resolves symlinks
# (applies in both real and --dry-run modes so symlinked homes are never hidden).
for home_root in "${LANE1_HOME}" "${LANE2_HOME}"; do
  if [ -L "${home_root}" ]; then
    echo "[FAIL] Security refusal: CODEX_HOME '${home_root}' must not be a symlink." >&2
    exit 1
  fi
done

# Canonicalize Lane roots so symlinked OS prefixes (e.g. macOS /var -> /private/var)
# stay consistent between install, symlink linking, and rollback verification.
LANE1_HOME="$(canonicalize_dir "${LANE1_HOME}")"
LANE2_HOME="$(canonicalize_dir "${LANE2_HOME}")"
LOCAL_BIN="$(canonicalize_dir "${LOCAL_BIN}")"

# Prevent catastrophic self-referential symlinks (`sessions -> sessions`) if
# both lanes resolve to the same directory.
if [ "${LANE1_HOME}" = "${LANE2_HOME}" ]; then
  echo "[FAIL] LANE1_HOME and LANE2_HOME must be distinct directories (both resolved to '${LANE1_HOME}')." >&2
  exit 1
fi

# Verify all required kit templates exist before mutating anything on disk.
for tpl in \
  "${KIT_ROOT}/templates/default.rules" \
  "${KIT_ROOT}/templates/AGENTS.lane1.md" \
  "${KIT_ROOT}/templates/AGENTS.lane2.md"; do
  if [ ! -f "${tpl}" ]; then
    echo "[FAIL] Missing required template file: ${tpl}" >&2
    exit 1
  fi
done
if [ ! -f "${KIT_ROOT}/scripts/codex-manager.sh" ]; then
  echo "[FAIL] Missing required manager script: ${KIT_ROOT}/scripts/codex-manager.sh" >&2
  exit 1
fi
if [ "${INSTALL_BRIDGE}" -eq 1 ] && [ ! -f "${KIT_ROOT}/templates/DUAL_LANE_BRIDGE.md" ]; then
  echo "[FAIL] Missing bridge template: ${KIT_ROOT}/templates/DUAL_LANE_BRIDGE.md" >&2
  exit 1
fi

echo "=== Codex Dual-Lane & Security Kit Installer (macOS / Linux / WSL) ==="
[ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No user files on disk will be modified."

# ------------------------------------------------------------------------------
# 1. Detect Real `codex` Binary (Excluding Our Own Wrapper to Avoid Recursion)
# ------------------------------------------------------------------------------
CODEX_BIN=""
while IFS= read -r candidate; do
  [ -z "${candidate}" ] && continue
  cand_dir="$(canonicalize_dir "$(dirname -- "${candidate}")")"
  if [ "${cand_dir}" = "${LOCAL_BIN}" ]; then
    continue
  fi
  if [ -f "${candidate}" ] && [ -x "${candidate}" ]; then
    CODEX_BIN="${candidate}"
    break
  fi
done < <(type -ap codex 2>/dev/null || true)

if [ -z "${CODEX_BIN}" ]; then
  echo "[FAIL] No 'codex' binary found in PATH. Install with 'npm i -g @openai/codex' first." >&2
  exit 1
fi
CODEX_BIN="$(validate_path_value "CODEX_BIN" "${CODEX_BIN}")"

# Read full stdout before selecting line 1 to prevent SIGPIPE under `pipefail`.
CODEX_VER_RAW="$("${CODEX_BIN}" --version 2>/dev/null || true)"
CODEX_VER="$(printf '%s\n' "${CODEX_VER_RAW}" | awk 'NR==1{line=$0} END{if (line != "") print line; else print "unknown"}')"
echo "[+] Found codex binary: ${CODEX_BIN} (${CODEX_VER})"

# ------------------------------------------------------------------------------
# 2. Dynamically Probe Supported Feature Flags in an Ephemeral CODEX_HOME
# ------------------------------------------------------------------------------
# Using an isolated temporary CODEX_HOME guarantees the probe never reads or
# mutates the user's real ~/.codex or ~/.codex-official directories.
PROBE_DIR="$(mktemp -d "${SAFE_TMPDIR}/codex-probe.XXXXXX")"
TEMP_ARTIFACTS+=("${PROBE_DIR}")

FEATURES_OUT="$(CODEX_HOME="${PROBE_DIR}" "${CODEX_BIN}" features list 2>/dev/null || true)"
HAS_DAEMON_FLAG=0
HAS_GOALS_FLAG=0
HAS_API_DISCOVERY_FLAG=0
HAS_IMAGE_GEN_FLAG=0
ACTIVE_FEATURE_STAGE_RE='(stable|experimental|under[[:space:]]+development|deprecated)'
if printf '%s\n' "${FEATURES_OUT}" | grep -Eqi "^daemon_auto_start[[:space:]]+${ACTIVE_FEATURE_STAGE_RE}([[:space:]]|$)"; then HAS_DAEMON_FLAG=1; fi
if printf '%s\n' "${FEATURES_OUT}" | grep -Eqi "^goals[[:space:]]+${ACTIVE_FEATURE_STAGE_RE}([[:space:]]|$)"; then HAS_GOALS_FLAG=1; fi
if printf '%s\n' "${FEATURES_OUT}" | grep -Eqi "^api_key_model_discovery[[:space:]]+${ACTIVE_FEATURE_STAGE_RE}([[:space:]]|$)"; then HAS_API_DISCOVERY_FLAG=1; fi
if printf '%s\n' "${FEATURES_OUT}" | grep -Eqi "^image_generation[[:space:]]+${ACTIVE_FEATURE_STAGE_RE}([[:space:]]|$)"; then HAS_IMAGE_GEN_FLAG=1; fi

# ------------------------------------------------------------------------------
# 3. Optional: Create Isolated Git Worktree for Lane 2 (Hard OS Write Boundary)
# ------------------------------------------------------------------------------
EFFECTIVE_LANE2_REPO="${REPO_PATH}"
if [ "${USE_GIT_WORKTREE}" -eq 1 ]; then
  # Reject branch names starting with '-' or invalid Git refs (option-injection guard).
  if [ -z "${LANE2_BRANCH}" ] || [ "${LANE2_BRANCH#-}" != "${LANE2_BRANCH}" ] || ! git check-ref-format --branch "${LANE2_BRANCH}" >/dev/null 2>&1; then
    echo "[FAIL] Invalid Git branch name for Lane 2 worktree: '${LANE2_BRANCH}'" >&2
    exit 1
  fi
  if ! git -C "${REPO_PATH}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[FAIL] --use-git-worktree requires '${REPO_PATH}' to be inside a Git repository." >&2
    exit 1
  fi

  WT_TARGET="${LANE2_WORKTREE_PATH:-${REPO_PATH}-lane2}"
  WT_TARGET="$(validate_path_value "LANE2_WORKTREE_PATH" "${WT_TARGET}")"
  if [ -L "${WT_TARGET}" ]; then
    echo "[FAIL] Security refusal: worktree path '${WT_TARGET}' is a symlink." >&2
    exit 1
  fi
  if [ -d "${WT_TARGET}" ]; then
    EFFECTIVE_LANE2_REPO="$(cd -P -- "${WT_TARGET}" && pwd -P)"
    echo "    Existing Lane 2 worktree: ${EFFECTIVE_LANE2_REPO}"
  else
    if [ "${DRY_RUN}" -eq 0 ]; then
      git -C "${REPO_PATH}" worktree add -B "${LANE2_BRANCH}" -- "${WT_TARGET}" HEAD
      EFFECTIVE_LANE2_REPO="$(cd -P -- "${WT_TARGET}" && pwd -P)"
      echo "    Created Lane 2 Git worktree: ${EFFECTIVE_LANE2_REPO} (branch: ${LANE2_BRANCH})"
    else
      EFFECTIVE_LANE2_REPO="${WT_TARGET}"
      echo "    [DRY-RUN] Would create Lane 2 Git worktree: ${EFFECTIVE_LANE2_REPO} (branch: ${LANE2_BRANCH})"
    fi
  fi
fi

# ------------------------------------------------------------------------------
# 4. Prepare Directories, Rollback Journal & Harden Owner-Only Permissions (0700)
# ------------------------------------------------------------------------------
base_stamp="$(date +%Y%m%d-%H%M%S)"
stamp="${base_stamp}"
UTC_NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)"
ROLLBACK_DIR="${LANE2_HOME}/.rollback"
if [ "${DRY_RUN}" -eq 0 ]; then
  for home_root in "${LANE1_HOME}" "${LANE2_HOME}"; do
    if [ -L "${home_root}" ]; then
      echo "[FAIL] Security refusal: CODEX_HOME '${home_root}' is a symlink." >&2
      exit 1
    fi
  done
  if [ -L "${ROLLBACK_DIR}" ]; then
    echo "[FAIL] Security refusal: rollback directory '${ROLLBACK_DIR}' is a symlink." >&2
    exit 1
  fi
  mkdir -p -- "${LANE1_HOME}/rules" "${LANE2_HOME}/rules" "${LOCAL_BIN}" "${ROLLBACK_DIR}"
  # Enforce 0700 on both CODEX_HOME roots, rules dirs, and rollback dir even if pre-existing.
  # Note: omit `--` on chmod for BSD/macOS compatibility (paths are validated absolute).
  chmod 700 "${LANE1_HOME}" "${LANE1_HOME}/rules" "${LANE2_HOME}" "${LANE2_HOME}/rules" "${ROLLBACK_DIR}" 2>/dev/null || true

  # Prevent same-second snapshot/backup collisions across rapid repeated install/rollback
  # cycles while keeping lexicographic timestamp ordering strictly chronological.
  if [ -e "${ROLLBACK_DIR}/snapshot-${stamp}.tsv" ] || [ -L "${ROLLBACK_DIR}/snapshot-${stamp}.tsv" ]; then
    seq_idx=1
    while :; do
      cand_stamp="$(printf '%s-%02d' "${base_stamp}" "${seq_idx}")"
      if [ ! -e "${ROLLBACK_DIR}/snapshot-${cand_stamp}.tsv" ] && [ ! -L "${ROLLBACK_DIR}/snapshot-${cand_stamp}.tsv" ]; then
        stamp="${cand_stamp}"
        break
      fi
      seq_idx=$((seq_idx + 1))
    done
  fi
  SNAP_FILE="${ROLLBACK_DIR}/snapshot-${stamp}.tsv"
  LATEST_FILE="${ROLLBACK_DIR}/latest.tsv"
  ROLLBACK_READY=1
  ROLLBACK_STATUS="in-progress"
  flush_rollback_manifest
fi

# ------------------------------------------------------------------------------
# 5. Share Memories, Sessions, Skills & Plugins via Symlinks (Non-Destructive)
# ------------------------------------------------------------------------------
SHARED_DIRS=(memories memories_v2 sessions archived_sessions skills plugins)
for d in "${SHARED_DIRS[@]}"; do
  src_dir="${LANE1_HOME}/${d}"
  dst_link="${LANE2_HOME}/${d}"
  if [ "${DRY_RUN}" -eq 0 ]; then
    mkdir -p -- "${src_dir}"
    chmod 700 "${src_dir}" 2>/dev/null || true
  fi
  if [ -L "${dst_link}" ]; then
    existing_target="$(readlink "${dst_link}" 2>/dev/null || true)"
    if [ "${existing_target}" = "${src_dir}" ]; then
      echo "    Already linked (pre-existing): ${dst_link} -> ${src_dir}"
    else
      echo "[WARN] Existing symlink ${dst_link} points to '${existing_target}' (expected '${src_dir}'); leaving untouched." >&2
    fi
    # Pre-existing symlinks were NOT created by this install (created_by_kit=0).
    # Record them explicitly in LINK_MANIFEST_ROWS so rollback preserves them intact.
    LINK_MANIFEST_ROWS+=("$(printf 'L\t0\t%s\t-\tpreexisting_link' "${dst_link}")")
    flush_rollback_manifest
    continue
  elif [ -e "${dst_link}" ]; then
    dir_bkp="$(unique_backup_path "${dst_link}")"
    if [ "${DRY_RUN}" -eq 0 ]; then
      mv -- "${dst_link}" "${dir_bkp}"
      echo "    Backed up existing directory: ${dir_bkp}"
      # Write-ahead manifest checkpoint with EXACT dir_bkp path BEFORE ln -s so
      # even an interrupt between mv and ln -s recovers the exact backup directory.
      LINK_MANIFEST_ROWS+=("$(printf 'L\t1\t%s\t%s\tpreexisting_dir' "${dst_link}" "${dir_bkp}")")
      LINKED_SHARED_DIRS+=("${d}")
      flush_rollback_manifest
    else
      echo "    [DRY-RUN] Would back up existing directory: ${dir_bkp}"
    fi
  else
    LINK_MANIFEST_ROWS+=("$(printf 'L\t1\t%s\t-\tabsent' "${dst_link}")")
    LINKED_SHARED_DIRS+=("${d}")
  fi
  if [ "${DRY_RUN}" -eq 0 ]; then
    ln -s -- "${src_dir}" "${dst_link}"
    echo "    Linked: ${dst_link} -> ${src_dir}"
    flush_rollback_manifest
  else
    echo "    [DRY-RUN] Would link: ${dst_link} -> ${src_dir}"
  fi
done

# ------------------------------------------------------------------------------
# 6. Install Command Firewall Rules & Lane-Specific Global AGENTS.md
# ------------------------------------------------------------------------------
backup_and_copy "${KIT_ROOT}/templates/default.rules" "${LANE1_HOME}/rules/default.rules" 600
backup_and_copy "${KIT_ROOT}/templates/default.rules" "${LANE2_HOME}/rules/default.rules" 600
backup_and_copy "${KIT_ROOT}/templates/AGENTS.lane1.md" "${LANE1_HOME}/AGENTS.md" 600
backup_and_copy "${KIT_ROOT}/templates/AGENTS.lane2.md" "${LANE2_HOME}/AGENTS.md" 600

# Optional (strictly opt-in, default off): Share / Harvest OAuth Login (`auth.json`) from Lane 1 (Desktop) to Lane 2 (CLI)
# Read-only on Lane 1: safely backs up any pre-existing Lane 2 auth.json into MANIFEST_ROWS,
# atomically copies Lane 1 auth.json to Lane 2 auth.json with chmod 600, and records
# Lane 2 auth.json in MANIFEST_ROWS so restore-original.sh restores/removes it deterministically
# while leaving Lane 1 auth.json 100% untouched.
if [ "${SHARE_AUTH_TO_LANE2}" -eq 1 ]; then
  LANE1_AUTH="${LANE1_HOME}/auth.json"
  LANE2_AUTH="${LANE2_HOME}/auth.json"
  echo "[WARN] --share-auth-to-lane2 is strictly opt-in: copying '${LANE1_AUTH}' creates a second copy of your OAuth credentials in Lane 2 ('${LANE2_AUTH}', mode 0600)." >&2
  if [ "${GATEWAY_ON_LANE2}" -eq 1 ]; then
    echo "[WARN] SECURITY WARNING: --share-auth-to-lane2 is combined with a third-party API gateway targeting Lane 2 (${GATEWAY_BASE_URL}). Avoid mixing copied official OAuth tokens (auth.json) with a third-party API gateway; prefer dedicated env_key (${GATEWAY_API_KEY_ENV}) without --share-auth-to-lane2 unless you explicitly trust the endpoint." >&2
  fi
  if [ -L "${LANE1_AUTH}" ]; then
    echo "[FAIL] Security refusal: '${LANE1_AUTH}' is a symlink; refusing to harvest auth.json." >&2
    exit 1
  fi
  if [ -L "${LANE2_AUTH}" ]; then
    echo "[FAIL] Security refusal: destination '${LANE2_AUTH}' is a symlink; refusing to overwrite." >&2
    exit 1
  fi
  if [ -f "${LANE1_AUTH}" ]; then
    backup_and_copy "${LANE1_AUTH}" "${LANE2_AUTH}" 600
  else
    echo "[WARN] --share-auth-to-lane2 specified, but '${LANE1_AUTH}' does not exist; skipping auth copy." >&2
  fi
fi

# ------------------------------------------------------------------------------
# 7. Non-Destructively Merge & Atomically Write Lane 2 (and Optional Lane 1 Gateway) config.toml
# ------------------------------------------------------------------------------
# Never writes plaintext API keys or bearer tokens:
#   - Lane 1 (Desktop, ~/.codex) = Primary Account (`acc chính`), or optional gateway via env_key.
#   - Lane 2 (CLI, ~/.codex-official) = Supports BOTH OAuth/ChatGPT Login (`codex login`) AND
#     API Key / gateway (`env_key` via `--configure-gateway --gateway-target-lane lane2|both`),
#     with full workspace directory tree traversal and file read/write/edit/delete inside
#     `sandbox_mode = "workspace-write"`.

# SECURITY: trust is NEVER raised implicitly. REPO_PATH / the Lane 2 worktree are written as
# trust_level = "trusted" ONLY with explicit --trust-repo-path; otherwise any existing trust_level
# (trusted / untrusted / unset) is preserved and Codex prompts for trust on first use.
if [ "${TRUST_REPO_PATH}" -eq 1 ]; then
  echo "    [INFO] --trust-repo-path (explicit opt-in): '${REPO_PATH}' will be recorded as trust_level = \"trusted\"."
else
  echo "    [INFO] Project trust left unchanged for '${REPO_PATH}' (pass --trust-repo-path to explicitly mark it trusted; Codex will ask on first use otherwise)."
fi
ESC_REPO="$(escape_toml "${REPO_PATH}")"
ESC_LANE2_REPO="$(escape_toml "${EFFECTIVE_LANE2_REPO}")"
ESC_CARGO="$(escape_toml "${CARGO_TARGET_LANE2}")"
ESC_GW_PROV="$(escape_toml "${GATEWAY_PROVIDER}")"
ESC_GW_URL="$(escape_toml "${GATEWAY_BASE_URL}")"
ESC_GW_MODELS_URL="$(escape_toml "${GATEWAY_MODELS_URL}")"
ESC_GW_MODEL="$(escape_toml "${GATEWAY_MODEL}")"
ESC_GW_ENV="$(escape_toml "${GATEWAY_API_KEY_ENV}")"
GW_PROV_LOWER="$(printf '%s' "${GATEWAY_PROVIDER}" | awk '{print tolower($0)}')"
HAS_GW_MODEL=0
[ -n "${GATEWAY_MODEL}" ] && HAS_GW_MODEL=1

# Fail-closed pre-write gate guaranteeing zero plaintext API keys or bearer tokens
# ever reach config.toml in either lane.
assert_no_plaintext_secret_in_toml() {
  local label="$1"
  local content="$2"
  if printf '%s\n' "${content}" | awk '
    { sub(/\r$/, "", $0) }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*experimental_bearer_token[[:space:]]*=/ { found = 1; exit }
    /^[[:space:]]*api_key[[:space:]]*=[[:space:]]*["\047][^"\047]+["\047]/ { found = 1; exit }
    END { exit(found ? 0 : 1) }
  '; then
    echo "[FAIL] Security invariant violation in ${label}: refusing to write plaintext api_key or experimental_bearer_token to config.toml. Use env_key instead." >&2
    exit 1
  fi
}

# Preserve custom user top-level keys (e.g. model, service_tier,
# cli_auth_credentials_store) except installer-managed sandbox/approval/gateway keys.
# Strips trailing CR and handles section headers with trailing `#` comments
# (while preserving `#` inside quoted paths like `[projects."/a#b"]`).
extract_preserved_top_keys() {
  local cfg_file="$1"
  local use_gw="$2"
  local has_model="$3"
  local preserve_sandbox="${4:-0}"
  awk -v use_gw="${use_gw}" -v has_model="${has_model}" -v preserve_sandbox="${preserve_sandbox}" '
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
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ { exit }
    clean ~ /^[[:space:]]*$/ { next }
    clean ~ /^[[:space:]]*["\047]?[A-Za-z0-9_-]+["\047]?[[:space:]]*=/ {
      key = clean
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*=.*$/, "", key)
      gsub(/^["\047]|["\047]$/, "", key)
      if (key == "experimental_bearer_token" || key == "api_key") {
        next
      }
      if (preserve_sandbox == 0 && (key == "sandbox_mode" || key == "approval_policy")) {
        next
      }
      if (use_gw == 1) {
        if (key == "model_provider" || key == "web_search" || key == "disable_response_storage") {
          next
        }
        if (has_model == 1 && (key == "model" || key == "review_model")) {
          next
        }
      }
      print $0
    }
  ' "${cfg_file}" || true
}

# Preserve custom user key assignments inside a specific managed TOML table
# (e.g. [features] or [memories]) while skipping kit-upserted keys and secrets.
extract_preserved_table_keys() {
  local cfg_file="$1"
  local target_table="$2"
  local skip_keys_csv="$3"
  awk -v target_table="${target_table}" -v skip_csv="${skip_keys_csv}" '
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
    BEGIN { in_target = 0 }
    {
      sub(/\r$/, "", $0)
      clean = strip_comment($0)
    }
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ {
      sec = clean
      sub(/^[[:space:]]*\[/, "", sec)
      sub(/\][[:space:]]*$/, "", sec)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
      in_target = (tolower(sec) == target_table)
      next
    }
    !in_target { next }
    clean ~ /^[[:space:]]*$/ { next }
    clean ~ /^[[:space:]]*(["\047]?[A-Za-z0-9_-]+["\047]?)[[:space:]]*=/ {
      key = clean
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*=.*$/, "", key)
      gsub(/^["\047]|["\047]$/, "", key)
      lkey = tolower(key)
      if (lkey == "experimental_bearer_token" || lkey == "api_key") {
        next
      }
      if (index(skip_csv, "," lkey ",") > 0) {
        next
      }
      print $0
    }
  ' "${cfg_file}" || true
}

# Check if a top-level TOML key (before the first [section]) exists in cfg_file.
toml_has_top_key() {
  local cfg_file="$1"
  local want_key="$2"
  [ -f "${cfg_file}" ] && [ ! -L "${cfg_file}" ] || return 1
  awk -v want="${want_key}" '
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
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ { exit(found ? 0 : 1) }
    clean ~ /^[[:space:]]*(["\047]?[A-Za-z0-9_-]+["\047]?)[[:space:]]*=/ {
      key = clean
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*=.*$/, "", key)
      gsub(/^["\047]|["\047]$/, "", key)
      if (tolower(key) == tolower(want)) {
        found = 1
        exit 0
      }
    }
    END { exit(found ? 0 : 1) }
  ' "${cfg_file}" 2>/dev/null
}

# Check if a TOML section `[sec]` (or optionally `[sec.*]` when match_prefix=1) exists.
toml_has_section() {
  local cfg_file="$1"
  local want_sec="$2"
  local match_prefix="${3:-0}"
  [ -f "${cfg_file}" ] && [ ! -L "${cfg_file}" ] || return 1
  awk -v want="${want_sec}" -v mp="${match_prefix}" '
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
      lsec = tolower(sec)
      lwant = tolower(want)
      if (lsec == lwant || (mp == 1 && index(lsec, lwant ".") == 1)) {
        found = 1
        exit 0
      }
    }
    END { exit(found ? 0 : 1) }
  ' "${cfg_file}" 2>/dev/null
}

# Extract an unquoted top-level scalar string value from rendered TOML text.
toml_get_top_key_from_text() {
  local text="$1"
  local want_key="$2"
  printf '%s\n' "${text}" | awk -v want="${want_key}" '
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
    clean ~ /^[[:space:]]*\[.*\][[:space:]]*$/ { exit }
    clean ~ /^[[:space:]]*(["\047]?[A-Za-z0-9_-]+["\047]?)[[:space:]]*=/ {
      key = clean
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*=.*$/, "", key)
      gsub(/^["\047]|["\047]$/, "", key)
      if (tolower(key) == tolower(want)) {
        val = clean
        sub(/^[^=]*=/, "", val)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        gsub(/^["\047]|["\047]$/, "", val)
        print val
        exit
      }
    }
  ' 2>/dev/null || true
}

# Preserve custom user sections (e.g. [mcp_servers.*], [tui], [plugins.*],
# pre-existing [projects.*]) while refreshing only Dual-Lane managed sections.
extract_preserved_user_sections() {
  local cfg_file="$1"
  local use_gw="$2"
  local gw_prov_lc="$3"
  local preserve_sw="${4:-0}"
  local preserve_ap_table="${5:-0}"
  awk -v use_gw="${use_gw}" -v gw_prov_lc="${gw_prov_lc}" -v preserve_sw="${preserve_sw}" -v preserve_ap_table="${preserve_ap_table}" '
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
    function norm_sec(sec,    s) {
      s = tolower(sec)
      if (s ~ /^model_providers\./) {
        sub(/^model_providers\.[[:space:]]*/, "", s)
        gsub(/^["\047]|["\047]$/, "", s)
        return "model_providers." s
      }
      return s
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
      nsec = norm_sec(sec)
      if (nsec == "windows" || nsec == "features" || nsec == "memories" || nsec == "shell_environment_policy" || nsec == "shell_environment_policy.set") {
        keep = 0
      } else if (preserve_sw == 0 && nsec == "sandbox_workspace_write") {
        keep = 0
      } else if (preserve_ap_table == 0 && (nsec == "approval_policy" || index(nsec, "approval_policy.") == 1)) {
        keep = 0
      } else if (use_gw == 1 && nsec == ("model_providers." gw_prov_lc)) {
        keep = 0
      } else {
        keep = 1
      }
    }
    keep == 1 {
      if (clean ~ /^[[:space:]]*(experimental_bearer_token|api_key)[[:space:]]*=/) {
        next
      }
      print $0
    }
  ' "${cfg_file}" || true
}

# Helper to test if a `[projects.*]` table for a given path already exists in
# preserved TOML sections (comment-aware; normalizes double/single quotes,
# TOML basic-string escapes, optional spaces around '.', and trailing slashes).
has_project_section_in() {
  local preserved_sections="$1"
  local raw_p="$2"
  printf '%s\n' "${preserved_sections}" | AWK_TARGET_PATH="${raw_p}" awk '
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
    function unescape_toml_basic(s,    i, c, n, out) {
      out = ""
      n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\" && i < n) {
          i++
          c = substr(s, i, 1)
          if (c == "\"" || c == "\\") out = out c
          else if (c == "t") out = out "\t"
          else if (c == "n") out = out "\n"
          else if (c == "r") out = out "\r"
          else if (c == "b") out = out "\b"
          else if (c == "f") out = out "\f"
          else out = out "\\" c
        } else {
          out = out c
        }
      }
      return out
    }
    function norm_path(p,    k) {
      k = p
      if (substr(k, 1, 2) != "//") {
        gsub(/\/+/, "/", k)
      }
      while (length(k) > 1 && substr(k, length(k), 1) == "/") {
        k = substr(k, 1, length(k) - 1)
      }
      return k
    }
    function extract_sec_header(line,    clean, sec) {
      sub(/\r$/, "", line)
      clean = strip_comment(line)
      if (clean !~ /^[[:space:]]*\[.*\][[:space:]]*$/) {
        return ""
      }
      sec = clean
      sub(/^[[:space:]]*\[/, "", sec)
      sub(/\][[:space:]]*$/, "", sec)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
      return sec
    }
    function parse_proj_section_key(sec,    k, q, i, c, n, esc, end_pos, raw) {
      if (sec !~ /^(projects|"projects"|\047projects\047)[[:space:]]*\./) return ""
      k = sec
      sub(/^(projects|"projects"|\047projects\047)[[:space:]]*\.[[:space:]]*/, "", k)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      if (k == "") return ""
      q = substr(k, 1, 1)
      if (q == "\"") {
        n = length(k)
        esc = 0
        end_pos = 0
        for (i = 2; i <= n; i++) {
          c = substr(k, i, 1)
          if (esc) { esc = 0; continue }
          if (c == "\\") { esc = 1; continue }
          if (c == "\"") { end_pos = i; break }
        }
        if (end_pos != n) return ""
        raw = unescape_toml_basic(substr(k, 2, n - 2))
      } else if (q == "\047") {
        n = length(k)
        end_pos = index(substr(k, 2), "\047")
        if (end_pos == 0 || (end_pos + 1) != n) return ""
        raw = substr(k, 2, n - 2)
      } else {
        if (k !~ /^[A-Za-z0-9_-]+$/) return ""
        raw = k
      }
      if (raw == "" || raw ~ /[[:cntrl:]]/) return ""
      return norm_path(raw)
    }
    BEGIN {
      target = norm_path(ENVIRON["AWK_TARGET_PATH"])
      found = 0
    }
    {
      if (!found) {
        sec = extract_sec_header($0)
        if (sec != "") {
          pk = parse_proj_section_key(sec)
          if (pk != "" && pk == target) {
            found = 1
          }
        }
      }
    }
    END { exit(found ? 0 : 1) }
  '
}

# Read-only harvest of `[projects."..."]` tables from Lane 1 (Codex Desktop)
# into Lane 2 (Codex CLI), strictly preserving trust boundaries:
#   - Only harvests sections with an explicit `trust_level = "trusted"` or
#     `trust_level = "untrusted"`, faithfully preserving each project's exact
#     `trust_level` (NEVER promoting `untrusted`, missing, or invalid values).
#   - Deduplicates against REPO_PATH, EFFECTIVE_LANE2_REPO, and all pre-existing
#     Lane 2 `[projects.*]` sections across quoting and trailing-slash variants
#     so an existing Lane 2 `untrusted` entry is never overwritten or duplicated.
extract_harvested_lane1_projects() {
  local lane1_cfg="$1"
  local existing_sections="$2"
  if [ ! -f "${lane1_cfg}" ] || [ -L "${lane1_cfg}" ]; then
    return 0
  fi
  local awk_repo_raw="" awk_wt_raw=""
  if [ "${TRUST_REPO_PATH}" -eq 1 ]; then
    awk_repo_raw="${REPO_PATH}"
    awk_wt_raw="${EFFECTIVE_LANE2_REPO}"
  fi
  AWK_EXISTING_SECTIONS="${existing_sections}" \
  AWK_REPO_RAW="${awk_repo_raw}" \
  AWK_WT_RAW="${awk_wt_raw}" \
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
    function unescape_toml_basic(s,    i, c, n, out) {
      out = ""
      n = length(s)
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\" && i < n) {
          i++
          c = substr(s, i, 1)
          if (c == "\"" || c == "\\") out = out c
          else if (c == "t") out = out "\t"
          else if (c == "n") out = out "\n"
          else if (c == "r") out = out "\r"
          else if (c == "b") out = out "\b"
          else if (c == "f") out = out "\f"
          else out = out "\\" c
        } else {
          out = out c
        }
      }
      return out
    }
    function escape_toml_basic(s,    i, c, out) {
      out = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") out = out "\\\\"
        else if (c == "\"") out = out "\\\""
        else out = out c
      }
      return out
    }
    function norm_path(p,    k) {
      k = p
      if (substr(k, 1, 2) != "//") {
        gsub(/\/+/, "/", k)
      }
      while (length(k) > 1 && substr(k, length(k), 1) == "/") {
        k = substr(k, 1, length(k) - 1)
      }
      return k
    }
    # Note: `[[array_of_tables]]` intentionally returns a non-empty, non-`projects.`
    # header so it cleanly terminates any preceding `[projects.*]` section.
    function extract_sec_header(line,    clean, sec) {
      sub(/\r$/, "", line)
      clean = strip_comment(line)
      if (clean !~ /^[[:space:]]*\[.*\][[:space:]]*$/) {
        return ""
      }
      sec = clean
      sub(/^[[:space:]]*\[/, "", sec)
      sub(/\][[:space:]]*$/, "", sec)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", sec)
      return sec
    }
    function parse_proj_section_key(sec,    k, q, i, c, n, esc, end_pos, raw) {
      if (sec !~ /^(projects|"projects"|\047projects\047)[[:space:]]*\./) return ""
      k = sec
      sub(/^(projects|"projects"|\047projects\047)[[:space:]]*\.[[:space:]]*/, "", k)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      if (k == "") return ""
      q = substr(k, 1, 1)
      if (q == "\"") {
        n = length(k)
        esc = 0
        end_pos = 0
        for (i = 2; i <= n; i++) {
          c = substr(k, i, 1)
          if (esc) { esc = 0; continue }
          if (c == "\\") { esc = 1; continue }
          if (c == "\"") { end_pos = i; break }
        }
        if (end_pos != n) return ""
        raw = unescape_toml_basic(substr(k, 2, n - 2))
      } else if (q == "\047") {
        n = length(k)
        end_pos = index(substr(k, 2), "\047")
        if (end_pos == 0 || (end_pos + 1) != n) return ""
        raw = substr(k, 2, n - 2)
      } else {
        if (k !~ /^[A-Za-z0-9_-]+$/) return ""
        raw = k
      }
      if (raw == "" || raw ~ /[[:cntrl:]]/) return ""
      return norm_path(raw)
    }
    function extract_trust_level_assignment(clean,    val) {
      if (clean !~ /^[[:space:]]*(trust_level|"trust_level"|\047trust_level\047)[[:space:]]*=/) {
        return ""
      }
      val = clean
      sub(/^[[:space:]]*(trust_level|"trust_level"|\047trust_level\047)[[:space:]]*=[[:space:]]*/, "", val)
      gsub(/[[:space:]]+$/, "", val)
      if (val == "\"trusted\"" || val == "\047trusted\047") {
        return "trusted"
      }
      if (val == "\"untrusted\"" || val == "\047untrusted\047") {
        return "untrusted"
      }
      return "__INVALID__"
    }
    function flush_proj(    j) {
      if (!in_proj) return
      if (!(cur_pk in seen_proj)) {
        if (cur_trust == "untrusted" || (cur_trust == "trusted" && !cur_trust_invalid)) {
          if (emitted > 0) {
            printf "\n"
          }
          printf "[projects.\"%s\"]\n", escape_toml_basic(cur_pk)
          printf "trust_level = \"%s\"\n", cur_trust
          for (j = 1; j <= extra_count; j++) {
            printf "%s\n", extra_lines[j]
          }
          seen_proj[cur_pk] = 1
          emitted++
        }
      }
      in_proj = 0
      cur_pk = ""
      cur_trust = ""
      cur_trust_invalid = 0
      extra_count = 0
    }
    BEGIN {
      if (ENVIRON["AWK_REPO_RAW"] != "") seen_proj[norm_path(ENVIRON["AWK_REPO_RAW"])] = 1
      if (ENVIRON["AWK_WT_RAW"] != "")   seen_proj[norm_path(ENVIRON["AWK_WT_RAW"])] = 1
      n = split(ENVIRON["AWK_EXISTING_SECTIONS"], lines, "\n")
      for (i = 1; i <= n; i++) {
        s = extract_sec_header(lines[i])
        if (s != "") {
          epk = parse_proj_section_key(s)
          if (epk != "") {
            seen_proj[epk] = 1
          }
        }
      }
      in_proj = 0
      cur_pk = ""
      cur_trust = ""
      cur_trust_invalid = 0
      extra_count = 0
      emitted = 0
    }
    {
      sub(/\r$/, "", $0)
      clean = strip_comment($0)
      sec = extract_sec_header($0)
      if (sec != "") {
        flush_proj()
        pk = parse_proj_section_key(sec)
        if (pk != "" && !(pk in seen_proj)) {
          in_proj = 1
          cur_pk = pk
          cur_trust = ""
          cur_trust_invalid = 0
          extra_count = 0
        }
        next
      }
      if (!in_proj) {
        next
      }
      if (clean ~ /^[[:space:]]*$/) {
        next
      }
      if (clean ~ /^[[:space:]]*(experimental_bearer_token|api_key)[[:space:]]*=/) {
        next
      }
      tl = extract_trust_level_assignment(clean)
      if (tl != "") {
        if (tl == "untrusted") {
          cur_trust = "untrusted"
        } else if (tl == "trusted") {
          if (cur_trust == "") {
            cur_trust = "trusted"
          }
        } else {
          cur_trust_invalid = 1
        }
        next
      }
      extra_count++
      extra_lines[extra_count] = $0
    }
    END {
      flush_proj()
    }
  ' "${lane1_cfg}" || true
}

CFG2="${LANE2_HOME}/config.toml"
PRESERVED_TOP_KEYS=""
PRESERVED_USER_SECTIONS=""
PRESERVED_FEATURES_KEYS=""
PRESERVED_MEMORIES_KEYS=""

L2_MANAGED_FEAT_KEYS=",memories,"
[ "${HAS_DAEMON_FLAG}" -eq 1 ] && L2_MANAGED_FEAT_KEYS="${L2_MANAGED_FEAT_KEYS}daemon_auto_start,"
[ "${HAS_GOALS_FLAG}" -eq 1 ] && L2_MANAGED_FEAT_KEYS="${L2_MANAGED_FEAT_KEYS}goals,"
[ "${HAS_API_DISCOVERY_FLAG}" -eq 1 ] && L2_MANAGED_FEAT_KEYS="${L2_MANAGED_FEAT_KEYS}api_key_model_discovery,"
[ "${HAS_IMAGE_GEN_FLAG}" -eq 1 ] && L2_MANAGED_FEAT_KEYS="${L2_MANAGED_FEAT_KEYS}image_generation,"

PRESERVE_TOP_SANDBOX=0
PRESERVE_SW_SECTION=0
PRESERVE_AP_TABLE=0
RENDER_SANDBOX_MODE="workspace-write"
RENDER_APPROVAL_POLICY="${APPROVAL_POLICY}"
EMIT_SW_SECTION=1

if [ "${CLI_MODE}" = "full-access" ]; then
  RENDER_SANDBOX_MODE="danger-full-access"
  RENDER_APPROVAL_POLICY="never"
elif [ "${CLI_MODE}" = "config" ]; then
  PRESERVE_TOP_SANDBOX=1
  PRESERVE_AP_TABLE=1
  if [ -f "${CFG2}" ] && [ ! -L "${CFG2}" ]; then
    if toml_has_top_key "${CFG2}" "sandbox_mode"; then
      RENDER_SANDBOX_MODE=""
    else
      RENDER_SANDBOX_MODE="workspace-write"
    fi
    if toml_has_top_key "${CFG2}" "approval_policy" || toml_has_section "${CFG2}" "approval_policy" 1; then
      RENDER_APPROVAL_POLICY=""
    else
      RENDER_APPROVAL_POLICY="on-request"
    fi
    if [ "${ALLOW_SANDBOX_NETWORK_EXPLICIT}" -eq 0 ] && toml_has_section "${CFG2}" "sandbox_workspace_write" 0; then
      PRESERVE_SW_SECTION=1
      EMIT_SW_SECTION=0
    fi
  else
    RENDER_SANDBOX_MODE="workspace-write"
    RENDER_APPROVAL_POLICY="on-request"
  fi
fi

if [ -L "${CFG2}" ]; then
  echo "[FAIL] Security refusal: '${CFG2}' is a symlink; refusing to overwrite." >&2
  exit 1
fi
if [ -d "${CFG2}" ]; then
  echo "[FAIL] Refusing to overwrite directory '${CFG2}'." >&2
  exit 1
fi

if [ -f "${CFG2}" ]; then
  CFG2_ORIG_HASH="$(sha256_file "${CFG2}")"
  CFG2_ORIG_MODE="$(get_octal_mode "${CFG2}")"
  [ -z "${CFG2_ORIG_MODE}" ] && CFG2_ORIG_MODE="-"
  CFG2_BKP="${CFG2}.backup-${stamp}"
  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${CFG2_BKP}" 600 < "${CFG2}"
    CFG2_BKP_HASH="$(sha256_file "${CFG2_BKP}")"
    if [ "${CFG2_BKP_HASH}" != "${CFG2_ORIG_HASH}" ]; then
      echo "[FAIL] Backup SHA-256 verification failed for ${CFG2_BKP}." >&2
      exit 1
    fi
    echo "    Backup saved: ${CFG2_BKP} (SHA256=${CFG2_ORIG_HASH:0:12}...)"
  else
    echo "    [DRY-RUN] Would save backup: ${CFG2_BKP} (SHA256=${CFG2_ORIG_HASH:0:12}...)"
  fi
  MANIFEST_ROWS+=("$(printf '1\t%s\t%s\t%s\t%s' "${CFG2_ORIG_HASH}" "${CFG2}" "${CFG2_BKP}" "${CFG2_ORIG_MODE}")")
  flush_rollback_manifest

  PRESERVED_TOP_KEYS="$(extract_preserved_top_keys "${CFG2}" "${GATEWAY_ON_LANE2}" "${HAS_GW_MODEL}" "${PRESERVE_TOP_SANDBOX}")"
  PRESERVED_USER_SECTIONS="$(extract_preserved_user_sections "${CFG2}" "${GATEWAY_ON_LANE2}" "${GW_PROV_LOWER}" "${PRESERVE_SW_SECTION}" "${PRESERVE_AP_TABLE}")"
  PRESERVED_FEATURES_KEYS="$(extract_preserved_table_keys "${CFG2}" "features" "${L2_MANAGED_FEAT_KEYS}")"
  PRESERVED_MEMORIES_KEYS="$(extract_preserved_table_keys "${CFG2}" "memories" ",generate_memories,use_memories,")"
else
  MANIFEST_ROWS+=("$(printf '0\t-\t%s\t-\t-' "${CFG2}")")
  flush_rollback_manifest
fi

render_lane2_config() {
  printf '# Official OpenAI / ChatGPT & Flexible API-Key Codex CLI configuration (LANE 2)\n'
  printf '# Zero plaintext secrets: supports BOTH `codex login` (OAuth/keyring) AND API key (`env_key`).\n'
  if [ "${GATEWAY_ON_LANE2}" -eq 1 ]; then
    printf 'model_provider = "%s"\n' "${ESC_GW_PROV}"
    if [ "${HAS_GW_MODEL}" -eq 1 ]; then
      printf 'model = "%s"\n' "${ESC_GW_MODEL}"
      printf 'review_model = "%s"\n' "${ESC_GW_MODEL}"
    fi
    printf 'web_search = "live"\n'
    printf 'disable_response_storage = true\n'
  fi
  if [ -n "${RENDER_SANDBOX_MODE}" ]; then
    printf 'sandbox_mode = "%s"\n' "${RENDER_SANDBOX_MODE}"
  fi
  if [ -n "${RENDER_APPROVAL_POLICY}" ]; then
    printf 'approval_policy = "%s"\n' "${RENDER_APPROVAL_POLICY}"
  fi
  if [ -n "${PRESERVED_TOP_KEYS}" ]; then
    printf '%s\n' "${PRESERVED_TOP_KEYS}"
  fi
  printf '\n'
  if [ "${GATEWAY_ON_LANE2}" -eq 1 ]; then
    printf '[model_providers."%s"]\n' "${ESC_GW_PROV}"
    printf 'name = "%s"\n' "${ESC_GW_PROV}"
    printf 'base_url = "%s"\n' "${ESC_GW_URL}"
    printf 'model_catalog_url = "%s"\n' "${ESC_GW_MODELS_URL}"
    printf 'wire_api = "responses"\n'
    printf 'env_key = "%s"\n\n' "${ESC_GW_ENV}"
  fi
  if [ "${TRUST_REPO_PATH}" -eq 1 ] && ! has_project_section_in "${PRESERVED_USER_SECTIONS}" "${REPO_PATH}"; then
    printf '[projects."%s"]\n' "${ESC_REPO}"
    printf 'trust_level = "trusted"\n\n'
  fi
  if [ "${TRUST_REPO_PATH}" -eq 1 ] && [ "${EFFECTIVE_LANE2_REPO}" != "${REPO_PATH}" ] && ! has_project_section_in "${PRESERVED_USER_SECTIONS}" "${EFFECTIVE_LANE2_REPO}"; then
    printf '[projects."%s"]\n' "${ESC_LANE2_REPO}"
    printf 'trust_level = "trusted"\n\n'
  fi
  if [ -f "${LANE1_HOME}/config.toml" ] && [ ! -L "${LANE1_HOME}/config.toml" ]; then
    local harvested_l1_projects=""
    harvested_l1_projects="$(extract_harvested_lane1_projects "${LANE1_HOME}/config.toml" "${PRESERVED_USER_SECTIONS}")"
    if [ -n "${harvested_l1_projects}" ]; then
      printf '# Inherited projects from Lane 1 (Codex Desktop; original trust_level preserved)\n%s\n\n' "${harvested_l1_projects}"
    fi
  fi
  printf '[features]\n'
  [ "${HAS_DAEMON_FLAG}" -eq 1 ] && printf 'daemon_auto_start = false\n'
  printf 'memories = true\n'
  [ "${HAS_API_DISCOVERY_FLAG}" -eq 1 ] && printf 'api_key_model_discovery = true\n'
  [ "${HAS_IMAGE_GEN_FLAG}" -eq 1 ] && printf 'image_generation = true\n'
  [ "${HAS_GOALS_FLAG}" -eq 1 ] && printf 'goals = true\n'
  if [ -n "${PRESERVED_FEATURES_KEYS}" ]; then
    printf '%s\n' "${PRESERVED_FEATURES_KEYS}"
  fi
  printf '\n[memories]\n'
  printf 'generate_memories = true\n'
  printf 'use_memories = true\n'
  if [ -n "${PRESERVED_MEMORIES_KEYS}" ]; then
    printf '%s\n' "${PRESERVED_MEMORIES_KEYS}"
  fi
  printf '\n'
  if [ "${EMIT_SW_SECTION}" -eq 1 ]; then
    printf '[sandbox_workspace_write]\n'
    printf 'network_access = %s\n\n' "${SANDBOX_NETWORK}"
  fi
  printf '[shell_environment_policy]\n'
  printf 'exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]\n\n'
  printf '[shell_environment_policy.set]\n'
  printf 'CODEX_ACTIVE_LANE = "LANE_2"\n'
  printf 'CARGO_TARGET_DIR = "%s"\n' "${ESC_CARGO}"
  if [ -n "${PRESERVED_USER_SECTIONS}" ]; then
    printf '\n# Preserved existing sections\n%s\n' "${PRESERVED_USER_SECTIONS}"
  fi
}

CFG2_RENDERED="$(render_lane2_config)"
assert_no_plaintext_secret_in_toml "Lane 2 config.toml" "${CFG2_RENDERED}"
if [ "${GATEWAY_ON_LANE2}" -eq 1 ]; then
  if ! printf '%s\n' "${CFG2_RENDERED}" | grep -Fq "env_key = \"${ESC_GW_ENV}\""; then
    echo "[FAIL] Security invariant violation in Lane 2 config.toml: expected env_key = \"${ESC_GW_ENV}\" is missing." >&2
    exit 1
  fi
fi

EFFECTIVE_SANDBOX_MODE="$(toml_get_top_key_from_text "${CFG2_RENDERED}" "sandbox_mode")"
[ -z "${EFFECTIVE_SANDBOX_MODE}" ] && EFFECTIVE_SANDBOX_MODE="custom/unset"
EFFECTIVE_APPROVAL_POLICY="$(toml_get_top_key_from_text "${CFG2_RENDERED}" "approval_policy")"
if [ -z "${EFFECTIVE_APPROVAL_POLICY}" ]; then
  if printf '%s\n' "${CFG2_RENDERED}" | grep -Eqi '^[[:space:]]*\[approval_policy(\]|\.)'; then
    EFFECTIVE_APPROVAL_POLICY="granular"
  else
    EFFECTIVE_APPROVAL_POLICY="custom/unset"
  fi
elif [ "${EFFECTIVE_APPROVAL_POLICY#\{}" != "${EFFECTIVE_APPROVAL_POLICY}" ]; then
  EFFECTIVE_APPROVAL_POLICY="granular"
fi

if [ "${DRY_RUN}" -eq 0 ]; then
  atomic_write_from_stdin "${CFG2}" 600 < <(printf '%s\n' "${CFG2_RENDERED}")
  echo "    Wrote: ${CFG2} (cli_mode=${CLI_MODE}, sandbox_mode=${EFFECTIVE_SANDBOX_MODE}, approval_policy=${EFFECTIVE_APPROVAL_POLICY}, network_access=${SANDBOX_NETWORK}, gateway=${GATEWAY_ON_LANE2})"
else
  echo "    [DRY-RUN] Would write: ${CFG2} (cli_mode=${CLI_MODE}, sandbox_mode=${EFFECTIVE_SANDBOX_MODE}, approval_policy=${EFFECTIVE_APPROVAL_POLICY}, network_access=${SANDBOX_NETWORK}, gateway=${GATEWAY_ON_LANE2})"
fi

# Optional: Also configure gateway / API key in Lane 1 when --gateway-target-lane is 'lane1' or 'both'.
if [ "${GATEWAY_ON_LANE1}" -eq 1 ]; then
  CFG1="${LANE1_HOME}/config.toml"
  CFG1_CLEAN_BKP="${LANE1_HOME}/config.backup.toml"
  CFG1_TOP_KEYS=""
  CFG1_USER_SECTIONS=""

  for p1 in "${CFG1}" "${CFG1_CLEAN_BKP}"; do
    if [ -L "${p1}" ]; then
      echo "[FAIL] Security refusal: '${p1}' is a symlink; refusing to overwrite." >&2
      exit 1
    fi
    if [ -d "${p1}" ]; then
      echo "[FAIL] Refusing to overwrite directory '${p1}'." >&2
      exit 1
    fi
  done

  if [ -f "${CFG1}" ] && [ ! -e "${CFG1_CLEAN_BKP}" ]; then
    MANIFEST_ROWS+=("$(printf '0\t-\t%s\t-\t-' "${CFG1_CLEAN_BKP}")")
    flush_rollback_manifest
    if [ "${DRY_RUN}" -eq 0 ]; then
      atomic_write_from_stdin "${CFG1_CLEAN_BKP}" 600 < "${CFG1}"
      echo "    Saved clean original backup: ${CFG1_CLEAN_BKP}"
    else
      echo "    [DRY-RUN] Would save clean original backup: ${CFG1_CLEAN_BKP}"
    fi
  fi

  if [ -f "${CFG1}" ]; then
    CFG1_ORIG_HASH="$(sha256_file "${CFG1}")"
    CFG1_ORIG_MODE="$(get_octal_mode "${CFG1}")"
    [ -z "${CFG1_ORIG_MODE}" ] && CFG1_ORIG_MODE="-"
    CFG1_BKP="${CFG1}.backup-${stamp}"
    if [ "${DRY_RUN}" -eq 0 ]; then
      atomic_write_from_stdin "${CFG1_BKP}" 600 < "${CFG1}"
      CFG1_BKP_HASH="$(sha256_file "${CFG1_BKP}")"
      if [ "${CFG1_BKP_HASH}" != "${CFG1_ORIG_HASH}" ]; then
        echo "[FAIL] Backup SHA-256 verification failed for ${CFG1_BKP}." >&2
        exit 1
      fi
      echo "    Backup saved: ${CFG1_BKP} (SHA256=${CFG1_ORIG_HASH:0:12}...)"
    else
      echo "    [DRY-RUN] Would save backup: ${CFG1_BKP} (SHA256=${CFG1_ORIG_HASH:0:12}...)"
    fi
    MANIFEST_ROWS+=("$(printf '1\t%s\t%s\t%s\t%s' "${CFG1_ORIG_HASH}" "${CFG1}" "${CFG1_BKP}" "${CFG1_ORIG_MODE}")")
    flush_rollback_manifest

    CFG1_TOP_KEYS="$(extract_preserved_top_keys "${CFG1}" 1 "${HAS_GW_MODEL}" 1)"
    CFG1_USER_SECTIONS="$(extract_preserved_user_sections "${CFG1}" 1 "${GW_PROV_LOWER}" 1 1)"
    CFG1_FEATURES_KEYS="$(extract_preserved_table_keys "${CFG1}" "features" "${L2_MANAGED_FEAT_KEYS}")"
    CFG1_MEMORIES_KEYS="$(extract_preserved_table_keys "${CFG1}" "memories" ",generate_memories,use_memories,")"
  else
    CFG1_FEATURES_KEYS=""
    CFG1_MEMORIES_KEYS=""
    MANIFEST_ROWS+=("$(printf '0\t-\t%s\t-\t-' "${CFG1}")")
    flush_rollback_manifest
  fi

  render_lane1_config() {
    printf '# Lane 1 Codex Desktop configuration (Primary Account / Gateway via env_key, full native authority)\n'
    printf 'model_provider = "%s"\n' "${ESC_GW_PROV}"
    if [ "${HAS_GW_MODEL}" -eq 1 ]; then
      printf 'model = "%s"\n' "${ESC_GW_MODEL}"
      printf 'review_model = "%s"\n' "${ESC_GW_MODEL}"
    fi
    printf 'web_search = "live"\n'
    printf 'disable_response_storage = true\n'
    if [ -n "${CFG1_TOP_KEYS}" ]; then
      printf '%s\n' "${CFG1_TOP_KEYS}"
    fi
    printf '\n[model_providers."%s"]\n' "${ESC_GW_PROV}"
    printf 'name = "%s"\n' "${ESC_GW_PROV}"
    printf 'base_url = "%s"\n' "${ESC_GW_URL}"
    printf 'model_catalog_url = "%s"\n' "${ESC_GW_MODELS_URL}"
    printf 'wire_api = "responses"\n'
    printf 'env_key = "%s"\n\n' "${ESC_GW_ENV}"
    if [ "${TRUST_REPO_PATH}" -eq 1 ] && ! has_project_section_in "${CFG1_USER_SECTIONS}" "${REPO_PATH}"; then
      printf '[projects."%s"]\n' "${ESC_REPO}"
      printf 'trust_level = "trusted"\n\n'
    fi
    if [ "${TRUST_REPO_PATH}" -eq 1 ] && [ "${EFFECTIVE_LANE2_REPO}" != "${REPO_PATH}" ] && ! has_project_section_in "${CFG1_USER_SECTIONS}" "${EFFECTIVE_LANE2_REPO}"; then
      printf '[projects."%s"]\n' "${ESC_LANE2_REPO}"
      printf 'trust_level = "trusted"\n\n'
    fi
    printf '[features]\n'
    [ "${HAS_DAEMON_FLAG}" -eq 1 ] && printf 'daemon_auto_start = false\n'
    printf 'memories = true\n'
    [ "${HAS_API_DISCOVERY_FLAG}" -eq 1 ] && printf 'api_key_model_discovery = true\n'
    [ "${HAS_IMAGE_GEN_FLAG}" -eq 1 ] && printf 'image_generation = true\n'
    [ "${HAS_GOALS_FLAG}" -eq 1 ] && printf 'goals = true\n'
    if [ -n "${CFG1_FEATURES_KEYS}" ]; then
      printf '%s\n' "${CFG1_FEATURES_KEYS}"
    fi
    printf '\n[memories]\n'
    printf 'generate_memories = true\n'
    printf 'use_memories = true\n'
    if [ -n "${CFG1_MEMORIES_KEYS}" ]; then
      printf '%s\n' "${CFG1_MEMORIES_KEYS}"
    fi
    printf '\n[shell_environment_policy]\n'
    printf 'exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]\n\n'
    printf '[shell_environment_policy.set]\n'
    printf 'CODEX_ACTIVE_LANE = "LANE_1"\n'
    if [ -n "${CFG1_USER_SECTIONS}" ]; then
      printf '\n# Preserved existing sections\n%s\n' "${CFG1_USER_SECTIONS}"
    fi
  }

  CFG1_RENDERED="$(render_lane1_config)"
  assert_no_plaintext_secret_in_toml "Lane 1 config.toml" "${CFG1_RENDERED}"
  if ! printf '%s\n' "${CFG1_RENDERED}" | grep -Fq "env_key = \"${ESC_GW_ENV}\""; then
    echo "[FAIL] Security invariant violation in Lane 1 config.toml: expected env_key = \"${ESC_GW_ENV}\" is missing." >&2
    exit 1
  fi

  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${CFG1}" 600 < <(printf '%s\n' "${CFG1_RENDERED}")
    echo "    Wrote: ${CFG1} (zero plaintext keys; reads from env ${GATEWAY_API_KEY_ENV})"
  else
    echo "    [DRY-RUN] Would write: ${CFG1} (zero plaintext keys; reads from env ${GATEWAY_API_KEY_ENV})"
  fi
fi

if [ "${DRY_RUN}" -eq 0 ]; then
  # Tighten permissions on sensitive auth/config files in both lanes (regular
  # files only; never traverse symlinks with chmod; omit `--` for BSD/macOS chmod).
  for sec_f in \
    "${LANE1_HOME}/auth.json" \
    "${LANE1_HOME}/config.toml" \
    "${LANE1_HOME}/config.backup.toml" \
    "${LANE2_HOME}/auth.json" \
    "${LANE2_HOME}/config.toml"; do
    if [ -f "${sec_f}" ] && [ ! -L "${sec_f}" ]; then
      chmod 600 "${sec_f}" 2>/dev/null || true
    fi
  done
fi

# ------------------------------------------------------------------------------
# 8. Install Shell-Safe CLI Launchers (`codex`, `codex-official`, `codex-t3`, `codex-manage`)
# ------------------------------------------------------------------------------
# Single-quote every embedded path so spaces, `$`, backticks, quotes, or `&` in
# directory names can NEVER be evaluated as shell code when users run `codex`.
# Pre-existing launchers in LOCAL_BIN are backed up with SHA-256 verification
# and recorded in MANIFEST_ROWS so rollback restores them instead of deleting.
Q_LANE1_HOME="$(shell_quote "${LANE1_HOME}")"
Q_LANE2_HOME="$(shell_quote "${LANE2_HOME}")"
Q_LOCAL_BIN="$(shell_quote "${LOCAL_BIN}")"
Q_CARGO_TARGET="$(shell_quote "${CARGO_TARGET_LANE2}")"
Q_CODEX_BIN="$(shell_quote "${CODEX_BIN}")"
Q_MANAGER_SCRIPT="$(shell_quote "${KIT_ROOT}/scripts/codex-manager.sh")"
Q_PRIMARY_REPO="$(shell_quote "${REPO_PATH}")"
Q_LANE2_REPO="$(shell_quote "${EFFECTIVE_LANE2_REPO}")"

render_lane2_wrapper() {
  printf '#!/usr/bin/env bash\n'
  printf '# Codex Dual-Lane wrapper: launches Lane 2 (Official OpenAI/ChatGPT CODEX_HOME)\n'
  printf 'export CODEX_HOME=%s\n' "${Q_LANE2_HOME}"
  printf 'export CODEX_ACTIVE_LANE=%s\n' "'LANE_2'"
  printf 'export CARGO_TARGET_DIR=%s\n' "${Q_CARGO_TARGET}"
  if [ "${USE_GIT_WORKTREE}" -eq 1 ] && [ "${EFFECTIVE_LANE2_REPO}" != "${REPO_PATH}" ]; then
    printf 'export CODEX_PRIMARY_REPO=%s\n' "${Q_PRIMARY_REPO}"
    printf 'export CODEX_LANE2_WORKTREE=%s\n' "${Q_LANE2_REPO}"
    cat <<'WRAPPER_WT_EOF'
_dl_prim="$(cd -P -- "${CODEX_PRIMARY_REPO}" 2>/dev/null && pwd -P || printf '%s' "${CODEX_PRIMARY_REPO}")"
_dl_prim="${_dl_prim%/}"
# 1. Hard fail-closed worktree boundary & auto cwd switch (opt-out auto-cd ONLY via CODEX_NO_AUTO_WORKTREE_CD)
if [ -z "${CODEX_NO_AUTO_WORKTREE_CD:-}" ]; then
  if [ -L "${CODEX_LANE2_WORKTREE}" ]; then
    printf '%s\n' "[FAIL] Security refusal: Lane 2 worktree '${CODEX_LANE2_WORKTREE}' is a symlink; refusing to fall back to primary repo '${CODEX_PRIMARY_REPO}'." >&2
    exit 1
  fi
  if [ ! -d "${CODEX_LANE2_WORKTREE}" ]; then
    printf '%s\n' "[FAIL] Lane 2 worktree '${CODEX_LANE2_WORKTREE}' is missing; refusing to fall back to primary repo '${CODEX_PRIMARY_REPO}'. Recreate the worktree or set CODEX_NO_AUTO_WORKTREE_CD=1 to opt out." >&2
    exit 1
  fi
  if ! _dl_wt="$(cd -P -- "${CODEX_LANE2_WORKTREE}" 2>/dev/null && pwd -P)" || [ -z "${_dl_wt}" ]; then
    printf '%s\n' "[FAIL] Lane 2 worktree '${CODEX_LANE2_WORKTREE}' is inaccessible (cd failed); refusing to fall back to primary repo '${CODEX_PRIMARY_REPO}'." >&2
    exit 1
  fi
  _dl_wt="${_dl_wt%/}"
  if [ -z "${_dl_wt}" ]; then
    printf '%s\n' "[FAIL] Security refusal: Lane 2 worktree '${CODEX_LANE2_WORKTREE}' resolved to filesystem root '/'; refusing to run." >&2
    exit 1
  fi
  case "${_dl_wt}/" in
    "${_dl_prim}/"*)
      printf '%s\n' "[FAIL] Security refusal: Lane 2 worktree '${_dl_wt}' resolves inside primary repo '${_dl_prim}'; refusing to run." >&2
      exit 1
      ;;
  esac
  _dl_cur="$(pwd -P 2>/dev/null || pwd)"
  _dl_cur="${_dl_cur%/}"
  case "${_dl_cur}/" in
    "${_dl_prim}/"*)
      _dl_rel="${_dl_cur#"${_dl_prim}"}"
      _dl_rel="${_dl_rel#/}"
      if [ -n "${_dl_rel}" ] && [ -d "${_dl_wt}/${_dl_rel}" ]; then
        _dl_target="${_dl_wt}/${_dl_rel}"
      else
        _dl_target="${_dl_wt}"
      fi
      if ! cd -P -- "${_dl_target}" 2>/dev/null; then
        printf '%s\n' "[FAIL] Failed to switch cwd into Lane 2 worktree '${_dl_target}' (cd failed); refusing to remain in primary repo '${CODEX_PRIMARY_REPO}'." >&2
        exit 1
      fi
      _dl_after="$(pwd -P 2>/dev/null || printf '')"
      _dl_after="${_dl_after%/}"
      case "${_dl_after}/" in
        "${_dl_wt}/"*) ;;
        *)
          printf '%s\n' "[FAIL] Post-cd verification failed: cwd '${_dl_after}' is outside canonical Lane 2 worktree '${_dl_wt}'; refusing to run." >&2
          exit 1
          ;;
      esac
      ;;
  esac
fi
# 2. Argument scan & primary repo blocking (ALWAYS executes fail-closed, even when CODEX_NO_AUTO_WORKTREE_CD is set)
_dl_canon_path() {
  local p="$1" suffix="" cur parent base resolved=""
  if [ -d "${p}" ]; then
    if resolved="$(cd -P -- "${p}" 2>/dev/null && pwd -P)" && [ -n "${resolved}" ]; then
      printf '%s' "${resolved}"
      return 0
    fi
  fi
  case "${p}" in
    /*) cur="${p}" ;;
    *)  resolved="$(pwd -P 2>/dev/null || pwd)"; cur="${resolved%/}/${p}" ;;
  esac
  while [ "${#cur}" -gt 1 ] && [ "${cur%/}" != "${cur}" ]; do
    cur="${cur%/}"
  done
  while [ ! -d "${cur}" ]; do
    parent="$(dirname -- "${cur}")"
    base="$(basename -- "${cur}")"
    [ "${parent}" = "${cur}" ] && break
    if [ -n "${suffix}" ]; then suffix="${base}/${suffix}"; else suffix="${base}"; fi
    cur="${parent}"
  done
  if [ -d "${cur}" ]; then
    if ! resolved="$(cd -P -- "${cur}" 2>/dev/null && pwd -P)" || [ -z "${resolved}" ]; then
      parent="$(dirname -- "${cur}")"
      base="$(basename -- "${cur}")"
      if [ "${parent}" != "${cur}" ] && [ -d "${parent}" ]; then
        resolved="$(cd -P -- "${parent}" 2>/dev/null && pwd -P || printf '%s' "${parent}")"
        resolved="${resolved%/}/${base}"
      else
        resolved="${cur}"
      fi
    fi
  else
    resolved="${cur}"
  fi
  if [ -n "${suffix}" ]; then
    if [ "${resolved}" = "/" ]; then printf '/%s' "${suffix}"; else printf '%s/%s' "${resolved%/}" "${suffix}"; fi
  else
    printf '%s' "${resolved}"
  fi
}
_dl_check_target_arg() {
  local cand="$1" abs=""
  [ -z "${cand}" ] && return 0
  abs="$(_dl_canon_path "${cand}")"
  abs="${abs%/}"
  case "${abs}/" in
    "${_dl_prim}/"*)
      printf '%s\n' "[FAIL] Lane 2 worktree isolation blocked -C/--cd/--add-dir targeting primary repo '${CODEX_PRIMARY_REPO}'. Use '${CODEX_LANE2_WORKTREE}' instead." >&2
      exit 1
      ;;
  esac
}
_dl_expect_val=0
for _dl_arg in "$@"; do
  if [ "${_dl_expect_val}" -eq 1 ]; then
    _dl_check_target_arg "${_dl_arg}"
    _dl_expect_val=0
    continue
  fi
  case "${_dl_arg}" in
    --) break ;;
    -C|--cd|--add-dir) _dl_expect_val=1 ;;
    -C=*) _dl_check_target_arg "${_dl_arg#-C=}" ;;
    -C?*) _dl_check_target_arg "${_dl_arg#-C}" ;;
    --cd=*) _dl_check_target_arg "${_dl_arg#--cd=}" ;;
    --add-dir=*) _dl_check_target_arg "${_dl_arg#--add-dir=}" ;;
  esac
done
WRAPPER_WT_EOF
  fi
  printf 'exec %s "$@"\n' "${Q_CODEX_BIN}"
}

render_lane1_wrapper() {
  printf '#!/usr/bin/env bash\n'
  printf '# Codex Dual-Lane wrapper: launches Lane 1 (Primary CODEX_HOME)\n'
  printf 'export CODEX_HOME=%s\n' "${Q_LANE1_HOME}"
  printf 'export CODEX_ACTIVE_LANE=%s\n' "'LANE_1'"
  printf 'exec %s "$@"\n' "${Q_CODEX_BIN}"
}

render_manage_wrapper() {
  printf '#!/usr/bin/env bash\n'
  printf '# Codex Dual-Lane wrapper: launches Sandbox 2 Control Center (codex-manager.sh)\n'
  printf '[ -n "${CODEX_LANE1_HOME:-}" ] || export CODEX_LANE1_HOME=%s\n' "${Q_LANE1_HOME}"
  printf '[ -n "${CODEX_LANE2_HOME:-}" ] || export CODEX_LANE2_HOME=%s\n' "${Q_LANE2_HOME}"
  printf '[ -n "${CODEX_LOCAL_BIN:-}" ] || export CODEX_LOCAL_BIN=%s\n' "${Q_LOCAL_BIN}"
  printf '[ -n "${CODEX_REAL_BIN:-}" ] || export CODEX_REAL_BIN=%s\n' "${Q_CODEX_BIN}"
  printf 'exec bash %s "$@"\n' "${Q_MANAGER_SCRIPT}"
}

for name in codex codex-official; do
  record_target_for_rollback "${LOCAL_BIN}/${name}" preserve
  if [ "${DRY_RUN}" -eq 0 ]; then
    atomic_write_from_stdin "${LOCAL_BIN}/${name}" 700 < <(render_lane2_wrapper)
    flush_rollback_manifest
  fi
done

record_target_for_rollback "${LOCAL_BIN}/codex-t3" preserve
if [ "${DRY_RUN}" -eq 0 ]; then
  atomic_write_from_stdin "${LOCAL_BIN}/codex-t3" 700 < <(render_lane1_wrapper)
  flush_rollback_manifest
fi

record_target_for_rollback "${LOCAL_BIN}/codex-manage" preserve
if [ "${DRY_RUN}" -eq 0 ]; then
  atomic_write_from_stdin "${LOCAL_BIN}/codex-manage" 700 < <(render_manage_wrapper)
  flush_rollback_manifest
  echo "    Installed wrappers in: ${LOCAL_BIN} (codex, codex-official, codex-t3, codex-manage)"
else
  echo "    [DRY-RUN] Would install wrappers in: ${LOCAL_BIN} (codex, codex-official, codex-t3, codex-manage)"
fi

# ------------------------------------------------------------------------------
# 9. Optional: Install Bridge Template (`DUAL_LANE_BRIDGE.md`) Non-Destructively
# ------------------------------------------------------------------------------
if [ "${INSTALL_BRIDGE}" -eq 1 ]; then
  BRIDGE_TARGETS=("${REPO_PATH}")
  if [ "${EFFECTIVE_LANE2_REPO}" != "${REPO_PATH}" ]; then
    BRIDGE_TARGETS+=("${EFFECTIVE_LANE2_REPO}")
  fi
  for target_repo in "${BRIDGE_TARGETS[@]}"; do
    BRIDGE_DST="${target_repo}/artifacts/dual-lane/DUAL_LANE_BRIDGE.md"
    if [ -L "${BRIDGE_DST}" ]; then
      echo "[FAIL] Security refusal: bridge path '${BRIDGE_DST}' is a symlink." >&2
      exit 1
    fi
    if [ ! -f "${BRIDGE_DST}" ]; then
      if [ "${DRY_RUN}" -eq 0 ]; then
        mkdir -p -- "$(dirname "${BRIDGE_DST}")"
        # Repo documentation file contains zero secrets; 0644 matches normal repo permissions.
        atomic_write_from_stdin "${BRIDGE_DST}" 644 < "${KIT_ROOT}/templates/DUAL_LANE_BRIDGE.md"
        echo "    Created: ${BRIDGE_DST}"
      else
        echo "    [DRY-RUN] Would create: ${BRIDGE_DST}"
      fi
    else
      echo "    Kept existing: ${BRIDGE_DST}"
    fi
  done
fi

# ------------------------------------------------------------------------------
# 10. Optional: Sync Session Index, Pinned Threads & Goals via sync-sessions.py
# ------------------------------------------------------------------------------
if [ "${SYNC_SESSIONS}" -eq 1 ]; then
  PY_BIN=""
  for cand in python3 python; do
    if command -v "${cand}" >/dev/null 2>&1; then
      py_ver="$("${cand}" --version 2>&1 || true)"
      if printf '%s\n' "${py_ver}" | grep -Eq '^Python 3\.'; then
        PY_BIN="${cand}"
        break
      fi
    fi
  done
  if [ -n "${PY_BIN}" ]; then
    SYNC_ARGS=("${KIT_ROOT}/scripts/sync-sessions.py" --lane1 "${LANE1_HOME}" --lane2 "${LANE2_HOME}" --repo "${EFFECTIVE_LANE2_REPO}")
    if [ "${EFFECTIVE_APPROVAL_POLICY}" = "on-request" ] || [ "${EFFECTIVE_APPROVAL_POLICY}" = "never" ]; then
      SYNC_ARGS+=(--approval-mode "${EFFECTIVE_APPROVAL_POLICY}")
    fi
    [ "${PINNED_ONLY}" -eq 1 ] && SYNC_ARGS+=(--pinned-only)
    [ "${DRY_RUN}" -eq 1 ] && SYNC_ARGS+=(--dry-run)
    "${PY_BIN}" "${SYNC_ARGS[@]}"
  else
    echo "[WARN] Real Python 3 not found; skipping session sync." >&2
  fi
fi

# ------------------------------------------------------------------------------
# 11. Finalize Deterministic SHA-256 Rollback Manifest (Skipped in --dry-run)
# ------------------------------------------------------------------------------
if [ "${DRY_RUN}" -eq 0 ]; then
  ROLLBACK_STATUS="complete"
  flush_rollback_manifest
  echo "    Rollback snapshot saved: ${LATEST_FILE}"
fi

echo ""
echo "[OK] Setup completed!"
echo "Ensure ${LOCAL_BIN} precedes ${CODEX_BIN%/*} in your PATH (e.g. export PATH=\"${LOCAL_BIN}:\$PATH\")."
echo "Next steps:"
echo "  1. ./scripts/doctor.sh"
echo "  2. codex-manage          (Interactive Sandbox 2 Control Center: API key / login / check / sync / safe uninstall)"
echo "  3. codex"
