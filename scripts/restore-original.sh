#!/usr/bin/env bash
# ==============================================================================
# Deterministic SHA-256 verified rollback & recovery tool (macOS / Linux / WSL)
# ==============================================================================
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Project   : Codex Dual-Lane & Security Kit
#
# Security & End-User Safety Guarantees:
#   - Strict Bash error handling (`set -euo pipefail`) and owner-only file
#     creation mask (`umask 077`).
#   - Strictly validates every target and backup path from rollback manifests
#     against trusted roots (LANE1_HOME, LANE2_HOME, LOCAL_BIN):
#       * Rejects any `..` path-traversal segments or relative paths.
#       * Rejects symlinks at the target, backup, or any intermediate directory
#         below the trusted roots.
#       * Never allows a tampered manifest to widen ALLOWED_ROOTS.
#   - Portable SHA-256 verification (`sha256sum`, `shasum -a 256`, or `openssl`)
#     BOTH before staging a backup AND after atomically moving it into place.
#   - Atomic file restoration (`mktemp` in target dir + `chmod 600` + `mv -f`)
#     with `trap` cleanup on EXIT/INT/TERM.
#   - Safely unlinks Lane 2 symlinks first (never `rm -rf` across a symlink) and
#     proves zero symlinks remain anywhere inside LANE2_HOME before permitting
#     `--remove-lane2-home`.
#   - Full `--dry-run` verification mode that validates paths and SHA-256 hashes
#     without modifying any files on disk.
# ==============================================================================
set -euo pipefail

# Enforce owner-only permissions on any temporary staging files created during recovery.
umask 077

# ------------------------------------------------------------------------------
# Temporary Artifact Tracking & Signal-Safe Cleanup
# ------------------------------------------------------------------------------
TEMP_ARTIFACTS=()
cleanup_temp_artifacts() {
  # Guard array length for Bash 3.2 (macOS) compatibility under `set -u`.
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
# Helper Functions
# ------------------------------------------------------------------------------

# Print CLI usage, options, and environment overrides.
usage() {
  cat <<'EOF'
Usage: ./scripts/restore-original.sh [OPTIONS]

Options:
  --snapshot PATH        Explicit rollback manifest path (default: <LANE2_HOME>/.rollback/latest.tsv)
  --remove-lane2-home    Remove <LANE2_HOME> after proving zero symlinks remain inside it
  --dry-run              Verify paths, symlinks, and SHA-256 hashes without modifying disk
  -h, --help             Show this help message

Environment overrides:
  CODEX_LANE1_HOME       Primary CODEX_HOME (default: ~/.codex)
  CODEX_LANE2_HOME       Secondary CODEX_HOME (default: ~/.codex-official)
  CODEX_LOCAL_BIN        CLI wrapper directory (default: ~/.local/bin)
EOF
}

# Validate that an option requiring a value received one before reading $2.
require_arg() {
  local opt_name="$1"
  local arg_count="$2"
  if [ "${arg_count}" -lt 2 ]; then
    echo "[FAIL] Option '${opt_name}' requires a value." >&2
    usage >&2
    exit 1
  fi
}

# Reject empty paths, filesystem root '/', or control characters; strip trailing slashes.
validate_path_value() {
  local label="$1"
  local raw="$2"
  if [ -z "${raw}" ]; then
    echo "[FAIL] ${label} must not be empty." >&2
    exit 1
  fi
  if printf '%s' "${raw}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "[FAIL] ${label} contains unsupported control characters." >&2
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

# Portable physical path canonicalizer (macOS BSD / Linux GNU / WSL / Git Bash).
# Resolves existing ancestor via `cd -P && pwd -P` so OS symlinks above the
# user's home/temp dirs (e.g. macOS `/var -> /private/var`) normalize consistently.
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

# Validate optional manifest octal permission mode strictly to standard 3-digit
# permission bits (000..777 or 0000..0777, never SUID/SGID/sticky 1xxx/2xxx/4xxx).
normalize_restore_mode() {
  local raw="$1"
  if [ -z "${raw}" ] || [ "${raw}" = "-" ]; then
    printf ''
    return 0
  fi
  if printf '%s' "${raw}" | grep -Eq '^0[0-7]{3}$'; then
    raw="${raw#0}"
  fi
  if printf '%s' "${raw}" | grep -Eq '^[0-7]{3}$'; then
    printf '%s' "${raw}"
    return 0
  fi
  return 1
}

# Portable lowercase 64-hex SHA-256 helper using stdin redirection to prevent
# leading-dash option injection and GNU backslash-escaped filename prefixes.
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

# Multi-layer containment & anti-symlink validator for rollback paths.
# Enforces all five invariants before any file read, overwrite, or deletion:
#   1. Non-empty, absolute path (`/*`), free of control characters.
#   2. Zero `..` or `.` path traversal segments anywhere in the path.
#   3. Strict descendant (depth >= 1) of a trusted root in ALLOWED_ROOTS
#      (prevents both sibling-prefix confusion and root-directory deletion).
#   4. Zero symlinks on the target itself OR any intermediate directory below
#      the matched trusted root (while permitting OS symlinks strictly above
#      the root, such as macOS `/var -> /private/var`).
#   5. Final canonical path starts strictly with `<matched_root>/`.
assert_safe_contained_path() {
  local label="$1"
  local candidate="$2"
  local allow_leaf_symlink="${3:-0}"

  if [ -z "${candidate}" ]; then
    echo "[FAIL] Security violation: empty path for ${label}." >&2
    exit 1
  fi
  if printf '%s' "${candidate}" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "[FAIL] Security violation: control characters in ${label}." >&2
    exit 1
  fi
  case "${candidate}" in
    /*) ;;
    *)
      echo "[FAIL] Security violation: relative path rejected for ${label}: '${candidate}'" >&2
      exit 1
      ;;
  esac
  # Reject any `..` or `.` path traversal segment lexically.
  case "/${candidate}/" in
    */../*|*/./*)
      echo "[FAIL] Security violation: path traversal segment rejected for ${label}: '${candidate}'" >&2
      exit 1
      ;;
  esac

  # Strip trailing slashes before component walk.
  local trimmed="${candidate}"
  while [ "${#trimmed}" -gt 1 ] && [ "${trimmed%/}" != "${trimmed}" ]; do
    trimmed="${trimmed%/}"
  done

  local depth=0
  local cur="${trimmed}"
  local matched_root=""
  while true; do
    # Reject any symlink BEFORE matching ALLOWED_ROOTS so a cross-root symlink
    # such as `LANE2_HOME/evil -> LANE1_HOME` (or `LANE2_HOME/loop -> LANE2_HOME`)
    # can NEVER masquerade as a trusted root. OS symlinks strictly above the
    # root (e.g. macOS `/var -> /private/var`) remain unaffected because `-L`
    # tests only the leaf component at each step and the loop breaks once the
    # non-symlink root directory itself matches ALLOWED_ROOTS.
    if [ -L "${cur}" ]; then
      if [ "${allow_leaf_symlink}" -eq 1 ] && [ "${depth}" -eq 0 ]; then
        :
      else
        echo "[FAIL] Security violation: symlink rejected for ${label}: '${cur}'" >&2
        exit 1
      fi
    fi

    if [ "${depth}" -ge 1 ]; then
      local cur_canon root
      cur_canon="$(canonicalize_dir "${cur}")"
      for root in "${ALLOWED_ROOTS[@]}"; do
        if [ "${cur_canon}" = "${root}" ]; then
          matched_root="${root}"
          break
        fi
      done
      if [ -n "${matched_root}" ]; then
        break
      fi
    fi

    local parent
    parent="$(dirname -- "${cur}")"
    if [ "${parent}" = "${cur}" ]; then
      break
    fi
    cur="${parent}"
    depth=$((depth + 1))
  done

  if [ -z "${matched_root}" ]; then
    echo "[FAIL] Security violation: ${label} '${candidate}' is outside allowed Codex directories!" >&2
    exit 1
  fi

  # Defense-in-depth: confirm canonicalized full path stays strictly beneath matched_root.
  local canon_parent canon_full
  canon_parent="$(canonicalize_dir "$(dirname -- "${trimmed}")")"
  canon_full="${canon_parent}/$(basename -- "${trimmed}")"
  case "${canon_full}" in
    "${matched_root}/"*) ;;
    *)
      echo "[FAIL] Security violation: canonical path '${canon_full}' escaped '${matched_root}'!" >&2
      exit 1
      ;;
  esac
}

# Atomically restore a verified backup file to its target path with exact
# POSIX permission metadata restoration (when available in manifest or backup).
# Checks SHA-256 on the backup BEFORE writing, on the staged temp file BEFORE
# moving, and on the restored target AFTER moving, then removes the backup.
atomic_restore_verified_file() {
  local bkp="$1"
  local target="$2"
  local expected_sha="$3"
  local expected_mode="${4:-}"

  assert_safe_contained_path "backup file" "${bkp}"
  assert_safe_contained_path "restore target" "${target}"

  if [ ! -f "${bkp}" ] || [ -L "${bkp}" ]; then
    if [ -n "${expected_sha}" ] && [ -f "${target}" ] && [ ! -L "${target}" ]; then
      local cur_sha
      cur_sha="$(sha256_file "${target}")"
      if [ "${cur_sha}" = "${expected_sha}" ]; then
        echo "    Already at original state (SHA-256 verified): ${target} (SHA256=${expected_sha:0:12}...)"
        return 0
      fi
    fi
    echo "[FAIL] Backup file missing or not a regular file: ${bkp} (cannot restore ${target})" >&2
    exit 1
  fi

  local bkp_sha
  bkp_sha="$(sha256_file "${bkp}")"
  if [ -n "${expected_sha}" ] && [ "${bkp_sha}" != "${expected_sha}" ]; then
    echo "[FAIL] SHA-256 mismatch on backup ${bkp}! Expected ${expected_sha}, got ${bkp_sha}." >&2
    exit 1
  fi

  if [ -d "${target}" ]; then
    echo "[FAIL] Refusing to restore regular file over directory: ${target}" >&2
    exit 1
  fi

  local restore_mode="600"
  local norm_expected_mode=""
  if [ -n "${expected_mode}" ] && [ "${expected_mode}" != "-" ]; then
    if ! norm_expected_mode="$(normalize_restore_mode "${expected_mode}" 2>/dev/null)" || [ -z "${norm_expected_mode}" ]; then
      echo "[FAIL] Security violation: unsafe/invalid restore mode '${expected_mode}' for ${target}." >&2
      exit 1
    fi
    restore_mode="${norm_expected_mode}"
  else
    local target_dir_only bkp_mode
    target_dir_only="$(dirname -- "${target}")"
    bkp_mode="$(get_octal_mode "${bkp}")"
    if [ "${target_dir_only}" = "${LOCAL_BIN}" ] || [ -x "${bkp}" ]; then
      if [ -n "${bkp_mode}" ]; then
        restore_mode="${bkp_mode}"
      else
        restore_mode="700"
      fi
    fi
  fi

  if [ "${DRY_RUN}" -eq 0 ]; then
    local target_dir tmp staged_sha restored_sha post_mode
    target_dir="$(dirname -- "${target}")"
    mkdir -p -- "${target_dir}"
    tmp="$(mktemp "${target_dir}/.codex-restore.XXXXXX")"
    TEMP_ARTIFACTS+=("${tmp}")
    cp -- "${bkp}" "${tmp}"
    # Restore exact pre-existing POSIX mode (e.g. 755/644/600); omit `--` for BSD/macOS chmod.
    chmod "${restore_mode}" "${tmp}"

    staged_sha="$(sha256_file "${tmp}")"
    if [ "${staged_sha}" != "${bkp_sha}" ]; then
      echo "[FAIL] Staged SHA-256 verification failed before replacing ${target}!" >&2
      exit 1
    fi

    mv -f -- "${tmp}" "${target}"

    restored_sha="$(sha256_file "${target}")"
    if [ "${restored_sha}" != "${bkp_sha}" ]; then
      echo "[FAIL] Post-restore SHA-256 verification failed for ${target}!" >&2
      exit 1
    fi

    # Verify POSIX permission metadata on native Unix filesystems (skip on Windows MSYS/NTFS).
    case "$(uname -s 2>/dev/null || echo '')" in
      MINGW*|MSYS*|CYGWIN*) ;;
      *)
        post_mode="$(get_octal_mode "${target}")"
        if [ -n "${post_mode}" ] && [ "${post_mode}" != "${restore_mode}" ]; then
          echo "[FAIL] Post-restore permission verification failed for ${target}: expected ${restore_mode}, got ${post_mode}." >&2
          exit 1
        fi
        ;;
    esac

    # Remove the consumed backup only after post-restore checksum & metadata checks pass.
    rm -f -- "${bkp}"
    echo "    Restored & SHA-256 verified: ${target} (SHA256=${bkp_sha:0:12}..., mode=${restore_mode})"
  else
    echo "    [DRY-RUN] Verified backup & would restore: ${bkp} -> ${target} (SHA256=${bkp_sha:0:12}..., mode=${restore_mode})"
  fi
}

# Read-only preflight validator for rollback manifests.
# Runs BEFORE Step 1 touches any symlink, file, or wrapper so a tampered
# manifest OR any missing required file/directory backup (where the target is
# not already at its exact original state) fails closed with ZERO disk side effects.
MANIFEST_SCHEMA_VERSION=1
HAS_LINK_RECORDS=0
LINK_RECORDS=()

preflight_validate_manifest() {
  local manifest_path="$1"
  local line_num=0
  local line existed orig_sha target bkp orig_mode extra bkp_sha cur_sha
  MANIFEST_SCHEMA_VERSION=1
  HAS_LINK_RECORDS=0
  LINK_RECORDS=()
  while IFS= read -r line || [ -n "${line}" ]; do
    line_num=$((line_num + 1))
    line="${line%$'\r'}"
    [ -z "${line}" ] && continue
    case "${line}" in
      "# schema_version="*)
        local ver_val="${line#\# schema_version=}"
        if printf '%s' "${ver_val}" | grep -Eq '^[0-9]+$'; then
          MANIFEST_SCHEMA_VERSION="${ver_val}"
        fi
        continue
        ;;
      \#*) continue ;;
    esac

    existed=""
    orig_sha=""
    target=""
    bkp=""
    orig_mode=""
    extra=""
    IFS=$'\t' read -r existed orig_sha target bkp orig_mode extra <<< "${line}"

    if [ -n "${extra}" ] || [ -z "${existed}" ] || [ -z "${target}" ]; then
      echo "[FAIL] Malformed manifest entry at ${manifest_path}:${line_num}." >&2
      exit 1
    fi

    case "${existed}" in
      L)
        HAS_LINK_RECORDS=1
        case "${orig_sha}" in
          0|1) ;;
          *)
            echo "[FAIL] Invalid created_by_kit flag '${orig_sha}' in link record at ${manifest_path}:${line_num}." >&2
            exit 1
            ;;
        esac
        case "${orig_mode}" in
          absent|preexisting_link|preexisting_dir) ;;
          *)
            echo "[FAIL] Invalid prior_state '${orig_mode}' in link record at ${manifest_path}:${line_num}." >&2
            exit 1
            ;;
        esac
        assert_safe_contained_path "manifest shared link" "${target}" 1
        if [ "${orig_sha}" = "1" ] && [ "${orig_mode}" = "preexisting_dir" ]; then
          if [ -z "${bkp}" ] || [ "${bkp}" = "-" ]; then
            echo "[FAIL] Missing directory backup path for preexisting_dir '${target}' at ${manifest_path}:${line_num}." >&2
            exit 1
          fi
          assert_safe_contained_path "manifest dir backup" "${bkp}"
          if [ ! -d "${bkp}" ] || [ -L "${bkp}" ]; then
            # Idempotent re-run check: allow only if target is ALREADY restored to a real non-symlink dir.
            if [ -d "${target}" ] && [ ! -L "${target}" ]; then
              :
            else
              echo "[FAIL] Preflight failed: Required directory backup '${bkp}' for '${target}' is missing and target is not restored to a real directory. Aborting before any disk changes." >&2
              exit 1
            fi
          fi
        fi
        LINK_RECORDS+=("$(printf '%s\t%s\t%s\t%s' "${orig_sha}" "${target}" "${bkp}" "${orig_mode}")")
        ;;
      1)
        assert_safe_contained_path "manifest target" "${target}"
        orig_sha="$(printf '%s' "${orig_sha}" | awk '{print tolower($0)}')"
        if ! printf '%s' "${orig_sha}" | grep -Eq '^[0-9a-f]{64}$'; then
          echo "[FAIL] Invalid SHA-256 hash in manifest at ${manifest_path}:${line_num}." >&2
          exit 1
        fi
        if [ -n "${orig_mode}" ] && [ "${orig_mode}" != "-" ]; then
          if ! normalize_restore_mode "${orig_mode}" >/dev/null 2>&1; then
            echo "[FAIL] Security violation: unsafe/invalid file mode '${orig_mode}' in manifest at ${manifest_path}:${line_num}." >&2
            exit 1
          fi
        fi
        assert_safe_contained_path "manifest backup" "${bkp}"
        if [ -f "${bkp}" ] && [ ! -L "${bkp}" ]; then
          bkp_sha="$(sha256_file "${bkp}")"
          if [ "${bkp_sha}" != "${orig_sha}" ]; then
            echo "[FAIL] SHA-256 mismatch on backup ${bkp}! Expected ${orig_sha}, got ${bkp_sha}." >&2
            exit 1
          fi
        else
          # Missing backup file: allow ONLY for idempotent re-runs where target is ALREADY
          # byte-exact at original SHA-256. Otherwise fail closed BEFORE Step 1 mutates anything!
          if [ -f "${target}" ] && [ ! -L "${target}" ]; then
            cur_sha="$(sha256_file "${target}")"
            if [ "${cur_sha}" = "${orig_sha}" ]; then
              continue
            fi
          fi
          echo "[FAIL] Preflight failed: Required backup file '${bkp}' for '${target}' is missing and target is not at original SHA-256 (${orig_sha}). Aborting before unlinking any symlinks or modifying any files." >&2
          exit 1
        fi
        ;;
      0)
        assert_safe_contained_path "manifest target" "${target}"
        if [ -d "${target}" ]; then
          echo "[FAIL] Refusing to remove directory listed as newly created file: ${target}" >&2
          exit 1
        fi
        ;;
      *)
        echo "[FAIL] Invalid existed_prior flag '${existed}' at ${manifest_path}:${line_num}." >&2
        exit 1
        ;;
    esac
  done < "${manifest_path}"
}

# Find the newest timestamped backup matching `<prefix>.backup-*` safely via
# Bash `nullglob` (never parsing `ls`, immune to spaces/weird filenames).
# Filters strictly to regular files (`file`) or real directories (`dir`),
# rejecting symlinks at discovery time.
find_latest_backup() {
  local kind="$1"
  local prefix="$2"
  local latest=""
  local cand

  shopt -s nullglob
  for cand in "${prefix}.backup-"*; do
    # Skip symlinks unconditionally so attacker-planted backup links are ignored.
    [ -L "${cand}" ] && continue
    if [ "${kind}" = "dir" ] && [ ! -d "${cand}" ]; then
      continue
    fi
    if [ "${kind}" = "file" ] && [ ! -f "${cand}" ]; then
      continue
    fi
    # Timestamps are YYYYMMDD-HHMMSS, so lexicographic order is chronological.
    if [ -z "${latest}" ] || [[ "${cand}" > "${latest}" ]]; then
      latest="${cand}"
    fi
  done
  shopt -u nullglob

  printf '%s' "${latest}"
}

# ------------------------------------------------------------------------------
# CLI Argument Parsing & Trusted Root Initialization
# ------------------------------------------------------------------------------
LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"
SNAPSHOT_PATH=""
REMOVE_LANE2=0
DRY_RUN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --snapshot)
      require_arg "$1" "$#"
      SNAPSHOT_PATH="$2"
      shift 2
      ;;
    --remove-lane2-home)
      REMOVE_LANE2=1
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
    *)
      echo "[FAIL] Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

LANE1_HOME="$(validate_path_value "LANE1_HOME" "${LANE1_HOME}")"
LANE2_HOME="$(validate_path_value "LANE2_HOME" "${LANE2_HOME}")"
LOCAL_BIN="$(validate_path_value "LOCAL_BIN" "${LOCAL_BIN}")"

# Reject symlinked CODEX_HOME roots BEFORE canonicalize_dir resolves symlinks
# (applies in both normal and --dry-run modes so `--remove-lane2-home` can
# never resolve a symlinked LANE2_HOME and delete its target directory).
for home_root in "${LANE1_HOME}" "${LANE2_HOME}"; do
  if [ -L "${home_root}" ]; then
    echo "[FAIL] Security refusal: CODEX_HOME '${home_root}' must not be a symlink." >&2
    exit 1
  fi
done

# Canonicalize trusted roots once from user/env values ONLY; a rollback manifest
# is NEVER permitted to redefine or widen ALLOWED_ROOTS.
LANE1_HOME="$(canonicalize_dir "${LANE1_HOME}")"
LANE2_HOME="$(canonicalize_dir "${LANE2_HOME}")"
LOCAL_BIN="$(canonicalize_dir "${LOCAL_BIN}")"

if [ "${LANE1_HOME}" = "${LANE2_HOME}" ]; then
  echo "[FAIL] LANE1_HOME and LANE2_HOME resolve to the same directory ('${LANE1_HOME}'); aborting." >&2
  exit 1
fi

ALLOWED_ROOTS=("${LANE1_HOME}" "${LANE2_HOME}" "${LOCAL_BIN}")

echo "=== Codex Dual-Lane Deterministic Rollback & Recovery (Unix / macOS / WSL) ==="
[ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] Verifying paths & SHA-256 hashes without modifying disk."

# Resolve rollback manifest path (explicit --snapshot must exist and not be a symlink).
MANIFEST_FILE=""
if [ -n "${SNAPSHOT_PATH}" ]; then
  SNAPSHOT_PATH="$(validate_path_value "--snapshot" "${SNAPSHOT_PATH}")"
  case "/${SNAPSHOT_PATH}/" in
    */../*)
      echo "[FAIL] Security violation: path traversal rejected in --snapshot: '${SNAPSHOT_PATH}'" >&2
      exit 1
      ;;
  esac
  if [ -L "${SNAPSHOT_PATH}" ]; then
    echo "[FAIL] Security violation: --snapshot path must not be a symlink: '${SNAPSHOT_PATH}'" >&2
    exit 1
  fi
  if [ ! -f "${SNAPSHOT_PATH}" ]; then
    echo "[FAIL] Specified --snapshot manifest does not exist: '${SNAPSHOT_PATH}'" >&2
    exit 1
  fi
  MANIFEST_FILE="${SNAPSHOT_PATH}"
else
  DEFAULT_MANIFEST="${LANE2_HOME}/.rollback/latest.tsv"
  if [ -e "${DEFAULT_MANIFEST}" ] || [ -L "${DEFAULT_MANIFEST}" ]; then
    assert_safe_contained_path "default rollback manifest" "${DEFAULT_MANIFEST}"
    if [ -f "${DEFAULT_MANIFEST}" ]; then
      MANIFEST_FILE="${DEFAULT_MANIFEST}"
    fi
  fi
fi

# Run full read-only manifest preflight BEFORE Step 1 mutates any symlink or file.
if [ -n "${MANIFEST_FILE}" ]; then
  preflight_validate_manifest "${MANIFEST_FILE}"
fi

# ------------------------------------------------------------------------------
# Step 1: Safely Unlink Kit-Created Shared Symlinks & Restore Exact Dir Backups
# ------------------------------------------------------------------------------
# Critical safety invariant: ALWAYS unlink kit-created symlinks with `rm` (never `rm -rf`)
# before any other operation so Lane 1's real sessions/memories/skills are safe.
# Pre-existing user symlinks (`created_by_kit=0`) are preserved untouched, and
# backed-up directories are restored from the EXACT path recorded in the manifest.
echo "[+] Step 1: Unlinking kit-created shared symlinks in ${LANE2_HOME}..."
SHARED_DIRS=(memories memories_v2 sessions archived_sessions skills plugins)
if [ -n "${MANIFEST_FILE}" ] && { [ "${HAS_LINK_RECORDS}" -eq 1 ] || [ "${MANIFEST_SCHEMA_VERSION}" -ge 2 ]; }; then
  if [ "${#LINK_RECORDS[@]}" -eq 0 ]; then
    echo "    Manifest records 0 shared link mutations (interrupted before Step 5); pre-existing symlinks left untouched."
  else
    for lrec in "${LINK_RECORDS[@]}"; do
      lr_created=""
      lr_target=""
      lr_bkp=""
      lr_prior=""
      IFS=$'\t' read -r lr_created lr_target lr_bkp lr_prior <<< "${lrec}"
      if [ "${lr_created}" != "1" ]; then
        is_lane1_bridge_link=0
        if [ "${REMOVE_LANE2_HOME}" -eq 1 ] && [ -L "${lr_target}" ]; then
          lr_leaf="$(basename -- "${lr_target}")"
          for sd in "${SHARED_DIRS[@]}"; do
            if [ "${lr_leaf}" = "${sd}" ]; then
              raw_link_dest="$(readlink "${lr_target}" 2>/dev/null || true)"
              exp_l1="${LANE1_HOME%/}/${lr_leaf}"
              norm_dest="${raw_link_dest%/}"
              if [ -n "${norm_dest}" ] && [ "${norm_dest}" = "${exp_l1}" ]; then
                is_lane1_bridge_link=1
              fi
              break
            fi
          done
        fi
        if [ "${is_lane1_bridge_link}" -ne 1 ]; then
          if [ "${DRY_RUN}" -eq 0 ]; then
            echo "    Preserved pre-existing symlink (not created by kit): ${lr_target}"
          else
            echo "    [DRY-RUN] Would preserve pre-existing symlink (not created by kit): ${lr_target}"
          fi
          continue
        fi
        echo "    Unlinking pre-existing Dual-Lane bridge symlink pointing to Lane 1 (--remove-lane2-home): ${lr_target}"
      fi

      unlinked_or_would_unlink=0
      if [ -L "${lr_target}" ]; then
        if [ "${DRY_RUN}" -eq 0 ]; then
          rm -- "${lr_target}"
          if [ -L "${lr_target}" ] || [ -e "${lr_target}" ]; then
            echo "[FAIL] Failed to unlink symlink ${lr_target}; aborting to protect Lane 1 data." >&2
            exit 1
          fi
          echo "    Unlinked kit-created symlink: ${lr_target} (Lane 1 data untouched)"
        else
          echo "    [DRY-RUN] Would unlink kit-created symlink: ${lr_target} (Lane 1 data untouched)"
        fi
        unlinked_or_would_unlink=1
      fi

      if [ "${lr_prior}" = "preexisting_dir" ] && [ -n "${lr_bkp}" ] && [ "${lr_bkp}" != "-" ]; then
        if [ -d "${lr_bkp}" ] && [ ! -L "${lr_bkp}" ]; then
          if [ "${unlinked_or_would_unlink}" -eq 1 ] || { [ ! -e "${lr_target}" ] && [ ! -L "${lr_target}" ]; }; then
            assert_safe_contained_path "directory backup" "${lr_bkp}"
            if [ "${DRY_RUN}" -eq 0 ]; then
              mv -- "${lr_bkp}" "${lr_target}"
              echo "    Restored exact pre-existing directory from manifest: ${lr_bkp} -> ${lr_target}"
            else
              echo "    [DRY-RUN] Would restore exact pre-existing directory from manifest: ${lr_bkp} -> ${lr_target}"
            fi
          fi
        fi
      fi
    done
  fi
else
  # Legacy v1 manifest without `L` link records, or manifest-less emergency fallback.
  for d in "${SHARED_DIRS[@]}"; do
    target="${LANE2_HOME}/${d}"
    if [ -L "${target}" ]; then
      if [ "${DRY_RUN}" -eq 0 ]; then
        rm -- "${target}"
        if [ -L "${target}" ] || [ -e "${target}" ]; then
          echo "[FAIL] Failed to unlink symlink ${target}; aborting to protect Lane 1 data." >&2
          exit 1
        fi
        echo "    Unlinked symlink: ${target} (Lane 1 data untouched)"
      else
        echo "    [DRY-RUN] Would unlink symlink: ${target} (Lane 1 data untouched)"
      fi
    fi

    latest_dir_bkp="$(find_latest_backup "dir" "${target}")"
    if [ -n "${latest_dir_bkp}" ] && [ ! -e "${target}" ] && [ ! -L "${target}" ]; then
      assert_safe_contained_path "directory backup" "${latest_dir_bkp}"
      if [ "${DRY_RUN}" -eq 0 ]; then
        mv -- "${latest_dir_bkp}" "${target}"
        echo "    Restored pre-existing directory (legacy fallback): ${latest_dir_bkp} -> ${target}"
      else
        echo "    [DRY-RUN] Would restore pre-existing directory (legacy fallback): ${latest_dir_bkp} -> ${target}"
      fi
    fi
  done
fi

# Confirm primary Lane 1 directories remain intact after unlinking Lane 2.
for d in sessions memories; do
  if [ -d "${LANE1_HOME}/${d}" ]; then
    echo "    Verified Lane 1 data intact: ${LANE1_HOME}/${d}"
  fi
done

# ------------------------------------------------------------------------------
# Step 2: Restore Backed-Up Files with SHA-256 Integrity Verification
# ------------------------------------------------------------------------------
echo "[+] Step 2: Restoring configuration & rule files with SHA-256 verification..."
HANDLED_TARGETS=()
is_handled_target() {
  local needle="$1"
  local item
  if [ "${#HANDLED_TARGETS[@]}" -gt 0 ]; then
    for item in "${HANDLED_TARGETS[@]}"; do
      if [ "${item}" = "${needle}" ]; then
        return 0
      fi
    done
  fi
  return 1
}

if [ -n "${MANIFEST_FILE}" ]; then
  echo "    Loaded rollback manifest: ${MANIFEST_FILE}"
  if grep -Fq '# status=in-progress' "${MANIFEST_FILE}" 2>/dev/null; then
    echo "    Detected partial/interrupted install manifest (status=in-progress); recovering tracked mutations safely."
  fi
  line_num=0
  while IFS= read -r line || [ -n "${line}" ]; do
    line_num=$((line_num + 1))
    # Tolerate CRLF if manifest was edited or inspected across WSL/Windows.
    line="${line%$'\r'}"
    [ -z "${line}" ] && continue
    case "${line}" in
      \#*) continue ;;
    esac

    # Strict 4- or 5-column TSV parsing: existed_prior, original_sha256, target_path, backup_path[, original_mode].
    existed=""
    orig_sha=""
    target=""
    bkp=""
    orig_mode=""
    extra=""
    IFS=$'\t' read -r existed orig_sha target bkp orig_mode extra <<< "${line}"

    if [ -n "${extra}" ] || [ -z "${existed}" ] || [ -z "${target}" ]; then
      echo "[FAIL] Malformed manifest entry at ${MANIFEST_FILE}:${line_num}." >&2
      exit 1
    fi

    if [ "${existed}" = "L" ]; then
      # Shared link records are validated in preflight and processed in Step 1.
      continue
    fi

    # Validate target containment & anti-symlink BEFORE inspecting anything else.
    assert_safe_contained_path "manifest target" "${target}"
    HANDLED_TARGETS+=("${target}")

    case "${existed}" in
      1)
        orig_sha="$(printf '%s' "${orig_sha}" | awk '{print tolower($0)}')"
        if ! printf '%s' "${orig_sha}" | grep -Eq '^[0-9a-f]{64}$'; then
          echo "[FAIL] Invalid SHA-256 hash in manifest at ${MANIFEST_FILE}:${line_num}." >&2
          exit 1
        fi
        atomic_restore_verified_file "${bkp}" "${target}" "${orig_sha}" "${orig_mode}"
        ;;
      0)
        if [ -e "${target}" ] || [ -L "${target}" ]; then
          if [ -d "${target}" ]; then
            echo "[FAIL] Refusing to remove directory listed as newly created file: ${target}" >&2
            exit 1
          fi
          if [ "${DRY_RUN}" -eq 0 ]; then
            rm -f -- "${target}"
            echo "    Removed newly created file: ${target}"
          else
            echo "    [DRY-RUN] Would remove newly created file: ${target}"
          fi
        fi
        ;;
      *)
        echo "[FAIL] Invalid existed_prior flag '${existed}' at ${MANIFEST_FILE}:${line_num}." >&2
        exit 1
        ;;
    esac
  done < "${MANIFEST_FILE}"
else
  echo "    No rollback manifest found; falling back to latest timestamped .backup-* files."
  for home_dir in "${LANE1_HOME}" "${LANE2_HOME}"; do
    for rel in "config.toml" "auth.json" "AGENTS.md" "rules/default.rules"; do
      target_file="${home_dir}/${rel}"
      bkp_file="$(find_latest_backup "file" "${target_file}")"
      if [ -n "${bkp_file}" ]; then
        atomic_restore_verified_file "${bkp_file}" "${target_file}" ""
      fi
    done
  done
fi

# ------------------------------------------------------------------------------
# Step 3: Restore Pre-Existing Launchers or Remove Newly Created Wrappers
# ------------------------------------------------------------------------------
# Return 0 only if the regular file carries the Dual-Lane Kit wrapper header.
# Protects untouched pre-existing user launchers when rolling back an
# interrupted mid-install manifest that never reached Step 8.
is_dual_lane_wrapper() {
  local f="$1"
  [ -f "${f}" ] && [ ! -L "${f}" ] || return 1
  local line_count=0 line=""
  while IFS= read -r -n 256 line || [ -n "${line}" ]; do
    line_count=$((line_count + 1))
    case "${line}" in
      *"# Codex Dual-Lane wrapper:"*) return 0 ;;
    esac
    [ "${line_count}" -ge 5 ] && break
  done < "${f}"
  return 1
}

echo "[+] Step 3: Reconciling CLI wrappers in ${LOCAL_BIN}..."
for w in codex codex-official codex-t3 codex-manage; do
  wp="${LOCAL_BIN}/${w}"
  if is_handled_target "${wp}"; then
    continue
  fi
  bkp_wrapper="$(find_latest_backup "file" "${wp}")"
  if [ -n "${bkp_wrapper}" ]; then
    atomic_restore_verified_file "${bkp_wrapper}" "${wp}" ""
  elif [ -L "${wp}" ]; then
    echo "[WARN] Leaving unexpected symlink untouched in ${LOCAL_BIN}: ${wp}" >&2
  elif [ -f "${wp}" ]; then
    if is_dual_lane_wrapper "${wp}"; then
      if [ "${DRY_RUN}" -eq 0 ]; then
        rm -f -- "${wp}"
        echo "    Removed wrapper: ${wp}"
      else
        echo "    [DRY-RUN] Would remove wrapper: ${wp}"
      fi
    else
      echo "    Preserved untouched pre-existing launcher: ${wp}"
    fi
  fi
done

# ------------------------------------------------------------------------------
# Step 4: Optional Complete Removal of LANE2_HOME (After Proving Zero Symlinks)
# ------------------------------------------------------------------------------
if [ "${REMOVE_LANE2}" -eq 1 ]; then
  if [ -L "${LANE2_HOME}" ]; then
    echo "[FAIL] Security refusal: LANE2_HOME '${LANE2_HOME}' is itself a symlink; aborting removal." >&2
    exit 1
  fi
  HOME_CANON="$(canonicalize_dir "${HOME}")"
  if [ "${LANE2_HOME}" = "${HOME_CANON}" ] || [ "${LANE2_HOME}" = "${LANE1_HOME}" ]; then
    echo "[FAIL] Security refusal: refusing to remove '${LANE2_HOME}'." >&2
    exit 1
  fi
  if [ -d "${LANE2_HOME}" ]; then
    echo "[+] Step 4: Removing ${LANE2_HOME} (--remove-lane2-home)..."
    # Scan the entire Lane 2 tree for ANY remaining symlink before permitting rm -rf.
    remaining_links="$(find "${LANE2_HOME}" -type l 2>/dev/null || true)"
    if [ -n "${remaining_links}" ]; then
      if [ "${DRY_RUN}" -eq 1 ]; then
        echo "    [DRY-RUN] Note: symlinks still present only because --dry-run skipped unlinking in Step 1."
      else
        echo "[FAIL] Refusing to remove ${LANE2_HOME}: symlink(s) still present!" >&2
        exit 1
      fi
    fi
    if [ "${DRY_RUN}" -eq 0 ]; then
      rm -rf -- "${LANE2_HOME}"
      echo "    Removed directory: ${LANE2_HOME} (Lane 1 data verified safe)"
    else
      echo "    [DRY-RUN] Would remove directory: ${LANE2_HOME} (after unlinking symlinks)"
    fi
  fi
fi

echo "[OK] Deterministic rollback completed!"
