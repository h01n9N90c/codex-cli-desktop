#!/usr/bin/env bash
# Cross-platform installer for Codex Dual-Lane & Security Kit on macOS / Linux / WSL.
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Zero hardcoded secrets, zero hardcoded paths, zero mock data.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REPO_PATH="$(pwd)"
LANE1_HOME="${CODEX_LANE1_HOME:-${HOME}/.codex}"
LANE2_HOME="${CODEX_LANE2_HOME:-${HOME}/.codex-official}"
LOCAL_BIN="${CODEX_LOCAL_BIN:-${HOME}/.local/bin}"
CARGO_TARGET_LANE2="${CODEX_CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/codex-lane2-target}"
APPROVAL_POLICY="${CODEX_APPROVAL_POLICY:-on-request}"
SANDBOX_NETWORK="${CODEX_SANDBOX_NETWORK:-false}"
USE_GIT_WORKTREE=0
LANE2_WORKTREE_PATH=""
LANE2_BRANCH="dual-lane-2"
INSTALL_BRIDGE=0
SYNC_SESSIONS=0
PINNED_ONLY=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: ./scripts/setup-dual-lane.sh [REPO_PATH] [OPTIONS]

Options:
  --repo PATH                 Target repository directory (default: current directory)
  --approval-policy MODE      'on-request' (default, secure) or 'never' (unattended)
  --allow-sandbox-network     Enable network_access=true inside [sandbox_workspace_write]
  --use-git-worktree          Create an isolated Git worktree (<repo>-lane2) for OS-level file isolation
  --worktree-path PATH        Custom worktree path when using --use-git-worktree
  --install-bridge            Copy templates/DUAL_LANE_BRIDGE.md into <repo>/artifacts/dual-lane/
  --sync-sessions             Run scripts/sync-sessions.py after install (requires python3)
  --pinned-only               With --sync-sessions, only sync pinned threads
  --dry-run                   Preview every step without writing any files
  -h, --help                  Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      REPO_PATH="$2"
      shift 2
      ;;
    --approval-policy)
      APPROVAL_POLICY="$2"
      shift 2
      ;;
    --allow-sandbox-network)
      SANDBOX_NETWORK="true"
      shift
      ;;
    --use-git-worktree)
      USE_GIT_WORKTREE=1
      shift
      ;;
    --worktree-path)
      LANE2_WORKTREE_PATH="$2"
      shift 2
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

REPO_PATH="$(cd "${REPO_PATH}" && pwd)"
CARGO_TARGET_LANE2="${CARGO_TARGET_LANE2%/}"

echo "=== Codex Dual-Lane & Security Kit Installer (macOS / Linux / WSL) ==="
[ "${DRY_RUN}" -eq 1 ] && echo "[DRY-RUN MODE] No files on disk will be modified."

# 1. Detect real codex binary using bash built-in `type -ap` (excluding ~/.local/bin/codex wrapper)
CODEX_BIN=""
while IFS= read -r candidate; do
  [ -z "${candidate}" ] && continue
  if [ "${candidate}" != "${LOCAL_BIN}/codex" ] && [ -x "${candidate}" ]; then
    CODEX_BIN="${candidate}"
    break
  fi
done < <(type -ap codex 2>/dev/null || true)

if [ -z "${CODEX_BIN}" ]; then
  echo "[FAIL] No 'codex' binary found in PATH. Install with 'npm i -g @openai/codex' first." >&2
  exit 1
fi

CODEX_VER="$("${CODEX_BIN}" --version 2>/dev/null | head -n 1 || echo "unknown")"
echo "[+] Found codex binary: ${CODEX_BIN} (${CODEX_VER})"

# 2. Dynamically probe supported feature flags from installed binary
PROBE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t codex-probe)"
cleanup_probe() { rm -rf "${PROBE_DIR}"; }
trap cleanup_probe EXIT

FEATURES_OUT="$(CODEX_HOME="${PROBE_DIR}" "${CODEX_BIN}" features list 2>/dev/null || true)"
HAS_DAEMON_FLAG=0
HAS_GOALS_FLAG=0
if printf '%s\n' "${FEATURES_OUT}" | grep -Eq '^daemon_auto_start[[:space:]]+'; then HAS_DAEMON_FLAG=1; fi
if printf '%s\n' "${FEATURES_OUT}" | grep -Eq '^goals[[:space:]]+'; then HAS_GOALS_FLAG=1; fi

# 3. Optional: Create isolated Git worktree for Lane 2 (OS-level workspace-write boundary)
EFFECTIVE_LANE2_REPO="${REPO_PATH}"
if [ "${USE_GIT_WORKTREE}" -eq 1 ]; then
  WT_TARGET="${LANE2_WORKTREE_PATH:-${REPO_PATH}-lane2}"
  if [ -d "${WT_TARGET}" ]; then
    EFFECTIVE_LANE2_REPO="$(cd "${WT_TARGET}" && pwd)"
    echo "    Existing Lane 2 worktree: ${EFFECTIVE_LANE2_REPO}"
  else
    if [ "${DRY_RUN}" -eq 0 ]; then
      git -C "${REPO_PATH}" worktree add -B "${LANE2_BRANCH}" "${WT_TARGET}" HEAD
      EFFECTIVE_LANE2_REPO="$(cd "${WT_TARGET}" && pwd)"
    else
      EFFECTIVE_LANE2_REPO="${WT_TARGET}"
    fi
    echo "    Created Lane 2 Git worktree: ${EFFECTIVE_LANE2_REPO} (branch: ${LANE2_BRANCH})"
  fi
fi

# 4. Prepare directories
if [ "${DRY_RUN}" -eq 0 ]; then
  mkdir -p "${LANE1_HOME}/rules" "${LANE2_HOME}/rules" "${LOCAL_BIN}"
fi

# 5. Share memories, sessions, skills, plugins via symlinks (never delete existing dirs without backup)
stamp="$(date +%Y%m%d-%H%M%S)"
for d in memories memories_v2 sessions archived_sessions skills plugins; do
  if [ "${DRY_RUN}" -eq 0 ]; then mkdir -p "${LANE1_HOME}/${d}"; fi
  if [ -L "${LANE2_HOME}/${d}" ]; then
    echo "    Already linked: ${LANE2_HOME}/${d}"
    continue
  elif [ -e "${LANE2_HOME}/${d}" ]; then
    if [ "${DRY_RUN}" -eq 0 ]; then
      mv "${LANE2_HOME}/${d}" "${LANE2_HOME}/${d}.backup-${stamp}"
    fi
    echo "    Backed up existing directory: ${LANE2_HOME}/${d}.backup-${stamp}"
  fi
  if [ "${DRY_RUN}" -eq 0 ]; then
    ln -s "${LANE1_HOME}/${d}" "${LANE2_HOME}/${d}"
  fi
  echo "    Linked: ${LANE2_HOME}/${d} -> ${LANE1_HOME}/${d}"
done

# 6. Install firewall rules & global AGENTS.md (with timestamped backup)
backup_and_copy() {
  local src="$1"
  local dst="$2"
  if [ -f "${dst}" ]; then
    if [ "${DRY_RUN}" -eq 0 ]; then cp "${dst}" "${dst}.backup-${stamp}"; fi
    echo "    Backup saved: ${dst}.backup-${stamp}"
  fi
  if [ "${DRY_RUN}" -eq 0 ]; then cp "${src}" "${dst}"; fi
  echo "    Installed: ${dst}"
}

backup_and_copy "${KIT_ROOT}/templates/default.rules" "${LANE1_HOME}/rules/default.rules"
backup_and_copy "${KIT_ROOT}/templates/default.rules" "${LANE2_HOME}/rules/default.rules"
backup_and_copy "${KIT_ROOT}/templates/AGENTS.lane1.md" "${LANE1_HOME}/AGENTS.md"
backup_and_copy "${KIT_ROOT}/templates/AGENTS.lane2.md" "${LANE2_HOME}/AGENTS.md"

# 7. Non-destructively merge & write Lane 2 Official config.toml
CFG2="${LANE2_HOME}/config.toml"
PRESERVED_USER_SECTIONS=""
if [ -f "${CFG2}" ]; then
  if [ "${DRY_RUN}" -eq 0 ]; then cp "${CFG2}" "${CFG2}.backup-${stamp}"; fi
  echo "    Backup saved: ${CFG2}.backup-${stamp}"
  # Extract custom user sections (e.g. [mcp_servers.*], [tui], [plugins.*]) so they are not lost
  PRESERVED_USER_SECTIONS="$(awk '
    /^\[.*\]$/ {
      sec = $0
      gsub(/^\[|\]$/, "", sec)
      if (sec == "windows" || sec == "features" || sec == "memories" || sec == "sandbox_workspace_write" || sec == "shell_environment_policy" || sec == "shell_environment_policy.set") {
        keep = 0
      } else {
        keep = 1
      }
    }
    keep == 1 { print $0 }
  ' "${CFG2}" || true)"
fi

escape_toml() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

ESC_REPO="$(escape_toml "${REPO_PATH}")"
ESC_LANE2_REPO="$(escape_toml "${EFFECTIVE_LANE2_REPO}")"
ESC_CARGO="$(escape_toml "${CARGO_TARGET_LANE2}")"

if [ "${DRY_RUN}" -eq 0 ]; then
  {
    printf '# Official OpenAI / ChatGPT Codex CLI configuration (LANE 2)\n'
    printf 'sandbox_mode = "workspace-write"\n'
    printf 'approval_policy = "%s"\n\n' "${APPROVAL_POLICY}"
    if ! printf '%s\n' "${PRESERVED_USER_SECTIONS}" | grep -Fq "[projects.\"${ESC_REPO}\"]"; then
      printf '[projects."%s"]\n' "${ESC_REPO}"
      printf 'trust_level = "trusted"\n\n'
    fi
    if [ "${EFFECTIVE_LANE2_REPO}" != "${REPO_PATH}" ] && ! printf '%s\n' "${PRESERVED_USER_SECTIONS}" | grep -Fq "[projects.\"${ESC_LANE2_REPO}\"]"; then
      printf '[projects."%s"]\n' "${ESC_LANE2_REPO}"
      printf 'trust_level = "trusted"\n\n'
    fi
    printf '[features]\n'
    [ "${HAS_DAEMON_FLAG}" -eq 1 ] && printf 'daemon_auto_start = false\n'
    printf 'memories = true\n'
    printf 'js_repl = false\n'
    [ "${HAS_GOALS_FLAG}" -eq 1 ] && printf 'goals = true\n'
    printf '\n[memories]\n'
    printf 'generate_memories = true\n'
    printf 'use_memories = true\n\n'
    printf '[sandbox_workspace_write]\n'
    printf 'network_access = %s\n\n' "${SANDBOX_NETWORK}"
    printf '[shell_environment_policy]\n'
    printf 'exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]\n\n'
    printf '[shell_environment_policy.set]\n'
    printf 'CODEX_ACTIVE_LANE = "LANE_2"\n'
    printf 'CARGO_TARGET_DIR = "%s"\n' "${ESC_CARGO}"
    if [ -n "${PRESERVED_USER_SECTIONS}" ]; then
      printf '\n# Preserved existing sections\n%s\n' "${PRESERVED_USER_SECTIONS}"
    fi
  } > "${CFG2}"
fi
echo "    Wrote: ${CFG2} (approval_policy=${APPROVAL_POLICY}, network_access=${SANDBOX_NETWORK})"

# 8. Install launchers
if [ "${DRY_RUN}" -eq 0 ]; then
  for name in codex codex-official; do
    cat > "${LOCAL_BIN}/${name}" <<EOF
#!/usr/bin/env bash
export CODEX_HOME="${LANE2_HOME}"
export CODEX_ACTIVE_LANE="LANE_2"
export CARGO_TARGET_DIR="${CARGO_TARGET_LANE2}"
exec "${CODEX_BIN}" "\$@"
EOF
    chmod +x "${LOCAL_BIN}/${name}"
  done

  cat > "${LOCAL_BIN}/codex-t3" <<EOF
#!/usr/bin/env bash
export CODEX_HOME="${LANE1_HOME}"
export CODEX_ACTIVE_LANE="LANE_1"
exec "${CODEX_BIN}" "\$@"
EOF
  chmod +x "${LOCAL_BIN}/codex-t3"
fi
echo "    Installed wrappers in: ${LOCAL_BIN}"

# 9. Optional bridge template
if [ "${INSTALL_BRIDGE}" -eq 1 ]; then
  for target_repo in "${REPO_PATH}" "${EFFECTIVE_LANE2_REPO}"; do
    BRIDGE_DST="${target_repo}/artifacts/dual-lane/DUAL_LANE_BRIDGE.md"
    if [ ! -f "${BRIDGE_DST}" ]; then
      if [ "${DRY_RUN}" -eq 0 ]; then
        mkdir -p "$(dirname "${BRIDGE_DST}")"
        cp "${KIT_ROOT}/templates/DUAL_LANE_BRIDGE.md" "${BRIDGE_DST}"
      fi
      echo "    Created: ${BRIDGE_DST}"
    else
      echo "    Kept existing: ${BRIDGE_DST}"
    fi
  done
fi

# 10. Optional session sync
if [ "${SYNC_SESSIONS}" -eq 1 ]; then
  PY_BIN=""
  for cand in python3 python; do
    if command -v "${cand}" >/dev/null 2>&1; then
      if "${cand}" --version 2>&1 | grep -Eq '^Python 3\.'; then
        PY_BIN="${cand}"
        break
      fi
    fi
  done
  if [ -n "${PY_BIN}" ]; then
    SYNC_ARGS=("${KIT_ROOT}/scripts/sync-sessions.py" --lane1 "${LANE1_HOME}" --lane2 "${LANE2_HOME}" --repo "${EFFECTIVE_LANE2_REPO}" --approval-mode "${APPROVAL_POLICY}")
    [ "${PINNED_ONLY}" -eq 1 ] && SYNC_ARGS+=(--pinned-only)
    [ "${DRY_RUN}" -eq 1 ] && SYNC_ARGS+=(--dry-run)
    "${PY_BIN}" "${SYNC_ARGS[@]}"
  else
    echo "[WARN] Real Python 3 not found; skipping session sync."
  fi
fi

echo ""
echo "[OK] Setup completed!"
echo "Ensure ${LOCAL_BIN} precedes ${CODEX_BIN%/*} in your PATH (e.g. export PATH=\"${LOCAL_BIN}:\$PATH\")."
echo "Next steps:"
echo "  1. ./scripts/doctor.sh"
echo "  2. codex login"
echo "  3. codex"
