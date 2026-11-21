#!/usr/bin/env bash
# Cross-platform installer for Codex Dual-Lane & Security Kit on macOS / Linux / WSL.
# Author    : Lê Hoàng Ngọc Tươi
# Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
# License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
# Zero hardcoded secrets, zero hardcoded paths, zero mock data.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_PATH="${1:-$(pwd)}"
REPO_PATH="$(cd "${REPO_PATH}" && pwd)"

LANE1_HOME="${HOME}/.codex"
LANE2_HOME="${HOME}/.codex-official"
LOCAL_BIN="${HOME}/.local/bin"
CARGO_TARGET_LANE2="${TMPDIR:-/tmp}/codex-lane2-target"
APPROVAL_POLICY="${CODEX_APPROVAL_POLICY:-never}"
SANDBOX_NETWORK="${CODEX_SANDBOX_NETWORK:-false}"

# Detect real codex binary using bash built-in `type -ap` (excluding ~/.local/bin/codex wrapper)
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

echo "[+] Found codex binary: ${CODEX_BIN} ($(${CODEX_BIN} --version 2>/dev/null || echo unknown))"
mkdir -p "${LANE1_HOME}/rules" "${LANE2_HOME}/rules" "${LOCAL_BIN}"

# Share memories, sessions, skills, plugins via symlinks (never delete existing dirs without backup)
stamp="$(date +%Y%m%d-%H%M%S)"
for d in memories memories_v2 sessions archived_sessions skills plugins; do
  mkdir -p "${LANE1_HOME}/${d}"
  if [ -L "${LANE2_HOME}/${d}" ]; then
    continue
  elif [ -e "${LANE2_HOME}/${d}" ]; then
    mv "${LANE2_HOME}/${d}" "${LANE2_HOME}/${d}.backup-${stamp}"
    echo "    Backed up existing directory: ${LANE2_HOME}/${d}.backup-${stamp}"
  fi
  ln -s "${LANE1_HOME}/${d}" "${LANE2_HOME}/${d}"
  echo "    Linked: ${LANE2_HOME}/${d} -> ${LANE1_HOME}/${d}"
done

# Install firewall rules & global AGENTS.md (with timestamped backup)
for target in "${LANE1_HOME}/rules/default.rules" "${LANE2_HOME}/rules/default.rules"; do
  [ -f "${target}" ] && cp "${target}" "${target}.backup-${stamp}"
  cp "${KIT_ROOT}/templates/default.rules" "${target}"
done
[ -f "${LANE1_HOME}/AGENTS.md" ] && cp "${LANE1_HOME}/AGENTS.md" "${LANE1_HOME}/AGENTS.md.backup-${stamp}"
[ -f "${LANE2_HOME}/AGENTS.md" ] && cp "${LANE2_HOME}/AGENTS.md" "${LANE2_HOME}/AGENTS.md.backup-${stamp}"
cp "${KIT_ROOT}/templates/AGENTS.lane1.md" "${LANE1_HOME}/AGENTS.md"
cp "${KIT_ROOT}/templates/AGENTS.lane2.md" "${LANE2_HOME}/AGENTS.md"

# Write Lane 2 Official config.toml (without hardcoding model/tier)
CFG2="${LANE2_HOME}/config.toml"
[ -f "${CFG2}" ] && cp "${CFG2}" "${CFG2}.backup-${stamp}"
cat > "${CFG2}" <<EOF
# Official OpenAI / ChatGPT Codex CLI configuration (LANE 2)
sandbox_mode = "workspace-write"
approval_policy = "${APPROVAL_POLICY}"

[projects."${REPO_PATH}"]
trust_level = "trusted"

[features]
memories = true
js_repl = false

[memories]
generate_memories = true
use_memories = true

[sandbox_workspace_write]
network_access = ${SANDBOX_NETWORK}

[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]

[shell_environment_policy.set]
CODEX_ACTIVE_LANE = "LANE_2"
CARGO_TARGET_DIR = "${CARGO_TARGET_LANE2}"
EOF

# Install wrappers
cat > "${LOCAL_BIN}/codex" <<EOF
#!/usr/bin/env bash
export CODEX_HOME="${LANE2_HOME}"
export CODEX_ACTIVE_LANE="LANE_2"
export CARGO_TARGET_DIR="${CARGO_TARGET_LANE2}"
exec "${CODEX_BIN}" "\$@"
EOF
cat > "${LOCAL_BIN}/codex-official" <<EOF
#!/usr/bin/env bash
export CODEX_HOME="${LANE2_HOME}"
export CODEX_ACTIVE_LANE="LANE_2"
export CARGO_TARGET_DIR="${CARGO_TARGET_LANE2}"
exec "${CODEX_BIN}" "\$@"
EOF
cat > "${LOCAL_BIN}/codex-t3" <<EOF
#!/usr/bin/env bash
export CODEX_HOME="${LANE1_HOME}"
export CODEX_ACTIVE_LANE="LANE_1"
exec "${CODEX_BIN}" "\$@"
EOF
chmod +x "${LOCAL_BIN}/codex" "${LOCAL_BIN}/codex-official" "${LOCAL_BIN}/codex-t3"

echo "[OK] Installed wrappers in ${LOCAL_BIN}. Ensure ${LOCAL_BIN} precedes ${CODEX_BIN%/*} in PATH."
echo "Next steps:"
echo "  1. codex login"
echo "  2. codex"
