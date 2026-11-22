# Changelog

All notable changes to **Codex Dual-Lane & Security Kit** are documented in this file.

The format follows semantic versioning (`MAJOR.MINOR.PATCH`).

---

## [1.3.1] — 2026-11-22 (Flexible Dual-Lane Auth, Full Workspace File CRUD Mastery & Deterministic Link Ownership)

### Added
- **Flexible Dual-Lane Workflow (Codex Desktop = Primary Account `acc chính` with Full Native Authority; Codex CLI = Both OAuth Login & API Key)**:
  - Added `-GatewayTargetLane <Lane1|Lane2|Both>` to `scripts/setup-dual-lane.ps1` and `--configure-gateway` / `--gateway-target-lane <lane1|lane2|both>` (with `--gateway-provider`, `--gateway-base-url`, `--gateway-model`, `--gateway-api-key-env`) to `scripts/setup-dual-lane.sh`.
  - Allows users to keep **Codex Desktop (`~/.codex`, Lane 1)** on their Primary Account (`acc chính`) with **100% full authority as before (`toàn quyền như trước`)** — leaving `~/.codex/config.toml` completely untouched by default (and never injecting restrictive `sandbox_mode` or `network_access = false` into Lane 1 even when `-ConfigureGateway` targets `Lane1` or `Both`) — while **Codex CLI (`~/.codex-official`, Lane 2)** supports **BOTH ChatGPT/OpenAI OAuth Login (`codex login`) AND API Key (`env_key` / custom provider / `codex login --with-api-key`)** with zero plaintext secrets on disk.
  - Enhanced `scripts/doctor.ps1` and `scripts/doctor.sh` to report combined authentication posture (`auth.json` mode + `env_key=<VAR>`) across both lanes without ever echoing secrets.
- **Full Workspace Directory Tree Mastery & File CRUD Authority Guardrails**:
  - Updated `templates/AGENTS.lane1.md`, `templates/AGENTS.lane2.md`, `templates/DUAL_LANE_BRIDGE.md`, and `templates/default.rules` header documentation to explicitly guarantee full project authority on Codex Desktop (`Lane 1`), full workspace directory tree traversal (`rg --files`, `git status`, `Get-ChildItem`, `find`), and unobstructed project file read, create, edit, move, delete, build, and test operations inside the workspace, while keeping destructive OS/ACL/ransomware commands forbidden and enforcing `Static-Analysis-Only` strictly against executing third-party sample payloads.
- **Deterministic Junction & Symlink Ownership Tracking (`SchemaVersion=2` / `schema_version=2`)**:
  - `scripts/setup-dual-lane.ps1` records `SharedLinkRecords` containing `Name`, `LinkPath`, `PriorState` (`absent`, `preexisting_link`, `preexisting_dir`), `CreatedByKit`, and exact `BackupDirPath` in `.rollback/latest.json`.
  - `scripts/setup-dual-lane.sh` records `L\t<created_by_kit>\t<dst_link>\t<dir_bkp>\t<prior_state>` rows in `.rollback/latest.tsv`.
  - Rollback scripts (`restore-original.ps1` and `restore-original.sh`) inspect ownership: pre-existing user Junctions/symlinks created before kit installation are preserved untouched, restoring original machine state accurately.
- **Exact Directory Backup Restoration**:
  - Restores moved directories from the exact recorded `BackupDirPath` / `dir_bkp` rather than wildcard-sorting `.backup-*` directory names, eliminating decoy/stray directory misrestoration risks.
- **Fail-Closed Missing-Backup Preflight (Zero Disk Mutation on Error)**:
  - Preflight validates all file and directory backups upfront: if any required backup is missing and the target is not already at original state, rollback halts immediately (`exit 1`) **before** detaching any Junctions or touching any files on disk.
- **Regression Test Coverage (Test Stage 11+ & Unix CI Section 9)**:
  - Verifies `-GatewayTargetLane Lane2` / `--gateway-target-lane lane2` CLI API key + OAuth login coexistence, workspace directory tree & file CRUD operations, pre-existing Junction/symlink preservation, decoy backup resistance, fail-closed preflight abort with 0 links unlinked on missing file/directory backups, and clean idempotent re-run (exit 0).

### Changed
- Clarified worktree isolation, dual-lane authentication roles, and full workspace file CRUD authority across `README.md`, `SECURITY.md`, `docs/SECURITY_MODEL.md`, `docs/GUIDE_AND_MANIFEST.md`, `docs/TROUBLESHOOTING.md`, and `docs/REAL_CODEX_CHECKLIST.md`: `CODEX_NO_AUTO_WORKTREE_CD=1` intentionally skips automatic `cwd` directory switching while Guard 2 argument blocking (`-C`, `--cd`, `--add-dir`) remains fail-closed.

---

## [1.3.0] — 2026-11-22 (Stabilization & Release Readiness)

### Added
- **Windows 8.3 short-path canonicalization (`GetLongPathNameW` + runtime `%%~fs`)** across `scripts/setup-dual-lane.ps1`, `scripts/restore-original.ps1`, `scripts/doctor.ps1`, generated `.cmd` wrappers, and `tests/test-kit.ps1`, eliminating `RUNNER~1` vs `runneradmin` mismatches and 8.3 short-path `-C`/`--cd`/`--add-dir` bypasses.
- **Crash-safe incremental rollback journal** on both Windows (`.rollback/latest.json`) and Unix (`.rollback/latest.tsv`):
  - Checkpoints atomically with `status=in-progress` after every tracked file backup/write, Junction/symlink creation, and launcher install, finalizing `status=complete` on completion.
  - `restore-original.ps1` and `restore-original.sh` cleanly recover partial/interrupted installations with SHA-256 + POSIX mode (`000`–`777`) verification while protecting untouched pre-existing launchers.
  - `doctor.ps1` and `doctor.sh` add read-only Rollback Journal health diagnostics.
- **Expanded cross-OS regression suites (`tests/test-kit.ps1` 10 stages & `.github/workflows/ci.yml`)**:
  - Bidirectional 8.3 short-path routing and primary-repo blocking tests.
  - Hard fail-closed worktree tests (missing directory, regular-file replacement, symlinked worktree/escape, inaccessible `cd` failure via explicit NTFS `DENY (X)` / POSIX `chmod 000`).
  - Interrupted mid-install rollback recovery tests (partial files, partial Junctions/symlinks, untouched pre-existing launchers).
  - 3x consecutive `Install -> Verify -> Restore -> Verify` idempotency loops on Windows (PS 5.1 & 7+), Ubuntu, and macOS.
- **Real Codex CLI (`codex-cli 0.171.0-alpha.13`) verification evidence** documented in `docs/REAL_CODEX_CHECKLIST.md`, `SECURITY.md`, and `docs/SECURITY_MODEL.md`:
  - Live atomic config rewrite (`codex features enable ...`) -> NTFS DACL reset -> `-ReapplyAclOnly` recovery (SHA-256 bit-identical).
  - Live `codex sandbox` OS write-boundary verification (`WRITE_OK` in worktree, `WRITE_DENIED` on primary repo and canary/auth files).
  - Kernel `AuthzAccessCheck` effective-access probe for `CodexSandboxOffline` plus transparent disclosure of the unelevated write-restricted token read boundary.

### Changed
- **Hard fail-closed worktree boundary** (Windows & Unix): when `-UseGitWorktree` / `--use-git-worktree` is enabled and `CODEX_NO_AUTO_WORKTREE_CD` is not set, a missing/deleted/symlinked worktree, failed `cd`, or post-`cd` escape outside the worktree now refuses to run (`exit 1`) instead of silently falling back to the primary repository.
- **Guard 2 argument hardening**: blocks attached `-C<path>`, `-C=<path>`, embedded quotes, and 8.3 short-path aliases targeting the primary repository even when `CODEX_NO_AUTO_WORKTREE_CD=1` is set.
- **CI workflow modernization**: upgraded `actions/checkout` and `actions/setup-python` to `@v7` (Node 24 runtime) and isolated `py_compile` output into temporary directories so `__pycache__` is never left in the repository.

### Fixed
- Eliminated spurious User `PATH` rewrites in `restore-original.ps1` when `$LocalBin` is already absent from User `PATH`.
- Fixed Windows CI `cd`-failure simulation on elevated GitHub Actions runners by applying explicit `DENY *S-1-1-0:(X)` to both worktree root and nested subdirectory (overriding explicit Allow ACEs while keeping `WRITE_DAC` intact for cleanup).

---

## [1.2.3] — 2026-11-22
- Decoupled automatic worktree `cwd` switching (Guard 1) from `-C`/`--cd`/`--add-dir` argument blocking (Guard 2) on both Windows and Unix so `CODEX_NO_AUTO_WORKTREE_CD=1` never disables primary-repo argument guards.
- Split Windows test assertions into independent exit-code and active-path checks with explicit expected/actual diagnostics.

## [1.2.2] — 2026-11-22
- Added `-ReapplyAclOnly` fast maintenance mode (<1s) to `setup-dual-lane.ps1` for re-locking NTFS DACLs after Codex atomic file replacements.
- Added nested subdirectory worktree routing and `-C`/`--cd`/`--add-dir` primary-repo blocking on Windows (zero-parenthesis cmd.exe) and Unix (`pwd -P`).
- Upgraded Unix rollback manifest (`.rollback/latest.tsv`) to 5 columns recording exact 3-digit octal `original_mode` (rejecting SUID/SGID/sticky bits) so restored launchers and configs preserve original permissions.

## [1.2.1] — 2026-11-22
- Removed GNU-only `--` from `chmod` / `stat` calls in `.sh` scripts for full macOS BSD compatibility.
- Made `Protect-SensitiveFileAcl` fail-closed on `icacls.exe` errors with post-condition `Get-Acl` verification.
- Added SHA-256 backup and restoration for pre-existing CLI launchers (`codex`, `codex-official`, `codex-t3`) instead of deleting them on rollback.
- Added OS workspace-write worktree `cwd` redirection in Lane 2 wrappers.

## [1.2.0] — 2026-11-22
- Hardened end-user safety, inline WHAT/WHY documentation, adversarial test suites (`tests/test-kit.ps1` + 12 Python unit tests), and multi-OS GitHub Actions CI (`windows-latest`, `ubuntu-latest`, `macos-latest`).

## [1.1.1] — 2026-11-21
- Enforced two-step Windows NTFS kernel ACL isolation (`/inheritance:d` then `/remove:g "CodexSandboxUsers"`) on `auth.json`, `config.toml`, backups, and rollback manifests.
- Added strict path-traversal and reparse-point defenses to rollback scripts and blocked ACL/network commands in `templates/default.rules`.

## [1.1.0] — 2026-11-21
- Added deterministic SHA-256 rollback snapshot manifests and one-click recovery scripts (`restore-original.ps1` and `restore-original.sh`).

## [1.0.0] — 2026-11-21
- Initial release: Dual-Lane architecture (`~/.codex` + `~/.codex-official`), 6 shared-brain NTFS Junctions / Unix symlinks, 4-layer security model (`default.rules` Starlark firewall, `network_access = false`, `env_key` secret isolation, `AGENTS.md`), non-destructive TOML merge, `doctor.*`, `sync-sessions.py` SQLite UPSERT (`?mode=ro`), Git worktree support, and CI harness.
