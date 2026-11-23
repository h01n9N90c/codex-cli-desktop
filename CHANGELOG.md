# Changelog

All notable changes to **Codex Dual-Lane & Security Kit** are documented in this file.

The format follows semantic versioning (`MAJOR.MINOR.PATCH`).

---

## [1.4.1] — 2026-11-23 (Online API Probe HTTPS/No-Redirect Hardening & Explicit Opt-In Project Trust)

### Fixed
- **Fixed (Security — High): Online API Key Probe HTTPS-Only & No-Redirect Enforcement (`scripts/codex-manager.sh` & `scripts/codex-manager.ps1`):**
  - Enforced **HTTPS-only** for all remote `/models` probe URLs (plain `http://` is permitted strictly on loopback `127.0.0.1` / `localhost` / `::1` for local mock testing; any non-loopback `http://` URL or URL containing embedded `user:pass@` credentials is refused fail-closed with `REFUSED (https_required...)` BEFORE building an HTTP request).
  - Disabled automatic HTTP redirect following while carrying the `Authorization: Bearer ...` header (`_NoRedirect` `HTTPRedirectHandler` in Python `urllib` on Unix; `$req.AllowAutoRedirect = $false` in .NET `HttpWebRequest` on Windows), blocking `3xx` redirects (`REDIRECT_BLOCKED`) so an attacker-controlled or misconfigured endpoint can never redirect an API key to another host.
- **Fixed (Security — Medium): Explicit Opt-In Project Trust (`-TrustRepoPath` / `--trust-repo-path` in `scripts/setup-dual-lane.ps1` & `scripts/setup-dual-lane.sh`):**
  - Setup scripts no longer implicitly write `trust_level = "trusted"` for `-RepoPath` / `--repo-path` (or the Lane 2 worktree) without explicit user confirmation: pre-existing `trusted`, `untrusted`, or unset trust states are preserved untouched by default (allowing Codex itself to prompt for trust on first open).
  - Added explicit opt-in switch `-TrustRepoPath` (Windows) / `--trust-repo-path` (Unix), default OFF, for users who deliberately want setup to record `-RepoPath` as `trust_level = "trusted"`.

### Added
- **Regression Tests (Windows Stage 12d / 13d2 & Unix CI Section 9f / 10d):**
  - Verified remote plain-HTTP probe refusal (`REFUSED (https_required...)`) and two-endpoint loopback `302`/`307` redirect leak tests confirming the redirect target receives `0` requests and `0` `Authorization` headers on both Windows and Unix.
  - Verified pre-existing `untrusted` `-RepoPath` stays `untrusted`, absent `-RepoPath` is not auto-trusted, and explicit `-TrustRepoPath` / `--trust-repo-path` is required to record `trust_level = "trusted"`.

---

## [1.4.0] — 2026-11-23 (Interactive Sandbox 2 Control Center, API/Account Checkers & History-Preserving CLI Uninstall)

### Added
- **Interactive & Scriptable Sandbox 2 Control Center (`scripts/codex-manager.ps1`, `scripts/codex-manager.sh`, and `codex-manage` launcher in `~/.local/bin/`):**
  - Integrated `codex-manage` quick launcher (`codex-manage.cmd` + extensionless POSIX shim `codex-manage` on Windows; `codex-manage` on macOS/Linux/WSL) into `scripts/setup-dual-lane.*` and `scripts/restore-original.*` with full incremental rollback manifest tracking.
  - Supports both an interactive Vietnamese/English menu (`-Action Menu` / `--action menu`, default) and direct scriptable flags (`ApiGpt`/`api-gpt`, `ApiOther`/`api-other`, `Login`/`login`, `CheckApiKey`/`check-api-key`, `CheckAccounts`/`check-accounts`, `SyncHistory`/`sync-history`, `RemoveSandbox2`/`remove-sandbox2`) without ever accepting plaintext API keys on CLI argv:
    * **API Key — OpenAI / GPT (`ApiGpt` / `api-gpt`):** Prompts for a single masked API key (`Read-Host -AsSecureString` / `read -rs`, or `-ApiKeySecure` / `-ApiKeyFromStdin` / `--api-key-from-stdin`), backs up `~/.codex-official/config.toml`, cleanly strips conflicting third-party `model_provider` overrides while preserving `[projects.*]` trust levels and user sections, pipes the key over stdin to `codex login --with-api-key`, locks NTFS DACL (`/inheritance:d` + `/remove:g "CodexSandboxUsers"`) / `chmod 600`, and automatically triggers bidirectional chat history sync with GPT 1.
    * **API Key — Other Provider / Custom Gateway (`ApiOther` / `api-other`):** Creates a timestamped backup and opens `~/.codex-official/config.toml` directly for editing (`-Editor` / `$env:EDITOR` / `notepad.exe` on Windows; `--editor` / `${VISUAL:-${EDITOR:-vi}}` on Unix) with a safe `env_key` template, validates TOML syntax (`tomllib`), warns prominently if plaintext `api_key` or `experimental_bearer_token` is present, re-locks NTFS DACL / `chmod 600`, and runs bidirectional chat history sync with GPT 1.
    * **Official Login (`Login` / `login`):** Offers to clear conflicting third-party `model_provider` overrides (with backup), launches official `codex login` (with `-DeviceAuth` / `--device-auth` option) directly against Sandbox 2 (`CODEX_HOME=~/.codex-official`), locks NTFS DACL / `chmod 600` on `auth.json`, and runs bidirectional chat history sync with GPT 1.
    * **Check API Key (`CheckApiKey` / `check-api-key`):** Performs masked local inspection across `env_key` + environment variables, `OPENAI_API_KEY`, and `auth.json` (`sk-...xxxx (len=N)` — zero plaintext leakage), checks plaintext warnings and NTFS DACL / `0600` permissions, and supports an optional live `/models` endpoint probe (`-OnlineCheck` / `--online-check`) reporting `VALID (HTTP 200, N models)`, `INVALID/EXPIRED (HTTP 401/403)`, `QUOTA/RATE_LIMITED (HTTP 429)`, or `NETWORK_ERROR` without ever exposing the key in CLI argv, process lists, stdout, stderr, or exception messages.
    * **Check Existing Accounts (`CheckAccounts` / `check-accounts`):** Strictly read-only health and account inspection for BOTH GPT 1 (`~/.codex`, Codex Desktop) and Sandbox 2 (`~/.codex-official`, Codex CLI) — runs `codex login status`, inspects safe metadata (`auth_mode`, `model_provider`, `env_key`, `sandbox_mode`), 6 shared Junctions/symlinks, session counts, and NTFS DACL / `0600` permissions with zero token/key leakage and zero mutations to GPT 1.
    * **Bidirectional Chat History Sync (`SyncHistory` / `sync-history` & `scripts/sync-sessions.py --bidirectional --backup-target --rescue-shared-files`):** Automatically synchronizes `session_index.jsonl`, `state_*.sqlite` (threads & Pinned), and `goals_*.sqlite` (`thread_goals`) cleanly in both directions between GPT 1 (`~/.codex`) and Sandbox 2 (`~/.codex-official`) across operations while protecting newer GPT 1 `updated_at` metadata, preserving `is_pinned = 1` from either lane, creating pre-write SQLite backups (`--backup-target`), and offering non-destructive symlink-safe local rollout/memory file rescue (`--rescue-shared-files`).
    * **Safe Sandbox 2 Uninstall — History-Preserving (`RemoveSandbox2` / `remove-sandbox2`):** Fail-closed rescues and syncs 100% of Sandbox 2 chat history (`session_index.jsonl`, `state_*.sqlite` threads/Pinned, `goals_*.sqlite`) and any non-symlink local rollout/memory files back into GPT 1 (`~/.codex`) via `sync-sessions.py --source <Lane2> --target <Lane1> --rescue-shared-files --backup-target` **BEFORE** invoking `restore-original.ps1 -RemoveLane2Home` / `restore-original.sh --remove-lane2-home` to unlink all Junctions/symlinks and remove `~/.codex-official`, then verifies GPT 1 chat history remains intact.
- **Expanded Regression & CI Coverage (Windows 13 Stages, Python Unit Suite & Unix CI Section 10):**
  - Expanded `tests/test_sync_sessions.py` to test `--bidirectional` union convergence, `updated_at` / `is_pinned` conflict protection, `--backup-target` online SQLite backups (with 0 mutations under `--dry-run`), and `--rescue-shared-files` non-destructive copy + fail-closed symlink rejection.
  - Expanded `tests/test-kit.ps1` to **13 stages** (adding Stage 13 covering all `codex-manager.ps1` workflows, loopback HTTP `200`/`401` probe mocks, zero secret leakage, and history-preserving `RemoveSandbox2`) and added `codex-manager.ps1` to Stage 1 AST/CRLF/BOM verification.
  - Updated `.github/workflows/ci.yml` to cover `scripts/codex-manager.sh` (`bash -n`, LF/BOM) and `scripts/codex-manager.ps1` (CRLF/BOM), plus Unix CI **Section 10** validating all 6 actions of `scripts/codex-manager.sh`.

### Changed
- Updated `README.md`, `SECURITY.md`, `docs/GUIDE_AND_MANIFEST.md`, `docs/SECURITY_MODEL.md`, and `docs/TROUBLESHOOTING.md` to document `scripts/codex-manager.ps1`, `scripts/codex-manager.sh`, `codex-manage`, bidirectional chat sync, history-preserving Sandbox 2 removal, and the 13-stage Windows test suite.

---

## [1.3.3] — 2026-11-23 (Strict Project Trust-Level Preservation & Auth-Share Guardrails)

### Fixed
- **Fixed (Security — Trust Boundary):** Fixed `Get-ExistingTrustedProjects` and Lane 2 config generation in `scripts/setup-dual-lane.ps1` (and hardened parity in `scripts/setup-dual-lane.sh`) so harvesting/preserving `[projects.*]` entries inspects actual `trust_level` values — only projects genuinely marked `trust_level = "trusted"` are written as `"trusted"`, while `trust_level = "untrusted"` entries (in either Lane 1 or Lane 2) are preserved faithfully as `"untrusted"` and entries without an explicit `trust_level` are never promoted to `"trusted"`.

### Added
- **Added (Guardrails & Regression Tests):** Added explicit opt-in `[WARN]` security warnings when `-ShareAuthToLane2` / `--share-auth-to-lane2` duplicates `auth.json` into Lane 2 (with an elevated warning when combined with third-party API gateways via `-ConfigureGateway` / `-ConfigureCliGateway` / `--configure-gateway` / `--configure-cli-gateway`), and added Windows (`tests/test-kit.ps1` Stage 12) + Unix CI (`.github/workflows/ci.yml` Section 9e) regression tests covering `trusted`, `untrusted`, and missing-`trust_level` project tables alongside auth-share warnings.

### Changed
- Strengthened security transparency documentation across `README.md`, `SECURITY.md`, `docs/GUIDE_AND_MANIFEST.md`, `docs/SECURITY_MODEL.md`, and `docs/REAL_CODEX_CHECKLIST.md`:
  - Explicitly documented that `-ShareAuthToLane2` / `--share-auth-to-lane2` is strictly opt-in (off by default), creates a second copy of `auth.json` in Lane 2, and should be avoided or used with caution when Lane 2 is configured with a third-party API gateway.
  - Reiterated clearly that 4/4 green GitHub Actions CI validates kit scripts and invariants using mock `codex` binaries across OSes and does not replace running `doctor.ps1` / `doctor.sh` or verifying behavior directly against the specific real Codex Desktop/CLI release installed on the user's machine.

---

## [1.3.2] — 2026-11-23 (Zero-Intrusion Desktop Harvesting & Cross-Shell Compatibility)

### Added
- **Zero-Intrusion Codex Desktop (`~/.codex`) Read-Only Harvesting**:
  - By default, `~/.codex` (`config.toml` and `auth.json` of Codex Desktop / Primary Account `acc chính`) remains 100% untouched while `scripts/setup-dual-lane.ps1` and `scripts/setup-dual-lane.sh` **read-only harvest** already-trusted `[projects."..."]` entries from `~/.codex/config.toml` into `~/.codex-official/config.toml`. Every repository trusted in Codex Desktop is automatically trusted across its directory tree in Codex CLI (`~/.codex-official`) with zero modifications to `~/.codex/config.toml`.
  - Shares `memories`, `memories_v2`, `sessions`, `archived_sessions`, `skills`, and `plugins` read/write context via NTFS Directory Junctions (Windows) and symlinks (Unix), and supports `-ShareAuthToLane2` (alias `-ShareOfficialAuth`) on Windows and `--share-auth-to-lane2` (alias `--share-official-auth`) on Unix to atomically copy `~/.codex/auth.json` into `~/.codex-official/auth.json` with strict ACL / `chmod 600` protection and deterministic rollback tracking — leaving `~/.codex/auth.json` 100% untouched.
- **One-Flag CLI API Key + Login Configuration (`-ConfigureCliGateway` / `--configure-cli-gateway`)**:
  - Added `-ConfigureCliGateway` and `-CliApiKeyEnv` (alias for `-GatewayApiKeyEnv`) to `scripts/setup-dual-lane.ps1`, and `--configure-cli-gateway` and `--cli-api-key-env <VAR>` to `scripts/setup-dual-lane.sh`.
  - Automatically targets Lane 2 (`~/.codex-official`, Codex CLI) for `env_key` API key / custom provider routing (unless `Both` / `both` is explicitly selected), allowing Codex CLI to use **both OAuth Login and API Key** while guaranteeing Lane 1 (`~/.codex`, Codex Desktop) stays 100% untouched.
- **Cross-Shell Windows Launchers (`.cmd` + Extensionless POSIX Shims) & Relative `--repo-path` Support**:
  - On Windows, `scripts/setup-dual-lane.ps1` now generates both `.cmd` launchers (`codex.cmd`, `codex-official.cmd`, `codex-t3.cmd`) and extensionless LF POSIX shell shims (`codex`, `codex-official`, `codex-t3`) in `~/.local/bin`, enabling seamless invocation from **PowerShell, CMD, Git Bash, and MSYS2** (with full rollback tracking and pre-existing shim backup/restore in `restore-original.ps1` and health checks in `doctor.ps1`).
  - Added relative repository path normalization (`-RepoPath .` / `--repo-path .` / `./sub`) across `setup-dual-lane.ps1`, `doctor.ps1`, `setup-dual-lane.sh`, and `doctor.sh`.
  - Expanded Windows regression suite (`tests/test-kit.ps1` Stage 12) and Unix CI smoke suite (`.github/workflows/ci.yml` Section 9e) to verify read-only `[projects."..."]` harvesting (with bit-identical Lane 1 `config.toml` SHA-256), `-ConfigureCliGateway` / `--configure-cli-gateway`, `--share-auth-to-lane2`, relative `--repo-path .`, and extensionless Git Bash shims.

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
