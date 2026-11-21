# Security Policy

## Security Posture of This Repository

**Codex Dual-Lane & Security Kit** (`codex-cli-desktop`) is a local configuration and guardrail toolkit licensed under **Apache License 2.0** (`Copyright 2026 Lê Hoàng Ngọc Tươi`).

* **Zero telemetry / zero remote code execution:** All scripts run 100% locally and never download binaries or transmit data to external servers.
* **Zero secrets committed:** No API keys, OAuth tokens, or personal host configurations are stored in this repository.
* **4-Layer Defense-in-Depth for Codex Agents:**
  1. **Layer 1 — Workspace-Scoped OS Sandbox & Network Isolation:** `sandbox_mode = "workspace-write"`, `[windows] sandbox = "elevated"`, outbound shell network disabled by default (`[sandbox_workspace_write] network_access = false`), safe default `approval_policy = "on-request"`, and optional `-UseGitWorktree` / `--use-git-worktree` for OS-enforced write separation between Lane 1 and Lane 2.
  2. **Layer 2 — Secret Hygiene, Environment Filtering & File Permissions:**
     * Uses `env_key` (never plaintext API keys or `experimental_bearer_token`) in `config.toml` and timestamped backups.
     * Filters sensitive environment variables from sandboxed child shells (`[shell_environment_policy] exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]`).
     * Applies POSIX `chmod 600` (with restrictive `umask 077` / `chmod 700` on sensitive directories) on macOS/Linux/WSL, and a **two-step Windows `icacls.exe` sequence** (`/inheritance:d` followed by `/remove:g "CodexSandboxUsers"`) on `auth.json`, `config.toml`, backups, and rollback manifests.
     * **Strongest Secret Hygiene Recommendation:** Where supported by your installed Codex version, configure `cli_auth_credentials_store = "keyring"` so OAuth/login tokens are stored in the OS credential store rather than plaintext `auth.json`, and always supply third-party gateway credentials via `env_key`.
  3. **Layer 3 — Starlark Execpolicy Command Firewall (`templates/default.rules`):** Hard-blocks (`decision="forbidden"`) ransomware/system tampering (`vssadmin`, `bcdedit`, `wbadmin`, `diskpart`, `format`), persistence (`schtasks`, `sc`, `reg add/delete/import`), Windows NTFS ACL/ownership/network tampering (`icacls`, `takeown`, `net`, `net1`, `netsh`), remote history force-push (`git push --force`, `git push -f`), and static-analysis-only corpus interpreters & Windows LOLBins (`php`, `ruby`, `perl`, `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`/`saps`, `Invoke-Expression`/`iex`), including explicit `.exe`/`.com` and case variants. Prompts (`decision="prompt"`) before `git push`, `git reset --hard`, and `git clean`.
  4. **Layer 4 — Global `AGENTS.md` Guardrails:** Anti-prompt-injection, **Static-Analysis-Only Isolation**, secret/config isolation, and dual-lane zero-collision discipline.

## Honest Security Boundaries (Kit Guarantees vs. OS & Codex Runtime Limits)

This toolkit hardens local Codex deployments but cannot override OS kernel or Codex runtime behavior outside its control:

* **Windows `CodexSandboxUsers:(OI)(CI)(RX)` directory inheritance:** Codex's Windows elevated sandbox may grant `CodexSandboxUsers:(OI)(CI)(RX)` (inherited read/execute) on `~/.codex*` directories. Newly created files inside those directories automatically inherit that ACE. The kit's two-step `icacls.exe` strip (`/inheritance:d` then `/remove:g "CodexSandboxUsers"`) removes the inherited read ACE from targeted files while degrading gracefully on fresh machines where the `CodexSandboxUsers` group does not yet exist.
* **Atomic file replacement resets NTFS file DACLs (Cannot be blocked externally):** When Codex CLI or Codex Desktop updates `config.toml` (for example after `codex features` commands or UI settings edits) or recreates/refreshes `auth.json` via atomic temp-file replacement, the newly replaced file inherits the parent directory's DACL again. External scripts **cannot intercept or prevent** future DACL resets performed by Codex itself without upstream fixes in Codex; therefore `Protect-SensitiveFileAcl` is **point-in-time defense-in-depth**. Keep secrets out of files altogether via `env_key` + `cli_auth_credentials_store = "keyring"`, audit with `scripts/doctor.ps1`, and re-lock quickly with `scripts/setup-dual-lane.ps1 -ReapplyAclOnly` whenever Codex rewrites configuration or auth files.
* **Worktree wrapper routing vs. Codex Desktop / custom flags:** When `-UseGitWorktree` / `--use-git-worktree` is enabled, the generated CLI wrappers (`codex` / `codex-official`) switch `cwd` from the primary repo root **and any nested subdirectory** into the matching worktree subdirectory (or worktree root) and block explicit `-C`/`--cd`/`--add-dir` CLI flags targeting the primary repo. However, Codex Desktop UI workspace attachments, complex custom `--config` overrides, or non-CLI launch paths still require direct testing against your live Codex Desktop build.
* **`execpolicy` prefix-matching scope:** Starlark `prefix_rule` evaluates exact, case-sensitive direct command tokens (`argv[0]`, ...). It does not deeply inspect arbitrary code strings nested inside `powershell -Command "..."`, `cmd /c "..."`, or `bash -c "..."`. Containment always depends on keeping all 4 layers active together.
* **Unix rollback permission metadata scope:** On macOS/Linux/WSL, `setup-dual-lane.sh` records standard POSIX permission bits (`000`–`777` in column 5 of `.rollback/latest.tsv`) and `restore-original.sh` restores and verifies both SHA-256 and exact mode (e.g., `0755` vs `0700`, `0644` vs `0600`) while rejecting special SUID/SGID bits (`1xxx`/`2xxx`/`4xxx`) from tampered manifests. Non-mode attributes such as extended attributes (`xattr`), file ownership across users, or timestamps are not restored.
* **CI test scope boundary:** Cross-platform CI (`ci.yml`) validates script syntax, fail-closed guards, deterministic SHA-256/POSIX-mode rollback, and portability using mock `codex` binaries; passing CI does **not** by itself prove compatibility across every live Codex Desktop/CLI release configuration (verify live behavior per `docs/REAL_CODEX_CHECKLIST.md`).
* **Shared brain trade-off:** Linking `sessions/`, `memories/`, `skills/`, and `plugins/` across both lanes means conversation logs are shared between Lane 1 and Lane 2. Never put real secrets into prompts or repositories, and keep confidential codebases on your official OpenAI lane rather than third-party API relays.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full technical model, rollback procedures, and verification guidance.

## Reporting a Vulnerability

If you discover a security bug, path-traversal flaw, ACL bypass, or secret-leakage issue in any script or template in this repository:

1. **Do not** disclose exploit details or secrets in public issues.
2. Report privately via GitHub **Security Advisories** (Report a vulnerability) on `https://github.com/h01n9N90c/codex-cli-desktop`.
3. Include affected file(s), OS/shell version, reproduction steps, and suggested remediation.
