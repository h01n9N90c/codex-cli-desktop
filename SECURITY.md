# Security Policy

## Security Posture of This Repository

**Codex Dual-Lane & Security Kit** (`codex-cli-desktop`) is a local configuration and guardrail toolkit licensed under **Apache License 2.0** (`Copyright 2026 Lê Hoàng Ngọc Tươi`).

* **Zero telemetry / zero remote code execution:** All scripts run 100% locally and never download binaries or send data to external servers.
* **Zero secrets committed:** No API keys, OAuth tokens, or personal host configurations are stored in this repository.
* **4-Layer Defense-in-Depth for Codex Agents:**
  1. Workspace-scoped OS sandbox (`sandbox_mode = "workspace-write"`, `[windows] sandbox = "elevated"`) with outbound shell network disabled by default (`[sandbox_workspace_write] network_access = false`).
  2. Sensitive environment-variable filtering (`exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]`).
  3. Starlark execpolicy command firewall (`templates/default.rules`) hard-blocking destructive/persistence commands and Windows LOLBins/interpreters (`php`, `ruby`, `perl`, `cscript`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `Start-Process`, `Invoke-Expression`, `iex`).
  4. Global `AGENTS.md` anti-prompt-injection and **Static-Analysis-Only Isolation** rules.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for full details and honest technical boundaries.

## Reporting a Vulnerability

If you discover a security bug or bypass in any script or template in this repository:

1. **Do not** disclose exploit details or secrets in public issues.
2. Report privately via GitHub **Security Advisories** (Report a vulnerability) on `https://github.com/h01n9N90c/codex-cli-desktop`.
3. Include affected file(s), OS/shell version, reproduction steps, and suggested remediation.
