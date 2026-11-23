<#
.SYNOPSIS
    Universal, hardware-adaptive, security-hardened installer for Codex Dual-Lane & Security Kit on Windows.

.DESCRIPTION
    Configures two isolated OpenAI Codex lanes on ANY Windows 10/11 machine (single-drive C:\ or
    multi-drive, spaces/Unicode/'&' in paths, WindowsApps MSIX Desktop OR standalone/npm Codex CLI):

      - Lane 1 (default: %USERPROFILE%\.codex)          : Codex Desktop App (Primary Account / acc chính, or optional gateway via `codex-t3`)
      - Lane 2 (default: %USERPROFILE%\.codex-official) : Codex CLI via `codex` / `codex-official` (supports BOTH OAuth/ChatGPT Login AND API Key / `env_key` gateway)

    Security & Safety Guarantees:
      1. Zero hardcoded mock data, zero hardcoded model tiers, and zero plaintext secrets:
         - Auto-detects the real installed Codex executable and probes live supported feature flags
           via `codex features list` inside a disposable temporary CODEX_HOME.
         - Third-party gateway mode (-ConfigureGateway) writes ONLY `env_key = "<VAR>"` into config.toml
           and enforces a fail-closed pre-write assertion that blocks `experimental_bearer_token` or
           plaintext API keys from ever reaching config.toml or backup files.
      2. Non-destructive TOML merge, canonical long-path normalization & crash-safe rollback:
         - Normalizes all Windows paths via Win32 GetLongPathNameW (expanding 8.3 short names such
           as RUNNER~1 / PROGRA~1 without dereferencing NTFS Junctions or symlinks) so containment,
           trusted projects, and generated wrappers remain consistent on every Windows host.
         - Preserves custom top-level keys (including multi-line values), custom sections
           ([mcp_servers.*], [tui], [plugins.*], [[array_of_tables]]), and existing [projects.*]
           trust boundaries (`trusted` stays `trusted`, `untrusted` stays `untrusted`, and entries
           missing/unrecognized `trust_level` are never promoted to `trusted`).
         - Writes UTF-8 without BOM atomically via a same-directory temp file + File.Replace/Move so
           interrupted writes cannot corrupt config.toml.
         - Persists SHA-256 hashes, Junctions, and launchers incrementally into an ACL-locked
           rollback journal (<Lane2Home>\.rollback\latest.json) after every tracked mutation so even
           an interrupted mid-install run recovers byte-for-byte via restore-original.ps1.
         - When -UseGitWorktree is enabled, generated Lane 2 wrappers enforce a hard fail-closed
           worktree boundary (refusing to run if the worktree is missing or cd fails, rather than
           silently falling back to the primary repository) and always block -C/--cd/--add-dir
           targeting the primary repo across both long and 8.3 short path forms.
      3. Two-step NTFS Kernel ACL hardening (Protect-SensitiveFileAcl):
         - Step 1 (`icacls /inheritance:d`): converts inherited ACEs to explicit ACEs so future
           parent-folder grants cannot leak into sensitive files.
         - Step 2 (`icacls /remove:g "CodexSandboxUsers"`): strips Grant ACEs for the Codex Windows
           sandbox group whenever that principal exists (gracefully skipping on fresh machines where
           CodexSandboxUsers has not been created yet).
      4. Strict input validation & injection defense:
         - Validates all paths, Git branch names, URLs, and TOML/batch values against control-character,
           TOML-newline, Git-option, and CMD batch-metacharacter injection.
      5. Preview-safe execution:
         - Both `-DryRun` and PowerShell `-WhatIf` preview every step without modifying disk or PATH.

.PARAMETER RepoPath
    Target project directory (alias: -ProjectRoot) to mark as trusted in both lanes and optionally
    equip with DUAL_LANE_BRIDGE.md / isolated Git worktree / pinned session sync. Defaults to CWD.

.PARAMETER CodexPath
    Optional explicit path to codex.exe or codex.cmd. When omitted, auto-discovers WindowsApps MSIX,
    PATH (excluding LocalBin to prevent recursion), and common npm/Programs locations.

.PARAMETER Lane1Home
    CODEX_HOME directory for Lane 1 (Desktop / gateway). Default: %USERPROFILE%\.codex.

.PARAMETER Lane2Home
    CODEX_HOME directory for Lane 2 (Official CLI). Must reside on a local NTFS volume for
    Directory Junctions and must not equal or overlap Lane1Home. Default: %USERPROFILE%\.codex-official.

.PARAMETER LocalBin
    Directory where self-healing CLI wrappers (codex.cmd, codex-official.cmd, codex-t3.cmd,
    codex-manage.cmd and extensionless Git Bash / MSYS2 POSIX shims codex, codex-official,
    codex-t3, codex-manage) are installed. Default: %USERPROFILE%\.local\bin.

.PARAMETER CargoTargetDir
    Dedicated CARGO_TARGET_DIR exported for Lane 2 so parallel `cargo test`/`cargo build` runs in
    Lane 1 and Lane 2 never contend on `target/.cargo-lock`. Default: %TEMP%\codex-lane2-target.

.PARAMETER OfficialModel
    Optional explicit default model slug for Lane 2 config.toml. Leave empty to use your account's
    real server-side default.

.PARAMETER OfficialReasoning
    Optional explicit `model_reasoning_effort` value for Lane 2 (e.g. low, medium, high).

.PARAMETER OfficialServiceTier
    Optional explicit `service_tier` value for Lane 2 (e.g. priority) if your account supports it.

.PARAMETER ApprovalPolicy
    Codex approval policy written to managed configs in Ask mode (or fresh Config mode):
    'on-request' (secure default) or 'never' (unattended isolated runs only).

.PARAMETER CliMode
    Selects the Sandbox 2 (Lane 2 Codex CLI) permission mode in ~/.codex-official/config.toml
    (never restricts Lane 1 Desktop):
      - 'Ask' (default, Xin yêu cầu): writes approval_policy = "on-request" (or explicit
        -ApprovalPolicy) and sandbox_mode = "workspace-write" (neatly contained inside the
        project directory; external algorithms/docs may be referenced strictly read-only).
      - 'Config' (Thuộc cấu hình config.toml): respects existing approval_policy, sandbox_mode,
        and [sandbox_workspace_write] from Lane2\config.toml untouched (defaulting to
        on-request + workspace-write only when missing on a brand-new config).
      - 'FullAccess' (Toàn quyền — DANGER): writes approval_policy = "never" and
        sandbox_mode = "danger-full-access". Always displays a high-visibility RED/YELLOW danger
        warning and refuses fail-closed (exit 1, zero mutations) unless -ConfirmFullAccess is
        explicitly passed (or the user types exact confirmation phrase 'TOAN QUYEN' /
        'I UNDERSTAND' interactively).

.PARAMETER ConfirmFullAccess
    Explicit acknowledgement switch required for non-interactive/scripted -CliMode FullAccess
    runs after reviewing host-wide risks (bypasses workspace-write sandbox and approval prompts).

.PARAMETER AllowSandboxNetwork
    When specified, sets `[sandbox_workspace_write] network_access = true`. Default is `false`
    (offline shell sandbox for static-analysis-only isolation).

.PARAMETER UseGitWorktree
    Creates or attaches an isolated Git worktree for Lane 2 so OS-level `workspace-write` sandboxing
    physically separates Lane 1 and Lane 2 filesystem writes.

.PARAMETER Lane2WorktreePath
    Custom filesystem path for Lane 2's Git worktree when -UseGitWorktree is set. Must not overlap
    or nest inside RepoPath. Default: <RepoPath>-lane2.

.PARAMETER Lane2Branch
    Git branch name used for Lane 2's worktree when -UseGitWorktree is set. Strictly validated
    against Git ref rules and option injection. Default: dual-lane-2.

.PARAMETER ConfigureGateway
    Configures an OpenAI-compatible API key / gateway provider in config.toml using `env_key` ONLY
    (never writing plaintext API keys to disk). Use -GatewayTargetLane to target Lane 1, Lane 2 (CLI),
    or Both, or pass -ConfigureCliGateway to target Lane 2 CLI directly while leaving Lane 1 Desktop untouched.

.PARAMETER ConfigureCliGateway
    Convenience switch for Codex CLI API key / gateway configuration: automatically enables
    -ConfigureGateway and sets -GatewayTargetLane to 'Lane2' (unless -GatewayTargetLane 'Both' was
    explicitly specified), leaving Lane 1 (`~/.codex/config.toml`, Codex Desktop Primary Account)
    100% untouched.

.PARAMETER GatewayTargetLane
    Selects which lane(s) receive the `[model_providers."<Name>"]` (`env_key`) gateway configuration
    when -ConfigureGateway (or -ConfigureCliGateway) is enabled:
      - 'Lane1' (default for -ConfigureGateway): Lane 1 (`~/.codex`)
      - 'Lane2' (default for -ConfigureCliGateway): Lane 2 CLI (`~/.codex-official`), leaving Lane 1 Desktop
        on your Primary Account (`acc chính`) while Lane 2 CLI supports both OAuth Login (`auth.json`)
        and API Key (`env_key`)
      - 'Both' : Configures both Lane 1 and Lane 2 with `env_key`

.PARAMETER GatewayProviderName
    TOML provider identifier for [model_providers."<Name>"] when -ConfigureGateway is set. Default: OpenAI.

.PARAMETER GatewayBaseUrl
    Absolute http(s) base URL for the gateway (required with -ConfigureGateway / -ConfigureCliGateway).

.PARAMETER GatewayModel
    Optional default model and review_model slug for the target gateway lane(s) when -ConfigureGateway is set.

.PARAMETER GatewayApiKeyEnv
    Environment variable name (alias: -CliApiKeyEnv) referenced by `env_key` in the target lane's
    config.toml. Default: CODEX_GATEWAY_API_KEY.

.PARAMETER GatewayApiKey
    (Legacy compatibility) Stores the provided API key in the User environment variable named by
    -GatewayApiKeyEnv (never written to config.toml). Prefer -PromptGatewayApiKey to avoid shell history.

.PARAMETER PromptGatewayApiKey
    Prompts securely via Read-Host -AsSecureString and stores the key only in User environment
    variable -GatewayApiKeyEnv (never echoed, never written to config.toml).

.PARAMETER TrustRepoPath
    Explicit opt-in (default OFF): record `-RepoPath` (and the Lane 2 worktree, if any) as
    `trust_level = "trusted"` in the generated Codex config.toml. Without this switch setup NEVER
    raises trust: existing `trusted`/`untrusted`/unset entries are preserved exactly, and Codex asks
    for trust itself the first time it opens an unknown project.

.PARAMETER ShareAuthToLane2
    Opt-in (off by default): copies Lane 1's authenticated `auth.json` (if present) into Lane 2
    (`~/.codex-official\auth.json`), tracks it in the rollback journal, and locks its NTFS DACL via
    `Protect-SensitiveFileAcl`. SECURITY NOTE: Creates a second copy of your OAuth credentials on
    disk; avoid combining with a third-party API gateway (`-ConfigureCliGateway` / `-ConfigureGateway`
    targeting Lane 2 or Both) unless you intentionally want official OAuth tokens alongside gateway routing.

.PARAMETER SyncSessions
    Invokes scripts\sync-sessions.py (if Python 3 is installed) to UPSERT session index, pinned
    threads, and goals from Lane 1 (read-only) to Lane 2.

.PARAMETER PinnedOnlySync
    Passes --pinned-only to sync-sessions.py when -SyncSessions is enabled.

.PARAMETER InstallBridgeTemplate
    Copies templates\DUAL_LANE_BRIDGE.md into <RepoPath>\artifacts\dual-lane\DUAL_LANE_BRIDGE.md
    if not already present (never overwrites an existing bridge file).

.PARAMETER ReapplyAclOnly
    Fast maintenance mode: skips installing templates/configs/Junctions/wrappers and only
    re-applies fail-closed two-step NTFS ACL locking (`icacls /inheritance:d` then
    `/remove:g "CodexSandboxUsers"`) across existing sensitive files in Lane 1 & Lane 2.
    Useful immediately after `codex features`, `codex login`, or Codex Desktop settings edits
    whose atomic file replacement resets NTFS inheritance.

.PARAMETER SkipPathUpdate
    Skips modifying the Windows User PATH environment variable (ideal for CI/sandbox tests).

.PARAMETER DryRun
    Previews every validation, merge, junction, and file action without modifying disk or PATH.
    Equivalent to PowerShell's standard -WhatIf switch.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app" -DryRun

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app" -InstallBridgeTemplate

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -ProjectRoot "C:\Projects\my-app" -UseGitWorktree -SyncSessions

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -ReapplyAclOnly

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app" -ConfigureGateway -GatewayBaseUrl "https://gateway.example.invalid/v1" -PromptGatewayApiKey

.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
    License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
    Project   : Codex Dual-Lane & Security Kit
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
param(
    [Alias('ProjectRoot')]
    [string]$RepoPath = (Get-Location).Path,
    [string]$CodexPath = '',
    [string]$Lane1Home = (Join-Path $env:USERPROFILE '.codex'),
    [string]$Lane2Home = (Join-Path $env:USERPROFILE '.codex-official'),
    [string]$LocalBin  = (Join-Path $env:USERPROFILE '.local\bin'),
    [string]$CargoTargetDir = (Join-Path $env:TEMP 'codex-lane2-target'),
    [string]$OfficialModel = '',
    [string]$OfficialReasoning = '',
    [string]$OfficialServiceTier = '',
    [ValidateSet('on-request', 'never')]
    [string]$ApprovalPolicy = 'on-request',
    [ValidateSet('Ask', 'Config', 'FullAccess')]
    [string]$CliMode = 'Ask',
    [switch]$ConfirmFullAccess,
    [switch]$AllowSandboxNetwork,
    [switch]$UseGitWorktree,
    [string]$Lane2WorktreePath = '',
    [string]$Lane2Branch = 'dual-lane-2',
    [switch]$ConfigureGateway,
    [switch]$ConfigureCliGateway,
    [ValidateSet('Lane1', 'Lane2', 'Both')]
    [string]$GatewayTargetLane = 'Lane1',
    [string]$GatewayProviderName = 'OpenAI',
    [string]$GatewayBaseUrl = '',
    [string]$GatewayModel = '',
    [Alias('CliApiKeyEnv')]
    [string]$GatewayApiKeyEnv = 'CODEX_GATEWAY_API_KEY',
    [string]$GatewayApiKey = '',
    [switch]$PromptGatewayApiKey,
    [Alias('ShareOfficialAuth')]
    [switch]$ShareAuthToLane2,
    [switch]$TrustRepoPath,
    [switch]$SyncSessions,
    [switch]$PinnedOnlySync,
    [switch]$InstallBridgeTemplate,
    [switch]$ReapplyAclOnly,
    [switch]$SkipPathUpdate,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Unify -DryRun and standard PowerShell -WhatIf so neither .NET File calls nor native tools
# (icacls, git, SetEnvironmentVariable) can mutate state during a preview run.
# WHY reset $WhatIfPreference = $false right after capturing $script:IsDryRun:
# Every disk/env mutation in this script is explicitly gated by `if (-not $script:IsDryRun)`.
# Leaving $WhatIfPreference=$true active in PowerShell 5.1 breaks read-only helpers (Get-FileHash
# returns $null), prints noisy `What if: New Alias` during Get-Volume module auto-loading, and
# prevents `finally` cleanup of our disposable feature-probe temp folder.
$script:IsDryRun = $DryRun.IsPresent -or [bool]$WhatIfPreference
$WhatIfPreference = $false
$script:ExplicitApprovalPolicy      = $PSBoundParameters.ContainsKey('ApprovalPolicy')
$script:ExplicitAllowSandboxNetwork = $PSBoundParameters.ContainsKey('AllowSandboxNetwork')
$script:SnapshotEntries    = New-Object 'System.Collections.Generic.List[object]'
$script:TrackedJunctions   = New-Object 'System.Collections.Generic.List[string]'
$script:SharedLinkRecords  = New-Object 'System.Collections.Generic.List[object]'
$script:InstalledWrappers  = New-Object 'System.Collections.Generic.List[string]'
$script:InstallStamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:CreatedAtUtc       = (Get-Date).ToUniversalTime().ToString('o')
$script:RollbackDir        = ''
$script:RollbackSnapPath   = ''
$script:RollbackLatestPath = ''
$script:ManifestContext    = $null

# ============================================================================
# Helper Functions: Logging, Canonical Path Normalization & Injection Defense
# ============================================================================

function Write-Step([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Resolve-CanonicalLongPath {
    <#
    .SYNOPSIS
        Canonicalizes a Windows filesystem path to its full long-name form (expanding 8.3 short
        segments such as RUNNER~1 or PROGRA~1) without dereferencing NTFS Junctions or symlinks.
        WHY:
          On Windows CI runners and profiles with 8.3 short names, $env:TEMP / GetTempPath() can
          return short-name segments while git worktree or cmd.exe produces the long name. On
          PowerShell 7+ (.NET Core), [System.IO.Path]::GetFullPath() and Resolve-Path do NOT expand
          8.3 short names. Win32 GetLongPathNameW expands every existing 8.3 segment without
          following reparse points; walking upward to the deepest existing ancestor guarantees
          consistent canonical paths even when leaf segments do not exist yet.
    #>
    param(
        [AllowEmptyString()][string]$PathValue
    )
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return '' }

    # Respect PowerShell's current FileSystem location for relative paths (System.IO.Path.GetFullPath
    # uses process Environment.CurrentDirectory which does not track PowerShell Push-Location).
    $inputPath = $PathValue.Trim().Replace('/', '\')
    $psCwd = ''
    try {
        $psCwd = (Get-Location -PSProvider FileSystem).ProviderPath
    } catch {
        $psCwd = [System.Environment]::CurrentDirectory
    }
    if (-not [string]::IsNullOrEmpty($psCwd)) {
        if ($inputPath -match '^[A-Za-z]:([^\\].*)?$') {
            $drivePrefix = $inputPath.Substring(0, 2)
            $rest = $inputPath.Substring(2)
            if ($psCwd.StartsWith($drivePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $inputPath = [System.IO.Path]::Combine($psCwd, $rest)
            } else {
                $inputPath = $drivePrefix + '\' + $rest
            }
        } elseif ($inputPath.StartsWith('\') -and (-not $inputPath.StartsWith('\\'))) {
            $cwdRoot = [System.IO.Path]::GetPathRoot($psCwd)
            if (-not [string]::IsNullOrEmpty($cwdRoot)) {
                $inputPath = [System.IO.Path]::Combine($cwdRoot, $inputPath.TrimStart('\'))
            }
        } elseif (-not [System.IO.Path]::IsPathRooted($inputPath)) {
            $inputPath = [System.IO.Path]::Combine($psCwd, $inputPath)
        }
    }

    $full = [System.IO.Path]::GetFullPath($inputPath)
    $root = [System.IO.Path]::GetPathRoot($full)
    $normalized = if ($full.Length -gt $root.Length) { $full.TrimEnd('\', '/') } else { $full }

    # Compile the Win32 GetLongPathNameW P/Invoke wrapper once per PowerShell session.
    $useWin32 = $false
    try {
        if (-not ('CodexDualLane.NativePathApi' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CodexDualLane {
    public static class NativePathApi {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetLongPathNameW(
            string lpszShortPath,
            StringBuilder lpszLongPath,
            uint cchBuffer
        );

        public static string TryGetLongPath(string path) {
            if (string.IsNullOrEmpty(path)) return null;
            StringBuilder sb = new StringBuilder(Math.Max(260, path.Length + 64));
            uint required = GetLongPathNameW(path, sb, (uint)sb.Capacity);
            if (required == 0) return null;
            if (required > sb.Capacity) {
                sb = new StringBuilder((int)required + 1);
                required = GetLongPathNameW(path, sb, (uint)sb.Capacity);
                if (required == 0 || required > sb.Capacity) return null;
            }
            return sb.ToString();
        }
    }
}
'@ -ErrorAction Stop
        }
        $useWin32 = $true
    } catch {
        # Safe fallback if Add-Type is blocked (e.g., Constrained Language Mode / WDAC).
        $useWin32 = $false
    }

    # Walk up to the deepest existing ancestor so non-existent leaf directories still get
    # canonical long-path ancestors when re-attached.
    $tailSegments = New-Object 'System.Collections.Generic.Stack[string]'
    $probe = $normalized
    $resolvedBase = $null

    while (-not [string]::IsNullOrEmpty($probe)) {
        if ($useWin32) {
            $candidate = [CodexDualLane.NativePathApi]::TryGetLongPath($probe)
            if (-not [string]::IsNullOrEmpty($candidate)) {
                $resolvedBase = $candidate
                break
            }
        } else {
            if ([System.IO.File]::Exists($probe) -or [System.IO.Directory]::Exists($probe)) {
                $resolvedBase = $probe
                break
            }
        }

        $parent = [System.IO.Path]::GetDirectoryName($probe)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $probe) {
            $resolvedBase = $probe
            break
        }
        $leaf = [System.IO.Path]::GetFileName($probe)
        $tailSegments.Push($leaf)
        $probe = $parent
    }

    if ([string]::IsNullOrEmpty($resolvedBase)) {
        $resolvedBase = $normalized
    }

    # Pure-.NET segment expansion fallback when Win32 P/Invoke is unavailable.
    if (-not $useWin32) {
        $baseRoot = [System.IO.Path]::GetPathRoot($resolvedBase)
        if (-not [string]::IsNullOrEmpty($baseRoot) -and $resolvedBase.Length -gt $baseRoot.Length) {
            $relParts = $resolvedBase.Substring($baseRoot.Length).Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)
            $acc = $baseRoot
            foreach ($part in $relParts) {
                $nextAcc = $null
                try {
                    $di = New-Object System.IO.DirectoryInfo($acc)
                    $entries = @($di.GetFileSystemInfos($part))
                    if ($entries.Count -eq 1) {
                        $nextAcc = $entries[0].FullName
                    }
                } catch {}
                $acc = if ($nextAcc) { $nextAcc } else { [System.IO.Path]::Combine($acc, $part) }
            }
            $resolvedBase = $acc
        }
    }

    $result = $resolvedBase
    while ($tailSegments.Count -gt 0) {
        $result = [System.IO.Path]::Combine($result, $tailSegments.Pop())
    }

    # Canonicalize drive letter to uppercase and trim trailing separator except for drive roots (C:\).
    if ($result.Length -ge 2 -and $result[1] -eq ':') {
        $result = [char]::ToUpperInvariant($result[0]) + $result.Substring(1)
    }
    $resRoot = [System.IO.Path]::GetPathRoot($result)
    if ($result.Length -gt $resRoot.Length) {
        $result = $result.TrimEnd('\', '/')
    }
    return $result
}

function Assert-NoControlChars {
    <#
    .SYNOPSIS
        Rejects ASCII control characters (including CR, LF, NUL) in user-supplied strings.
        WHY: Embedded newlines or control characters could inject arbitrary TOML keys/sections
        into config.toml or break out of single-line commands inside generated .cmd wrappers.
    #>
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$ParamName
    )
    if ($null -eq $Value) { return }
    if ($Value -match '[\x00-\x1F\x7F]') {
        throw "Invalid value for -${ParamName}: control characters (CR/LF/NUL/etc.) are not permitted."
    }
}

function Assert-SafeWindowsPath {
    <#
    .SYNOPSIS
        Validates and canonicalizes a Windows filesystem path parameter (including 8.3 long-path expansion).
        WHY: Blocks control characters, double-quote CMD breakout characters, NTFS Alternate
        Data Streams (path:stream), raw device prefixes (\\?\ / \\.\), and accidental targeting
        of OS/drive/profile roots for lane or build directories.
    #>
    param(
        [AllowEmptyString()][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$ParamName,
        [switch]$AllowEmpty,
        [switch]$DisallowRootOrProfile
    )
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        if ($AllowEmpty) { return '' }
        throw "Parameter -${ParamName} cannot be empty or whitespace."
    }
    Assert-NoControlChars -Value $PathValue -ParamName $ParamName

    # Double quotes are illegal in NTFS filenames and would break out of `set "VAR=..."` in .cmd wrappers.
    if ($PathValue.IndexOf('"') -ge 0) {
        throw "Invalid value for -${ParamName}: double quotes are not allowed in Windows paths."
    }
    # Reject Win32 device/NT namespace prefixes that bypass standard path normalization.
    if ($PathValue -match '^(\\\\\?\\|\\\\\.\\|\\\?\?\\)') {
        throw "Invalid value for -${ParamName}: raw Win32 device namespace prefixes are not allowed."
    }
    # Reject NTFS Alternate Data Streams (any colon beyond the drive letter prefix like C:\).
    $afterDrive = if ($PathValue.Length -ge 2 -and $PathValue[1] -eq ':') { $PathValue.Substring(2) } else { $PathValue }
    if ($afterDrive.IndexOf(':') -ge 0) {
        throw "Invalid value for -${ParamName}: NTFS alternate data stream syntax (':') is not allowed."
    }

    try {
        $normalized = Resolve-CanonicalLongPath -PathValue $PathValue
    } catch {
        throw "Invalid path for -${ParamName} ('$PathValue'): $($_.Exception.Message)"
    }

    $root = [System.IO.Path]::GetPathRoot($normalized)

    if ($DisallowRootOrProfile) {
        # Guard against catastrophic misconfiguration (e.g., pointing Lane2Home at C:\ or %USERPROFILE%).
        # Canonicalize each blocked OS/env directory to its long path so 8.3 aliases cannot bypass the check.
        $blockedDirs = New-Object 'System.Collections.Generic.List[string]'
        if ($root) { $blockedDirs.Add($root.TrimEnd('\')) }
        foreach ($envDir in @($env:USERPROFILE, $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:TEMP)) {
            if (-not [string]::IsNullOrWhiteSpace($envDir)) {
                try { $blockedDirs.Add((Resolve-CanonicalLongPath -PathValue $envDir).TrimEnd('\')) } catch {}
            }
        }
        $normNoTrail = $normalized.TrimEnd('\')
        foreach ($blocked in $blockedDirs) {
            if ($normNoTrail.Equals($blocked, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing unsafe -${ParamName} path '$normalized': cannot target a drive root, user profile root, TEMP root, or OS system directory directly."
            }
        }
    }

    return $normalized
}

function Test-PathsOverlap([string]$PathA, [string]$PathB) {
    <#
    .SYNOPSIS
        Returns $true if PathA and PathB are identical or one is nested inside the other.
        WHY: Overlapping Lane1Home/Lane2Home would create circular NTFS Directory Junctions, and
        nesting a Lane 2 Git worktree inside Lane 1's repo would break workspace-write isolation.
        Both sides are canonicalized via Resolve-CanonicalLongPath so 8.3 short aliases cannot
        evade overlap detection.
    #>
    $a = (Resolve-CanonicalLongPath -PathValue $PathA).TrimEnd('\').ToLowerInvariant()
    $b = (Resolve-CanonicalLongPath -PathValue $PathB).TrimEnd('\').ToLowerInvariant()
    return ($a -eq $b) -or $a.StartsWith("$b\") -or $b.StartsWith("$a\")
}

function Assert-SafeGitBranchName([string]$BranchName) {
    <#
    .SYNOPSIS
        Validates a Git branch name against git-check-ref-format rules and CLI option injection.
        WHY: Passing a branch name starting with '-' to `git worktree add` could be interpreted
        as a Git command flag; illegal ref patterns also cause unsafe or cryptic failures.
    #>
    if ([string]::IsNullOrWhiteSpace($BranchName)) {
        throw 'Parameter -Lane2Branch cannot be empty when -UseGitWorktree is enabled.'
    }
    Assert-NoControlChars -Value $BranchName -ParamName 'Lane2Branch'
    if ($BranchName.Length -gt 255) {
        throw "Invalid -Lane2Branch '$BranchName': exceeds maximum length of 255 characters."
    }
    if ($BranchName.StartsWith('-') -or $BranchName.StartsWith('/') -or $BranchName.StartsWith('.')) {
        throw "Invalid -Lane2Branch '$BranchName': branch name must not start with '-', '/', or '.'."
    }
    if ($BranchName -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$') {
        throw "Invalid -Lane2Branch '$BranchName': only ASCII letters, digits, '.', '_', '/', and '-' are permitted."
    }
    if ($BranchName.Contains('..') -or $BranchName.Contains('//') -or $BranchName.Contains('@{') -or
        $BranchName.EndsWith('.') -or $BranchName.EndsWith('/') -or $BranchName.EndsWith('.lock')) {
        throw "Invalid -Lane2Branch '$BranchName': contains disallowed Git ref sequence ('..', '//', '@{', or trailing '.', '/', '.lock')."
    }
}

function Assert-SafeGatewayUrl([string]$Url) {
    <#
    .SYNOPSIS
        Validates -GatewayBaseUrl as an absolute HTTP(S) URI without whitespace/control chars.
        WHY: Prevents malformed TOML/URL injection and warns if credentials would travel over
        unencrypted HTTP to a non-loopback host.
    #>
    if ([string]::IsNullOrWhiteSpace($Url)) {
        throw '-ConfigureGateway requires -GatewayBaseUrl.'
    }
    Assert-NoControlChars -Value $Url -ParamName 'GatewayBaseUrl'
    if ($Url -match '\s') {
        throw "Invalid -GatewayBaseUrl '$Url': URL must not contain whitespace."
    }
    $parsedUri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$parsedUri)) {
        throw "Invalid -GatewayBaseUrl '$Url': must be a valid absolute http:// or https:// URI."
    }
    if ($parsedUri.Scheme -ne 'https' -and $parsedUri.Scheme -ne 'http') {
        throw "Invalid -GatewayBaseUrl '$Url': only https:// or http:// schemes are permitted (got '$($parsedUri.Scheme)')."
    }
    if ($parsedUri.Scheme -eq 'http' -and -not $parsedUri.IsLoopback) {
        Write-Warning "Gateway URL '$Url' uses unencrypted HTTP to a non-loopback host. Use HTTPS whenever possible so your API key is encrypted in transit."
    }
}

function Escape-TomlBasicString([AllowEmptyString()][string]$Value) {
    <#
    .SYNOPSIS
        Escapes a string according to the TOML 1.0 basic-string specification.
        WHY: Ensures Windows backslashes, quotes, and control chars are safely represented in
        config.toml without regex replacement hazards (such as '$&' or '$1') or TOML injection.
    #>
    if ($null -eq $Value) { return '' }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    $escaped = $escaped.Replace("`b", '\b').Replace("`t", '\t').Replace("`n", '\n').Replace("`f", '\f').Replace("`r", '\r')
    return $escaped
}

function Escape-CmdSetValue([string]$Value, [string]$Label) {
    <#
    .SYNOPSIS
        Escapes a value for safe interpolation inside `set "VAR=VALUE"` in a Windows .cmd script.
        WHY: Inside quoted `set "VAR=..."`, spaces, '&', '|', '(', ')', and Unicode are literal,
        provided there are no double quotes or newlines and literal '%' signs are doubled to '%%'
        so cmd.exe does not expand unexpected environment variables at batch parse time.
    #>
    if ($null -eq $Value) { return '' }
    if ($Value -match '["\r\n\x00]') {
        throw "Refusing to embed unsafe characters into .cmd wrapper for ${Label}."
    }
    return $Value.Replace('%', '%%')
}

function Assert-NotReparsePoint {
    <#
    .SYNOPSIS
        Refuses to read, write, copy, or create through an existing symlink or NTFS Junction.
        WHY: `Copy-Item -Force` follows symlinks on Windows, and `Test-Path` on PowerShell 5.1
        can return `$false` for dangling symlinks/broken junctions. Calling `[System.IO.File]::GetAttributes`
        directly catches BOTH live and dangling reparse points fail-closed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $full = Resolve-CanonicalLongPath -PathValue $PathValue
    try {
        $attrs = [System.IO.File]::GetAttributes($full)
        if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Security violation: Refusing to operate on symlink/reparse point at '$full' ($Label)."
        }
    } catch [System.IO.FileNotFoundException] {
        return
    } catch [System.IO.DirectoryNotFoundException] {
        return
    }
}

function Ensure-Directory([string]$DirPath) {
    <#
    .SYNOPSIS
        Creates a directory using .NET APIs so literal brackets ('[' / ']') are never treated as wildcards.
    #>
    Assert-NotReparsePoint -PathValue $DirPath -Label 'managed directory'
    if (-not (Test-Path -LiteralPath $DirPath)) {
        if (-not $script:IsDryRun) {
            [void][System.IO.Directory]::CreateDirectory($DirPath)
        }
        Write-Host "    Create dir: $DirPath"
    }
}

function Write-Utf8NoBom {
    <#
    .SYNOPSIS
        Atomically writes a UTF-8 file without BOM (same-directory temp file + File.Replace/Move).
        WHY:
          1. UTF-8 without BOM is required by Rust/TOML parsers and Windows PowerShell 5.1 interop.
          2. Writing to a temp file on the same NTFS volume and atomically swapping prevents partial
             or zero-byte config.toml corruption if power drops or antivirus interrupts the write.
          3. Refuses symlink/reparse-point targets and parent directories to block symlink-clobber attacks.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $fullPath = Resolve-CanonicalLongPath -PathValue $FilePath
    $parentDir = [System.IO.Path]::GetDirectoryName($fullPath)
    if ($parentDir) {
        Assert-NotReparsePoint -PathValue $parentDir -Label 'Write-Utf8NoBom parent directory'
    }
    Assert-NotReparsePoint -PathValue $fullPath -Label 'Write-Utf8NoBom target file'
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        [void][System.IO.Directory]::CreateDirectory($parentDir)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $tmpPath = "$fullPath.tmp.$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    try {
        [System.IO.File]::WriteAllText($tmpPath, $Text, $utf8NoBom)
        if (Test-Path -LiteralPath $fullPath) {
            try {
                # Same-volume atomic replacement ([NullString]::Value avoids PS 5.1 $null->"" conversion quirk)
                [System.IO.File]::Replace($tmpPath, $fullPath, [NullString]::Value)
            } catch {
                # Graceful fallback for virtualized/filter-driver filesystems that reject ReplaceFileW
                Copy-Item -LiteralPath $tmpPath -Destination $fullPath -Force
                Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
            }
        } else {
            [System.IO.File]::Move($tmpPath, $fullPath)
        }
    } finally {
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Protect-SensitiveFileAcl([string]$FilePath) {
    <#
    .SYNOPSIS
        Fail-closed two-step Windows NTFS DACL lockdown for sensitive credential, config, and manifest files.
        WHY:
          On Windows, Codex's elevated sandbox creates a local group named `CodexSandboxUsers` and
          can grant `CodexSandboxUsers:(OI)(CI)(RX)` on parent directories such as `%USERPROFILE%\.codex`.
          A single `icacls /remove:g` cannot strip INHERITED ACEs, and combining flags can fail on fresh
          machines where `CodexSandboxUsers` does not exist yet (ERROR_NONE_MAPPED = 1332).

          Two-step fail-closed mitigation:
            Step 1: `icacls.exe <file> /inheritance:d`
                    Converts inherited ACEs into explicit ACEs while disabling future inheritance.
                    Current user, SYSTEM, and Administrators retain full access (never locking you out),
                    AND the file is immunized even if Codex later adds inherited ACEs to the parent folder.
            Step 2: `icacls.exe <file> /remove:g "CodexSandboxUsers"`
                    Runs whenever `CodexSandboxUsers` exists locally (or appears in the file's DACL),
                    stripping ONLY Grant ACEs while leaving any protective Deny ACEs untouched.
                    On fresh machines without `CodexSandboxUsers`, Step 2 is gracefully skipped.
            Step 3: Post-condition verification via `Get-Acl` asserts `AreAccessRulesProtected == $true`
                    and zero remaining `CodexSandboxUsers` Allow ACEs. Any failure throws a terminating
                    security error rather than silently continuing with an exposed credential/config file.
    #>
    if ($script:IsDryRun -or -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return }

    $fullPath = Resolve-CanonicalLongPath -PathValue $FilePath
    Assert-NotReparsePoint -PathValue $fullPath -Label 'Protect-SensitiveFileAcl target file'
    if (-not (Get-Command 'icacls.exe' -ErrorAction SilentlyContinue)) {
        throw "Security error: 'icacls.exe' was not found in PATH; cannot lock NTFS DACL on '$fullPath'."
    }

    $prevPref = $ErrorActionPreference
    try {
        # In PowerShell 5.1, native stderr throws a terminating NativeCommandError when
        # ErrorActionPreference='Stop'; temporarily set Continue and inspect $LASTEXITCODE explicitly.
        $ErrorActionPreference = 'Continue'

        # Step 1: Disable inheritance while copying existing ACEs as explicit ACEs.
        $icaclsOut1 = (& icacls.exe $fullPath /inheritance:d 2>&1) -join ' '
        $exit1 = $LASTEXITCODE
        if ($exit1 -ne 0) {
            throw "Security error: icacls.exe /inheritance:d failed (exit code $exit1) for '$fullPath': $icaclsOut1"
        }

        # Step 2: Check whether CodexSandboxUsers exists on this machine (or is referenced in the file ACL).
        $sandboxGroupExists = $false
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount('CodexSandboxUsers')
            $null = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $sandboxGroupExists = $true
        } catch {
            $sandboxGroupExists = $false
        }
        if (-not $sandboxGroupExists) {
            $preAcl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
            $matchingAces = @($preAcl.Access | Where-Object { $_.IdentityReference.Value -like '*CodexSandboxUsers*' })
            if ($matchingAces.Count -gt 0) { $sandboxGroupExists = $true }
        }

        if ($sandboxGroupExists) {
            # Remove Grant ACEs only (/remove:g) so protective Deny ACEs remain intact.
            $icaclsOut2 = (& icacls.exe $fullPath /remove:g "CodexSandboxUsers" 2>&1) -join ' '
            $exit2 = $LASTEXITCODE
            if ($exit2 -ne 0) {
                throw "Security error: icacls.exe /remove:g CodexSandboxUsers failed (exit code $exit2) for '$fullPath': $icaclsOut2"
            }
        }

        # Step 3: Fail-closed post-condition verification on the resulting NTFS DACL.
        $postAcl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
        if (-not $postAcl.AreAccessRulesProtected) {
            throw "Security error: NTFS DACL inheritance remained active on '$fullPath' after icacls /inheritance:d."
        }
        $remainingAllow = @($postAcl.Access | Where-Object {
            ($_.IdentityReference.Value -like '*CodexSandboxUsers*') -and
            ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
        })
        if ($remainingAllow.Count -gt 0) {
            throw "Security error: '$fullPath' still grants $($remainingAllow.Count) Allow ACE(s) to CodexSandboxUsers after icacls lockdown."
        }
    } finally {
        $ErrorActionPreference = $prevPref
        # Never leak an icacls exit code into subsequent script checks.
        $global:LASTEXITCODE = 0
    }
}

function Get-FileSha256([string]$FilePath) {
    <#
    .SYNOPSIS
        Computes uppercase 64-hex SHA-256 directly via .NET System.Security.Cryptography.SHA256.
        WHY: Immune to PowerShell 5.1's `Get-FileHash` script function `-WhatIf` propagation quirk
        and avoids wildcard issues on literal paths.
    #>
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $hashBytes = $sha.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $sha.Dispose()
    }
}

function Get-UniqueBackupPath([string]$BasePath) {
    <#
    .SYNOPSIS
        Generates a timestamped backup path that will never overwrite an existing backup created in
        the same second.
    #>
    $candidate = "$BasePath.backup-$($script:InstallStamp)"
    $suffix = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = "$BasePath.backup-$($script:InstallStamp)-$suffix"
        $suffix++
    }
    return $candidate
}

function Save-RollbackManifestCheckpoint {
    <#
    .SYNOPSIS
        Atomically persists the incremental rollback journal to both .rollback\latest.json and the
        timestamped snapshot file, immediately locking NTFS DACLs on both files.
        WHY: Writing the manifest ONLY at the end of installation leaves a crash window: if setup is
        interrupted mid-way (Ctrl+C, disk error, or exception after creating Junctions or modifying
        files), restore-original.ps1 would lack a manifest for those mutations. Calling this helper
        incrementally after .rollback creation and after every tracked backup, Junction, file write,
        and wrapper install guarantees crash-safe byte-exact recovery at every point in setup.
    #>
    param(
        [string]$Stage = 'checkpoint',
        [bool]$Completed = $false
    )
    if ($script:IsDryRun -or $null -eq $script:ManifestContext -or [string]::IsNullOrWhiteSpace($script:RollbackLatestPath)) {
        return
    }
    Assert-NotReparsePoint -PathValue $script:RollbackDir -Label '.rollback directory'
    if (-not (Test-Path -LiteralPath $script:RollbackDir)) {
        [void][System.IO.Directory]::CreateDirectory($script:RollbackDir)
    }

    $manifestObj = [PSCustomObject]@{
        SchemaVersion     = 2
        Timestamp         = $script:InstallStamp
        CreatedAtUtc      = $script:CreatedAtUtc
        UpdatedAtUtc      = (Get-Date).ToUniversalTime().ToString('o')
        Completed         = $Completed
        LastStage         = $Stage
        Lane1Home         = $script:ManifestContext.Lane1Home
        Lane2Home         = $script:ManifestContext.Lane2Home
        LocalBin          = $script:ManifestContext.LocalBin
        RepoPath          = $script:ManifestContext.RepoPath
        Lane2Worktree     = $script:ManifestContext.Lane2Worktree
        GatewayApiKeyEnv  = $script:ManifestContext.GatewayApiKeyEnv
        SharedJunctions   = @($script:TrackedJunctions.ToArray())
        SharedLinkRecords = @($script:SharedLinkRecords.ToArray())
        Wrappers          = @($script:InstalledWrappers.ToArray())
        Files             = @($script:SnapshotEntries.ToArray())
    }
    $manifestJson = $manifestObj | ConvertTo-Json -Depth 6
    Write-Utf8NoBom -FilePath $script:RollbackSnapPath   -Text $manifestJson
    Write-Utf8NoBom -FilePath $script:RollbackLatestPath -Text $manifestJson
    Protect-SensitiveFileAcl $script:RollbackSnapPath
    Protect-SensitiveFileAcl $script:RollbackLatestPath
}

function Backup-IfExists([string]$FilePath) {
    <#
    .SYNOPSIS
        Backs up a pre-existing file with its SHA-256 hash, records the entry for deterministic
        rollback via restore-original.ps1, and flushes an incremental rollback checkpoint BEFORE
        the target file is overwritten. Files that did not exist prior are also recorded and
        checkpointed so interrupted writes can still be cleaned up cleanly.
    #>
    $canonicalPath = Resolve-CanonicalLongPath -PathValue $FilePath
    if (Test-Path -LiteralPath $canonicalPath -PathType Leaf) {
        $origHash = Get-FileSha256 $canonicalPath
        $backup = Resolve-CanonicalLongPath -PathValue (Get-UniqueBackupPath $canonicalPath)
        if (-not $script:IsDryRun) {
            Copy-Item -LiteralPath $canonicalPath -Destination $backup -Force
            Protect-SensitiveFileAcl $backup
        }
        $script:SnapshotEntries.Add([PSCustomObject]@{
            TargetPath     = $canonicalPath
            ExistedPrior   = $true
            BackupPath     = $backup
            OriginalSha256 = $origHash
        })
        Save-RollbackManifestCheckpoint -Stage ("backup:" + [System.IO.Path]::GetFileName($canonicalPath))
        Write-Host "    Backup saved: $backup (SHA256=$($origHash.Substring(0, 12))...)" -ForegroundColor DarkGray
    } else {
        $script:SnapshotEntries.Add([PSCustomObject]@{
            TargetPath     = $canonicalPath
            ExistedPrior   = $false
            BackupPath     = ''
            OriginalSha256 = ''
        })
        Save-RollbackManifestCheckpoint -Stage ("track-new:" + [System.IO.Path]::GetFileName($canonicalPath))
    }
}

function Assert-NoPlaintextSecretInToml {
    <#
    .SYNOPSIS
        Fail-closed pre-write gate guaranteeing zero plaintext API keys ever reach config.toml.
        WHY: Defense-in-depth invariant ensuring even unexpected merged lines or future edits can
        never write `experimental_bearer_token`, inline `api_key`, or a raw supplied key to disk.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TomlContent,
        [Parameter(Mandatory = $true)][string]$ContextLabel,
        [AllowEmptyString()][string]$ForbiddenLiteralSecret = ''
    )
    $nonCommentLines = @($TomlContent -split "\r?\n" | Where-Object { $_ -notmatch '^\s*#' })
    foreach ($line in $nonCommentLines) {
        if ($line -match '^\s*experimental_bearer_token\s*=') {
            throw "Security invariant violation in ${ContextLabel}: refusing to write 'experimental_bearer_token' to config.toml. Use env_key instead."
        }
        if ($line -match '^\s*api_key\s*=\s*["''][^"'']+["'']') {
            throw "Security invariant violation in ${ContextLabel}: refusing to write plaintext 'api_key' to config.toml. Use env_key instead."
        }
    }
    if (-not [string]::IsNullOrEmpty($ForbiddenLiteralSecret) -and $TomlContent.Contains($ForbiddenLiteralSecret)) {
        throw "Security invariant violation in ${ContextLabel}: detected supplied API key literal inside generated config.toml; aborting write."
    }
}

# ============================================================================
# Helper Functions: Real Codex Discovery, Feature Probe & Non-Destructive TOML Merge
# ============================================================================

function Resolve-CodexExecutable([string]$ExplicitPath, [string]$ExcludedDir) {
    <#
    .SYNOPSIS
        Locates the real installed Codex executable without relying on mock paths or recursing
        into our own ~/.local/bin wrapper scripts.
    #>
    # 1. Explicit user-specified binary path
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "Specified -CodexPath does not exist or is not a file: $ExplicitPath"
        }
        $resolvedExplicit = Resolve-CanonicalLongPath -PathValue (Resolve-Path -LiteralPath $ExplicitPath).Path
        return [PSCustomObject]@{ Path = $resolvedExplicit; Source = 'Explicit' }
    }

    # 2. Microsoft Store / MSIX OpenAI.Codex Desktop package
    $appx = $null
    try {
        $appx = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue | Select-Object -First 1
    } catch {
        $appx = $null
    }
    if ($appx -and $appx.InstallLocation) {
        $msixExe = Join-Path $appx.InstallLocation 'app\resources\codex.exe'
        if (Test-Path -LiteralPath $msixExe -PathType Leaf) {
            return [PSCustomObject]@{ Path = (Resolve-CanonicalLongPath -PathValue $msixExe); Source = 'WindowsApps' }
        }
    }

    # 3. Existing codex binary in PATH (strictly excluding our own LocalBin wrapper to avoid infinite recursion)
    $excludedNorm = (Resolve-CanonicalLongPath -PathValue $ExcludedDir).TrimEnd('\').ToLowerInvariant()
    $cmdCandidates = @(Get-Command codex -All -ErrorAction SilentlyContinue)
    $exeMatch = $null
    $batchMatch = $null
    foreach ($cmd in $cmdCandidates) {
        if (-not $cmd -or -not $cmd.Source) { continue }
        $src = Resolve-CanonicalLongPath -PathValue $cmd.Source
        $parent = (Resolve-CanonicalLongPath -PathValue (Split-Path -Parent $src)).TrimEnd('\').ToLowerInvariant()
        if ($parent -eq $excludedNorm) { continue }
        $ext = [System.IO.Path]::GetExtension($src).ToLowerInvariant()
        # Prefer .exe / .cmd siblings over PowerShell .ps1 npm shims so our .cmd wrappers invoke cleanly.
        if ($ext -eq '.ps1' -or $ext -eq '') {
            $siblingExe = Join-Path (Split-Path -Parent $src) 'codex.exe'
            $siblingCmd = Join-Path (Split-Path -Parent $src) 'codex.cmd'
            if ((Test-Path -LiteralPath $siblingExe -PathType Leaf) -and -not $exeMatch) { $exeMatch = $siblingExe }
            elseif ((Test-Path -LiteralPath $siblingCmd -PathType Leaf) -and -not $batchMatch) { $batchMatch = $siblingCmd }
            continue
        }
        if ($ext -eq '.exe' -and (Test-Path -LiteralPath $src -PathType Leaf) -and -not $exeMatch) {
            $exeMatch = $src
        } elseif (($ext -eq '.cmd' -or $ext -eq '.bat') -and (Test-Path -LiteralPath $src -PathType Leaf) -and -not $batchMatch) {
            $batchMatch = $src
        }
    }
    if ($exeMatch) { return [PSCustomObject]@{ Path = $exeMatch; Source = 'PATH' } }
    if ($batchMatch) { return [PSCustomObject]@{ Path = $batchMatch; Source = 'PATH' } }

    # 4. Common standalone / npm global locations
    $fallbacks = @(
        (Join-Path $env:APPDATA 'npm\codex.cmd'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Codex\codex.exe')
    )
    foreach ($fb in $fallbacks) {
        if (Test-Path -LiteralPath $fb -PathType Leaf) {
            return [PSCustomObject]@{ Path = $fb; Source = 'Fallback' }
        }
    }

    throw @"
No Codex binary was found on this machine.
Install one of the following first, then re-run this script:
  - OpenAI Codex Desktop app (Microsoft Store / MSIX), OR
  - Standalone Codex CLI (`npm i -g @openai/codex`), OR
  - Pass an explicit path via: -CodexPath "C:\path\to\codex.exe"
"@
}

function Get-SupportedCodexFeatures([string]$ExePath, [string]$ProbeHome) {
    <#
    .SYNOPSIS
        Queries the real installed Codex CLI (`codex features list`) in an isolated temporary
        CODEX_HOME so only genuinely supported feature flags are written into config.toml.
    #>
    $supported = @{}
    $prevHome = $env:CODEX_HOME
    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $env:CODEX_HOME = $ProbeHome
        $lines = @(& $ExePath features list 2>$null)
        foreach ($line in $lines) {
            $text = [string]$line
            if ($text -match '^([a-z0-9_]+)\s+(stable|experimental|under development|deprecated)\s+') {
                $supported[$Matches[1]] = $Matches[2]
            }
        }
    } catch {
        # Older CLI builds may not implement `features list`; return empty map safely.
    } finally {
        $ErrorActionPreference = $prevPref
        $env:CODEX_HOME = $prevHome
        $global:LASTEXITCODE = 0
    }
    return $supported
}

function Unescape-TomlBasicString([AllowEmptyString()][string]$Escaped) {
    <#
    .SYNOPSIS
        Unescapes a TOML 1.0 basic string (double-quoted) in a single pass.
        WHY: Avoids chained `.Replace()` ordering bugs when paths contain escaped backslashes or quotes.
    #>
    if ([string]::IsNullOrEmpty($Escaped)) { return '' }
    $sb = New-Object 'System.Text.StringBuilder' $Escaped.Length
    $i = 0
    while ($i -lt $Escaped.Length) {
        $ch = $Escaped[$i]
        if ($ch -eq '\' -and ($i + 1) -lt $Escaped.Length) {
            $next = $Escaped[$i + 1]
            switch ($next) {
                '\' { [void]$sb.Append('\') }
                '"' { [void]$sb.Append('"') }
                'n' { [void]$sb.Append("`n") }
                'r' { [void]$sb.Append("`r") }
                't' { [void]$sb.Append("`t") }
                'b' { [void]$sb.Append("`b") }
                'f' { [void]$sb.Append("`f") }
                default { [void]$sb.Append('\').Append($next) }
            }
            $i += 2
        } else {
            [void]$sb.Append($ch)
            $i++
        }
    }
    return $sb.ToString()
}

function Get-TomlProjectSectionPath([AllowEmptyString()][string]$HeaderInner) {
    <#
    .SYNOPSIS
        Extracts the unescaped project path from a direct `[projects."..."]` or `[projects.'...']`
        TOML table header inner text, or returns `$null` for non-project or subtable headers.
    #>
    if ([string]::IsNullOrWhiteSpace($HeaderInner)) { return $null }
    $trimmed = $HeaderInner.Trim()
    $m = [regex]::Match($trimmed, '^projects\s*\.\s*(?:''([^'']+)''|"((?:[^"\\]|\\.)+)")\s*$')
    if (-not $m.Success) { return $null }
    $raw = if ($m.Groups[1].Success) {
        $m.Groups[1].Value
    } else {
        Unescape-TomlBasicString $m.Groups[2].Value
    }
    if ([string]::IsNullOrWhiteSpace($raw) -or ($raw -match '[\x00-\x1F\x7F]')) {
        return $null
    }
    return $raw
}

function Get-ProjectDedupKey([AllowEmptyString()][string]$ProjectPath) {
    <#
    .SYNOPSIS
        Produces a canonical, separator-normalized deduplication key for a project path.
    #>
    if ([string]::IsNullOrWhiteSpace($ProjectPath)) { return '' }
    $dedupKey = try { (Resolve-CanonicalLongPath -PathValue $ProjectPath).TrimEnd('\', '/') } catch { $ProjectPath.TrimEnd('\', '/') }
    if ([string]::IsNullOrWhiteSpace($dedupKey)) { $dedupKey = $ProjectPath }
    return $dedupKey
}

function Update-TomlMultilineState {
    <#
    .SYNOPSIS
        Tracks bracket/brace depth and multi-line triple-quote state across top-level TOML value lines.
        WHY: Prevents multi-line top-level arrays/inline-tables (e.g., `notify = [\n "a",\n "b"\n]`)
        from being truncated into invalid TOML during a non-destructive merge.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][ref]$BracketDepth,
        [Parameter(Mandatory = $true)][ref]$MultilineQuote
    )
    $i = 0
    $len = $Text.Length
    $inSingleQuote = $false
    $inDoubleQuote = $false
    while ($i -lt $len) {
        if ($MultilineQuote.Value -ne '') {
            $delim = $MultilineQuote.Value
            if ($delim -eq '"""' -and $Text[$i] -eq '\' -and ($i + 1) -lt $len) {
                $i += 2
                continue
            }
            if (($i + 2) -lt $len -and $Text.Substring($i, 3) -eq $delim) {
                $MultilineQuote.Value = ''
                $i += 3
                continue
            }
            $i++
            continue
        }
        $ch = $Text[$i]
        if ($inDoubleQuote) {
            if ($ch -eq '\' -and ($i + 1) -lt $len) { $i += 2; continue }
            if ($ch -eq '"') { $inDoubleQuote = $false }
            $i++
            continue
        }
        if ($inSingleQuote) {
            if ($ch -eq "'") { $inSingleQuote = $false }
            $i++
            continue
        }
        # Unquoted comment terminates the remainder of this TOML line.
        if ($ch -eq '#') { break }
        if (($i + 2) -lt $len) {
            $tri = $Text.Substring($i, 3)
            if ($tri -eq '"""' -or $tri -eq "'''") {
                $MultilineQuote.Value = $tri
                $i += 3
                continue
            }
        }
        if ($ch -eq '"') { $inDoubleQuote = $true; $i++; continue }
        if ($ch -eq "'") { $inSingleQuote = $true; $i++; continue }
        if ($ch -eq '[' -or $ch -eq '{') { $BracketDepth.Value++ }
        elseif ($ch -eq ']' -or $ch -eq '}') { if ($BracketDepth.Value -gt 0) { $BracketDepth.Value-- } }
        $i++
    }
}

function Normalize-TomlSectionKey([string]$HeaderInner) {
    <#
    .SYNOPSIS
        Canonicalizes dotted TOML table headers (e.g. `model_providers."OpenAI"` and
        `model_providers.'OpenAI'` -> `model_providers.openai`) for duplicate-free replacement.
        WHY: Ensures an old `[model_providers.'OpenAI']` section containing a legacy bearer token
        is cleanly replaced instead of duplicated beside `[model_providers."OpenAI"]`.
    #>
    $trimmed = $HeaderInner.Trim()
    if ($trimmed -match '^model_providers\.\s*(?:"((?:[^"\\]|\\.)+)"|''([^'']+)''|([A-Za-z0-9_-]+))\s*$') {
        $prov = if ($Matches[1]) { $Matches[1].Replace('\"', '"').Replace('\\', '\') }
                elseif ($Matches[2]) { $Matches[2] }
                else { $Matches[3] }
        return ('model_providers.' + $prov.ToLowerInvariant())
    }
    return $trimmed.ToLowerInvariant()
}

function Remove-TomlInlineComment([string]$Line) {
    <#
    .SYNOPSIS
        Strips an unquoted trailing TOML `# comment` while preserving `#` inside quoted keys/paths
        such as `[projects."C:\\my#app"]`.
    #>
    $inDouble = $false
    $inSingle = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $ch = $Line[$i]
        if ($inDouble) {
            if ($ch -eq '\' -and ($i + 1) -lt $Line.Length) { $i++; continue }
            if ($ch -eq '"') { $inDouble = $false }
            continue
        }
        if ($inSingle) {
            if ($ch -eq "'") { $inSingle = $false }
            continue
        }
        if ($ch -eq '"') { $inDouble = $true; continue }
        if ($ch -eq "'") { $inSingle = $true; continue }
        if ($ch -eq '#') { return $Line.Substring(0, $i) }
    }
    return $Line
}

function Add-ParsedProjectTrustEntry {
    <#
    .SYNOPSIS
        Records a parsed `[projects.*]` section into a per-file list/map using fail-closed
        deduplication so a duplicate table header in the same file can never promote `untrusted`,
        missing, or unrecognized entries to `trusted`.
    #>
    param(
        [Parameter(Mandatory = $true)]$ByKey,
        [Parameter(Mandatory = $true)]$Entries,
        [Parameter(Mandatory = $true)][string]$ProjectPath,
        [Parameter(Mandatory = $true)][string]$DedupKey,
        [Parameter(Mandatory = $true)][string]$TrustLevel,
        [Parameter(Mandatory = $true)][bool]$HasExtraKeys
    )
    if ($ByKey.ContainsKey($DedupKey)) {
        $existing = $ByKey[$DedupKey]
        if ($TrustLevel -ceq 'untrusted') {
            $existing.TrustLevel = 'untrusted'
        } elseif ($TrustLevel -cne 'trusted' -and $existing.TrustLevel -ceq 'trusted') {
            $existing.TrustLevel = $TrustLevel
        }
        if ($HasExtraKeys) {
            $existing.HasExtraKeys = $true
        }
    } else {
        $obj = [PSCustomObject]@{
            Path         = $ProjectPath
            DedupKey     = $DedupKey
            TrustLevel   = $TrustLevel
            HasExtraKeys = $HasExtraKeys
        }
        $ByKey[$DedupKey] = $obj
        $Entries.Add($obj)
    }
}

function Get-TomlProjectTrustEntries([string]$ConfigPath) {
    <#
    .SYNOPSIS
        Strictly read-only parser for `[projects."..."]` and `[projects.'...']` tables in a single
        config.toml file, capturing each project's real `trust_level` value (`trusted`, `untrusted`,
        `missing`, or `unrecognized`) while safely handling single/double quotes, comments, and
        multi-line TOML values.
        WHY: Replaces header-only project harvesting so `untrusted`, missing, or unrecognized
        `trust_level` entries are NEVER silently promoted to `trusted`.
    #>
    $entries = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) { return , $entries }
    Assert-NotReparsePoint -PathValue $ConfigPath -Label 'config.toml project trust parse'
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return , $entries }

    # Explicit UTF-8 read avoids PowerShell 5.1 ANSI/Windows-1252 mojibake on UTF-8 no-BOM files with Unicode paths.
    $content = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $content) { return , $entries }

    $byKey = New-Object 'System.Collections.Generic.Dictionary[string, object]' ([System.StringComparer]::OrdinalIgnoreCase)

    $inProjectSection = $false
    $currentPath = ''
    $currentDedupKey = ''
    $currentTrust = 'missing'
    $currentHasExtraKeys = $false

    $inMultiline = $false
    $bracketDepth = 0
    $multilineQuote = ''

    foreach ($line in ($content -split "\r?\n")) {
        if ($inMultiline) {
            Update-TomlMultilineState -Text $line -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            if ($bracketDepth -eq 0 -and $multilineQuote -eq '') {
                $inMultiline = $false
            }
            continue
        }

        $noComment = (Remove-TomlInlineComment $line).Trim()
        if ([string]::IsNullOrWhiteSpace($noComment)) { continue }

        # Array of tables: [[section]] closes any open [projects.*] section.
        if ($noComment -match '^\[\[(.+)\]\]$') {
            if ($inProjectSection) {
                Add-ParsedProjectTrustEntry -ByKey $byKey -Entries $entries -ProjectPath $currentPath -DedupKey $currentDedupKey -TrustLevel $currentTrust -HasExtraKeys $currentHasExtraKeys
                $inProjectSection = $false
            }
            continue
        }

        # Standard table header: [section] (inline `#` comments already stripped outside quotes).
        $hdrMatch = [regex]::Match($noComment, '^\[(.+)\]$')
        if ($hdrMatch.Success) {
            if ($inProjectSection) {
                Add-ParsedProjectTrustEntry -ByKey $byKey -Entries $entries -ProjectPath $currentPath -DedupKey $currentDedupKey -TrustLevel $currentTrust -HasExtraKeys $currentHasExtraKeys
                $inProjectSection = $false
            }
            $projPath = Get-TomlProjectSectionPath $hdrMatch.Groups[1].Value
            if ($null -ne $projPath) {
                $inProjectSection = $true
                $currentPath = $projPath
                $currentDedupKey = Get-ProjectDedupKey $projPath
                $currentTrust = 'missing'
                $currentHasExtraKeys = $false
            }
            continue
        }

        # Key-value assignment (top-level or inside a section).
        $kvMatch = [regex]::Match($line, '^\s*(?:([A-Za-z0-9_-]+)|"((?:[^"\\]|\\.)+)"|''([^'']+)'')\s*=(.*)$')
        if ($kvMatch.Success) {
            $rawKey = if ($kvMatch.Groups[1].Success) {
                $kvMatch.Groups[1].Value
            } elseif ($kvMatch.Groups[2].Success) {
                Unescape-TomlBasicString $kvMatch.Groups[2].Value
            } else {
                $kvMatch.Groups[3].Value
            }
            $rawRhs = $kvMatch.Groups[4].Value

            $bracketDepth = 0
            $multilineQuote = ''
            Update-TomlMultilineState -Text $rawRhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            $startsMultiline = ($bracketDepth -gt 0 -or $multilineQuote -ne '')
            if ($startsMultiline) {
                $inMultiline = $true
            }

            if ($inProjectSection) {
                if ($rawKey -ceq 'trust_level') {
                    $parsedTrust = 'unrecognized'
                    if (-not $startsMultiline) {
                        $rhsClean = (Remove-TomlInlineComment $rawRhs).Trim()
                        $valMatch = [regex]::Match($rhsClean, '^(?:"((?:[^"\\]|\\.)*)"|''([^'']*)'')\s*$')
                        if ($valMatch.Success) {
                            $valStr = if ($valMatch.Groups[1].Success) {
                                Unescape-TomlBasicString $valMatch.Groups[1].Value
                            } else {
                                $valMatch.Groups[2].Value
                            }
                            if ($valStr -ceq 'trusted') {
                                $parsedTrust = 'trusted'
                            } elseif ($valStr -ceq 'untrusted') {
                                $parsedTrust = 'untrusted'
                            } else {
                                $parsedTrust = 'unrecognized'
                            }
                        }
                    }
                    # Fail-closed if trust_level appears more than once in the same section.
                    if ($parsedTrust -ceq 'untrusted') {
                        $currentTrust = 'untrusted'
                    } elseif ($parsedTrust -ceq 'trusted') {
                        if ($currentTrust -ceq 'missing') { $currentTrust = 'trusted' }
                    } else {
                        if ($currentTrust -cne 'untrusted') { $currentTrust = 'unrecognized' }
                    }
                } else {
                    $currentHasExtraKeys = $true
                }
            }
        } else {
            # Dotted key or other non-blank TOML assignment line: track multiline state and mark extra keys.
            $eqIdx = $line.IndexOf('=')
            if ($eqIdx -ge 0) {
                $fallbackRhs = $line.Substring($eqIdx + 1)
                $bracketDepth = 0
                $multilineQuote = ''
                Update-TomlMultilineState -Text $fallbackRhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
                if ($bracketDepth -gt 0 -or $multilineQuote -ne '') {
                    $inMultiline = $true
                }
            }
            if ($inProjectSection) {
                $currentHasExtraKeys = $true
            }
        }
    }

    if ($inProjectSection) {
        Add-ParsedProjectTrustEntry -ByKey $byKey -Entries $entries -ProjectPath $currentPath -DedupKey $currentDedupKey -TrustLevel $currentTrust -HasExtraKeys $currentHasExtraKeys
    }
    return , $entries
}

function Get-ExistingTrustedProjects([string[]]$ConfigPaths) {
    <#
    .SYNOPSIS
        Strictly read-only harvest of `[projects."..."]` and `[projects.'...']` entries across
        prior Lane 2 and Lane 1 (Codex Desktop) config.toml files, recording each project's real
        `trust_level` (`trusted`, `untrusted`, `missing`, or `unrecognized`) while deduplicating
        with earlier config paths taking precedence.
        WHY: Inspecting real `trust_level` values guarantees `untrusted`, missing, or unrecognized
        entries are NEVER silently promoted to `trusted`.
    #>
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object 'System.Collections.Generic.List[object]'
    $srcIndex = 0
    foreach ($cfg in $ConfigPaths) {
        if (-not [string]::IsNullOrWhiteSpace($cfg)) {
            $entries = Get-TomlProjectTrustEntries -ConfigPath $cfg
            foreach ($entry in $entries) {
                if ($seen.Add($entry.DedupKey)) {
                    $list.Add([PSCustomObject]@{
                        Path         = $entry.Path
                        DedupKey     = $entry.DedupKey
                        TrustLevel   = $entry.TrustLevel
                        HasExtraKeys = $entry.HasExtraKeys
                        SourceIndex  = $srcIndex
                    })
                }
            }
        }
        $srcIndex++
    }
    return , $list
}

function Resolve-MergedProjectTrustState {
    <#
    .SYNOPSIS
        Merges `[projects.*]` trust entries for a target lane config.toml from:
          1. Existing entries in PrimaryConfigPath (the config file being updated),
          2. Strictly read-only harvested entries from SecondaryConfigPath (the peer lane),
          3. Explicitly targeted setup repositories (EnsureTrustedPaths, e.g. -RepoPath / worktree).
        SECURITY INVARIANT:
          - `trusted` stays `trusted`; `untrusted` stays `untrusted` (never promoted to `trusted`).
          - Entries with missing or unrecognized `trust_level` are NEVER promoted to `trusted`
            (skipped when harvesting from SecondaryConfigPath; preserved verbatim on PrimaryConfigPath).
          - Only explicitly targeted EnsureTrustedPaths (-RepoPath and optional worktree) are
            ensured `trust_level = "trusted"` by setup.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PrimaryConfigPath,
        [AllowEmptyString()][string]$SecondaryConfigPath = '',
        [string[]]$EnsureTrustedPaths = @()
    )
    $managedProjects = New-Object 'System.Collections.Generic.List[object]'
    $managedByKey = New-Object 'System.Collections.Generic.Dictionary[string, object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $managedProjectKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $preservedByKey = New-Object 'System.Collections.Generic.Dictionary[string, object]' ([System.StringComparer]::OrdinalIgnoreCase)

    $harvestPaths = if ([string]::IsNullOrWhiteSpace($SecondaryConfigPath)) {
        @($PrimaryConfigPath)
    } else {
        @($PrimaryConfigPath, $SecondaryConfigPath)
    }

    # 1 & 2. Harvest [projects.*] with real trust_level values (PrimaryConfigPath at SourceIndex=0 takes precedence).
    $harvested = Get-ExistingTrustedProjects -ConfigPaths $harvestPaths
    foreach ($entry in $harvested) {
        if ($entry.SourceIndex -eq 0) {
            if (($entry.TrustLevel -ceq 'trusted' -or $entry.TrustLevel -ceq 'untrusted') -and (-not $entry.HasExtraKeys)) {
                $item = [PSCustomObject]@{
                    Path       = $entry.Path
                    DedupKey   = $entry.DedupKey
                    TrustLevel = $entry.TrustLevel
                }
                $managedProjects.Add($item)
                $managedByKey[$entry.DedupKey] = $item
                [void]$managedProjectKeys.Add($entry.DedupKey)
            } else {
                # Preserve original block verbatim in Merge-CodexConfigToml (missing/unrecognized trust_level or extra keys).
                $preservedByKey[$entry.DedupKey] = $entry
            }
        } else {
            # Secondary lane (read-only harvest): inherit ONLY explicit 'trusted' or 'untrusted'; skip missing/unrecognized.
            if ($entry.TrustLevel -ceq 'trusted' -or $entry.TrustLevel -ceq 'untrusted') {
                $item = [PSCustomObject]@{
                    Path       = $entry.Path
                    DedupKey   = $entry.DedupKey
                    TrustLevel = $entry.TrustLevel
                }
                $managedProjects.Add($item)
                $managedByKey[$entry.DedupKey] = $item
                [void]$managedProjectKeys.Add($entry.DedupKey)
            }
        }
    }

    # 3. Ensure explicitly targeted setup repositories (-RepoPath / optional Lane 2 worktree) are trusted.
    foreach ($rp in $EnsureTrustedPaths) {
        if ([string]::IsNullOrWhiteSpace($rp)) { continue }
        $rpCanon = Resolve-CanonicalLongPath -PathValue $rp
        $rpKey = Get-ProjectDedupKey $rpCanon
        if ($managedByKey.ContainsKey($rpKey)) {
            $managedByKey[$rpKey].TrustLevel = 'trusted'
            [void]$managedProjectKeys.Add($rpKey)
        } elseif ($preservedByKey.ContainsKey($rpKey)) {
            if ($preservedByKey[$rpKey].TrustLevel -ceq 'trusted') {
                # Already trusted with preserved custom extra keys -> keep intact without duplicating header.
                continue
            }
            # Explicitly targeted repo had untrusted/missing/unrecognized trust_level -> replace with managed trusted block.
            [void]$preservedByKey.Remove($rpKey)
            $item = [PSCustomObject]@{
                Path       = $rpCanon
                DedupKey   = $rpKey
                TrustLevel = 'trusted'
            }
            $managedProjects.Add($item)
            $managedByKey[$rpKey] = $item
            [void]$managedProjectKeys.Add($rpKey)
        } else {
            $item = [PSCustomObject]@{
                Path       = $rpCanon
                DedupKey   = $rpKey
                TrustLevel = 'trusted'
            }
            $managedProjects.Add($item)
            $managedByKey[$rpKey] = $item
            [void]$managedProjectKeys.Add($rpKey)
        }
    }

    $blockLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($mp in $managedProjects) {
        if ($mp.TrustLevel -cne 'trusted' -and $mp.TrustLevel -cne 'untrusted') {
            throw "Internal trust invariant violation: refusing to emit unexpected trust_level '$($mp.TrustLevel)' for '$($mp.Path)'."
        }
        $blockLines.Add("[projects.`"$(Escape-TomlBasicString $mp.Path)`"]`r`ntrust_level = `"$($mp.TrustLevel)`"")
    }

    $managedKeyList = New-Object 'System.Collections.Generic.List[string]'
    foreach ($mk in $managedProjectKeys) { $managedKeyList.Add($mk) }

    $preservedTrusted = 0
    $preservedUntrusted = 0
    foreach ($pe in $preservedByKey.Values) {
        if ($pe.TrustLevel -ceq 'trusted') { $preservedTrusted++ }
        elseif ($pe.TrustLevel -ceq 'untrusted') { $preservedUntrusted++ }
    }

    $trustedCount   = @($managedProjects | Where-Object { $_.TrustLevel -ceq 'trusted' }).Count + $preservedTrusted
    $untrustedCount = @($managedProjects | Where-Object { $_.TrustLevel -ceq 'untrusted' }).Count + $preservedUntrusted

    return [PSCustomObject]@{
        ManagedProjects     = $managedProjects
        ManagedProjectKeys  = $managedKeyList.ToArray()
        ProjectsBlock       = ($blockLines -join "`r`n`r`n")
        TrustedCount        = $trustedCount
        UntrustedCount      = $untrustedCount
        PreservedOtherCount = ($preservedByKey.Count - $preservedTrusted - $preservedUntrusted)
    }
}

function Merge-CodexConfigToml {
    <#
    .SYNOPSIS
        Non-destructively merges managed Dual-Lane keys/sections into an existing config.toml.
        WHY: Preserves user customizations ([mcp_servers.*], [tui], [plugins.*], [[array_tables]],
        custom top-level settings, and any unmanaged `[projects.*]` blocks without promoting
        missing/unrecognized `trust_level` entries) while updating managed settings cleanly.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExistingPath,
        [Parameter(Mandatory = $true)][string]$ManagedTopBlock,
        [Parameter(Mandatory = $true)][string]$ManagedSectionsBlock,
        [Parameter(Mandatory = $true)][string[]]$ManagedTopKeys,
        [Parameter(Mandatory = $true)][string[]]$ManagedSectionNames,
        [string[]]$ManagedProjectKeys = @()
    )
    if (-not (Test-Path -LiteralPath $ExistingPath -PathType Leaf)) {
        return ($ManagedTopBlock.TrimEnd() + "`r`n`r`n" + $ManagedSectionsBlock.TrimEnd() + "`r`n")
    }
    # Explicit UTF-8 read preserves Unicode paths/comments on PowerShell 5.1 when reading UTF-8 no-BOM config.toml.
    $raw = Get-Content -LiteralPath $ExistingPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $raw) {
        return ($ManagedTopBlock.TrimEnd() + "`r`n`r`n" + $ManagedSectionsBlock.TrimEnd() + "`r`n")
    }

    $topKeySet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $ManagedTopKeys) { [void]$topKeySet.Add($k) }

    $secSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $ManagedSectionNames) {
        [void]$secSet.Add((Normalize-TomlSectionKey $s))
    }

    $managedProjSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pk in $ManagedProjectKeys) {
        if (-not [string]::IsNullOrWhiteSpace($pk)) { [void]$managedProjSet.Add($pk) }
    }

    $preservedTop = New-Object 'System.Collections.Generic.List[string]'
    $preservedSections = New-Object 'System.Collections.Generic.List[string]'

    $lines = $raw -split "\r?\n"
    $inSection = $false
    $keepCurrentSection = $false
    $currentSectionLines = New-Object 'System.Collections.Generic.List[string]'

    # State for tracking multi-line top-level TOML assignments (arrays, inline tables, triple quotes).
    $inMultilineTop = $false
    $keepMultilineTop = $false
    $bracketDepth = 0
    $multilineQuote = ''

    foreach ($line in $lines) {
        # Only recognize section headers when we are NOT inside a multi-line top-level value.
        if (-not $inMultilineTop) {
            $headerNoComment = (Remove-TomlInlineComment $line).Trim()
            # Array of tables: [[section]] (never managed by this kit -> always preserve).
            if ($headerNoComment -match '^\[\[(.+)\]\]$') {
                if ($inSection -and $keepCurrentSection -and $currentSectionLines.Count -gt 0) {
                    $preservedSections.Add(($currentSectionLines -join "`r`n").TrimEnd())
                }
                $currentSectionLines.Clear()
                $inSection = $true
                $keepCurrentSection = $true
                $currentSectionLines.Add($line)
                continue
            }
            # Standard table header: [section] (inline `#` comments safely stripped outside quotes).
            if ($headerNoComment -match '^\[(.+)\]$') {
                if ($inSection -and $keepCurrentSection -and $currentSectionLines.Count -gt 0) {
                    $preservedSections.Add(($currentSectionLines -join "`r`n").TrimEnd())
                }
                $currentSectionLines.Clear()
                $inSection = $true
                $rawSecName = $Matches[1].Trim()
                $normSecName = Normalize-TomlSectionKey $rawSecName
                $isManagedProject = $false
                $projPath = Get-TomlProjectSectionPath $rawSecName
                if ($null -ne $projPath) {
                    $projKey = Get-ProjectDedupKey $projPath
                    if ($managedProjSet.Contains($projKey)) {
                        $isManagedProject = $true
                    }
                }
                $isManagedSubtable = ($secSet.Contains('approval_policy') -and $normSecName -like 'approval_policy.*')
                if ($secSet.Contains($normSecName) -or $isManagedProject -or $isManagedSubtable) {
                    $keepCurrentSection = $false
                } else {
                    $keepCurrentSection = $true
                    $currentSectionLines.Add($line)
                }
                continue
            }
        }

        if (-not $inSection) {
            if ($inMultilineTop) {
                if ($keepMultilineTop) { $preservedTop.Add($line) }
                Update-TomlMultilineState -Text $line -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
                if ($bracketDepth -eq 0 -and $multilineQuote -eq '') {
                    $inMultilineTop = $false
                    $keepMultilineTop = $false
                }
                continue
            }
            if ($line -match '^\s*#' -or $line -match '^\s*$') { continue }
            if ($line -match '^\s*([A-Za-z0-9_-]+|"[^"]+"|''[^'']+'')\s*=(.*)$') {
                $keyName = $Matches[1].Trim('"', "'")
                $rhs = $Matches[2]
                $keepKey = -not $topKeySet.Contains($keyName)
                if ($keepKey) {
                    $preservedTop.Add($line)
                }
                $bracketDepth = 0
                $multilineQuote = ''
                Update-TomlMultilineState -Text $rhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
                if ($bracketDepth -gt 0 -or $multilineQuote -ne '') {
                    $inMultilineTop = $true
                    $keepMultilineTop = $keepKey
                }
            }
        } elseif ($keepCurrentSection) {
            $currentSectionLines.Add($line)
        }
    }
    if ($inSection -and $keepCurrentSection -and $currentSectionLines.Count -gt 0) {
        $preservedSections.Add(($currentSectionLines -join "`r`n").TrimEnd())
    }

    $combinedTop = $ManagedTopBlock.TrimEnd()
    if ($preservedTop.Count -gt 0) {
        $combinedTop += "`r`n" + ($preservedTop -join "`r`n")
    }
    $result = $combinedTop + "`r`n`r`n" + $ManagedSectionsBlock.TrimEnd()
    if ($preservedSections.Count -gt 0) {
        $result += "`r`n`r`n# Preserved custom user sections`r`n" + ($preservedSections -join "`r`n`r`n")
    }
    return ($result.TrimEnd() + "`r`n")
}

function Show-FullAccessDangerWarning {
    <#
    .SYNOPSIS
        Displays a high-visibility RED/YELLOW danger warning modeled on Codex CLI's
        `--dangerously-bypass-approvals-and-sandbox` ("EXTREMELY DANGEROUS") banner.
    #>
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host "  [!] CANH BAO NGUY HIEM -- EXTREMELY DANGEROUS (FULL ACCESS / TOAN QUYEN)" -ForegroundColor Red
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host "  Che do nay se ghi vao Sandbox 2 (~/.codex-official/config.toml):" -ForegroundColor Yellow
    Write-Host '    approval_policy = "never"               (TAT HOAN TOAN hoi duyet lenh)' -ForegroundColor Red
    Write-Host '    sandbox_mode    = "danger-full-access"  (TAT HOAN TOAN OS sandbox)' -ForegroundColor Red
    Write-Host ""
    Write-Host "  RUI RO TREN TOAN MAY (HOST-WIDE RISKS):" -ForegroundColor Yellow
    Write-Host "    - Bo qua ranh gioi workspace-write: Codex CLI co toan quyen DOC / GHI / XOA" -ForegroundColor Yellow
    Write-Host "      file, CHAY LENH shell va truy cap MANG tren TOAN MAY theo quyen user OS." -ForegroundColor Yellow
    Write-Host "    - Khong hoi duyet truoc khi thuc thi lenh hay sua file ngoai thu muc du an." -ForegroundColor Yellow
    Write-Host "    - rules\default.rules chi kiem tra prefix lenh truc tiep (argv), KHONG the" -ForegroundColor Yellow
    Write-Host "      chan het lenh long trong powershell -Command / cmd /c / bash -c." -ForegroundColor Yellow
    Write-Host "    - Prompt injection hoac loi AI co the lam mat du lieu ngoai du an." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  KHUYEN NGHI AN TOAN:" -ForegroundColor Yellow
    Write-Host "    - Tao Git commit checkpoint (hoac dung -UseGitWorktree / VM co lap) truoc!" -ForegroundColor Yellow
    Write-Host "    - Chuyen lai ve che do Ask (Xin yeu cau) ngay khi xong viec bang codex-manage." -ForegroundColor Yellow
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host ""
}

function Confirm-FullAccessOrExit {
    <#
    .SYNOPSIS
        Fail-closed pre-flight confirmation gate for -CliMode FullAccess.
        Always displays Show-FullAccessDangerWarning; requires explicit -ConfirmFullAccess in
        non-interactive/non-TTY sessions, or exact typed phrase 'TOAN QUYEN' / 'I UNDERSTAND'
        in interactive terminals. Exits 1 with zero filesystem mutations if unconfirmed.
    #>
    Show-FullAccessDangerWarning
    if ($ConfirmFullAccess.IsPresent) {
        Write-Host "[WARN] -ConfirmFullAccess acknowledged: proceeding with Full Access (danger-full-access / never)." -ForegroundColor Yellow
        return
    }
    $isNonInteractiveHost = $false
    try {
        if ([Console]::IsInputRedirected -or (-not [System.Environment]::UserInteractive)) {
            $isNonInteractiveHost = $true
        }
    } catch {
        $isNonInteractiveHost = $true
    }
    if ($isNonInteractiveHost) {
        Write-Host "[FAIL] REFUSED (fail-closed): -CliMode FullAccess requires explicit -ConfirmFullAccess in non-interactive/non-TTY sessions. Zero files modified." -ForegroundColor Red
        exit 1
    }
    $typed = Read-Host "Nhap chinh xac 'TOAN QUYEN' hoac 'I UNDERSTAND' de xac nhan bat Toan quyen (de trong de huy)"
    $trimmed = if ($null -ne $typed) { $typed.Trim() } else { '' }
    if (($trimmed -cne 'TOAN QUYEN') -and ($trimmed -cne 'I UNDERSTAND')) {
        Write-Host "[FAIL] REFUSED / CANCELLED (fail-closed): Cum tu xac nhan khong khop (yeu cau chinh xac 'TOAN QUYEN' hoac 'I UNDERSTAND'). Zero files modified." -ForegroundColor Red
        exit 1
    }
    Write-Host "[WARN] Interactive Full Access confirmation accepted: proceeding with danger-full-access / never." -ForegroundColor Yellow
}

function Get-ExistingLane2CliSettings([string]$ConfigPath) {
    <#
    .SYNOPSIS
        Strictly read-only parser for existing Lane 2 approval_policy, sandbox_mode, and
        [sandbox_workspace_write] presence so -CliMode Config preserves user settings verbatim.
    #>
    $info = [PSCustomObject]@{
        Exists                          = $false
        HasSandboxMode                  = $false
        SandboxModeValue                = ''
        HasApprovalPolicy               = $false
        ApprovalPolicyValue             = ''
        HasSandboxWorkspaceWriteSection = $false
    }
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        return $info
    }
    Assert-NotReparsePoint -PathValue $ConfigPath -Label 'existing Lane 2 config.toml'
    $info.Exists = $true
    $raw = [string](Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrEmpty($raw)) { return $info }

    $inSection = $false
    $inMultiline = $false
    $bracketDepth = 0
    $multilineQuote = ''

    foreach ($line in ($raw -split "\r?\n")) {
        if ($inMultiline) {
            Update-TomlMultilineState -Text $line -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            if ($bracketDepth -eq 0 -and $multilineQuote -eq '') { $inMultiline = $false }
            continue
        }
        $noComment = (Remove-TomlInlineComment $line).Trim()
        if ([string]::IsNullOrWhiteSpace($noComment)) { continue }

        if ($noComment -match '^\[\[(.+)\]\]$') {
            $inSection = $true
            continue
        }
        if ($noComment -match '^\[(.+)\]$') {
            $inSection = $true
            $hdr = $Matches[1].Trim().ToLowerInvariant()
            if ($hdr -eq 'sandbox_workspace_write') {
                $info.HasSandboxWorkspaceWriteSection = $true
            } elseif ($hdr -eq 'approval_policy' -or $hdr -like 'approval_policy.*') {
                $info.HasApprovalPolicy = $true
                if ([string]::IsNullOrEmpty($info.ApprovalPolicyValue)) { $info.ApprovalPolicyValue = 'granular' }
            }
            continue
        }

        if (-not $inSection) {
            $kv = [regex]::Match($line, '^\s*([A-Za-z0-9_-]+)\s*=(.*)$')
            if ($kv.Success) {
                $k = $kv.Groups[1].Value
                $rhs = $kv.Groups[2].Value
                $bracketDepth = 0
                $multilineQuote = ''
                Update-TomlMultilineState -Text $rhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
                $startsMultiline = ($bracketDepth -gt 0 -or $multilineQuote -ne '')
                if ($startsMultiline) { $inMultiline = $true }

                $rhsClean = (Remove-TomlInlineComment $rhs).Trim()
                $valStr = ''
                $vm = [regex]::Match($rhsClean, '^(?:"((?:[^"\\]|\\.)*)"|''([^'']*)'')\s*$')
                if ($vm.Success) {
                    $valStr = if ($vm.Groups[1].Success) { Unescape-TomlBasicString $vm.Groups[1].Value } else { $vm.Groups[2].Value }
                } elseif ($rhsClean.StartsWith('{')) {
                    $valStr = 'granular'
                }

                if ($k -ceq 'sandbox_mode') {
                    $info.HasSandboxMode = $true
                    $info.SandboxModeValue = $valStr
                } elseif ($k -ceq 'approval_policy') {
                    $info.HasApprovalPolicy = $true
                    $info.ApprovalPolicyValue = if ($valStr) { $valStr } else { 'custom' }
                }
            }
        }
    }
    return $info
}

function Get-MergedFeaturesSectionLines {
    <#
    .SYNOPSIS
        Non-destructively merges managed Codex [features] flags with any pre-existing user
        [features] entries (e.g., multi_agent_v2, plugins, hooks, fast_mode, apps, browser_use)
        so native user feature toggles are never wiped during setup.
    #>
    param(
        [AllowEmptyString()][string]$ExistingConfigPath = '',
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ManagedFeatureMap
    )
    $managedKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $outLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($mk in $ManagedFeatureMap.Keys) {
        [void]$managedKeys.Add([string]$mk)
        $outLines.Add("$mk = $($ManagedFeatureMap[$mk])")
    }

    if ([string]::IsNullOrWhiteSpace($ExistingConfigPath) -or -not (Test-Path -LiteralPath $ExistingConfigPath -PathType Leaf)) {
        return , $outLines
    }
    Assert-NotReparsePoint -PathValue $ExistingConfigPath -Label 'existing config.toml [features] merge'
    $raw = [string](Get-Content -LiteralPath $ExistingConfigPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrEmpty($raw)) { return , $outLines }

    $seenUserKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $inFeatures = $false
    $inMultiline = $false
    $keepMultiline = $false
    $bracketDepth = 0
    $multilineQuote = ''

    foreach ($line in ($raw -split "\r?\n")) {
        if ($inMultiline) {
            if ($keepMultiline) { $outLines.Add($line) }
            Update-TomlMultilineState -Text $line -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            if ($bracketDepth -eq 0 -and $multilineQuote -eq '') {
                $inMultiline = $false
                $keepMultiline = $false
            }
            continue
        }
        $noComment = (Remove-TomlInlineComment $line).Trim()
        if ($noComment -match '^\[\[(.+)\]\]$') {
            $inFeatures = $false
            continue
        }
        if ($noComment -match '^\[(.+)\]$') {
            $inFeatures = ($Matches[1].Trim().ToLowerInvariant() -eq 'features')
            continue
        }
        if (-not $inFeatures) { continue }
        if ([string]::IsNullOrWhiteSpace($noComment)) { continue }

        $kv = [regex]::Match($line, '^\s*([A-Za-z0-9_-]+|"[^"]+"|''[^'']+'')\s*=(.*)$')
        if ($kv.Success) {
            $kName = $kv.Groups[1].Value.Trim('"', "'")
            $rhs = $kv.Groups[2].Value
            $keep = (-not $managedKeys.Contains($kName)) -and $seenUserKeys.Add($kName)
            if ($keep) { $outLines.Add($line.Trim()) }
            $bracketDepth = 0
            $multilineQuote = ''
            Update-TomlMultilineState -Text $rhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            if ($bracketDepth -gt 0 -or $multilineQuote -ne '') {
                $inMultiline = $true
                $keepMultiline = $keep
            }
        }
    }
    return , $outLines
}

# ============================================================================
# Pre-Flight Input Validation (Fail-Closed Before Any Disk Activity)
# ============================================================================

$KitRoot = Resolve-CanonicalLongPath -PathValue (Join-Path $PSScriptRoot '..')

# Convenience CLI gateway flag: -ConfigureCliGateway automatically enables gateway configuration
# targeting Lane 2 (Codex CLI) unless -GatewayTargetLane was explicitly passed as 'Both',
# guaranteeing Lane 1 (~/.codex/config.toml, Codex Desktop Primary Account) stays 100% untouched.
if ($ConfigureCliGateway.IsPresent) {
    $ConfigureGateway = [switch]$true
    if ($GatewayTargetLane -ne 'Both') {
        $GatewayTargetLane = 'Lane2'
    }
}

# Validate and normalize all path parameters upfront (including relative paths, forward/trailing slashes, and Win32 8.3 long-path expansion).
$RepoPath       = Assert-SafeWindowsPath -PathValue $RepoPath       -ParamName 'RepoPath'
$CodexPath      = Assert-SafeWindowsPath -PathValue $CodexPath      -ParamName 'CodexPath' -AllowEmpty
$Lane1Home      = Assert-SafeWindowsPath -PathValue $Lane1Home      -ParamName 'Lane1Home' -DisallowRootOrProfile
$Lane2Home      = Assert-SafeWindowsPath -PathValue $Lane2Home      -ParamName 'Lane2Home' -DisallowRootOrProfile
$LocalBin       = Assert-SafeWindowsPath -PathValue $LocalBin       -ParamName 'LocalBin'  -DisallowRootOrProfile
$CargoTargetDir = Assert-SafeWindowsPath -PathValue $CargoTargetDir -ParamName 'CargoTargetDir' -DisallowRootOrProfile
$Lane2WorktreePath = Assert-SafeWindowsPath -PathValue $Lane2WorktreePath -ParamName 'Lane2WorktreePath' -AllowEmpty -DisallowRootOrProfile

# Verify RepoPath exists as a real filesystem directory (not a file or non-filesystem PSDrive).
if (-not (Test-Path -LiteralPath $RepoPath -PathType Container)) {
    throw "Target -RepoPath does not exist or is not a directory: $RepoPath"
}
$repoItem = Get-Item -LiteralPath $RepoPath -Force
if ($repoItem.PSProvider.Name -ne 'FileSystem') {
    throw "Target -RepoPath must be a local filesystem directory: $RepoPath"
}
# Re-canonicalize via GetLongPathNameW because PowerShell's Resolve-Path preserves 8.3 short names.
$RepoPath = Resolve-CanonicalLongPath -PathValue (Resolve-Path -LiteralPath $RepoPath).ProviderPath

# Lane 1 and Lane 2 homes must be distinct, non-overlapping paths to prevent circular NTFS Junctions.
if (Test-PathsOverlap -PathA $Lane1Home -PathB $Lane2Home) {
    throw "Invalid configuration: -Lane1Home ('$Lane1Home') and -Lane2Home ('$Lane2Home') must not be identical or nested inside each other."
}

# Refuse symlink/reparse-point roots (including dangling links) for Lane1Home, Lane2Home, and LocalBin
# so installer writes and future rollback deletions cannot be redirected outside the intended Codex directories.
foreach ($rootCheck in @(@('Lane1Home', $Lane1Home), @('Lane2Home', $Lane2Home), @('LocalBin', $LocalBin))) {
    Assert-NotReparsePoint -PathValue $rootCheck[1] -Label "-$($rootCheck[0])"
}

# ============================================================================
# Fast Maintenance Path: -ReapplyAclOnly
# ============================================================================
# WHY: When Codex Desktop or CLI later rewrites config.toml (e.g. `codex features`)
# or recreates auth.json via atomic replacement, Windows re-inherits parent DACLs.
# -ReapplyAclOnly re-locks existing sensitive files across both lanes in <1s without
# touching templates, Junctions, wrappers, or PATH.
if ($ReapplyAclOnly) {
    Write-Step 'Re-applying fail-closed two-step NTFS ACL lockdown across existing sensitive files...'
    $aclTargets = New-Object 'System.Collections.Generic.List[string]'
    foreach ($candidate in @(
        (Join-Path $Lane1Home 'auth.json'),
        (Join-Path $Lane1Home 'config.toml'),
        (Join-Path $Lane1Home 'config.backup.toml'),
        (Join-Path $Lane2Home 'auth.json'),
        (Join-Path $Lane2Home 'config.toml'),
        (Join-Path $Lane2Home 'config.backup.toml')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $aclTargets.Add($candidate) }
    }
    $rbDir = Join-Path $Lane2Home '.rollback'
    if (Test-Path -LiteralPath $rbDir -PathType Container) {
        Assert-NotReparsePoint -PathValue $rbDir -Label '.rollback directory'
        foreach ($mf in @(Get-ChildItem -LiteralPath $rbDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            $aclTargets.Add($mf.FullName)
        }
    }
    foreach ($tFile in $aclTargets) {
        if (-not $script:IsDryRun) {
            Protect-SensitiveFileAcl $tFile
            Write-Host "    Locked NTFS DACL: $tFile" -ForegroundColor Green
        } else {
            Write-Host "    [DRY-RUN] Would lock NTFS DACL: $tFile" -ForegroundColor DarkGray
        }
    }
    Write-Host "`n[OK] ACL re-lock finished ($($aclTargets.Count) file(s) processed)." -ForegroundColor Green
    exit 0
}

# Validate optional TOML string parameters against control characters / TOML newline injection.
Assert-NoControlChars -Value $OfficialModel       -ParamName 'OfficialModel'
Assert-NoControlChars -Value $OfficialReasoning   -ParamName 'OfficialReasoning'
Assert-NoControlChars -Value $OfficialServiceTier -ParamName 'OfficialServiceTier'
Assert-NoControlChars -Value $GatewayProviderName -ParamName 'GatewayProviderName'
Assert-NoControlChars -Value $GatewayModel        -ParamName 'GatewayModel'

if ($UseGitWorktree) {
    Assert-SafeGitBranchName -BranchName $Lane2Branch
}

if ($ConfigureGateway) {
    Assert-SafeGatewayUrl -Url $GatewayBaseUrl
    if ([string]::IsNullOrWhiteSpace($GatewayProviderName) -or ($GatewayProviderName -match '[\[\]]')) {
        throw "Invalid -GatewayProviderName '$GatewayProviderName': must be non-empty and must not contain '[' or ']'."
    }
    if (-not ($GatewayApiKeyEnv -match '^[A-Za-z_][A-Za-z0-9_]*$')) {
        throw "Invalid environment variable name for -GatewayApiKeyEnv: $GatewayApiKeyEnv"
    }
}

# Fail-closed Full Access danger warning & confirmation gate BEFORE any disk activity.
if ($CliMode -eq 'FullAccess') {
    Confirm-FullAccessOrExit
}

# Verify required kit templates are present before starting any installation mutations.
$rulesTemplate  = Join-Path $KitRoot 'templates\default.rules'
$lane1AgentsSrc = Join-Path $KitRoot 'templates\AGENTS.lane1.md'
$lane2AgentsSrc = Join-Path $KitRoot 'templates\AGENTS.lane2.md'
$bridgeSrc      = Join-Path $KitRoot 'templates\DUAL_LANE_BRIDGE.md'
foreach ($reqTpl in @($rulesTemplate, $lane1AgentsSrc, $lane2AgentsSrc)) {
    if (-not (Test-Path -LiteralPath $reqTpl -PathType Leaf)) {
        throw "Missing required kit template file: $reqTpl"
    }
}
if ($InstallBridgeTemplate -and -not (Test-Path -LiteralPath $bridgeSrc -PathType Leaf)) {
    throw "Missing required bridge template file: $bridgeSrc"
}

Write-Host "=== Codex Dual-Lane & Security Kit Installer ===" -ForegroundColor Green
if ($script:IsDryRun) { Write-Host "[DRY-RUN MODE] No files, Junctions, or environment variables will be modified." -ForegroundColor Yellow }

# ============================================================================
# Step 1: Detect Real Codex Executable & Version
# ============================================================================
Write-Step 'Detecting real Codex installation on this machine...'
$resolvedCodex = Resolve-CodexExecutable -ExplicitPath $CodexPath -ExcludedDir $LocalBin
$CodexExe = Assert-SafeWindowsPath -PathValue $resolvedCodex.Path -ParamName 'CodexPath'
$CodexSource = $resolvedCodex.Source
$prevVerPref = $ErrorActionPreference
$codexVersion = 'unknown'
try {
    $ErrorActionPreference = 'Continue'
    $verLines = @(& $CodexExe --version 2>&1 | Where-Object { [string]$_ -notmatch '^WARNING:' })
    if ($verLines.Count -gt 0) { $codexVersion = [string]$verLines[0] }
} finally {
    $ErrorActionPreference = $prevVerPref
    $global:LASTEXITCODE = 0
}
Write-Host "    Source  : $CodexSource"
Write-Host "    Binary  : $CodexExe"
Write-Host "    Version : $codexVersion"

# ============================================================================
# Step 2: Check NTFS Filesystem Compatibility & Free Disk Space
# ============================================================================
Write-Step 'Checking filesystem compatibility (NTFS) and free disk space...'
$homeRoot = [System.IO.Path]::GetPathRoot($Lane2Home)
$homeDrive = $homeRoot.TrimEnd(':\')
if ($homeDrive -notmatch '^[A-Za-z]$') {
    throw "Lane2Home ('$Lane2Home') must be located on a local NTFS drive letter (UNC/network paths do not support NTFS Directory Junctions)."
}
$homeVol = $null
try { $homeVol = Get-Volume -DriveLetter $homeDrive -ErrorAction SilentlyContinue } catch { $homeVol = $null }
if ($homeVol -and $homeVol.FileSystem -ne 'NTFS') {
    throw "Drive ${homeDrive}: uses $($homeVol.FileSystem). NTFS is required for Directory Junctions. Pass -Lane2Home on an NTFS drive."
}
$homeFs = if ($homeVol -and $homeVol.FileSystem) { $homeVol.FileSystem } else { 'Unknown' }
$homeFreeGB = if ($homeVol) { [math]::Round($homeVol.SizeRemaining / 1GB, 2) } else { 0 }
Write-Host ("    Home drive {0}: FileSystem={1}, Free={2} GB" -f $homeDrive, $homeFs, $homeFreeGB)

$targetDrive = ([System.IO.Path]::GetPathRoot($CargoTargetDir)).TrimEnd(':\')
$targetVol = $null
if ($targetDrive -match '^[A-Za-z]$') {
    try { $targetVol = Get-Volume -DriveLetter $targetDrive -ErrorAction SilentlyContinue } catch { $targetVol = $null }
}
if ($targetVol) {
    $freeGB = [math]::Round($targetVol.SizeRemaining / 1GB, 2)
    Write-Host ("    Build drive {0}: Free={1} GB (CARGO_TARGET_DIR={2})" -f $targetDrive, $freeGB, $CargoTargetDir)
    if ($freeGB -lt 10) {
        Write-Warning "Drive ${targetDrive}: has less than 10 GB free ($freeGB GB). For large Rust projects, pass -CargoTargetDir on a drive with more space."
    }
}

# ============================================================================
# Step 3: Dynamically Probe Supported Codex Feature Flags
# ============================================================================
# NOTE: Even in -DryRun mode, we probe `codex features list` using an isolated disposable
# temp directory (deleted in `finally`) so preview output reflects your real binary's capabilities
# without touching Lane1Home, Lane2Home, LocalBin, or RepoPath.
Write-Step 'Probing supported Codex feature flags from your installed binary...'
$probeDir = Join-Path $env:TEMP ('codex-feature-probe-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
[void][System.IO.Directory]::CreateDirectory($probeDir)
try {
    $supportedFeatures = Get-SupportedCodexFeatures -ExePath $CodexExe -ProbeHome $probeDir
} finally {
    Remove-Item -LiteralPath $probeDir -Recurse -Force -WhatIf:$false -ErrorAction SilentlyContinue
}
Write-Host ("    Detected {0} feature flags (daemon_auto_start={1}, goals={2}, memories={3})" -f `
    $supportedFeatures.Count, `
    $supportedFeatures.ContainsKey('daemon_auto_start'), `
    $supportedFeatures.ContainsKey('goals'), `
    $supportedFeatures.ContainsKey('memories'))

# ============================================================================
# Step 4: Optional Isolated Git Worktree for Lane 2 (OS-Level Write Boundary)
# ============================================================================
$effectiveLane2Repo = $RepoPath
if ($UseGitWorktree) {
    Write-Step 'Configuring isolated Git worktree for Lane 2 (OS-level workspace-write boundary)...'
    if (-not (Get-Command 'git' -ErrorAction SilentlyContinue)) {
        throw '-UseGitWorktree requires Git to be installed and available in PATH.'
    }

    # Verify RepoPath is a valid Git work tree with at least one commit (HEAD).
    $prevGitPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $isGitTree = (& git -C $RepoPath rev-parse --is-inside-work-tree 2>$null) -join ''
        if ($LASTEXITCODE -ne 0 -or $isGitTree.Trim() -ne 'true') {
            throw "-UseGitWorktree requires -RepoPath to be inside a valid Git repository: $RepoPath"
        }
        $null = & git -C $RepoPath rev-parse --verify HEAD 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "-UseGitWorktree requires at least one commit (valid HEAD) in repository: $RepoPath"
        }
        # Double-check branch name against Git's own ref validator.
        $null = & git -C $RepoPath check-ref-format --branch $Lane2Branch 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Git rejected -Lane2Branch '$Lane2Branch' as an invalid branch name."
        }
    } finally {
        $ErrorActionPreference = $prevGitPref
        $global:LASTEXITCODE = 0
    }

    $wtTarget = if ($Lane2WorktreePath) {
        $Lane2WorktreePath
    } else {
        Assert-SafeWindowsPath -PathValue "${RepoPath}-lane2" -ParamName 'Lane2WorktreePath' -DisallowRootOrProfile
    }

    # Prevent nesting Lane 2's worktree inside Lane 1's repository (which would defeat workspace-write isolation).
    if (Test-PathsOverlap -PathA $RepoPath -PathB $wtTarget) {
        throw "Unsafe -Lane2WorktreePath '$wtTarget': worktree must not equal or nest inside -RepoPath ('$RepoPath')."
    }
    Assert-NotReparsePoint -PathValue $wtTarget -Label 'Lane2WorktreePath'

    if (Test-Path -LiteralPath $wtTarget) {
        if (-not (Test-Path -LiteralPath $wtTarget -PathType Container)) {
            throw "Existing path at -Lane2WorktreePath is a file, not a directory: $wtTarget"
        }
        $effectiveLane2Repo = Resolve-CanonicalLongPath -PathValue (Resolve-Path -LiteralPath $wtTarget).Path
        if (-not (Test-Path -LiteralPath (Join-Path $effectiveLane2Repo '.git'))) {
            Write-Warning "Existing directory '$effectiveLane2Repo' does not contain a .git pointer; verify it is a valid Git worktree."
        }
        Write-Host "    Existing Lane 2 worktree: $effectiveLane2Repo"
    } else {
        if (-not $script:IsDryRun) {
            $prevGitPref = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                # Check if the branch already exists locally: attach cleanly instead of force-resetting with -B.
                $null = & git -C $RepoPath show-ref --verify --quiet "refs/heads/$Lane2Branch" 2>$null
                $branchExists = ($LASTEXITCODE -eq 0)

                # Use explicit argument array with '--' terminator so paths cannot be parsed as Git flags.
                $gitAddArgs = if ($branchExists) {
                    @('-C', $RepoPath, 'worktree', 'add', '--', $wtTarget, $Lane2Branch)
                } else {
                    @('-C', $RepoPath, 'worktree', 'add', '-b', $Lane2Branch, '--', $wtTarget, 'HEAD')
                }
                & git @gitAddArgs
                if ($LASTEXITCODE -ne 0) {
                    throw "Failed to create Git worktree at '$wtTarget' for branch '$Lane2Branch' (exit $LASTEXITCODE)."
                }
            } finally {
                $ErrorActionPreference = $prevGitPref
                $global:LASTEXITCODE = 0
            }
            $effectiveLane2Repo = Resolve-CanonicalLongPath -PathValue (Resolve-Path -LiteralPath $wtTarget).Path
            Write-Host "    Created Lane 2 Git worktree: $effectiveLane2Repo (branch: $Lane2Branch)"
        } else {
            $effectiveLane2Repo = Resolve-CanonicalLongPath -PathValue $wtTarget
            Write-Host "    [DRY-RUN] Would create Lane 2 Git worktree: $effectiveLane2Repo (branch: $Lane2Branch)"
        }
    }
}

# ============================================================================
# Step 5: Prepare Directories & Initialize Crash-Safe Incremental Rollback Journal
# ============================================================================
Write-Step "Preparing directories: $Lane1Home, $Lane2Home, $LocalBin..."
foreach ($dir in @($Lane1Home, (Join-Path $Lane1Home 'rules'), $Lane2Home, (Join-Path $Lane2Home 'rules'), $LocalBin)) {
    Ensure-Directory $dir
}

# Initialize .rollback\latest.json BEFORE creating any NTFS Junctions or modifying any files so
# that even an interrupted mid-install run (Ctrl+C, exception, power loss) can recover cleanly.
$script:ManifestContext = [PSCustomObject]@{
    Lane1Home        = $Lane1Home
    Lane2Home        = $Lane2Home
    LocalBin         = $LocalBin
    RepoPath         = $RepoPath
    Lane2Worktree    = if ($UseGitWorktree) { $effectiveLane2Repo } else { '' }
    GatewayApiKeyEnv = if ($ConfigureGateway) { $GatewayApiKeyEnv } else { '' }
}
$script:RollbackDir = Resolve-CanonicalLongPath -PathValue (Join-Path $Lane2Home '.rollback')
Assert-NotReparsePoint -PathValue $script:RollbackDir -Label '.rollback directory'
$snapCandidate = Join-Path $script:RollbackDir "snapshot-$($script:InstallStamp).json"
$snapSuffix = 1
while (Test-Path -LiteralPath $snapCandidate) {
    $snapCandidate = Join-Path $script:RollbackDir "snapshot-$($script:InstallStamp)-$snapSuffix.json"
    $snapSuffix++
}
$script:RollbackSnapPath   = Resolve-CanonicalLongPath -PathValue $snapCandidate
$script:RollbackLatestPath = Resolve-CanonicalLongPath -PathValue (Join-Path $script:RollbackDir 'latest.json')
if (-not $script:IsDryRun) {
    [void][System.IO.Directory]::CreateDirectory($script:RollbackDir)
    Save-RollbackManifestCheckpoint -Stage 'initialized' -Completed $false
}

# ============================================================================
# Step 6: Create NTFS Directory Junctions for Shared Brain Directories
# ============================================================================
# WHY: NTFS Directory Junctions share memories, sessions, skills, and plugins across Lane 1 and
# Lane 2 in real time with zero duplication while keeping config.toml and auth.json strictly separate.
Write-Step 'Linking shared memories, sessions, skills, and plugins via NTFS Junctions...'
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
foreach ($name in $sharedDirs) {
    $src = Resolve-CanonicalLongPath -PathValue (Join-Path $Lane1Home $name)
    $dst = Resolve-CanonicalLongPath -PathValue (Join-Path $Lane2Home $name)
    if (-not (Test-Path -LiteralPath $src)) {
        if (-not $script:IsDryRun) { [void][System.IO.Directory]::CreateDirectory($src) }
    }
    if (Test-Path -LiteralPath $dst) {
        $item = Get-Item -LiteralPath $dst -Force
        if ($item.LinkType -eq 'Junction' -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            $existingTarget = (@($item.Target) | Select-Object -First 1)
            $cleanExisting  = if ($existingTarget) { ($existingTarget -replace '^\\\?\?\\', '') } else { '' }
            $normExisting   = if ($cleanExisting) { (Resolve-CanonicalLongPath -PathValue $cleanExisting).TrimEnd('\').ToLowerInvariant() } else { '' }
            $normExpected   = $src.TrimEnd('\').ToLowerInvariant()
            if ($normExisting -and ($normExisting -ne $normExpected)) {
                Write-Warning "Existing Junction/link '$dst' points to '$existingTarget' instead of expected '$src'; leaving untouched."
            } else {
                Write-Host "    Already linked (pre-existing): $name -> $existingTarget"
            }
            # SECURITY & ROLLBACK INVARIANT: Pre-existing user links were NOT created by this install.
            # Record CreatedByKit=$false (and do NOT add to TrackedJunctions) so rollback preserves them intact.
            $script:SharedLinkRecords.Add([PSCustomObject]@{
                Name          = $name
                LinkPath      = $dst
                PriorState    = 'preexisting_link'
                CreatedByKit  = $false
                BackupDirPath = ''
            })
            Save-RollbackManifestCheckpoint -Stage "junction:$name"
            continue
        }
        # Never delete a pre-existing real directory in Lane 2; move it safely aside with a unique backup name
        # and record the EXACT BackupDirPath in the manifest so rollback never guesses by wildcard sorting.
        $dirBackup = Resolve-CanonicalLongPath -PathValue (Get-UniqueBackupPath $dst)
        if (-not $script:IsDryRun) { Move-Item -LiteralPath $dst -Destination $dirBackup -Force }
        Write-Host "    Moved existing directory safely to: $dirBackup" -ForegroundColor DarkGray
        $script:SharedLinkRecords.Add([PSCustomObject]@{
            Name          = $name
            LinkPath      = $dst
            PriorState    = 'preexisting_dir'
            CreatedByKit  = $true
            BackupDirPath = $dirBackup
        })
        if (-not $script:TrackedJunctions.Contains($name)) {
            $script:TrackedJunctions.Add($name)
        }
        Save-RollbackManifestCheckpoint -Stage "backup-dir:$name"
    } else {
        $script:SharedLinkRecords.Add([PSCustomObject]@{
            Name          = $name
            LinkPath      = $dst
            PriorState    = 'absent'
            CreatedByKit  = $true
            BackupDirPath = ''
        })
        if (-not $script:TrackedJunctions.Contains($name)) {
            $script:TrackedJunctions.Add($name)
        }
    }
    if (-not $script:IsDryRun) { New-Item -ItemType Junction -Path $dst -Target $src | Out-Null }
    Save-RollbackManifestCheckpoint -Stage "junction:$name"
    Write-Host "    Linked: $dst -> $src"
}

# ============================================================================
# Step 7: Install Starlark Command Firewall (rules/default.rules) into Both Lanes
# ============================================================================
Write-Step 'Installing Starlark command firewall (rules/default.rules) into both lanes...'
foreach ($homeDir in @($Lane1Home, $Lane2Home)) {
    $rulesDir = Join-Path $homeDir 'rules'
    $targetRule = Join-Path $rulesDir 'default.rules'
    Assert-NotReparsePoint -PathValue $rulesDir   -Label 'rules directory'
    Assert-NotReparsePoint -PathValue $targetRule -Label 'rules\default.rules'
    Backup-IfExists $targetRule
    if (-not $script:IsDryRun) {
        Copy-Item -LiteralPath $rulesTemplate -Destination $targetRule -Force
        Save-RollbackManifestCheckpoint -Stage 'write:default.rules'
    }
    Write-Host "    Installed: $targetRule"
}

# ============================================================================
# Step 8: Install Anti-Prompt-Injection & Static-Analysis-Only AGENTS.md Guardrails
# ============================================================================
Write-Step 'Installing anti-prompt-injection & dual-lane AGENTS.md guardrails...'
$lane1AgentsDst = Join-Path $Lane1Home 'AGENTS.md'
$lane2AgentsDst = Join-Path $Lane2Home 'AGENTS.md'
Assert-NotReparsePoint -PathValue $lane1AgentsDst -Label 'Lane 1 AGENTS.md'
Assert-NotReparsePoint -PathValue $lane2AgentsDst -Label 'Lane 2 AGENTS.md'
Backup-IfExists $lane1AgentsDst
if (-not $script:IsDryRun) {
    Copy-Item -LiteralPath $lane1AgentsSrc -Destination $lane1AgentsDst -Force
    Save-RollbackManifestCheckpoint -Stage 'write:lane1-AGENTS.md'
}
Backup-IfExists $lane2AgentsDst
if (-not $script:IsDryRun) {
    Copy-Item -LiteralPath $lane2AgentsSrc -Destination $lane2AgentsDst -Force
    Save-RollbackManifestCheckpoint -Stage 'write:lane2-AGENTS.md'
}
Write-Host "    Installed: $lane1AgentsDst"
Write-Host "    Installed: $lane2AgentsDst"

# ============================================================================
# Step 9: Non-Destructively Merge & Atomically Write Lane 2 config.toml
# ============================================================================
$configureGatewayLane1 = $ConfigureGateway.IsPresent -and ($GatewayTargetLane -in @('Lane1', 'Both'))
$configureGatewayLane2 = $ConfigureGateway.IsPresent -and ($GatewayTargetLane -in @('Lane2', 'Both'))
$suppliedSecretForGuard = ''

if ($ConfigureGateway) {
    if ($GatewayApiKey) {
        $suppliedSecretForGuard = $GatewayApiKey
        Write-Warning "Passing -GatewayApiKey on the command line may leave the key in PowerShell history. Prefer -PromptGatewayApiKey or setting `$env:$GatewayApiKeyEnv before running."
        if (-not $script:IsDryRun) {
            [System.Environment]::SetEnvironmentVariable($GatewayApiKeyEnv, $GatewayApiKey, 'User')
            Set-Item -Path "Env:\$GatewayApiKeyEnv" -Value $GatewayApiKey
            Write-Host "    Stored API key in User environment variable: $GatewayApiKeyEnv (not written to config.toml)"
        } else {
            Write-Host "    [DRY-RUN] Would store API key in User environment variable: $GatewayApiKeyEnv (not written to config.toml)"
        }
    } elseif ($PromptGatewayApiKey) {
        if ($script:IsDryRun) {
            Write-Host "    [DRY-RUN] Would prompt securely (AsSecureString) and store key in User env: $GatewayApiKeyEnv"
        } else {
            $sec = Read-Host -Prompt "Enter API key for $GatewayProviderName (stored in User env $GatewayApiKeyEnv, never in config.toml)" -AsSecureString
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            $plainKey = $null
            try {
                $plainKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                if ($plainKey) {
                    $suppliedSecretForGuard = $plainKey
                    [System.Environment]::SetEnvironmentVariable($GatewayApiKeyEnv, $plainKey, 'User')
                    Set-Item -Path "Env:\$GatewayApiKeyEnv" -Value $plainKey
                    Write-Host "    Stored API key securely in User environment variable: $GatewayApiKeyEnv"
                } else {
                    Write-Warning "No API key entered; ensure User env '$GatewayApiKeyEnv' is set before launching target lane ($GatewayTargetLane)."
                }
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                $plainKey = $null
            }
        }
    }
}

if ($configureGatewayLane2) {
    Write-Step "Merging & writing Lane 2 CLI config.toml with API Key / Gateway (env_key = `"$GatewayApiKeyEnv`", compatible with OAuth Login)..."
} else {
    Write-Step 'Merging & writing Lane 2 Official OpenAI config.toml (non-destructive TOML merge)...'
}
$lane2ConfigPath = Join-Path $Lane2Home 'config.toml'
Assert-NotReparsePoint -PathValue $lane2ConfigPath -Label 'Lane 2 config.toml'
# Strictly read-only harvest of `[projects.*]` trust boundaries from Lane 2 and Lane 1 (Codex Desktop):
#   - `trusted` stays `trusted`, `untrusted` stays `untrusted` (never promoted to `trusted`).
#   - Missing/unrecognized `trust_level` entries are skipped from Lane 1 and preserved verbatim on Lane 2.
#   - `-RepoPath` (and optional Lane 2 worktree) is ensured `trust_level = "trusted"` ONLY with explicit `-TrustRepoPath`.
# SECURITY: trust is NEVER raised implicitly. -RepoPath / the Lane 2 worktree are written as `trusted`
# ONLY when the user explicitly passes -TrustRepoPath; otherwise their current trust_level (trusted,
# untrusted, or unset) is preserved exactly and Codex prompts for trust on first use.
$repoTrustTargets = if ($TrustRepoPath) { @($RepoPath, $effectiveLane2Repo) } else { @() }
if ($TrustRepoPath) {
    Write-Host "    [INFO] -TrustRepoPath (explicit opt-in): '$RepoPath' will be recorded as trust_level = ""trusted""." -ForegroundColor Yellow
} else {
    Write-Host "    [INFO] Project trust left unchanged for '$RepoPath' (pass -TrustRepoPath to explicitly mark it trusted; Codex will ask on first use otherwise)." -ForegroundColor DarkGray
}
$lane2ProjectState = Resolve-MergedProjectTrustState `
    -PrimaryConfigPath $lane2ConfigPath `
    -SecondaryConfigPath (Join-Path $Lane1Home 'config.toml') `
    -EnsureTrustedPaths $repoTrustTargets

if ($configureGatewayLane2) {
    $lane2CleanBackup = Join-Path $Lane2Home 'config.backup.toml'
    Assert-NotReparsePoint -PathValue $lane2CleanBackup -Label 'Lane 2 config.backup.toml'
    if ((Test-Path -LiteralPath $lane2ConfigPath -PathType Leaf) -and -not (Test-Path -LiteralPath $lane2CleanBackup)) {
        Backup-IfExists $lane2CleanBackup
        if (-not $script:IsDryRun) {
            Copy-Item -LiteralPath $lane2ConfigPath -Destination $lane2CleanBackup -Force
            Protect-SensitiveFileAcl $lane2CleanBackup
            Save-RollbackManifestCheckpoint -Stage 'write:lane2-config.backup.toml'
        }
        Write-Host "    Saved clean original backup: $lane2CleanBackup"
    }
}

$existingCliSettings = Get-ExistingLane2CliSettings -ConfigPath $lane2ConfigPath

$managedTopKeys = New-Object 'System.Collections.Generic.List[string]'
$managedTopKeys.Add('windows_wsl_setup_acknowledged')

$lane2TopLines = New-Object 'System.Collections.Generic.List[string]'
if ($configureGatewayLane2) {
    $managedTopKeys.AddRange([string[]]@('model_provider', 'web_search', 'disable_response_storage'))
    $lane2TopLines.Add('# Lane 2 Codex CLI configuration (Flexible OAuth Login + API Key Gateway via env_key)')
    $lane2TopLines.Add("model_provider = `"$(Escape-TomlBasicString $GatewayProviderName)`"")
    $effectiveLane2Model = if ($GatewayModel) { $GatewayModel } else { $OfficialModel }
    if ($effectiveLane2Model) {
        $managedTopKeys.Add('model')
        $managedTopKeys.Add('review_model')
        $lane2TopLines.Add("model = `"$(Escape-TomlBasicString $effectiveLane2Model)`"")
        $lane2TopLines.Add("review_model = `"$(Escape-TomlBasicString $effectiveLane2Model)`"")
    }
    $lane2TopLines.Add('web_search = "live"')
    $lane2TopLines.Add('disable_response_storage = true')
} else {
    $lane2TopLines.Add('# Official OpenAI / ChatGPT Codex CLI configuration (LANE 2 - supports Login & API Key)')
    $lane2TopLines.Add('# Leave model/service_tier unset unless overridden so Codex uses your account''s real defaults.')
    if ($OfficialModel) {
        $lane2TopLines.Add("model = `"$(Escape-TomlBasicString $OfficialModel)`"")
        $managedTopKeys.Add('model')
    }
}

$manageSandboxWorkspaceWrite = $true
$dropGranularApprovalSection = $false
$effectiveApprovalForSync = $ApprovalPolicy
$cliModeDesc = ''

switch ($CliMode) {
    'FullAccess' {
        $managedTopKeys.Add('sandbox_mode')
        $managedTopKeys.Add('approval_policy')
        $lane2TopLines.Add('sandbox_mode = "danger-full-access"')
        $lane2TopLines.Add('approval_policy = "never"')
        $dropGranularApprovalSection = $true
        $effectiveApprovalForSync = 'never'
        $cliModeDesc = 'FullAccess (Toan quyen -- DANGER: approval_policy=never, sandbox_mode=danger-full-access)'
    }
    'Config' {
        if (-not $existingCliSettings.HasSandboxMode) {
            $managedTopKeys.Add('sandbox_mode')
            $lane2TopLines.Add('sandbox_mode = "workspace-write"')
        }
        if (-not $existingCliSettings.HasApprovalPolicy) {
            $managedTopKeys.Add('approval_policy')
            $lane2TopLines.Add("approval_policy = `"$ApprovalPolicy`"")
        }
        if ($existingCliSettings.HasSandboxWorkspaceWriteSection -and (-not $script:ExplicitAllowSandboxNetwork)) {
            $manageSandboxWorkspaceWrite = $false
        }
        $effectiveApprovalForSync = if ($existingCliSettings.HasApprovalPolicy) { $existingCliSettings.ApprovalPolicyValue } else { $ApprovalPolicy }
        $effSbLabel = if ($existingCliSettings.HasSandboxMode) { $existingCliSettings.SandboxModeValue } else { 'workspace-write (default)' }
        $effApLabel = if ($existingCliSettings.HasApprovalPolicy) { $existingCliSettings.ApprovalPolicyValue } else { "$ApprovalPolicy (default)" }
        $cliModeDesc = "Config (Thuoc cau hinh config.toml: approval_policy=$effApLabel, sandbox_mode=$effSbLabel)"
    }
    default {
        # Ask (Xin yeu cau -- default): workspace-write + on-request (or explicit -ApprovalPolicy if passed)
        $managedTopKeys.Add('sandbox_mode')
        $managedTopKeys.Add('approval_policy')
        $lane2TopLines.Add('sandbox_mode = "workspace-write"')
        $lane2TopLines.Add("approval_policy = `"$ApprovalPolicy`"")
        $dropGranularApprovalSection = $true
        $effectiveApprovalForSync = $ApprovalPolicy
        $cliModeDesc = "Ask (Xin yeu cau: approval_policy=$ApprovalPolicy, sandbox_mode=workspace-write)"
    }
}
$lane2TopLines.Add('windows_wsl_setup_acknowledged = true')

if ($OfficialReasoning) {
    $lane2TopLines.Add("model_reasoning_effort = `"$(Escape-TomlBasicString $OfficialReasoning)`"")
    $managedTopKeys.Add('model_reasoning_effort')
}
if ($OfficialServiceTier) {
    $lane2TopLines.Add("service_tier = `"$(Escape-TomlBasicString $OfficialServiceTier)`"")
    $managedTopKeys.Add('service_tier')
}

# Preserve native official Codex capabilities and merge non-destructively with any user [features] flags.
$lane2ManagedFeatures = [ordered]@{}
if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('daemon_auto_start')) {
    $lane2ManagedFeatures['daemon_auto_start'] = 'false'
}
if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('memories')) {
    $lane2ManagedFeatures['memories'] = 'true'
}
if ($supportedFeatures.ContainsKey('goals')) {
    $lane2ManagedFeatures['goals'] = 'true'
}
if ($supportedFeatures.ContainsKey('image_generation')) {
    $lane2ManagedFeatures['image_generation'] = 'true'
}
if ($supportedFeatures.ContainsKey('api_key_model_discovery')) {
    $lane2ManagedFeatures['api_key_model_discovery'] = 'true'
}
$featureLines = Get-MergedFeaturesSectionLines -ExistingConfigPath $lane2ConfigPath -ManagedFeatureMap $lane2ManagedFeatures

$lane2ProjectsSection = if ($lane2ProjectState.ProjectsBlock) { "`r`n`r`n" + $lane2ProjectState.ProjectsBlock } else { '' }

$sandboxNetworkValue = if ($AllowSandboxNetwork) { 'true' } else { 'false' }
$lane2TopBlock = $lane2TopLines -join "`r`n"

$managedSectionList = New-Object 'System.Collections.Generic.List[string]'
$managedSectionList.AddRange([string[]]@(
    'windows',
    'features',
    'memories',
    'shell_environment_policy',
    'shell_environment_policy.set'
))
if ($manageSandboxWorkspaceWrite) {
    $managedSectionList.Add('sandbox_workspace_write')
}
if ($dropGranularApprovalSection) {
    $managedSectionList.Add('approval_policy')
}
$managedSectionNames = $managedSectionList.ToArray()

$lane2ProviderBlock = ''
$lane2ManagedSectionNames = $managedSectionNames
if ($configureGatewayLane2) {
    $modelsUrlL2 = $GatewayBaseUrl.TrimEnd('/') + '/models'
    $provHeaderL2 = "model_providers.`"$(Escape-TomlBasicString $GatewayProviderName)`""
    $lane2ProviderBlock = @"
[$provHeaderL2]
name = "$(Escape-TomlBasicString $GatewayProviderName)"
base_url = "$(Escape-TomlBasicString $GatewayBaseUrl)"
model_catalog_url = "$(Escape-TomlBasicString $modelsUrlL2)"
wire_api = "responses"
env_key = "$(Escape-TomlBasicString $GatewayApiKeyEnv)"

"@
    $lane2ManagedSectionNames = $managedSectionNames + @($provHeaderL2, "model_providers.$GatewayProviderName", "model_providers.'$GatewayProviderName'")
}

$sandboxWorkspaceWriteBlock = if ($manageSandboxWorkspaceWrite) {
    "`r`n`r`n[sandbox_workspace_write]`r`nnetwork_access = $sandboxNetworkValue"
} else { '' }

$lane2SectionsBlock = $lane2ProviderBlock + @"
[windows]
sandbox = "elevated"$lane2ProjectsSection

[features]
$($featureLines -join "`r`n")

[memories]
generate_memories = true
use_memories = true$sandboxWorkspaceWriteBlock

[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]

[shell_environment_policy.set]
CODEX_ACTIVE_LANE = "LANE_2"
CARGO_TARGET_DIR = "$(Escape-TomlBasicString $CargoTargetDir)"
"@

$mergedLane2Config = Merge-CodexConfigToml `
    -ExistingPath $lane2ConfigPath `
    -ManagedTopBlock $lane2TopBlock `
    -ManagedSectionsBlock $lane2SectionsBlock `
    -ManagedTopKeys ($managedTopKeys.ToArray()) `
    -ManagedSectionNames $lane2ManagedSectionNames `
    -ManagedProjectKeys $lane2ProjectState.ManagedProjectKeys

# Fail-closed secret check before touching disk.
Assert-NoPlaintextSecretInToml -TomlContent $mergedLane2Config -ContextLabel 'Lane 2 config.toml' -ForbiddenLiteralSecret $suppliedSecretForGuard
if ($configureGatewayLane2) {
    $expectedEnvKeyLineL2 = "env_key = `"$(Escape-TomlBasicString $GatewayApiKeyEnv)`""
    if (-not $mergedLane2Config.Contains($expectedEnvKeyLineL2)) {
        throw "Security invariant violation in Lane 2 config.toml: expected '$expectedEnvKeyLineL2' is missing."
    }
}

Backup-IfExists $lane2ConfigPath
if (-not $script:IsDryRun) {
    Write-Utf8NoBom -FilePath $lane2ConfigPath -Text $mergedLane2Config
    Protect-SensitiveFileAcl $lane2ConfigPath
    Save-RollbackManifestCheckpoint -Stage 'write:lane2-config.toml'
}
Write-Host "    CLI Mode: $cliModeDesc"
Write-Host "    Wrote: $lane2ConfigPath (preserved custom sections & user [features]; $($lane2ProjectState.TrustedCount) trusted, $($lane2ProjectState.UntrustedCount) untrusted project(s))"

if ($ShareAuthToLane2) {
    Write-Step "Sharing authenticated session (auth.json) from Lane 1 to Lane 2 (-ShareAuthToLane2)..."
    $lane1AuthPath = Join-Path $Lane1Home 'auth.json'
    $lane2AuthPath = Join-Path $Lane2Home 'auth.json'
    Write-Host "    [WARN] -ShareAuthToLane2 (opt-in) duplicates auth.json, placing a second copy of OAuth credentials in Lane 2 ('$lane2AuthPath'). Omit -ShareAuthToLane2 and run 'codex login' separately if you prefer isolated credentials." -ForegroundColor Yellow
    if ($configureGatewayLane2) {
        Write-Host "    [WARN] SECURITY CAUTION: Combining -ShareAuthToLane2 with a third-party API gateway on Lane 2 ('$GatewayBaseUrl') mixes copied official OAuth tokens with third-party gateway routing. Prefer using env_key ('$GatewayApiKeyEnv') alone on Lane 2 unless you explicitly intend both." -ForegroundColor Yellow
    }
    Assert-NotReparsePoint -PathValue $lane1AuthPath -Label 'Lane 1 auth.json'
    Assert-NotReparsePoint -PathValue $lane2AuthPath -Label 'Lane 2 auth.json'
    if (-not (Test-Path -LiteralPath $lane1AuthPath -PathType Leaf)) {
        Write-Warning "Lane 1 auth.json was not found at '$lane1AuthPath'; skipping -ShareAuthToLane2. Run 'codex login' to sign in to Lane 2."
    } else {
        Backup-IfExists $lane2AuthPath
        if (-not $script:IsDryRun) {
            Copy-Item -LiteralPath $lane1AuthPath -Destination $lane2AuthPath -Force
            Protect-SensitiveFileAcl $lane2AuthPath
            Save-RollbackManifestCheckpoint -Stage 'write:lane2-auth.json'
        }
        Write-Host "    Shared & ACL-locked auth.json: $lane1AuthPath -> $lane2AuthPath"
    }
}

# ============================================================================
# Step 10: Optional Lane 1 Gateway Configuration (env_key ONLY, Zero Plaintext Keys)
# ============================================================================
if ($configureGatewayLane1) {
    Write-Step "Configuring Lane 1 gateway in $Lane1Home\config.toml (using env_key = `"$GatewayApiKeyEnv`", zero plaintext secrets in file)..."

    $lane1ConfigPath = Join-Path $Lane1Home 'config.toml'
    $lane1CleanBackup = Join-Path $Lane1Home 'config.backup.toml'
    Assert-NotReparsePoint -PathValue $lane1ConfigPath  -Label 'Lane 1 config.toml'
    Assert-NotReparsePoint -PathValue $lane1CleanBackup -Label 'Lane 1 config.backup.toml'
    # Preserve one immutable pre-gateway clean backup (only if it does not exist yet).
    # Track newly created config.backup.toml (ExistedPrior=$false) so rollback removes stray
    # backups cleanly without ever touching a pre-existing user config.backup.toml.
    if ((Test-Path -LiteralPath $lane1ConfigPath -PathType Leaf) -and -not (Test-Path -LiteralPath $lane1CleanBackup)) {
        Backup-IfExists $lane1CleanBackup
        if (-not $script:IsDryRun) {
            Copy-Item -LiteralPath $lane1ConfigPath -Destination $lane1CleanBackup -Force
            Protect-SensitiveFileAcl $lane1CleanBackup
            Save-RollbackManifestCheckpoint -Stage 'write:lane1-config.backup.toml'
        }
        Write-Host "    Saved clean original backup: $lane1CleanBackup"
    }
    Backup-IfExists $lane1ConfigPath

    $modelsUrl = $GatewayBaseUrl.TrimEnd('/') + '/models'
    $gwTopKeys = New-Object 'System.Collections.Generic.List[string]'
    $gwTopKeys.AddRange([string[]]@('model_provider', 'web_search', 'disable_response_storage', 'windows_wsl_setup_acknowledged'))

    $lane1TopLines = New-Object 'System.Collections.Generic.List[string]'
    $lane1TopLines.Add('# Lane 1 Codex Desktop configuration (Full Desktop Authority + Gateway via env_key)')
    $lane1TopLines.Add("model_provider = `"$(Escape-TomlBasicString $GatewayProviderName)`"")
    if ($GatewayModel) {
        $gwTopKeys.Add('model')
        $gwTopKeys.Add('review_model')
        $lane1TopLines.Add("model = `"$(Escape-TomlBasicString $GatewayModel)`"")
        $lane1TopLines.Add("review_model = `"$(Escape-TomlBasicString $GatewayModel)`"")
    }
    $lane1TopLines.Add('web_search = "live"')
    $lane1TopLines.Add('disable_response_storage = true')
    $lane1TopLines.Add('windows_wsl_setup_acknowledged = true')

    $gwManagedFeatures = [ordered]@{}
    if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('memories')) { $gwManagedFeatures['memories'] = 'true' }
    if ($supportedFeatures.ContainsKey('api_key_model_discovery')) { $gwManagedFeatures['api_key_model_discovery'] = 'true' }
    if ($supportedFeatures.ContainsKey('image_generation')) { $gwManagedFeatures['image_generation'] = 'true' }
    if ($supportedFeatures.ContainsKey('goals')) { $gwManagedFeatures['goals'] = 'true' }
    $gwFeatureLines = Get-MergedFeaturesSectionLines -ExistingConfigPath $lane1ConfigPath -ManagedFeatureMap $gwManagedFeatures

    $provHeader = "model_providers.`"$(Escape-TomlBasicString $GatewayProviderName)`""
    $lane1TopBlock = $lane1TopLines -join "`r`n"

    $lane1ProjectState = Resolve-MergedProjectTrustState `
        -PrimaryConfigPath $lane1ConfigPath `
        -SecondaryConfigPath $lane2ConfigPath `
        -EnsureTrustedPaths $repoTrustTargets
    $lane1ProjectsSection = if ($lane1ProjectState.ProjectsBlock) { "`r`n`r`n" + $lane1ProjectState.ProjectsBlock } else { '' }

    $lane1SectionsBlock = @"
[$provHeader]
name = "$(Escape-TomlBasicString $GatewayProviderName)"
base_url = "$(Escape-TomlBasicString $GatewayBaseUrl)"
model_catalog_url = "$(Escape-TomlBasicString $modelsUrl)"
wire_api = "responses"
env_key = "$(Escape-TomlBasicString $GatewayApiKeyEnv)"

[windows]
sandbox = "elevated"$lane1ProjectsSection

[features]
$($gwFeatureLines -join "`r`n")

[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]

[shell_environment_policy.set]
CODEX_ACTIVE_LANE = "LANE_1"
"@

    $lane1ManagedSections = @(
        'windows',
        'features',
        'shell_environment_policy',
        'shell_environment_policy.set',
        $provHeader,
        "model_providers.$GatewayProviderName",
        "model_providers.'$GatewayProviderName'"
    )

    $mergedLane1Config = Merge-CodexConfigToml `
        -ExistingPath $lane1ConfigPath `
        -ManagedTopBlock $lane1TopBlock `
        -ManagedSectionsBlock $lane1SectionsBlock `
        -ManagedTopKeys ($gwTopKeys.ToArray()) `
        -ManagedSectionNames $lane1ManagedSections `
        -ManagedProjectKeys $lane1ProjectState.ManagedProjectKeys

    # Fail-closed invariant check: zero plaintext bearer tokens or supplied API key literals in TOML,
    # and env_key MUST be present.
    Assert-NoPlaintextSecretInToml -TomlContent $mergedLane1Config -ContextLabel 'Lane 1 config.toml' -ForbiddenLiteralSecret $suppliedSecretForGuard
    $expectedEnvKeyLine = "env_key = `"$(Escape-TomlBasicString $GatewayApiKeyEnv)`""
    if (-not $mergedLane1Config.Contains($expectedEnvKeyLine)) {
        throw "Security invariant violation in Lane 1 config.toml: expected '$expectedEnvKeyLine' is missing."
    }

    if (-not $script:IsDryRun) {
        Write-Utf8NoBom -FilePath $lane1ConfigPath -Text $mergedLane1Config
        Protect-SensitiveFileAcl $lane1ConfigPath
        Save-RollbackManifestCheckpoint -Stage 'write:lane1-config.toml'
    }
    Write-Host "    Wrote: $lane1ConfigPath (zero plaintext keys; reads from env $GatewayApiKeyEnv)"
}
$suppliedSecretForGuard = ''

# ============================================================================
# Step 11: Install Self-Healing CLI Wrappers into LocalBin & Update User PATH
# ============================================================================
Write-Step "Installing codex.cmd, codex-official.cmd, codex-t3.cmd, codex-manage.cmd and Git Bash POSIX shims (codex, codex-official, codex-t3, codex-manage) into $LocalBin..."

# For Microsoft Store / MSIX installs, the versioned WindowsApps directory changes after updates;
# this self-healing fallback re-queries Get-AppxPackage automatically when the cached path disappears.
# Uses zero-parenthesis goto flow so paths containing '(' or ')' can never trigger cmd.exe syntax errors.
$windowsAppsRefresh = if ($CodexSource -eq 'WindowsApps') {
@"
if exist "%CODEX_EXE%" goto :_dl_exe_ready
for /f "usebackq delims=" %%I in (``powershell -NoProfile -Command "(Get-AppxPackage OpenAI.Codex | Select-Object -First 1).InstallLocation"``) do set "CODEX_EXE=%%I\app\resources\codex.exe"
:_dl_exe_ready
"@ + "`r`n"
} else { '' }

$managerScriptPath = Resolve-CanonicalLongPath -PathValue (Join-Path $KitRoot 'scripts\codex-manager.ps1')

# Switch cmd.exe to UTF-8 codepage (65001) whenever any embedded path contains non-ASCII/Unicode characters.
$needsUtf8Codepage = ($Lane1Home -match '[^\x00-\x7F]') -or ($Lane2Home -match '[^\x00-\x7F]') -or ($LocalBin -match '[^\x00-\x7F]') -or ($CargoTargetDir -match '[^\x00-\x7F]') -or ($CodexExe -match '[^\x00-\x7F]') -or ($RepoPath -match '[^\x00-\x7F]') -or ($effectiveLane2Repo -match '[^\x00-\x7F]') -or ($managerScriptPath -match '[^\x00-\x7F]')
$utf8Header = if ($needsUtf8Codepage) { "chcp 65001 >nul`r`n" } else { '' }

# Escape '%' -> '%%' and reject quotes/newlines before embedding canonical long paths into .cmd files.
$cmdLane1Home     = Escape-CmdSetValue -Value $Lane1Home          -Label 'Lane1Home'
$cmdLane2Home     = Escape-CmdSetValue -Value $Lane2Home          -Label 'Lane2Home'
$cmdLocalBin      = Escape-CmdSetValue -Value $LocalBin           -Label 'LocalBin'
$cmdCargoDir      = Escape-CmdSetValue -Value $CargoTargetDir     -Label 'CargoTargetDir'
$cmdCodexExe      = Escape-CmdSetValue -Value $CodexExe           -Label 'CodexExe'
$cmdRepoPath      = Escape-CmdSetValue -Value $RepoPath           -Label 'RepoPath'
$cmdLane2Repo     = Escape-CmdSetValue -Value $effectiveLane2Repo -Label 'Lane2WorktreePath'
$cmdManagerScript = Escape-CmdSetValue -Value $managerScriptPath  -Label 'CodexManagerScript'

# When -UseGitWorktree is enabled, enforce a HARD FAIL-CLOSED OS workspace-write boundary using
# zero-parenthesis batch labels (safe with spaces, '&', '(', ')', '!', '%', Unicode, and 8.3 short paths):
#   Canonicalization: Computes %%~fs short-path equivalents (_DL_PRIMARY_SHORT, _DL_WT_SHORT) at
#            runtime alongside the canonical long paths embedded by Resolve-CanonicalLongPath so
#            8.3 short aliases (e.g. RUNNER~1 / PROGRA~1) always match their long names consistently.
#   Guard 1: Unless CODEX_NO_AUTO_WORKTREE_CD is defined:
#            - If %CODEX_LANE2_WORKTREE%\ is missing/deleted/not a directory, REFUSE TO RUN (exit 1)
#              rather than silently falling back to the primary repo.
#            - If launched from PrimaryRepo root or any nested subdirectory, switch cwd to the
#              matching worktree subdirectory (or worktree root), check `if errorlevel 1` on `cd /d`,
#              AND verify post-`cd` that %CD% actually switched inside %CODEX_LANE2_WORKTREE%.
#            When CODEX_NO_AUTO_WORKTREE_CD IS defined: skips auto-cd ONLY; NEVER skips Guard 2.
#   Guard 2: ALWAYS scans CLI flags (before `--`) for `-C`, `-C=`, attached `-C<path>`, `--cd`,
#            `--cd=`, `--add-dir`, and `--add-dir=` targeting PrimaryRepo (long or 8.3 short path)
#            and fails closed (exit 1). Strips embedded quotes safely without breaking cmd.exe parsing.
$worktreeCdBlock = if ($UseGitWorktree -and ($effectiveLane2Repo -ne $RepoPath)) {
@"
set "CODEX_PRIMARY_REPO=$cmdRepoPath"
set "CODEX_LANE2_WORKTREE=$cmdLane2Repo"
set "_DL_PRIMARY_SHORT="
for %%R in ("%CODEX_PRIMARY_REPO%") do set "_DL_PRIMARY_SHORT=%%~fsR"
if "%_DL_PRIMARY_SHORT%"=="" set "_DL_PRIMARY_SHORT=%CODEX_PRIMARY_REPO%"
if "%_DL_PRIMARY_SHORT:~-1%"=="\" if not "%_DL_PRIMARY_SHORT:~-2%"==":\" set "_DL_PRIMARY_SHORT=%_DL_PRIMARY_SHORT:~0,-1%"
set "_DL_WT_SHORT="
for %%W in ("%CODEX_LANE2_WORKTREE%") do set "_DL_WT_SHORT=%%~fsW"
if "%_DL_WT_SHORT%"=="" set "_DL_WT_SHORT=%CODEX_LANE2_WORKTREE%"
if "%_DL_WT_SHORT:~-1%"=="\" if not "%_DL_WT_SHORT:~-2%"==":\" set "_DL_WT_SHORT=%_DL_WT_SHORT:~0,-1%"

rem === Guard 1: Mandatory fail-closed worktree boundary & auto cwd switch ===
rem (CODEX_NO_AUTO_WORKTREE_CD skips auto-cd ONLY; Guard 2 still runs fail-closed)
if defined CODEX_NO_AUTO_WORKTREE_CD goto :_dl_wt_scan_args
if not exist "%CODEX_LANE2_WORKTREE%\" goto :_dl_wt_missing
set "_DL_CUR=%CD%"
if "%_DL_CUR:~-1%"=="\" if not "%_DL_CUR:~-2%"==":\" set "_DL_CUR=%_DL_CUR:~0,-1%"
set "_DL_REL="
:_dl_wt_loop
if /I "%_DL_CUR%"=="%CODEX_PRIMARY_REPO%" goto :_dl_wt_hit
set "_DL_CUR_S="
for %%S in ("%_DL_CUR%") do set "_DL_CUR_S=%%~fsS"
if "%_DL_CUR_S%"=="" goto :_dl_wt_step
if "%_DL_CUR_S:~-1%"=="\" if not "%_DL_CUR_S:~-2%"==":\" set "_DL_CUR_S=%_DL_CUR_S:~0,-1%"
if /I "%_DL_CUR_S%"=="%_DL_PRIMARY_SHORT%" goto :_dl_wt_hit
:_dl_wt_step
for %%A in ("%_DL_CUR%") do set "_DL_PAR=%%~dpA" & set "_DL_LEAF=%%~nxA"
if "%_DL_LEAF%"=="" goto :_dl_wt_scan_args
if "%_DL_PAR:~-2%"==":\" goto :_dl_wt_scan_args
set "_DL_CUR=%_DL_PAR:~0,-1%"
if "%_DL_REL%"=="" goto :_dl_rel_first
set "_DL_REL=%_DL_LEAF%\%_DL_REL%"
goto :_dl_wt_loop
:_dl_rel_first
set "_DL_REL=%_DL_LEAF%"
goto :_dl_wt_loop
:_dl_wt_hit
if "%_DL_REL%"=="" goto :_dl_wt_root
if not exist "%CODEX_LANE2_WORKTREE%\%_DL_REL%\" goto :_dl_wt_root
cd /d "%CODEX_LANE2_WORKTREE%\%_DL_REL%"
if errorlevel 1 goto :_dl_wt_cd_fail
goto :_dl_wt_verify_cd
:_dl_wt_root
cd /d "%CODEX_LANE2_WORKTREE%"
if errorlevel 1 goto :_dl_wt_cd_fail
:_dl_wt_verify_cd
set "_DL_POST=%CD%"
if "%_DL_POST:~-1%"=="\" if not "%_DL_POST:~-2%"==":\" set "_DL_POST=%_DL_POST:~0,-1%"
:_dl_wt_verify_loop
if /I "%_DL_POST%"=="%CODEX_LANE2_WORKTREE%" goto :_dl_wt_scan_args
set "_DL_POST_S="
for %%S in ("%_DL_POST%") do set "_DL_POST_S=%%~fsS"
if "%_DL_POST_S%"=="" goto :_dl_wt_verify_step
if "%_DL_POST_S:~-1%"=="\" if not "%_DL_POST_S:~-2%"==":\" set "_DL_POST_S=%_DL_POST_S:~0,-1%"
if /I "%_DL_POST_S%"=="%_DL_WT_SHORT%" goto :_dl_wt_scan_args
:_dl_wt_verify_step
for %%A in ("%_DL_POST%") do set "_DL_VPAR=%%~dpA" & set "_DL_VLEAF=%%~nxA"
if "%_DL_VLEAF%"=="" goto :_dl_wt_cd_fail
if "%_DL_VPAR:~-2%"==":\" goto :_dl_wt_cd_fail
set "_DL_POST=%_DL_VPAR:~0,-1%"
goto :_dl_wt_verify_loop
:_dl_wt_missing
echo [FAIL] Lane 2 worktree "%CODEX_LANE2_WORKTREE%" is missing or inaccessible. Refusing to fall back to primary repo "%CODEX_PRIMARY_REPO%". Recreate it via setup-dual-lane.ps1 -UseGitWorktree, or set CODEX_NO_AUTO_WORKTREE_CD=1 to opt out of auto-cd. >&2
exit /b 1
:_dl_wt_cd_fail
echo [FAIL] Lane 2 worktree isolation failed to switch working directory into "%CODEX_LANE2_WORKTREE%". Refusing to remain in primary repo "%CODEX_PRIMARY_REPO%". >&2
exit /b 1

rem === Guard 2: Argument scan & primary repo blocking ===
rem (ALWAYS executes, even if CODEX_NO_AUTO_WORKTREE_CD is defined)
:_dl_wt_scan_args
set "_DL_A="
set _DL_A=%1
if not defined _DL_A goto :_dl_wt_done
set "_DL_A=%_DL_A:"=%"
if not defined _DL_A goto :_dl_wt_skip_arg
if "%_DL_A%"=="--" goto :_dl_wt_done
if "%_DL_A%"=="-C" goto :_dl_chk_next
if "%_DL_A%"=="--cd" goto :_dl_chk_next
if "%_DL_A%"=="--add-dir" goto :_dl_chk_next
if "%_DL_A:~0,3%"=="-C=" goto :_dl_chk_eq3
if "%_DL_A:~0,2%"=="-C" goto :_dl_chk_c2
if /I "%_DL_A:~0,5%"=="--cd=" goto :_dl_chk_eq5
if /I "%_DL_A:~0,10%"=="--add-dir=" goto :_dl_chk_eq10
:_dl_wt_skip_arg
shift
goto :_dl_wt_scan_args
:_dl_chk_next
set "_DL_CAND="
set _DL_CAND=%2
if not defined _DL_CAND goto :_dl_wt_done
shift
shift
goto :_dl_chk_path
:_dl_chk_eq3
set "_DL_CAND=%_DL_A:~3%"
shift
goto :_dl_chk_path
:_dl_chk_c2
set "_DL_CAND=%_DL_A:~2%"
shift
goto :_dl_chk_path
:_dl_chk_eq5
set "_DL_CAND=%_DL_A:~5%"
shift
goto :_dl_chk_path
:_dl_chk_eq10
set "_DL_CAND=%_DL_A:~10%"
shift
:_dl_chk_path
if not defined _DL_CAND goto :_dl_wt_scan_args
set "_DL_CAND=%_DL_CAND:"=%"
if not defined _DL_CAND goto :_dl_wt_scan_args
set "_DL_ABS="
for %%P in ("%_DL_CAND%") do set "_DL_ABS=%%~fP"
if "%_DL_ABS%"=="" goto :_dl_wt_scan_args
if "%_DL_ABS:~-1%"=="\" if not "%_DL_ABS:~-2%"==":\" set "_DL_ABS=%_DL_ABS:~0,-1%"
:_dl_cand_loop
if /I "%_DL_ABS%"=="%CODEX_PRIMARY_REPO%" goto :_dl_block_primary
set "_DL_ABS_S="
for %%S in ("%_DL_ABS%") do set "_DL_ABS_S=%%~fsS"
if "%_DL_ABS_S%"=="" goto :_dl_cand_step
if "%_DL_ABS_S:~-1%"=="\" if not "%_DL_ABS_S:~-2%"==":\" set "_DL_ABS_S=%_DL_ABS_S:~0,-1%"
if /I "%_DL_ABS_S%"=="%_DL_PRIMARY_SHORT%" goto :_dl_block_primary
:_dl_cand_step
for %%A in ("%_DL_ABS%") do set "_DL_CPAR=%%~dpA" & set "_DL_CLEAF=%%~nxA"
if "%_DL_CLEAF%"=="" goto :_dl_wt_scan_args
if "%_DL_CPAR:~-2%"==":\" goto :_dl_wt_scan_args
set "_DL_ABS=%_DL_CPAR:~0,-1%"
goto :_dl_cand_loop
:_dl_block_primary
echo [FAIL] Lane 2 worktree isolation blocked -C/--cd/--add-dir targeting primary repo "%CODEX_PRIMARY_REPO%". Use "%CODEX_LANE2_WORKTREE%" instead. >&2
exit /b 1
:_dl_wt_done
"@ + "`r`n"
} else { '' }

# WHY direct `"%CODEX_EXE%" %*` (without `call`) is used for both .exe and .cmd/.bat targets:
# `call` triggers a second cmd.exe `%` expansion pass, which corrupts target paths containing
# literal `%` (e.g. `100%`). Direct tail-invocation works cleanly for .exe and .cmd/.bat alike,
# preserves `%ERRORLEVEL%`, and still returns cleanly to an outer `call codex.cmd` caller.
$officialWrapper = @"
@echo off
setlocal
${utf8Header}set "CODEX_HOME=$cmdLane2Home"
set "CODEX_ACTIVE_LANE=LANE_2"
set "CARGO_TARGET_DIR=$cmdCargoDir"
set "CODEX_EXE=$cmdCodexExe"
${worktreeCdBlock}${windowsAppsRefresh}if exist "%CODEX_EXE%" goto :_dl_exec_codex
echo [ERROR] Codex binary not found at "%CODEX_EXE%". Re-run setup-dual-lane.ps1. >&2
exit /b 1
:_dl_exec_codex
"%CODEX_EXE%" %*
exit /b %ERRORLEVEL%
"@

$t3Wrapper = @"
@echo off
setlocal
${utf8Header}set "CODEX_HOME=$cmdLane1Home"
set "CODEX_ACTIVE_LANE=LANE_1"
set "CODEX_EXE=$cmdCodexExe"
${windowsAppsRefresh}if exist "%CODEX_EXE%" goto :_dl_exec_codex
echo [ERROR] Codex binary not found at "%CODEX_EXE%". Re-run setup-dual-lane.ps1. >&2
exit /b 1
:_dl_exec_codex
"%CODEX_EXE%" %*
exit /b %ERRORLEVEL%
"@

$manageWrapper = @"
@echo off
setlocal
${utf8Header}set "CODEX_MANAGER_SCRIPT=$cmdManagerScript"
if not defined CODEX_LANE1_HOME set "CODEX_LANE1_HOME=$cmdLane1Home"
if not defined CODEX_LANE2_HOME set "CODEX_LANE2_HOME=$cmdLane2Home"
if not defined CODEX_LOCAL_BIN set "CODEX_LOCAL_BIN=$cmdLocalBin"
if not defined CODEX_MANAGER_EXE set "CODEX_MANAGER_EXE=$cmdCodexExe"
if exist "%CODEX_MANAGER_SCRIPT%" goto :_dl_mgr_ready
echo [ERROR] Codex Manager script not found at "%CODEX_MANAGER_SCRIPT%". Re-run setup-dual-lane.ps1. >&2
exit /b 1
:_dl_mgr_ready
where pwsh.exe >nul 2>nul
if %ERRORLEVEL%==0 goto :_dl_mgr_pwsh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%CODEX_MANAGER_SCRIPT%" %*
exit /b %ERRORLEVEL%
:_dl_mgr_pwsh
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%CODEX_MANAGER_SCRIPT%" %*
exit /b %ERRORLEVEL%
"@

# Enforce strict CRLF line endings on generated .cmd wrappers so cmd.exe goto labels never corrupt.
$officialWrapper = ($officialWrapper -replace "\r?\n", "`r`n").TrimEnd("`r", "`n") + "`r`n"
$t3Wrapper       = ($t3Wrapper       -replace "\r?\n", "`r`n").TrimEnd("`r", "`n") + "`r`n"
$manageWrapper   = ($manageWrapper   -replace "\r?\n", "`r`n").TrimEnd("`r", "`n") + "`r`n"

function New-PosixWrapperShim([string]$CmdFileName) {
    <#
    .SYNOPSIS
        Generates an extensionless POSIX shell shim (with strict LF line endings) for Git Bash /
        MSYS2 / Cygwin on Windows that delegates to the sibling .cmd wrapper via cmd.exe.
    #>
    $lines = @(
        '#!/usr/bin/env sh',
        'basedir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
        'if command -v cygpath >/dev/null 2>&1; then',
        '  basedir="$(cygpath -w "$basedir")"',
        'fi',
        ('MSYS2_ARG_CONV_EXCL="/d;/c" exec cmd.exe /d /c call "${basedir}\\' + $CmdFileName + '" "$@"')
    )
    return (($lines -join "`n") + "`n")
}

# Back up, write, and checkpoint each launcher individually so even an interruption mid-Step 11
# preserves pre-existing user launchers and tracks every newly written wrapper cleanly.
$wrapperSpecs = @(
    @{ Name = 'codex.cmd';          Content = $officialWrapper },
    @{ Name = 'codex-official.cmd'; Content = $officialWrapper },
    @{ Name = 'codex-t3.cmd';       Content = $t3Wrapper },
    @{ Name = 'codex-manage.cmd';   Content = $manageWrapper },
    @{ Name = 'codex';              Content = (New-PosixWrapperShim -CmdFileName 'codex.cmd') },
    @{ Name = 'codex-official';     Content = (New-PosixWrapperShim -CmdFileName 'codex-official.cmd') },
    @{ Name = 'codex-t3';           Content = (New-PosixWrapperShim -CmdFileName 'codex-t3.cmd') },
    @{ Name = 'codex-manage';       Content = (New-PosixWrapperShim -CmdFileName 'codex-manage.cmd') }
)
foreach ($spec in $wrapperSpecs) {
    $wrapperFullPath = Resolve-CanonicalLongPath -PathValue (Join-Path $LocalBin $spec.Name)
    Assert-NotReparsePoint -PathValue $wrapperFullPath -Label "Launcher $($spec.Name)"
    Backup-IfExists $wrapperFullPath
    if (-not $script:IsDryRun) {
        Write-Utf8NoBom -FilePath $wrapperFullPath -Text $spec.Content
        if (-not $script:InstalledWrappers.Contains($wrapperFullPath)) {
            $script:InstalledWrappers.Add($wrapperFullPath)
        }
        Save-RollbackManifestCheckpoint -Stage "wrapper:$($spec.Name)"
    }
}
Write-Host "    Installed wrappers in: $LocalBin"

# Prepend LocalBin to User PATH so our wrappers take precedence over npm/global codex shims.
if (-not $SkipPathUpdate) {
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $pathEntries = @()
    if ($userPath) {
        $pathEntries = @($userPath -split ';' | Where-Object { $_ -and $_.Trim() -ne '' })
    }
    $normLocalBin = $LocalBin.TrimEnd('\').ToLowerInvariant()
    $firstCanon = if ($pathEntries.Count -gt 0) {
        try { (Resolve-CanonicalLongPath -PathValue $pathEntries[0]).TrimEnd('\').ToLowerInvariant() } catch { $pathEntries[0].TrimEnd('\').ToLowerInvariant() }
    } else { '' }
    $firstIsLocalBin = ($pathEntries.Count -gt 0) -and ($firstCanon -eq $normLocalBin)
    if (-not $firstIsLocalBin) {
        $filtered = @($pathEntries | Where-Object {
            $entryCanon = try { (Resolve-CanonicalLongPath -PathValue $_).TrimEnd('\').ToLowerInvariant() } catch { $_.TrimEnd('\').ToLowerInvariant() }
            $entryCanon -ne $normLocalBin
        })
        $newPath = (@($LocalBin) + $filtered) -join ';'
        if (-not $script:IsDryRun) {
            [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        }
        Write-Host "    Prepended $LocalBin to User PATH (highest priority). Open a new terminal window to pick up PATH changes." -ForegroundColor Yellow
    }
} else {
    Write-Host "    Skipped User PATH modification (-SkipPathUpdate)." -ForegroundColor DarkGray
}

# ============================================================================
# Step 12: Optional Dual-Lane Coordination Bridge Template
# ============================================================================
if ($InstallBridgeTemplate) {
    foreach ($targetRepo in (@($RepoPath, $effectiveLane2Repo) | Select-Object -Unique)) {
        $artifactsDir = Join-Path $targetRepo 'artifacts'
        $bridgeDir    = Join-Path $artifactsDir 'dual-lane'
        $bridgeDst    = Join-Path $bridgeDir 'DUAL_LANE_BRIDGE.md'
        Assert-NotReparsePoint -PathValue $artifactsDir -Label 'artifacts directory'
        Assert-NotReparsePoint -PathValue $bridgeDir    -Label 'artifacts\dual-lane directory'
        Assert-NotReparsePoint -PathValue $bridgeDst    -Label 'DUAL_LANE_BRIDGE.md'
        Write-Step "Ensuring bridge template at $bridgeDst..."
        if (-not (Test-Path -LiteralPath $bridgeDst)) {
            if (-not $script:IsDryRun) {
                [void][System.IO.Directory]::CreateDirectory($bridgeDir)
                Copy-Item -LiteralPath $bridgeSrc -Destination $bridgeDst
            }
            Write-Host "    Created: $bridgeDst"
        } else {
            Write-Host "    Kept existing: $bridgeDst"
        }
    }
}

# ============================================================================
# Step 13: Finalize Rollback Manifest & NTFS ACL Lockdown
# ============================================================================
# WHY: Mark the incrementally persisted rollback journal Completed=$true BEFORE optional post-steps
# (SyncSessions / smoke check) and run a final NTFS ACL lockdown sweep across all sensitive files.
if (-not $script:IsDryRun) {
    Save-RollbackManifestCheckpoint -Stage 'complete' -Completed $true

    # Apply two-step NTFS ACL hardening across all sensitive credential, config, and manifest files.
    foreach ($secFile in @(
        (Join-Path $Lane1Home 'auth.json'),
        (Join-Path $Lane1Home 'config.toml'),
        (Join-Path $Lane1Home 'config.backup.toml'),
        (Join-Path $Lane2Home 'auth.json'),
        (Join-Path $Lane2Home 'config.toml'),
        (Join-Path $Lane2Home 'config.backup.toml'),
        $script:RollbackSnapPath,
        $script:RollbackLatestPath
    )) {
        Protect-SensitiveFileAcl $secFile
    }
    Write-Host "    Rollback manifest finalized & NTFS sandbox ACLs locked: $($script:RollbackLatestPath)" -ForegroundColor DarkGray
}

# ============================================================================
# Step 14: Optional Session Sync (SQLite UPSERT) & Post-Install Verification
# ============================================================================
if ($SyncSessions) {
    Write-Step 'Syncing session index, pinned threads, and goals via sync-sessions.py...'
    $pythonExe = $null
    foreach ($cand in @('python', 'python3')) {
        foreach ($cmd in @(Get-Command $cand -All -ErrorAction SilentlyContinue)) {
            if (-not $cmd -or -not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
            $prevPyPref = $ErrorActionPreference
            $v = ''
            try {
                $ErrorActionPreference = 'Continue'
                $v = [string](& $cmd.Source --version 2>&1 | Select-Object -First 1)
            } finally {
                $ErrorActionPreference = $prevPyPref
                $global:LASTEXITCODE = 0
            }
            if ($v -match '^Python 3\.') { $pythonExe = $cmd.Source; break }
        }
        if ($pythonExe) { break }
    }
    if (-not $pythonExe) {
        Write-Warning 'Real Python 3 was not found in PATH (ignoring Microsoft Store stub); skipping SQLite session sync.'
    } else {
        $syncScript = Join-Path $KitRoot 'scripts\sync-sessions.py'
        if (-not (Test-Path -LiteralPath $syncScript -PathType Leaf)) {
            Write-Warning "Session sync script not found at $syncScript; skipping."
        } else {
            $pyArgs = @($syncScript, '--lane1', $Lane1Home, '--lane2', $Lane2Home, '--repo', $effectiveLane2Repo)
            if ($effectiveApprovalForSync -in @('on-request', 'never')) {
                $pyArgs += @('--approval-mode', $effectiveApprovalForSync)
            }
            if ($PinnedOnlySync) { $pyArgs += '--pinned-only' }
            if ($script:IsDryRun) { $pyArgs += '--dry-run' }
            $prevSyncPref = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & $pythonExe @pyArgs
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "sync-sessions.py exited with code $LASTEXITCODE. Your installation and rollback manifest are intact; re-run sync-sessions.py once Codex Desktop is idle."
                }
            } finally {
                $ErrorActionPreference = $prevSyncPref
                $global:LASTEXITCODE = 0
            }
        }
    }
}

if (-not $script:IsDryRun) {
    Write-Step 'Running post-install verification...'
    $prevCheckPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & (Join-Path $LocalBin 'codex.cmd') --version
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Post-install wrapper check 'codex.cmd --version' exited with code $LASTEXITCODE."
        }
    } finally {
        $ErrorActionPreference = $prevCheckPref
        $global:LASTEXITCODE = 0
    }
}

Write-Host "`n[OK] Setup completed!" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Open Sandbox 2 Control Center: codex-manage"
Write-Host "  2. Run health check anytime:      powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1"
Write-Host "  3. Sign in to Lane 2 (once):      codex login"
Write-Host "  4. Start Lane 2 Official CLI:     codex"
Write-Host "  5. Start Lane 1 (Desktop/T3):     codex-t3 (or open Codex Desktop App)"
