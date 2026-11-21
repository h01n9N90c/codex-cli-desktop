<#
.SYNOPSIS
    Universal, hardware-adaptive, security-hardened installer for Codex Dual-Lane & Security Kit on Windows.

.DESCRIPTION
    Configures two isolated OpenAI Codex lanes on ANY Windows 10/11 machine (single-drive C:\ or
    multi-drive, spaces/Unicode/'&' in paths, WindowsApps MSIX Desktop OR standalone/npm Codex CLI):

      - Lane 1 (default: %USERPROFILE%\.codex)          : Codex Desktop App / optional gateway via `codex-t3`
      - Lane 2 (default: %USERPROFILE%\.codex-official) : Official OpenAI/ChatGPT CLI via `codex` / `codex-official`

    Security & Safety Guarantees:
      1. Zero hardcoded mock data, zero hardcoded model tiers, and zero plaintext secrets:
         - Auto-detects the real installed Codex executable and probes live supported feature flags
           via `codex features list` inside a disposable temporary CODEX_HOME.
         - Third-party gateway mode (-ConfigureGateway) writes ONLY `env_key = "<VAR>"` into config.toml
           and enforces a fail-closed pre-write assertion that blocks `experimental_bearer_token` or
           plaintext API keys from ever reaching config.toml or backup files.
      2. Non-destructive TOML merge & atomic file writes:
         - Preserves custom top-level keys (including multi-line values), custom sections
           ([mcp_servers.*], [tui], [plugins.*], [[array_of_tables]]), and all existing [projects.*]
           trust entries.
         - Writes UTF-8 without BOM atomically via a same-directory temp file + File.Replace/Move so
           interrupted writes cannot corrupt config.toml.
         - Records SHA-256 hashes of every pre-existing file into a deterministic rollback snapshot
           (<Lane2Home>\.rollback\latest.json) for byte-exact recovery via restore-original.ps1.
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
    Directory where self-healing CLI wrappers (codex.cmd, codex-official.cmd, codex-t3.cmd) are
    installed. Default: %USERPROFILE%\.local\bin.

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
    Codex approval policy written to managed configs: 'on-request' (secure default) or 'never'
    (unattended isolated runs only).

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
    Configures a third-party OpenAI-compatible gateway in Lane 1 config.toml using `env_key` ONLY
    (never writing plaintext API keys to disk).

.PARAMETER GatewayProviderName
    TOML provider identifier for [model_providers."<Name>"] when -ConfigureGateway is set. Default: OpenAI.

.PARAMETER GatewayBaseUrl
    Absolute http(s) base URL for the Lane 1 gateway (required with -ConfigureGateway).

.PARAMETER GatewayModel
    Optional default model and review_model slug for Lane 1 when -ConfigureGateway is set.

.PARAMETER GatewayApiKeyEnv
    Environment variable name referenced by `env_key` in Lane 1 config.toml. Default: CODEX_GATEWAY_API_KEY.

.PARAMETER GatewayApiKey
    (Legacy compatibility) Stores the provided API key in the User environment variable named by
    -GatewayApiKeyEnv (never written to config.toml). Prefer -PromptGatewayApiKey to avoid shell history.

.PARAMETER PromptGatewayApiKey
    Prompts securely via Read-Host -AsSecureString and stores the key only in User environment
    variable -GatewayApiKeyEnv (never echoed, never written to config.toml).

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
    [switch]$AllowSandboxNetwork,
    [switch]$UseGitWorktree,
    [string]$Lane2WorktreePath = '',
    [string]$Lane2Branch = 'dual-lane-2',
    [switch]$ConfigureGateway,
    [string]$GatewayProviderName = 'OpenAI',
    [string]$GatewayBaseUrl = '',
    [string]$GatewayModel = '',
    [string]$GatewayApiKeyEnv = 'CODEX_GATEWAY_API_KEY',
    [string]$GatewayApiKey = '',
    [switch]$PromptGatewayApiKey,
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
$script:SnapshotEntries = New-Object 'System.Collections.Generic.List[object]'
$script:InstallStamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ============================================================================
# Helper Functions: Logging, Input Validation & Injection Defense
# ============================================================================

function Write-Step([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
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
        Validates and canonicalizes a Windows filesystem path parameter.
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
        $full = [System.IO.Path]::GetFullPath($PathValue)
    } catch {
        throw "Invalid path for -${ParamName} ('$PathValue'): $($_.Exception.Message)"
    }

    # Trim trailing separator unless path is a drive root like C:\
    $root = [System.IO.Path]::GetPathRoot($full)
    $normalized = if ($full.Length -gt $root.Length) { $full.TrimEnd('\', '/') } else { $full }

    if ($DisallowRootOrProfile) {
        # Guard against catastrophic misconfiguration (e.g., pointing Lane2Home at C:\ or %USERPROFILE%).
        $blockedDirs = New-Object 'System.Collections.Generic.List[string]'
        if ($root) { $blockedDirs.Add($root.TrimEnd('\')) }
        foreach ($envDir in @($env:USERPROFILE, $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:TEMP)) {
            if (-not [string]::IsNullOrWhiteSpace($envDir)) {
                try { $blockedDirs.Add([System.IO.Path]::GetFullPath($envDir).TrimEnd('\')) } catch {}
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
    #>
    $a = $PathA.TrimEnd('\').ToLowerInvariant()
    $b = $PathB.TrimEnd('\').ToLowerInvariant()
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
    $full = [System.IO.Path]::GetFullPath($PathValue)
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
    $fullPath = [System.IO.Path]::GetFullPath($FilePath)
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

    $fullPath = [System.IO.Path]::GetFullPath($FilePath)
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

function Backup-IfExists([string]$FilePath) {
    <#
    .SYNOPSIS
        Backs up a pre-existing file with its SHA-256 hash and records the entry for deterministic
        rollback via restore-original.ps1. Files that did not exist prior are also recorded so
        rollback knows to delete them cleanly.
    #>
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
        $origHash = Get-FileSha256 $FilePath
        $backup = Get-UniqueBackupPath $FilePath
        if (-not $script:IsDryRun) {
            Copy-Item -LiteralPath $FilePath -Destination $backup -Force
            Protect-SensitiveFileAcl $backup
        }
        $script:SnapshotEntries.Add([PSCustomObject]@{
            TargetPath     = $FilePath
            ExistedPrior   = $true
            BackupPath     = $backup
            OriginalSha256 = $origHash
        })
        Write-Host "    Backup saved: $backup (SHA256=$($origHash.Substring(0, 12))...)" -ForegroundColor DarkGray
    } else {
        $script:SnapshotEntries.Add([PSCustomObject]@{
            TargetPath     = $FilePath
            ExistedPrior   = $false
            BackupPath     = ''
            OriginalSha256 = ''
        })
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
        return [PSCustomObject]@{ Path = (Resolve-Path -LiteralPath $ExplicitPath).Path; Source = 'Explicit' }
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
            return [PSCustomObject]@{ Path = $msixExe; Source = 'WindowsApps' }
        }
    }

    # 3. Existing codex binary in PATH (strictly excluding our own LocalBin wrapper to avoid infinite recursion)
    $excludedNorm = $ExcludedDir.TrimEnd('\').ToLowerInvariant()
    $cmdCandidates = @(Get-Command codex -All -ErrorAction SilentlyContinue)
    $exeMatch = $null
    $batchMatch = $null
    foreach ($cmd in $cmdCandidates) {
        if (-not $cmd -or -not $cmd.Source) { continue }
        $src = $cmd.Source
        $parent = (Split-Path -Parent $src).TrimEnd('\').ToLowerInvariant()
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

function Get-ExistingTrustedProjects([string[]]$ConfigPaths) {
    <#
    .SYNOPSIS
        Harvests all existing [projects."..."] and [projects.'...'] trust entries across prior
        Lane 1 and Lane 2 config.toml files so upgrading or installing never loses trusted repos.
    #>
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($cfg in $ConfigPaths) {
        if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) { continue }
        # Explicit UTF-8 read avoids PowerShell 5.1 ANSI/Windows-1252 mojibake on UTF-8 no-BOM files with Unicode paths.
        $content = Get-Content -LiteralPath $cfg -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        $matches = [regex]::Matches($content, '(?m)^\s*\[projects\.''([^'']+)''\]|^\s*\[projects\."((?:[^"\\]|\\.)+)"\]')
        foreach ($m in $matches) {
            $raw = if ($m.Groups[1].Success) {
                $m.Groups[1].Value
            } else {
                # Unescape TOML basic-string escapes back to a native Windows path before re-escaping on write.
                $m.Groups[2].Value.Replace('\"', '"').Replace('\\', '\')
            }
            if ($raw -and $seen.Add($raw)) {
                $list.Add($raw)
            }
        }
    }
    return , $list
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

function Merge-CodexConfigToml {
    <#
    .SYNOPSIS
        Non-destructively merges managed Dual-Lane keys/sections into an existing config.toml.
        WHY: Preserves user customizations ([mcp_servers.*], [tui], [plugins.*], [[array_tables]],
        and custom top-level settings) while updating only Dual-Lane managed settings cleanly.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExistingPath,
        [Parameter(Mandatory = $true)][string]$ManagedTopBlock,
        [Parameter(Mandatory = $true)][string]$ManagedSectionsBlock,
        [Parameter(Mandatory = $true)][string[]]$ManagedTopKeys,
        [Parameter(Mandatory = $true)][string[]]$ManagedSectionNames
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
                if ($secSet.Contains($normSecName) -or ($rawSecName -match '^projects\.')) {
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

# ============================================================================
# Pre-Flight Input Validation (Fail-Closed Before Any Disk Activity)
# ============================================================================

$KitRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

# Validate and normalize all path parameters upfront.
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
$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path

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
        (Join-Path $Lane2Home 'config.toml')
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
        $effectiveLane2Repo = (Resolve-Path -LiteralPath $wtTarget).Path
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
            $effectiveLane2Repo = (Resolve-Path -LiteralPath $wtTarget).Path
            Write-Host "    Created Lane 2 Git worktree: $effectiveLane2Repo (branch: $Lane2Branch)"
        } else {
            $effectiveLane2Repo = $wtTarget
            Write-Host "    [DRY-RUN] Would create Lane 2 Git worktree: $effectiveLane2Repo (branch: $Lane2Branch)"
        }
    }
}

# ============================================================================
# Step 5: Prepare Directories for Lane 1, Lane 2, and CLI Wrappers
# ============================================================================
Write-Step "Preparing directories: $Lane1Home, $Lane2Home, $LocalBin..."
foreach ($dir in @($Lane1Home, (Join-Path $Lane1Home 'rules'), $Lane2Home, (Join-Path $Lane2Home 'rules'), $LocalBin)) {
    Ensure-Directory $dir
}

# ============================================================================
# Step 6: Create NTFS Directory Junctions for Shared Brain Directories
# ============================================================================
# WHY: NTFS Directory Junctions share memories, sessions, skills, and plugins across Lane 1 and
# Lane 2 in real time with zero duplication while keeping config.toml and auth.json strictly separate.
Write-Step 'Linking shared memories, sessions, skills, and plugins via NTFS Junctions...'
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
foreach ($name in $sharedDirs) {
    $src = Join-Path $Lane1Home $name
    $dst = Join-Path $Lane2Home $name
    if (-not (Test-Path -LiteralPath $src)) {
        if (-not $script:IsDryRun) { [void][System.IO.Directory]::CreateDirectory($src) }
    }
    if (Test-Path -LiteralPath $dst) {
        $item = Get-Item -LiteralPath $dst -Force
        if ($item.LinkType -eq 'Junction') {
            $existingTarget = (@($item.Target) | Select-Object -First 1)
            $normExisting = if ($existingTarget) { ($existingTarget -replace '^\\\?\?\\', '').TrimEnd('\').ToLowerInvariant() } else { '' }
            $normExpected = $src.TrimEnd('\').ToLowerInvariant()
            if ($normExisting -and ($normExisting -ne $normExpected)) {
                Write-Warning "Existing Junction '$dst' points to '$existingTarget' instead of expected '$src'."
            } else {
                Write-Host "    Already linked: $name -> $existingTarget"
            }
            continue
        }
        # Never delete a pre-existing real directory in Lane 2; move it safely aside with a unique backup name.
        $dirBackup = Get-UniqueBackupPath $dst
        if (-not $script:IsDryRun) { Move-Item -LiteralPath $dst -Destination $dirBackup -Force }
        Write-Host "    Moved existing directory safely to: $dirBackup" -ForegroundColor DarkGray
    }
    if (-not $script:IsDryRun) { New-Item -ItemType Junction -Path $dst -Target $src | Out-Null }
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
    if (-not $script:IsDryRun) { Copy-Item -LiteralPath $rulesTemplate -Destination $targetRule -Force }
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
Backup-IfExists $lane2AgentsDst
if (-not $script:IsDryRun) {
    Copy-Item -LiteralPath $lane1AgentsSrc -Destination $lane1AgentsDst -Force
    Copy-Item -LiteralPath $lane2AgentsSrc -Destination $lane2AgentsDst -Force
}
Write-Host "    Installed: $lane1AgentsDst"
Write-Host "    Installed: $lane2AgentsDst"

# ============================================================================
# Step 9: Non-Destructively Merge & Atomically Write Lane 2 config.toml
# ============================================================================
Write-Step 'Merging & writing Lane 2 Official OpenAI config.toml (non-destructive TOML merge)...'
$lane2ConfigPath = Join-Path $Lane2Home 'config.toml'
Assert-NotReparsePoint -PathValue $lane2ConfigPath -Label 'Lane 2 config.toml'
$trustedProjects = Get-ExistingTrustedProjects -ConfigPaths @((Join-Path $Lane1Home 'config.toml'), $lane2ConfigPath)
foreach ($rp in @($RepoPath, $effectiveLane2Repo)) {
    $alreadyTrusted = @($trustedProjects | Where-Object { $_.Equals($rp, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    if (-not $alreadyTrusted) {
        $trustedProjects.Add($rp)
    }
}

$managedTopKeys = New-Object 'System.Collections.Generic.List[string]'
$managedTopKeys.AddRange([string[]]@('sandbox_mode', 'approval_policy', 'windows_wsl_setup_acknowledged'))

$lane2TopLines = New-Object 'System.Collections.Generic.List[string]'
$lane2TopLines.Add('# Official OpenAI / ChatGPT Codex CLI configuration (LANE 2)')
$lane2TopLines.Add('# Leave model/service_tier unset unless overridden so Codex uses your account''s real defaults.')
$lane2TopLines.Add('sandbox_mode = "workspace-write"')
$lane2TopLines.Add("approval_policy = `"$ApprovalPolicy`"")
$lane2TopLines.Add('windows_wsl_setup_acknowledged = true')

if ($OfficialModel) {
    $lane2TopLines.Add("model = `"$(Escape-TomlBasicString $OfficialModel)`"")
    $managedTopKeys.Add('model')
}
if ($OfficialReasoning) {
    $lane2TopLines.Add("model_reasoning_effort = `"$(Escape-TomlBasicString $OfficialReasoning)`"")
    $managedTopKeys.Add('model_reasoning_effort')
}
if ($OfficialServiceTier) {
    $lane2TopLines.Add("service_tier = `"$(Escape-TomlBasicString $OfficialServiceTier)`"")
    $managedTopKeys.Add('service_tier')
}

# Only enable feature flags confirmed by the real binary (or safe defaults when probing is unsupported).
$featureLines = New-Object 'System.Collections.Generic.List[string]'
if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('daemon_auto_start')) {
    $featureLines.Add('daemon_auto_start = false')
}
if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('memories')) {
    $featureLines.Add('memories = true')
}
if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('js_repl')) {
    $featureLines.Add('js_repl = false')
}
if ($supportedFeatures.ContainsKey('goals')) {
    $featureLines.Add('goals = true')
}

$projectsBlock = ($trustedProjects | ForEach-Object {
    "[projects.`"$(Escape-TomlBasicString $_)`"]`r`ntrust_level = `"trusted`""
}) -join "`r`n`r`n"

$sandboxNetworkValue = if ($AllowSandboxNetwork) { 'true' } else { 'false' }
$lane2TopBlock = $lane2TopLines -join "`r`n"

$lane2SectionsBlock = @"
[windows]
sandbox = "elevated"

$projectsBlock

[features]
$($featureLines -join "`r`n")

[memories]
generate_memories = true
use_memories = true

[sandbox_workspace_write]
network_access = $sandboxNetworkValue

[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]

[shell_environment_policy.set]
CODEX_ACTIVE_LANE = "LANE_2"
CARGO_TARGET_DIR = "$(Escape-TomlBasicString $CargoTargetDir)"
"@

$managedSectionNames = @(
    'windows',
    'features',
    'memories',
    'sandbox_workspace_write',
    'shell_environment_policy',
    'shell_environment_policy.set'
)

$mergedLane2Config = Merge-CodexConfigToml `
    -ExistingPath $lane2ConfigPath `
    -ManagedTopBlock $lane2TopBlock `
    -ManagedSectionsBlock $lane2SectionsBlock `
    -ManagedTopKeys ($managedTopKeys.ToArray()) `
    -ManagedSectionNames $managedSectionNames

# Fail-closed secret check before touching disk.
Assert-NoPlaintextSecretInToml -TomlContent $mergedLane2Config -ContextLabel 'Lane 2 config.toml'

Backup-IfExists $lane2ConfigPath
if (-not $script:IsDryRun) {
    Write-Utf8NoBom -FilePath $lane2ConfigPath -Text $mergedLane2Config
    Protect-SensitiveFileAcl $lane2ConfigPath
}
Write-Host "    Wrote: $lane2ConfigPath (preserved custom sections & $($trustedProjects.Count) trusted project(s))"

# ============================================================================
# Step 10: Optional Lane 1 Gateway Configuration (env_key ONLY, Zero Plaintext Keys)
# ============================================================================
if ($ConfigureGateway) {
    Write-Step "Configuring Lane 1 gateway in $Lane1Home\config.toml (using env_key = `"$GatewayApiKeyEnv`", zero plaintext secrets in file)..."
    $suppliedSecretForGuard = ''

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
                    Write-Warning "No API key entered; ensure User env '$GatewayApiKeyEnv' is set before launching Lane 1."
                }
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                $plainKey = $null
            }
        }
    }

    $lane1ConfigPath = Join-Path $Lane1Home 'config.toml'
    $lane1CleanBackup = Join-Path $Lane1Home 'config.backup.toml'
    Assert-NotReparsePoint -PathValue $lane1ConfigPath  -Label 'Lane 1 config.toml'
    Assert-NotReparsePoint -PathValue $lane1CleanBackup -Label 'Lane 1 config.backup.toml'
    # Preserve one immutable pre-gateway clean backup (only if it does not exist yet).
    if ((Test-Path -LiteralPath $lane1ConfigPath -PathType Leaf) -and -not (Test-Path -LiteralPath $lane1CleanBackup)) {
        if (-not $script:IsDryRun) {
            Copy-Item -LiteralPath $lane1ConfigPath -Destination $lane1CleanBackup -Force
            Protect-SensitiveFileAcl $lane1CleanBackup
        }
        Write-Host "    Saved clean original backup: $lane1CleanBackup"
    }
    Backup-IfExists $lane1ConfigPath

    $modelsUrl = $GatewayBaseUrl.TrimEnd('/') + '/models'
    $gwTopKeys = New-Object 'System.Collections.Generic.List[string]'
    $gwTopKeys.AddRange([string[]]@('model_provider', 'web_search', 'disable_response_storage', 'sandbox_mode', 'approval_policy', 'windows_wsl_setup_acknowledged'))

    $lane1TopLines = New-Object 'System.Collections.Generic.List[string]'
    $lane1TopLines.Add('# Lane 1 Codex configuration (Gateway via env_key + Security Guardrails)')
    $lane1TopLines.Add("model_provider = `"$(Escape-TomlBasicString $GatewayProviderName)`"")
    if ($GatewayModel) {
        $gwTopKeys.Add('model')
        $gwTopKeys.Add('review_model')
        $lane1TopLines.Add("model = `"$(Escape-TomlBasicString $GatewayModel)`"")
        $lane1TopLines.Add("review_model = `"$(Escape-TomlBasicString $GatewayModel)`"")
    }
    $lane1TopLines.Add('web_search = "live"')
    $lane1TopLines.Add('disable_response_storage = true')
    $lane1TopLines.Add('sandbox_mode = "workspace-write"')
    $lane1TopLines.Add("approval_policy = `"$ApprovalPolicy`"")
    $lane1TopLines.Add('windows_wsl_setup_acknowledged = true')

    $gwFeatureLines = New-Object 'System.Collections.Generic.List[string]'
    if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('memories')) { $gwFeatureLines.Add('memories = true') }
    if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('js_repl')) { $gwFeatureLines.Add('js_repl = false') }
    if ($supportedFeatures.ContainsKey('api_key_model_discovery')) { $gwFeatureLines.Add('api_key_model_discovery = true') }
    if ($supportedFeatures.ContainsKey('image_generation')) { $gwFeatureLines.Add('image_generation = true') }
    if ($supportedFeatures.ContainsKey('goals')) { $gwFeatureLines.Add('goals = true') }

    $provHeader = "model_providers.`"$(Escape-TomlBasicString $GatewayProviderName)`""
    $lane1TopBlock = $lane1TopLines -join "`r`n"

    $lane1SectionsBlock = @"
[$provHeader]
name = "$(Escape-TomlBasicString $GatewayProviderName)"
base_url = "$(Escape-TomlBasicString $GatewayBaseUrl)"
model_catalog_url = "$(Escape-TomlBasicString $modelsUrl)"
wire_api = "responses"
env_key = "$(Escape-TomlBasicString $GatewayApiKeyEnv)"

[windows]
sandbox = "elevated"

$projectsBlock

[features]
$($gwFeatureLines -join "`r`n")

[sandbox_workspace_write]
network_access = $sandboxNetworkValue

[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]

[shell_environment_policy.set]
CODEX_ACTIVE_LANE = "LANE_1"
"@

    $mergedLane1Config = Merge-CodexConfigToml `
        -ExistingPath $lane1ConfigPath `
        -ManagedTopBlock $lane1TopBlock `
        -ManagedSectionsBlock $lane1SectionsBlock `
        -ManagedTopKeys ($gwTopKeys.ToArray()) `
        -ManagedSectionNames ($managedSectionNames + @($provHeader, "model_providers.$GatewayProviderName", "model_providers.'$GatewayProviderName'"))

    # Fail-closed invariant check: zero plaintext bearer tokens or supplied API key literals in TOML,
    # and env_key MUST be present.
    Assert-NoPlaintextSecretInToml -TomlContent $mergedLane1Config -ContextLabel 'Lane 1 config.toml' -ForbiddenLiteralSecret $suppliedSecretForGuard
    $expectedEnvKeyLine = "env_key = `"$(Escape-TomlBasicString $GatewayApiKeyEnv)`""
    if (-not $mergedLane1Config.Contains($expectedEnvKeyLine)) {
        throw "Security invariant violation in Lane 1 config.toml: expected '$expectedEnvKeyLine' is missing."
    }
    $suppliedSecretForGuard = ''

    if (-not $script:IsDryRun) {
        Write-Utf8NoBom -FilePath $lane1ConfigPath -Text $mergedLane1Config
        Protect-SensitiveFileAcl $lane1ConfigPath
    }
    Write-Host "    Wrote: $lane1ConfigPath (zero plaintext keys; reads from env $GatewayApiKeyEnv)"
}

# ============================================================================
# Step 11: Install Self-Healing CLI Wrappers into LocalBin & Update User PATH
# ============================================================================
Write-Step "Installing codex.cmd, codex-official.cmd, and codex-t3.cmd into $LocalBin..."

# For Microsoft Store / MSIX installs, the versioned WindowsApps directory changes after updates;
# this self-healing fallback re-queries Get-AppxPackage automatically when the cached path disappears.
$windowsAppsRefresh = if ($CodexSource -eq 'WindowsApps') {
@"
if not exist "%CODEX_EXE%" (
    for /f "usebackq delims=" %%I in (``powershell -NoProfile -Command "(Get-AppxPackage OpenAI.Codex | Select-Object -First 1).InstallLocation"``) do (
        set "CODEX_EXE=%%I\app\resources\codex.exe"
    )
)
"@
} else { '' }

# Switch cmd.exe to UTF-8 codepage (65001) whenever any embedded path contains non-ASCII/Unicode characters.
$needsUtf8Codepage = ($Lane1Home -match '[^\x00-\x7F]') -or ($Lane2Home -match '[^\x00-\x7F]') -or ($CargoTargetDir -match '[^\x00-\x7F]') -or ($CodexExe -match '[^\x00-\x7F]') -or ($RepoPath -match '[^\x00-\x7F]') -or ($effectiveLane2Repo -match '[^\x00-\x7F]')
$utf8Header = if ($needsUtf8Codepage) { "chcp 65001 >nul`r`n" } else { '' }

# Escape '%' -> '%%' and reject quotes/newlines before embedding paths into .cmd files.
$cmdLane1Home = Escape-CmdSetValue -Value $Lane1Home          -Label 'Lane1Home'
$cmdLane2Home = Escape-CmdSetValue -Value $Lane2Home          -Label 'Lane2Home'
$cmdCargoDir  = Escape-CmdSetValue -Value $CargoTargetDir     -Label 'CargoTargetDir'
$cmdCodexExe  = Escape-CmdSetValue -Value $CodexExe           -Label 'CodexExe'
$cmdRepoPath  = Escape-CmdSetValue -Value $RepoPath           -Label 'RepoPath'
$cmdLane2Repo = Escape-CmdSetValue -Value $effectiveLane2Repo -Label 'Lane2WorktreePath'

# When -UseGitWorktree is enabled, enforce OS workspace-write isolation using zero-parenthesis
# batch labels (safe with spaces, '&', '(', ')', '!', '%', and Unicode):
#   Guard 1: If launched from PrimaryRepo root OR ANY nested subdirectory (`PrimaryRepo\src\...`),
#            automatically switch cwd to the matching worktree subdirectory (or worktree root).
#   Guard 2: Scan CLI flags (before `--`) for `-C`, `--cd`, or `--add-dir` pointing inside
#            PrimaryRepo and fail closed instead of letting Codex target PrimaryRepo directly.
$worktreeCdBlock = if ($UseGitWorktree -and ($effectiveLane2Repo -ne $RepoPath)) {
@"
set "CODEX_PRIMARY_REPO=$cmdRepoPath"
set "CODEX_LANE2_WORKTREE=$cmdLane2Repo"
if defined CODEX_NO_AUTO_WORKTREE_CD goto :_dl_wt_done
if not exist "%CODEX_LANE2_WORKTREE%\" goto :_dl_wt_done
set "_DL_CUR=%CD%"
if "%_DL_CUR:~-1%"=="\" if not "%_DL_CUR:~-2%"==":\" set "_DL_CUR=%_DL_CUR:~0,-1%"
set "_DL_REL="
:_dl_wt_loop
if /I "%_DL_CUR%"=="%CODEX_PRIMARY_REPO%" goto :_dl_wt_hit
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
goto :_dl_wt_scan_args
:_dl_wt_root
cd /d "%CODEX_LANE2_WORKTREE%"
:_dl_wt_scan_args
if "%~1"=="" goto :_dl_wt_done
set "_DL_A=%~1"
if "%_DL_A%"=="--" goto :_dl_wt_done
if "%_DL_A%"=="-C" goto :_dl_chk_next
if "%_DL_A%"=="--cd" goto :_dl_chk_next
if "%_DL_A%"=="--add-dir" goto :_dl_chk_next
if /I "%_DL_A:~0,5%"=="--cd=" goto :_dl_chk_eq5
if /I "%_DL_A:~0,10%"=="--add-dir=" goto :_dl_chk_eq10
shift
goto :_dl_wt_scan_args
:_dl_chk_next
if "%~2"=="" goto :_dl_wt_done
set "_DL_CAND=%~2"
shift
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
if "%_DL_CAND%"=="" goto :_dl_wt_scan_args
set "_DL_ABS="
for %%P in ("%_DL_CAND%") do set "_DL_ABS=%%~fP"
if "%_DL_ABS%"=="" goto :_dl_wt_scan_args
if "%_DL_ABS:~-1%"=="\" if not "%_DL_ABS:~-2%"==":\" set "_DL_ABS=%_DL_ABS:~0,-1%"
:_dl_cand_loop
if /I "%_DL_ABS%"=="%CODEX_PRIMARY_REPO%" goto :_dl_block_primary
for %%A in ("%_DL_ABS%") do set "_DL_CPAR=%%~dpA" & set "_DL_CLEAF=%%~nxA"
if "%_DL_CLEAF%"=="" goto :_dl_wt_scan_args
if "%_DL_CPAR:~-2%"==":\" goto :_dl_wt_scan_args
set "_DL_ABS=%_DL_CPAR:~0,-1%"
goto :_dl_cand_loop
:_dl_block_primary
echo [FAIL] Lane 2 worktree isolation blocked -C/--cd/--add-dir targeting primary repo "%CODEX_PRIMARY_REPO%". Use "%CODEX_LANE2_WORKTREE%" instead. >&2
exit /b 1
:_dl_wt_done
"@
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
$worktreeCdBlock$windowsAppsRefresh
if not exist "%CODEX_EXE%" (
    echo [ERROR] Codex binary not found at "%CODEX_EXE%". Re-run setup-dual-lane.ps1. >&2
    exit /b 1
)
"%CODEX_EXE%" %*
exit /b %ERRORLEVEL%
"@

$t3Wrapper = @"
@echo off
setlocal
${utf8Header}set "CODEX_HOME=$cmdLane1Home"
set "CODEX_ACTIVE_LANE=LANE_1"
set "CODEX_EXE=$cmdCodexExe"
$windowsAppsRefresh
if not exist "%CODEX_EXE%" (
    echo [ERROR] Codex binary not found at "%CODEX_EXE%". Re-run setup-dual-lane.ps1. >&2
    exit /b 1
)
"%CODEX_EXE%" %*
exit /b %ERRORLEVEL%
"@

# Back up any pre-existing launcher in LocalBin BEFORE writing so restore-original.ps1
# restores pre-existing user launchers with SHA-256 verification instead of deleting them.
foreach ($wrapperName in @('codex.cmd', 'codex-official.cmd', 'codex-t3.cmd')) {
    $wrapperFullPath = Join-Path $LocalBin $wrapperName
    Assert-NotReparsePoint -PathValue $wrapperFullPath -Label "Launcher $wrapperName"
    Backup-IfExists $wrapperFullPath
}

if (-not $script:IsDryRun) {
    Write-Utf8NoBom -FilePath (Join-Path $LocalBin 'codex.cmd')          -Text $officialWrapper
    Write-Utf8NoBom -FilePath (Join-Path $LocalBin 'codex-official.cmd') -Text $officialWrapper
    Write-Utf8NoBom -FilePath (Join-Path $LocalBin 'codex-t3.cmd')       -Text $t3Wrapper
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
    $firstIsLocalBin = ($pathEntries.Count -gt 0) -and ($pathEntries[0].TrimEnd('\').ToLowerInvariant() -eq $normLocalBin)
    if (-not $firstIsLocalBin) {
        $filtered = @($pathEntries | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -ne $normLocalBin })
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
# Step 13: Save Deterministic Rollback Manifest & Finalize NTFS ACL Lockdown
# ============================================================================
# WHY: Persist the SHA-256 rollback manifest BEFORE optional post-steps (SyncSessions / smoke check)
# so the user always has a complete rollback record even if an optional post-step emits a warning.
$rollbackDir = Join-Path $Lane2Home '.rollback'
Assert-NotReparsePoint -PathValue $rollbackDir -Label '.rollback directory'
if (-not $script:IsDryRun) {
    [void][System.IO.Directory]::CreateDirectory($rollbackDir)

    $manifestObj = [PSCustomObject]@{
        SchemaVersion    = 1
        Timestamp        = $script:InstallStamp
        CreatedAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
        Lane1Home        = $Lane1Home
        Lane2Home        = $Lane2Home
        LocalBin         = $LocalBin
        RepoPath         = $RepoPath
        Lane2Worktree    = if ($UseGitWorktree) { $effectiveLane2Repo } else { '' }
        GatewayApiKeyEnv = if ($ConfigureGateway) { $GatewayApiKeyEnv } else { '' }
        SharedJunctions  = $sharedDirs
        Wrappers         = @(
            (Join-Path $LocalBin 'codex.cmd'),
            (Join-Path $LocalBin 'codex-official.cmd'),
            (Join-Path $LocalBin 'codex-t3.cmd')
        )
        Files            = @($script:SnapshotEntries.ToArray())
    }
    $manifestJson = $manifestObj | ConvertTo-Json -Depth 6
    $snapPath   = Join-Path $rollbackDir "snapshot-$($script:InstallStamp).json"
    $latestPath = Join-Path $rollbackDir 'latest.json'
    Write-Utf8NoBom -FilePath $snapPath   -Text $manifestJson
    Write-Utf8NoBom -FilePath $latestPath -Text $manifestJson

    # Apply two-step NTFS ACL hardening across all sensitive credential, config, and manifest files.
    foreach ($secFile in @(
        (Join-Path $Lane1Home 'auth.json'),
        (Join-Path $Lane1Home 'config.toml'),
        (Join-Path $Lane1Home 'config.backup.toml'),
        (Join-Path $Lane2Home 'auth.json'),
        (Join-Path $Lane2Home 'config.toml'),
        $snapPath,
        $latestPath
    )) {
        Protect-SensitiveFileAcl $secFile
    }
    Write-Host "    Rollback manifest saved & NTFS sandbox ACLs locked: $latestPath" -ForegroundColor DarkGray
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
            $pyArgs = @($syncScript, '--lane1', $Lane1Home, '--lane2', $Lane2Home, '--repo', $effectiveLane2Repo, '--approval-mode', $ApprovalPolicy)
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
Write-Host "  1. Run health check anytime:   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1"
Write-Host "  2. Sign in to Lane 2 (once):   codex login"
Write-Host "  3. Start Lane 2 Official CLI:  codex"
Write-Host "  4. Start Lane 1 (Desktop/T3):  codex-t3 (or open Codex Desktop App)"
