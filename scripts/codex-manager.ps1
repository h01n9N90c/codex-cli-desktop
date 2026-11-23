<#
.SYNOPSIS
    Interactive & scriptable Control Center for Sandbox 2 (Codex CLI) authentication,
    API key & account diagnostics, bidirectional chat history sync, and history-preserving uninstall.

.DESCRIPTION
    Provides an easy bilingual (Vietnamese/English) interactive menu (-Action Menu, default) AND
    direct non-interactive CLI actions for managing Sandbox 2 (~/.codex-official -- Codex CLI)
    alongside GPT 1 (~/.codex -- Codex Desktop) on Windows 10/11 (PowerShell 5.1 & 7+):

      [1A] ApiGpt         : Authenticates Sandbox 2 with a single Official OpenAI / GPT API key
                            via masked prompt (Read-Host -AsSecureString), -ApiKeySecure, or
                            -ApiKeyFromStdin (NEVER accepts plaintext secrets on CLI arguments).
                            Automatically backs up Lane2\config.toml, removes conflicting third-party
                            model_provider overrides while preserving all [projects.*] trust_level
                            boundaries, [features], sandbox_mode, and [mcp_servers.*], pipes the key
                            via ProcessStartInfo stdin to `codex login --with-api-key`, locks two-step
                            NTFS DACLs on auth.json & config.toml, and runs bidirectional chat sync.
      [1B] ApiOther       : Points directly to Lane2\config.toml for third-party / custom provider
                            editing. Creates a timestamped backup first, displays full path + safe
                            env_key template, opens your editor (-Editor / $env:EDITOR / notepad.exe),
                            validates TOML syntax, warns on plaintext api_key / experimental_bearer_token,
                            re-locks two-step NTFS DACLs, and runs bidirectional chat sync.
      [2]  Login          : Launches official OpenAI / ChatGPT login (`codex login` or
                            `codex login --device-auth`) with CODEX_HOME=<Lane2Home>, optionally
                            backing up and cleaning conflicting third-party model_provider first,
                            locks NTFS DACLs on auth.json, and runs bidirectional chat sync.
      [3]  CheckApiKey    : Strictly read-only inspection of all Sandbox 2 API key sources
                            (config.toml env_key + Process/User env, OPENAI_API_KEY, auth.json),
                            active base_url, plaintext-secret warnings, and NTFS DACL status.
                            Masks all keys (`sk-...xxxx (len=N)`). With -OnlineCheck, probes
                            `GET <base_url>/models` (10s timeout) with zero secret echo.
      [4]  CheckAccounts  : Strictly 100% read-only diagnostic across BOTH GPT 1 (~/.codex, Desktop)
                            and Sandbox 2 (~/.codex-official, CLI): `codex login status`, safe
                            auth.json metadata (zero token/key echo), config.toml settings, 6 shared
                            NTFS Junctions, synced session counts, and NTFS DACLs.
      [5]  SyncHistory    : Runs bidirectional chat history sync (`sync-sessions.py --bidirectional
                            --backup-target`) between GPT 1 and Sandbox 2.
      [6]  RemoveSandbox2 : History-preserving safe uninstall of Sandbox 2 (Codex CLI):
                            Step 1 (MANDATORY, fail-closed): rescues 100% of Sandbox 2 chat history,
                            pinned threads, goals, and any local non-Junction rollout/memory files
                            back into GPT 1 (`sync-sessions.py --source <Lane2> --target <Lane1>
                            --rescue-shared-files --backup-target`) BEFORE deleting anything.
                            Step 2: invokes `restore-original.ps1 -RemoveLane2Home` to detach all
                            NTFS Junctions first, verify zero reparse points at all depths, and
                            remove Sandbox 2 + CLI wrappers cleanly.
                            Step 3: verifies GPT 1 chat history remains 100% intact.

.PARAMETER Action
    Operation to execute: Menu (default), ApiGpt, ApiOther, Login, CheckApiKey, CheckAccounts,
    SyncHistory, or RemoveSandbox2.

.PARAMETER Lane1Home
    CODEX_HOME directory for GPT 1 (Codex Desktop). Defaults to $env:CODEX_LANE1_HOME or %USERPROFILE%\.codex.

.PARAMETER Lane2Home
    CODEX_HOME directory for Sandbox 2 (Codex CLI). Defaults to $env:CODEX_LANE2_HOME or %USERPROFILE%\.codex-official.

.PARAMETER LocalBin
    Directory containing installed CLI wrappers. Defaults to $env:CODEX_LOCAL_BIN or %USERPROFILE%\.local\bin.

.PARAMETER CodexPath
    Optional explicit path to codex.exe or codex.cmd. When omitted, checks $env:CODEX_MANAGER_EXE
    (if valid) and auto-discovers WindowsApps MSIX, PATH (excluding LocalBin), and fallback locations.

.PARAMETER OnlineCheck
    Enables live HTTP `GET <base_url>/models` verification in CheckApiKey (10s timeout, zero secret echo).

.PARAMETER DeviceAuth
    Uses `codex login --device-auth` instead of browser redirect in Login action.

.PARAMETER Editor
    Explicit editor executable or script path for ApiOther (overrides $env:EDITOR and notepad.exe).

.PARAMETER DryRun
    Previews all actions without modifying files, ACLs, Junctions, or directories. Equivalent to -WhatIf.

.PARAMETER Force
    Skips interactive confirmation prompts (e.g., auto-cleans conflicting model_provider in Login and
    confirms deletion in RemoveSandbox2).

.PARAMETER NonInteractive
    Disables interactive prompts for CI/automation. Requires an explicit -Action (not Menu), requires
    -ApiKeySecure or -ApiKeyFromStdin for ApiGpt (unless -DryRun), and requires -Force for RemoveSandbox2.

.PARAMETER ApiKeySecure
    SecureString carrying a single OpenAI / GPT API key for ApiGpt (never accepts plaintext CLI args).

.PARAMETER ApiKeyFromStdin
    Reads a single OpenAI / GPT API key line from Standard Input for ApiGpt (zero CLI arg exposure).

.PARAMETER SkipPathUpdate
    Forwards -SkipPathUpdate to restore-original.ps1 during RemoveSandbox2 (ideal for CI/sandbox tests).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\codex-manager.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\codex-manager.ps1 -Action CheckAccounts -NonInteractive

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\codex-manager.ps1 -Action CheckApiKey -OnlineCheck -NonInteractive

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\codex-manager.ps1 -Action RemoveSandbox2 -DryRun

.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
    License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
    Project   : Codex Dual-Lane & Security Kit
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
param(
    [ValidateSet('Menu', 'ApiGpt', 'ApiOther', 'Login', 'CheckApiKey', 'CheckAccounts', 'SyncHistory', 'RemoveSandbox2')]
    [string]$Action = 'Menu',
    [string]$Lane1Home = $(if (-not [string]::IsNullOrWhiteSpace($env:CODEX_LANE1_HOME)) { $env:CODEX_LANE1_HOME } else { Join-Path $env:USERPROFILE '.codex' }),
    [string]$Lane2Home = $(if (-not [string]::IsNullOrWhiteSpace($env:CODEX_LANE2_HOME)) { $env:CODEX_LANE2_HOME } else { Join-Path $env:USERPROFILE '.codex-official' }),
    [string]$LocalBin  = $(if (-not [string]::IsNullOrWhiteSpace($env:CODEX_LOCAL_BIN))  { $env:CODEX_LOCAL_BIN }  else { Join-Path $env:USERPROFILE '.local\bin' }),
    [string]$CodexPath = '',
    [switch]$OnlineCheck,
    [switch]$DeviceAuth,
    [string]$Editor = '',
    [switch]$DryRun,
    [switch]$Force,
    [switch]$NonInteractive,
    [System.Security.SecureString]$ApiKeySecure = $null,
    [switch]$ApiKeyFromStdin,
    [switch]$SkipPathUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Unify -DryRun and standard PowerShell -WhatIf so neither .NET File calls nor native tools
# (icacls, codex, python, restore-original.ps1) can mutate state during a preview run.
$script:IsDryRun = $DryRun.IsPresent -or [bool]$WhatIfPreference
$WhatIfPreference = $false
$script:ExplicitCodexPath = $PSBoundParameters.ContainsKey('CodexPath') -and (-not [string]::IsNullOrWhiteSpace($CodexPath))
$script:CurrentPsExe = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { 'powershell.exe' }
if ([string]::IsNullOrWhiteSpace($script:CurrentPsExe)) { $script:CurrentPsExe = 'powershell.exe' }

# ============================================================================
# Helper Functions: Logging, Canonical Path Normalization & Security Guards
# ============================================================================

function Write-Section([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "    [OK]   $Message" -ForegroundColor Green
}

function Write-Info([string]$Message) {
    Write-Host "    [INFO] $Message" -ForegroundColor Gray
}

function Write-WarnLine([string]$Message) {
    Write-Host "    [WARN] $Message" -ForegroundColor Yellow
}

function Write-FailLine([string]$Message) {
    Write-Host "    [FAIL] $Message" -ForegroundColor Red
}

function Resolve-CanonicalLongPath {
    <#
    .SYNOPSIS
        Canonicalizes a Windows path to its full long-name form (expanding 8.3 short names)
        without dereferencing NTFS Junctions or symlinks.
    #>
    param(
        [AllowEmptyString()][string]$PathValue
    )
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return '' }

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
        $useWin32 = $false
    }

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
    if ($PathValue.IndexOf('"') -ge 0) {
        throw "Invalid value for -${ParamName}: double quotes are not allowed in Windows paths."
    }
    if ($PathValue -match '^(\\\\\?\\|\\\\\.\\|\\\?\?\\)') {
        throw "Invalid value for -${ParamName}: raw Win32 device namespace prefixes are not allowed."
    }
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
    $a = (Resolve-CanonicalLongPath -PathValue $PathA).TrimEnd('\').ToLowerInvariant()
    $b = (Resolve-CanonicalLongPath -PathValue $PathB).TrimEnd('\').ToLowerInvariant()
    return ($a -eq $b) -or $a.StartsWith("$b\") -or $b.StartsWith("$a\")
}

function Assert-NotReparsePoint {
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

function Test-IsReparsePoint([string]$PathValue) {
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return $false }
    try {
        $attrs = [System.IO.File]::GetAttributes($PathValue)
        return [bool]($attrs -band [System.IO.FileAttributes]::ReparsePoint)
    } catch {
        return $false
    }
}

function Write-Utf8NoBom {
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
                [System.IO.File]::Replace($tmpPath, $fullPath, [NullString]::Value)
            } catch {
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
        Fail-closed two-step Windows NTFS DACL lockdown (/inheritance:d + conditional /remove:g "CodexSandboxUsers")
        with Get-Acl post-condition verification.
    #>
    if ($script:IsDryRun -or -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return }

    $fullPath = Resolve-CanonicalLongPath -PathValue $FilePath
    Assert-NotReparsePoint -PathValue $fullPath -Label 'Protect-SensitiveFileAcl target file'
    if (-not (Get-Command 'icacls.exe' -ErrorAction SilentlyContinue)) {
        throw "Security error: 'icacls.exe' was not found in PATH; cannot lock NTFS DACL on '$fullPath'."
    }

    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $icaclsOut1 = (& icacls.exe $fullPath /inheritance:d 2>&1) -join ' '
        $exit1 = $LASTEXITCODE
        if ($exit1 -ne 0) {
            throw "Security error: icacls.exe /inheritance:d failed (exit code $exit1) for '$fullPath': $icaclsOut1"
        }

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
            $icaclsOut2 = (& icacls.exe $fullPath /remove:g "CodexSandboxUsers" 2>&1) -join ' '
            $exit2 = $LASTEXITCODE
            if ($exit2 -ne 0) {
                throw "Security error: icacls.exe /remove:g CodexSandboxUsers failed (exit code $exit2) for '$fullPath': $icaclsOut2"
            }
        }

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
        $global:LASTEXITCODE = 0
    }
}

function Get-FileAclStatus([string]$FilePath) {
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return [PSCustomObject]@{ Exists = $false; Protected = $false; SandboxAllowCount = 0; Label = 'missing' }
    }
    if (Test-IsReparsePoint $FilePath) {
        return [PSCustomObject]@{ Exists = $true; Protected = $false; SandboxAllowCount = -1; Label = 'SYMLINK_REJECTED' }
    }
    try {
        $acl = Get-Acl -LiteralPath $FilePath -ErrorAction Stop
        $prot = [bool]$acl.AreAccessRulesProtected
        $allowRules = @($acl.Access | Where-Object {
            ($_.IdentityReference.Value -like '*CodexSandboxUsers*') -and
            ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
        })
        $allowCnt = $allowRules.Count
        $lbl = if ($allowCnt -gt 0) {
            "EXPOSED (sandbox_allow=$allowCnt, inheritance_protected=$prot)"
        } elseif ($prot) {
            'locked (inheritance_protected=True, sandbox_allow=0)'
        } else {
            'unlocked-inheritance (inheritance_protected=False, sandbox_allow=0)'
        }
        return [PSCustomObject]@{ Exists = $true; Protected = $prot; SandboxAllowCount = $allowCnt; Label = $lbl }
    } catch {
        return [PSCustomObject]@{ Exists = $true; Protected = $false; SandboxAllowCount = -1; Label = 'unreadable-acl' }
    }
}

function New-TimestampedBackup([string]$FilePath) {
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return '' }
    $full = Resolve-CanonicalLongPath -PathValue $FilePath
    Assert-NotReparsePoint -PathValue $full -Label 'Backup source file'
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $candidate = "$full.backup-$stamp"
    $suffix = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = "$full.backup-$stamp-$suffix"
        $suffix++
    }
    if (-not $script:IsDryRun) {
        Copy-Item -LiteralPath $full -Destination $candidate -Force
        Protect-SensitiveFileAcl $candidate
    }
    return $candidate
}

# ============================================================================
# Secret Masking, SecureString Handling & Output Redaction (Zero Secret Echo)
# ============================================================================

function Format-MaskedSecret([AllowEmptyString()][string]$Secret) {
    if ([string]::IsNullOrWhiteSpace($Secret)) { return 'NOT_SET' }
    $trimmed = $Secret.Trim()
    $len = $trimmed.Length
    if ($len -lt 12) {
        return "*** (len=$len)"
    }
    $last4 = $trimmed.Substring($len - 4)
    if ($trimmed.StartsWith('sk-', [System.StringComparison]::OrdinalIgnoreCase)) {
        return "sk-...$last4 (len=$len)"
    }
    return "***...$last4 (len=$len)"
}

function Format-MaskedEmail([AllowEmptyString()][string]$Email) {
    if ([string]::IsNullOrWhiteSpace($Email)) { return '' }
    $e = $Email.Trim()
    if ($e -match '^(sk-|eyJ|Bearer|ghp_|gho_|xox)') { return 'redacted' }
    $m = [regex]::Match($e, '^([A-Za-z0-9._%+\-]{1,64})@([A-Za-z0-9.\-]{1,128})$')
    if (-not $m.Success) { return 'redacted' }
    $local = $m.Groups[1].Value
    $domain = $m.Groups[2].Value
    return ($local.Substring(0, 1) + '***@' + $domain)
}

function Format-MaskedIdentifier([AllowEmptyString()][string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $v = $Value.Trim()
    if ($v -match '^(sk-|eyJ|Bearer|ghp_|gho_|xox)') { return 'redacted' }
    if ($v.Length -lt 8) { return "*** (len=$($v.Length))" }
    return "...$($v.Substring($v.Length - 4)) (len=$($v.Length))"
}

function Redact-SecretsFromText {
    param(
        [AllowEmptyString()][string]$Text,
        [string[]]$ExplicitSecrets = @()
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $out = $Text
    foreach ($sec in $ExplicitSecrets) {
        if (-not [string]::IsNullOrWhiteSpace($sec) -and $sec.Length -ge 4) {
            $out = [regex]::Replace($out, [regex]::Escape($sec), '[REDACTED]')
        }
    }
    $out = [regex]::Replace($out, '(?i)Bearer\s+[A-Za-z0-9._\-+/=]{8,}', 'Bearer [REDACTED]')
    $out = [regex]::Replace($out, '\bsk-[A-Za-z0-9_\-]{8,}\b', 'sk-[REDACTED]')
    $out = [regex]::Replace($out, '\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}(?:\.[A-Za-z0-9_\-]*)?\b', '[REDACTED_JWT]')
    $out = [regex]::Replace($out, '\b(?:ghp|gho|ghu|ghs|xox[baprs])_[A-Za-z0-9_\-]{8,}\b', '[REDACTED_TOKEN]')
    $out = [regex]::Replace($out, '(?i)("?(?:access_token|refresh_token|id_token|api_key|openai_api_key|experimental_bearer_token|authorization)"?\s*[:=]\s*["'']?)([^"''\s,}]{6,})', '$1[REDACTED]')
    return $out
}

function ConvertFrom-SecureStringPlain([System.Security.SecureString]$Sec) {
    if ($null -eq $Sec) { return '' }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Sec)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        if ($null -eq $plain) { return '' }
        return $plain
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-EnvVarValueAndScope([string]$VarName) {
    if ([string]::IsNullOrWhiteSpace($VarName)) {
        return [PSCustomObject]@{ Value = ''; Scope = 'None' }
    }
    $procVal = [System.Environment]::GetEnvironmentVariable($VarName, 'Process')
    if (-not [string]::IsNullOrWhiteSpace($procVal)) {
        return [PSCustomObject]@{ Value = $procVal; Scope = 'Process' }
    }
    $userVal = [System.Environment]::GetEnvironmentVariable($VarName, 'User')
    if (-not [string]::IsNullOrWhiteSpace($userVal)) {
        return [PSCustomObject]@{ Value = $userVal; Scope = 'User' }
    }
    return [PSCustomObject]@{ Value = ''; Scope = 'None' }
}

# ============================================================================
# Discovery & Process Execution Helpers (Codex CLI & Python 3)
# ============================================================================

function Resolve-CodexExecutable {
    param(
        [AllowEmptyString()][string]$ExplicitPath = '',
        [string]$ExcludedDir = '',
        [switch]$AllowMissing
    )
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            if ($AllowMissing) { return $null }
            throw "Specified -CodexPath does not exist or is not a file: $ExplicitPath"
        }
        $resolvedExplicit = Resolve-CanonicalLongPath -PathValue (Resolve-Path -LiteralPath $ExplicitPath).Path
        return [PSCustomObject]@{ Path = $resolvedExplicit; Source = 'Explicit' }
    }

    # Soft fallback from codex-manage wrapper environment variable (auto-discovers if stale after MSIX update)
    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MANAGER_EXE)) {
        try {
            $envCandidate = Assert-SafeWindowsPath -PathValue $env:CODEX_MANAGER_EXE -ParamName 'CODEX_MANAGER_EXE' -AllowEmpty
            if ($envCandidate -and (Test-Path -LiteralPath $envCandidate -PathType Leaf)) {
                return [PSCustomObject]@{ Path = $envCandidate; Source = 'EnvWrapper' }
            }
        } catch {}
    }

    # Microsoft Store / MSIX OpenAI.Codex Desktop package
    try {
        $appx = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($appx -and $appx.InstallLocation) {
            $msixExe = Join-Path $appx.InstallLocation 'app\resources\codex.exe'
            if (Test-Path -LiteralPath $msixExe -PathType Leaf) {
                return [PSCustomObject]@{ Path = (Resolve-CanonicalLongPath -PathValue $msixExe); Source = 'WindowsApps' }
            }
        }
    } catch {}

    # Existing codex binary in PATH (strictly excluding LocalBin wrapper to avoid recursion)
    $excludedNorm = if ($ExcludedDir) { (Resolve-CanonicalLongPath -PathValue $ExcludedDir).TrimEnd('\').ToLowerInvariant() } else { '' }
    $cmdCandidates = @(Get-Command codex -All -ErrorAction SilentlyContinue)
    $exeMatch = $null
    $batchMatch = $null
    foreach ($cmd in $cmdCandidates) {
        if (-not $cmd -or -not $cmd.Source) { continue }
        $src = Resolve-CanonicalLongPath -PathValue $cmd.Source
        $parent = (Resolve-CanonicalLongPath -PathValue (Split-Path -Parent $src)).TrimEnd('\').ToLowerInvariant()
        if ($excludedNorm -and ($parent -eq $excludedNorm)) { continue }
        $ext = [System.IO.Path]::GetExtension($src).ToLowerInvariant()
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

    foreach ($fb in @((Join-Path $env:APPDATA 'npm\codex.cmd'), (Join-Path $env:LOCALAPPDATA 'Programs\Codex\codex.exe'))) {
        if (Test-Path -LiteralPath $fb -PathType Leaf) {
            return [PSCustomObject]@{ Path = (Resolve-CanonicalLongPath -PathValue $fb); Source = 'Fallback' }
        }
    }

    if ($AllowMissing) { return $null }
    throw "No Codex binary found on this machine. Install Codex Desktop/CLI or pass -CodexPath."
}

function Find-Python3Executable {
    foreach ($cand in @('python', 'python3')) {
        foreach ($cmd in @(Get-Command $cand -All -ErrorAction SilentlyContinue)) {
            if (-not $cmd -or -not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
            $prevPref = $ErrorActionPreference
            $v = ''
            try {
                $ErrorActionPreference = 'Continue'
                $v = [string](& $cmd.Source --version 2>&1 | Select-Object -First 1)
            } finally {
                $ErrorActionPreference = $prevPref
                $global:LASTEXITCODE = 0
            }
            if ($v -match '^Python 3\.') {
                return (Resolve-CanonicalLongPath -PathValue $cmd.Source)
            }
        }
    }
    return $null
}

function Invoke-CodexProcess {
    <#
    .SYNOPSIS
        Executes a Codex CLI command with isolated CODEX_HOME, optional stdin piping (so API keys
        never touch command line or disk), async stdout/stderr capture, and optional timeout.
        Works identically for .exe and .cmd/.bat binaries on PowerShell 5.1 and 7+.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$TargetCodexHome,
        [AllowNull()][string]$StdinText = $null,
        [int]$TimeoutMs = 30000
    )
    $ext = [System.IO.Path]::GetExtension($ExePath).ToLowerInvariant()
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    if ($ext -eq '.cmd' -or $ext -eq '.bat') {
        $psi.FileName = if ($env:ComSpec) { $env:ComSpec } else { 'cmd.exe' }
        # Outer quotes around the entire command line let cmd.exe /d /c preserve spaces & '&' in $ExePath.
        $psi.Arguments = '/d /c ""' + $ExePath + '" ' + ($Arguments -join ' ') + '"'
    } else {
        $psi.FileName = $ExePath
        $psi.Arguments = ($Arguments -join ' ')
    }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = ($null -ne $StdinText)
    $psi.EnvironmentVariables['CODEX_HOME'] = $TargetCodexHome

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        if (-not $proc.Start()) {
            throw "Failed to start Codex process: $ExePath"
        }
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        if ($null -ne $StdinText) {
            try {
                $proc.StandardInput.WriteLine($StdinText)
                $proc.StandardInput.Flush()
            } finally {
                $proc.StandardInput.Close()
            }
        }

        $exited = if ($TimeoutMs -gt 0) { $proc.WaitForExit($TimeoutMs) } else { $proc.WaitForExit(); $true }
        if (-not $exited) {
            try { $proc.Kill() } catch {}
            return [PSCustomObject]@{ ExitCode = -1; StdOut = ''; StdErr = "Timed out after ${TimeoutMs}ms"; TimedOut = $true }
        }
        $proc.WaitForExit()
        $outStr = $stdoutTask.GetAwaiter().GetResult()
        $errStr = $stderrTask.GetAwaiter().GetResult()
        return [PSCustomObject]@{
            ExitCode = $proc.ExitCode
            StdOut   = if ($null -eq $outStr) { '' } else { $outStr }
            StdErr   = if ($null -eq $errStr) { '' } else { $errStr }
            TimedOut = $false
        }
    } finally {
        $proc.Dispose()
    }
}

# ============================================================================
# TOML & Auth.json Safe Read-Only Inspection + Provider Cleanup Helpers
# ============================================================================

function Remove-TomlInlineComment([string]$Line) {
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

function Unescape-TomlBasicString([AllowEmptyString()][string]$Escaped) {
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

function Update-TomlMultilineState {
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
            if ($delim -eq '"""' -and $Text[$i] -eq '\' -and ($i + 1) -lt $len) { $i += 2; continue }
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

function Parse-TomlQuotedString([AllowEmptyString()][string]$RhsRaw) {
    $clean = (Remove-TomlInlineComment $RhsRaw).Trim()
    $m = [regex]::Match($clean, '^(?:"((?:[^"\\]|\\.)*)"|''([^'']*)'')\s*$')
    if (-not $m.Success) { return '' }
    if ($m.Groups[1].Success) { return (Unescape-TomlBasicString $m.Groups[1].Value) }
    return $m.Groups[2].Value
}

function Get-ModelProviderHeaderName([AllowEmptyString()][string]$HeaderInner) {
    if ([string]::IsNullOrWhiteSpace($HeaderInner)) { return $null }
    $t = $HeaderInner.Trim()
    $m = [regex]::Match($t, '^model_providers\s*\.\s*(?:"((?:[^"\\]|\\.)+)"|''([^'']+)''|([A-Za-z0-9_-]+))(?:\..+)?$')
    if (-not $m.Success) { return $null }
    if ($m.Groups[1].Success) { return (Unescape-TomlBasicString $m.Groups[1].Value) }
    if ($m.Groups[2].Success) { return $m.Groups[2].Value }
    return $m.Groups[3].Value
}

function Test-IsOfficialOpenAiBaseUrl([AllowEmptyString()][string]$BaseUrl) {
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) { return $true }
    return ($BaseUrl.Trim() -match '^https://api\.openai\.com(/v1)?/?$')
}

function Find-PlaintextSecretsInToml([AllowEmptyString()][string]$ConfigText) {
    $offendingKeys = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrEmpty($ConfigText)) { return @() }
    foreach ($line in ($ConfigText -split "\r?\n")) {
        if ($line -match '^\s*#') { continue }
        if ($line -match '^\s*(experimental_bearer_token)\s*=\s*\S+') {
            if (-not $offendingKeys.Contains($Matches[1])) { $offendingKeys.Add($Matches[1]) }
        } elseif ($line -match '^\s*(api_key)\s*=\s*["''][^"'']+["'']') {
            if (-not $offendingKeys.Contains($Matches[1])) { $offendingKeys.Add($Matches[1]) }
        }
    }
    return @($offendingKeys.ToArray())
}

function Get-TomlConfigSummary([string]$ConfigPath) {
    $providers = New-Object 'System.Collections.Generic.Dictionary[string, object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $summary = [PSCustomObject]@{
        Exists                = $false
        IsSymlink             = $false
        ModelProvider         = ''
        Model                 = ''
        SandboxMode           = ''
        ApprovalPolicy        = ''
        Providers             = $providers
        ActiveEnvKey          = ''
        ActiveBaseUrl         = 'https://api.openai.com/v1'
        IsThirdPartyActive    = $false
        PlaintextSecretKeys   = @()
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return $summary }
    if (Test-IsReparsePoint $ConfigPath) {
        $summary.Exists = $true
        $summary.IsSymlink = $true
        return $summary
    }
    $summary.Exists = $true
    $raw = [string](Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrEmpty($raw)) { return $summary }

    $summary.PlaintextSecretKeys = @(Find-PlaintextSecretsInToml -ConfigText $raw)

    $inSection = $false
    $currentProviderKey = $null
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
            $currentProviderKey = $null
            continue
        }
        if ($noComment -match '^\[(.+)\]$') {
            $inSection = $true
            $hdrInner = $Matches[1].Trim()
            # Direct [model_providers.<name>] section (ignore deeper subtables for base_url/env_key)
            $directProvMatch = [regex]::Match($hdrInner, '^model_providers\s*\.\s*(?:"((?:[^"\\]|\\.)+)"|''([^'']+)''|([A-Za-z0-9_-]+))\s*$')
            if ($directProvMatch.Success) {
                $pName = if ($directProvMatch.Groups[1].Success) { Unescape-TomlBasicString $directProvMatch.Groups[1].Value }
                         elseif ($directProvMatch.Groups[2].Success) { $directProvMatch.Groups[2].Value }
                         else { $directProvMatch.Groups[3].Value }
                $pKey = $pName.ToLowerInvariant()
                if (-not $providers.ContainsKey($pKey)) {
                    $providers[$pKey] = [PSCustomObject]@{
                        RawName = $pName
                        BaseUrl = ''
                        EnvKey  = ''
                        WireApi = ''
                    }
                }
                $currentProviderKey = $pKey
            } else {
                $currentProviderKey = $null
            }
            continue
        }

        $kv = [regex]::Match($line, '^\s*([A-Za-z0-9_-]+)\s*=(.*)$')
        if ($kv.Success) {
            $k = $kv.Groups[1].Value
            $rhs = $kv.Groups[2].Value
            $bracketDepth = 0
            $multilineQuote = ''
            Update-TomlMultilineState -Text $rhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            if ($bracketDepth -gt 0 -or $multilineQuote -ne '') {
                $inMultiline = $true
                continue
            }
            $valStr = Parse-TomlQuotedString $rhs
            if (-not $inSection) {
                switch ($k) {
                    'model_provider'  { $summary.ModelProvider  = $valStr }
                    'model'           { $summary.Model          = $valStr }
                    'sandbox_mode'    { $summary.SandboxMode    = $valStr }
                    'approval_policy' { $summary.ApprovalPolicy = $valStr }
                }
            } elseif ($null -ne $currentProviderKey) {
                $pObj = $providers[$currentProviderKey]
                switch ($k) {
                    'base_url' {
                        if ($valStr -match '^https?://\S+$') { $pObj.BaseUrl = $valStr }
                    }
                    'env_key' {
                        if ($valStr -notmatch '^(sk-|eyJ|Bearer|ghp_|gho_|xox)' -and $valStr -match '^[A-Za-z_][A-Za-z0-9_]{1,63}$') {
                            $pObj.EnvKey = $valStr
                        } elseif (-not [string]::IsNullOrWhiteSpace($valStr)) {
                            $pObj.EnvKey = 'redacted-env-key'
                        }
                    }
                    'wire_api' { $pObj.WireApi = $valStr }
                }
            }
        }
    }

    $activeSec = $null
    if (-not [string]::IsNullOrWhiteSpace($summary.ModelProvider)) {
        $mpKey = $summary.ModelProvider.ToLowerInvariant()
        if ($providers.ContainsKey($mpKey)) { $activeSec = $providers[$mpKey] }
    } elseif ($providers.ContainsKey('openai')) {
        $activeSec = $providers['openai']
    }

    if ($null -ne $activeSec) {
        if (-not [string]::IsNullOrWhiteSpace($activeSec.EnvKey)) {
            $summary.ActiveEnvKey = $activeSec.EnvKey
        }
        if (-not [string]::IsNullOrWhiteSpace($activeSec.BaseUrl)) {
            $summary.ActiveBaseUrl = $activeSec.BaseUrl
        }
    }

    # Third-party override is active if:
    #   (a) top-level model_provider is set AND (it is not literal 'openai', OR a custom [model_providers.<name>] exists with non-official base_url or env_key), OR
    #   (b) [model_providers.openai] exists with a non-official base_url.
    if (-not [string]::IsNullOrWhiteSpace($summary.ModelProvider)) {
        if ($summary.ModelProvider -cne 'openai') {
            $summary.IsThirdPartyActive = $true
        } elseif ($null -ne $activeSec -and ((-not (Test-IsOfficialOpenAiBaseUrl $activeSec.BaseUrl)) -or (-not [string]::IsNullOrWhiteSpace($activeSec.EnvKey)))) {
            $summary.IsThirdPartyActive = $true
        }
    } elseif ($providers.ContainsKey('openai') -and (-not (Test-IsOfficialOpenAiBaseUrl $providers['openai'].BaseUrl))) {
        $summary.IsThirdPartyActive = $true
    }

    return $summary
}

function Clear-ThirdPartyProviderFromConfig([string]$ConfigPath) {
    $summary = Get-TomlConfigSummary -ConfigPath $ConfigPath
    if (-not $summary.Exists -or -not $summary.IsThirdPartyActive) {
        return [PSCustomObject]@{ Modified = $false; BackupPath = ''; RemovedProvider = '' }
    }
    if ($summary.IsSymlink) {
        throw "Security violation: Refusing to edit symlink/reparse point at '$ConfigPath'."
    }
    $removedLabel = if ($summary.ModelProvider) { $summary.ModelProvider } else { 'openai (custom override)' }
    if ($script:IsDryRun) {
        Write-Info "[DRY-RUN] Would backup '$ConfigPath' and remove third-party model_provider='$removedLabel' (preserving all [projects.*], [features], sandbox_mode, and [mcp_servers.*])."
        return [PSCustomObject]@{ Modified = $true; BackupPath = ''; RemovedProvider = $removedLabel }
    }

    $backupPath = New-TimestampedBackup -FilePath $ConfigPath
    $raw = [string](Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 -ErrorAction Stop)

    $dropProviders = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if (-not [string]::IsNullOrWhiteSpace($summary.ModelProvider)) {
        [void]$dropProviders.Add($summary.ModelProvider)
    }
    if ($summary.Providers.ContainsKey('openai') -and (-not (Test-IsOfficialOpenAiBaseUrl $summary.Providers['openai'].BaseUrl))) {
        [void]$dropProviders.Add('openai')
    }

    $keptLines = New-Object 'System.Collections.Generic.List[string]'
    $inSection = $false
    $skipSection = $false
    $inMultiline = $false
    $skipMultiline = $false
    $bracketDepth = 0
    $multilineQuote = ''

    foreach ($line in ($raw -split "\r?\n")) {
        if ($inMultiline) {
            if (-not $skipMultiline) { $keptLines.Add($line) }
            Update-TomlMultilineState -Text $line -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
            if ($bracketDepth -eq 0 -and $multilineQuote -eq '') {
                $inMultiline = $false
                $skipMultiline = $false
            }
            continue
        }

        $noComment = (Remove-TomlInlineComment $line).Trim()
        if ($noComment -match '^\[\[(.+)\]\]$') {
            $inSection = $true
            $skipSection = $false
            $keptLines.Add($line)
            continue
        }
        if ($noComment -match '^\[(.+)\]$') {
            $inSection = $true
            $hdrInner = $Matches[1].Trim()
            $provName = Get-ModelProviderHeaderName $hdrInner
            if ($null -ne $provName -and $dropProviders.Contains($provName)) {
                $skipSection = $true
            } else {
                $skipSection = $false
                $keptLines.Add($line)
            }
            continue
        }

        if (-not $inSection) {
            $kv = [regex]::Match($line, '^\s*([A-Za-z0-9_-]+)\s*=(.*)$')
            if ($kv.Success) {
                $k = $kv.Groups[1].Value
                $rhs = $kv.Groups[2].Value
                $isDropKey = ($k -ceq 'model_provider')
                $bracketDepth = 0
                $multilineQuote = ''
                Update-TomlMultilineState -Text $rhs -BracketDepth ([ref]$bracketDepth) -MultilineQuote ([ref]$multilineQuote)
                if ($bracketDepth -gt 0 -or $multilineQuote -ne '') {
                    $inMultiline = $true
                    $skipMultiline = $isDropKey
                }
                if (-not $isDropKey) { $keptLines.Add($line) }
                continue
            }
            $keptLines.Add($line)
        } else {
            if (-not $skipSection) {
                $keptLines.Add($line)
            }
        }
    }

    # Collapse excessive consecutive blank lines neatly while preserving all remaining content verbatim.
    $cleanLines = New-Object 'System.Collections.Generic.List[string]'
    $blankRun = 0
    foreach ($kl in $keptLines) {
        if ([string]::IsNullOrWhiteSpace($kl)) {
            $blankRun++
            if ($blankRun -le 2) { $cleanLines.Add('') }
        } else {
            $blankRun = 0
            $cleanLines.Add($kl)
        }
    }
    $finalText = (($cleanLines -join "`r`n").Trim()) + "`r`n"
    Write-Utf8NoBom -FilePath $ConfigPath -Text $finalText
    Protect-SensitiveFileAcl $ConfigPath
    return [PSCustomObject]@{ Modified = $true; BackupPath = $backupPath; RemovedProvider = $removedLabel }
}

function Test-TomlSyntax([string]$ConfigPath) {
    $py = Find-Python3Executable
    if (-not $py) {
        return [PSCustomObject]@{ Checked = $false; Valid = $true; Message = 'Python 3 not installed (skipped tomllib syntax check)' }
    }
    $pyCode = @'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
loader = None
if sys.version_info >= (3, 11):
    import tomllib as loader
else:
    try:
        import tomli as loader
    except ImportError:
        print("SKIP_NO_TOMLLIB")
        sys.exit(0)
try:
    loader.loads(p.read_text(encoding="utf-8"))
    print("TOML_OK")
except Exception as exc:
    print(f"TOML_ERR: {type(exc).__name__}: {exc}")
    sys.exit(2)
'@
    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = ($pyCode | & $py -B - $ConfigPath 2>&1) -join ' '
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevPref
        $global:LASTEXITCODE = 0
    }
    if ($out -match 'SKIP_NO_TOMLLIB') {
        return [PSCustomObject]@{ Checked = $false; Valid = $true; Message = 'Python < 3.11 without tomli (skipped tomllib syntax check)' }
    }
    if ($code -eq 0 -and $out -match 'TOML_OK') {
        return [PSCustomObject]@{ Checked = $true; Valid = $true; Message = 'Valid TOML syntax (verified via Python tomllib)' }
    }
    $safeErr = Redact-SecretsFromText -Text $out
    return [PSCustomObject]@{ Checked = $true; Valid = $false; Message = $safeErr }
}

function Get-SafeAuthMetadata([string]$AuthJsonPath) {
    <#
    .SYNOPSIS
        Strictly read-only parser for auth.json. Extracts non-sensitive metadata and masked
        indicators ONLY; collects raw tokens internally solely for downstream redaction.
    #>
    $secrets = New-Object 'System.Collections.Generic.List[string]'
    $meta = [PSCustomObject]@{
        Exists          = $false
        IsSymlink       = $false
        ValidJson       = $false
        AuthMode        = 'missing'
        HasApiKey       = $false
        ApiKeyRaw       = ''
        MaskedApiKey    = 'NOT_SET'
        HasOAuthTokens  = $false
        MaskedAccountId = ''
        MaskedEmail     = ''
        PlanLabel       = ''
        LastRefresh     = ''
        SecretsToRedact = @()
    }
    if (-not (Test-Path -LiteralPath $AuthJsonPath -PathType Leaf)) { return $meta }
    if (Test-IsReparsePoint $AuthJsonPath) {
        $meta.Exists = $true
        $meta.IsSymlink = $true
        $meta.AuthMode = 'SYMLINK_REJECTED'
        return $meta
    }
    $meta.Exists = $true
    try {
        $parsed = Get-Content -LiteralPath $AuthJsonPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $meta.ValidJson = $true
        if ($null -eq $parsed) {
            $meta.AuthMode = 'empty'
            return $meta
        }

        $modeProp = $parsed.PSObject.Properties['auth_mode']
        if ($null -eq $modeProp -or [string]::IsNullOrWhiteSpace([string]$modeProp.Value)) {
            $meta.AuthMode = 'present(mode-unset)'
        } else {
            $mv = ([string]$modeProp.Value).Trim()
            if ($mv -match '^(sk-|eyJ|Bearer|ghp_|gho_|xox)' -or $mv -notmatch '^[A-Za-z0-9_.-]{1,32}$') {
                $secrets.Add($mv)
                $meta.AuthMode = 'redacted-nonstandard'
            } else {
                $meta.AuthMode = $mv
            }
        }

        $apiKeyProp = $parsed.PSObject.Properties['OPENAI_API_KEY']
        if ($null -ne $apiKeyProp -and ($apiKeyProp.Value -is [string]) -and (-not [string]::IsNullOrWhiteSpace($apiKeyProp.Value))) {
            $rawKey = $apiKeyProp.Value.Trim()
            $meta.HasApiKey = $true
            $meta.ApiKeyRaw = $rawKey
            $meta.MaskedApiKey = Format-MaskedSecret $rawKey
            $secrets.Add($rawKey)
        }

        $tokensProp = $parsed.PSObject.Properties['tokens']
        if ($null -ne $tokensProp -and $null -ne $tokensProp.Value) {
            $tokObj = $tokensProp.Value
            foreach ($tkName in @('access_token', 'refresh_token', 'id_token')) {
                $tp = $tokObj.PSObject.Properties[$tkName]
                if ($null -ne $tp -and ($tp.Value -is [string]) -and (-not [string]::IsNullOrWhiteSpace($tp.Value))) {
                    $meta.HasOAuthTokens = $true
                    $secrets.Add($tp.Value.Trim())
                }
            }
            $accProp = $tokObj.PSObject.Properties['account_id']
            if ($null -ne $accProp -and ($accProp.Value -is [string]) -and (-not [string]::IsNullOrWhiteSpace($accProp.Value))) {
                $meta.MaskedAccountId = Format-MaskedIdentifier $accProp.Value
            }
        }

        if ([string]::IsNullOrEmpty($meta.MaskedAccountId)) {
            $topAcc = $parsed.PSObject.Properties['account_id']
            if ($null -ne $topAcc -and ($topAcc.Value -is [string]) -and (-not [string]::IsNullOrWhiteSpace($topAcc.Value))) {
                $meta.MaskedAccountId = Format-MaskedIdentifier $topAcc.Value
            }
        }

        foreach ($emailField in @('email', 'account_email')) {
            $ep = $parsed.PSObject.Properties[$emailField]
            if ($null -ne $ep -and ($ep.Value -is [string]) -and (-not [string]::IsNullOrWhiteSpace($ep.Value))) {
                $meta.MaskedEmail = Format-MaskedEmail $ep.Value
                break
            }
        }

        foreach ($planField in @('plan_type', 'plan')) {
            $pp = $parsed.PSObject.Properties[$planField]
            if ($null -ne $pp -and ($pp.Value -is [string])) {
                $pv = $pp.Value.Trim().ToLowerInvariant()
                if ($pv -match '^(free|plus|pro|team|enterprise|edu|business|go|api)$') {
                    $meta.PlanLabel = $pv
                    break
                }
            }
        }

        $lrProp = $parsed.PSObject.Properties['last_refresh']
        if ($null -ne $lrProp -and ($lrProp.Value -is [string]) -and ($lrProp.Value.Trim() -match '^\d{4}-\d{2}-\d{2}')) {
            $meta.LastRefresh = $lrProp.Value.Trim()
        }
    } catch {
        $meta.AuthMode = 'unreadable'
    }
    $meta.SecretsToRedact = @($secrets.ToArray())
    return $meta
}

function Get-SessionIndexCount([string]$LaneHomePath) {
    $idxPath = Join-Path $LaneHomePath 'session_index.jsonl'
    if (-not (Test-Path -LiteralPath $idxPath -PathType Leaf)) { return 0 }
    if (Test-IsReparsePoint $idxPath) { return -1 }
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    try {
        foreach ($line in [System.IO.File]::ReadLines($idxPath, [System.Text.Encoding]::UTF8)) {
            $t = $line.Trim()
            if ([string]::IsNullOrEmpty($t)) { continue }
            try {
                $obj = $t | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $obj) {
                    $idProp = $obj.PSObject.Properties['id']
                    if ($null -ne $idProp -and -not [string]::IsNullOrWhiteSpace([string]$idProp.Value)) {
                        [void]$ids.Add(([string]$idProp.Value).Trim())
                    }
                }
            } catch {}
        }
    } catch {
        return -1
    }
    return $ids.Count
}

function Get-LatestVersionedSqliteName([string]$LaneHomePath, [string]$Prefix) {
    if (-not (Test-Path -LiteralPath $LaneHomePath -PathType Container)) { return '' }
    $bestNum = -1
    $bestName = ''
    foreach ($f in @(Get-ChildItem -LiteralPath $LaneHomePath -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -match "^$([regex]::Escape($Prefix))_(\d+)\.sqlite$") {
            $n = [int]$Matches[1]
            if ($n -gt $bestNum) {
                $bestNum = $n
                $bestName = $f.Name
            }
        }
    }
    return $bestName
}

function Invoke-HistorySync {
    <#
    .SYNOPSIS
        Runs scripts\sync-sessions.py for bidirectional sync or pre-uninstall chat rescue.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$SourceHome,
        [Parameter(Mandatory = $true)][string]$TargetHome,
        [switch]$Bidirectional,
        [switch]$RescueSharedFiles,
        [switch]$FailClosed
    )
    $syncScript = Join-Path $script:KitRoot 'scripts\sync-sessions.py'
    if (-not (Test-Path -LiteralPath $syncScript -PathType Leaf)) {
        if ($FailClosed) { throw "Required sync script missing: $syncScript" }
        Write-WarnLine "sync-sessions.py not found at '$syncScript'; skipping chat history sync."
        return $false
    }
    $py = Find-Python3Executable
    if (-not $py) {
        if ($FailClosed) { throw 'Python 3 is required for chat history sync/rescue (sync-sessions.py), but no Python 3 executable was found in PATH.' }
        Write-WarnLine 'Python 3 not found in PATH; skipping automatic bidirectional chat history sync.'
        return $false
    }
    if (-not (Test-Path -LiteralPath $SourceHome -PathType Container) -or -not (Test-Path -LiteralPath $TargetHome -PathType Container)) {
        if ($FailClosed) {
            throw "Cannot sync chat history: both source ('$SourceHome') and target ('$TargetHome') directories must exist."
        }
        Write-Info "Skipping automatic bidirectional chat sync (source or target directory does not exist yet)."
        return $false
    }

    $pyArgs = @('-B', $syncScript, '--source', $SourceHome, '--target', $TargetHome, '--backup-target')
    if ($Bidirectional)     { $pyArgs += '--bidirectional' }
    if ($RescueSharedFiles) { $pyArgs += '--rescue-shared-files' }
    if ($script:IsDryRun)   { $pyArgs += '--dry-run' }

    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $syncLines = @(& $py @pyArgs 2>&1)
        $syncExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevPref
        $global:LASTEXITCODE = 0
    }
    foreach ($sl in $syncLines) {
        $safeLine = Redact-SecretsFromText -Text ([string]$sl)
        if (-not [string]::IsNullOrWhiteSpace($safeLine)) {
            Write-Host "    $safeLine" -ForegroundColor Gray
        }
    }
    if ($syncExit -ne 0) {
        if ($FailClosed) {
            Write-FailLine "sync-sessions.py failed with exit code $syncExit."
            return $false
        }
        Write-WarnLine "sync-sessions.py exited with code $syncExit; re-run SyncHistory when Codex Desktop/CLI is idle."
        return $false
    }
    Write-Ok 'Chat history synchronization completed cleanly.'
    return $true
}

# ============================================================================
# Action 1A: ApiGpt -- Official OpenAI / GPT API Key for Sandbox 2
# ============================================================================

function Invoke-ActionApiGpt {
    Write-Section '[1A] Xac thuc API Key OpenAI / GPT Chinh Chu cho Sandbox 2 (Codex CLI)'
    Write-Info "Sandbox 2 (CLI): $Lane2Home"

    $plainKey = ''
    try {
        if ($null -ne $ApiKeySecure) {
            $plainKey = ConvertFrom-SecureStringPlain $ApiKeySecure
        } elseif ($ApiKeyFromStdin) {
            if (-not $script:IsDryRun -or [Console]::IsInputRedirected) {
                $stdinLine = [Console]::In.ReadLine()
                if ($null -ne $stdinLine) { $plainKey = $stdinLine }
            }
        } elseif (-not $NonInteractive) {
            if ($script:IsDryRun) {
                Write-Info '[DRY-RUN] Would prompt securely via Read-Host -AsSecureString for 1 OpenAI / GPT API key.'
            } else {
                $secInput = Read-Host -Prompt 'Nhap duy nhat 1 OpenAI / GPT API Key (an ky tu)' -AsSecureString
                $plainKey = ConvertFrom-SecureStringPlain $secInput
            }
        } else {
            if ($script:IsDryRun) {
                Write-Info '[DRY-RUN] NonInteractive preview without API key input.'
            } else {
                Write-FailLine 'NonInteractive ApiGpt requires -ApiKeySecure or -ApiKeyFromStdin (plaintext CLI key args are forbidden).'
                return 1
            }
        }

        if (-not $script:IsDryRun) {
            $plainKey = $plainKey.Trim()
            if ([string]::IsNullOrWhiteSpace($plainKey)) {
                Write-FailLine 'API key cannot be empty. Operation aborted.'
                return 1
            }
            if ($plainKey -match '[\x00-\x1F\x7F]') {
                Write-FailLine 'API key contains invalid control characters. Operation aborted.'
                return 1
            }
            Write-Info ("API key received (masked): " + (Format-MaskedSecret $plainKey))
        }

        if (-not (Test-Path -LiteralPath $Lane2Home)) {
            if ($script:IsDryRun) {
                Write-Info "[DRY-RUN] Would create directory: $Lane2Home"
            } else {
                [void][System.IO.Directory]::CreateDirectory($Lane2Home)
            }
        }

        # Step 1: Backup & clean conflicting third-party model_provider in Lane2\config.toml
        $lane2Cfg = Join-Path $Lane2Home 'config.toml'
        $cleanRes = Clear-ThirdPartyProviderFromConfig -ConfigPath $lane2Cfg
        if ($cleanRes.Modified) {
            if ($script:IsDryRun) {
                Write-Ok "[DRY-RUN] Would clean third-party model_provider '$($cleanRes.RemovedProvider)' from Lane2\config.toml."
            } else {
                Write-Ok "Backed up config.toml -> $($cleanRes.BackupPath)"
                Write-Ok "Cleaned third-party model_provider '$($cleanRes.RemovedProvider)' (preserved [projects.*] trust_level, [features], sandbox_mode, [mcp_servers.*])."
            }
        } else {
            Write-Info 'Lane2\config.toml already targets Official OpenAI (no third-party model_provider override to remove).'
        }

        # Step 2: Locate Codex CLI & pipe key strictly via stdin to `codex login --with-api-key`
        $codexInfo = Resolve-CodexExecutable -ExplicitPath $(if ($script:ExplicitCodexPath) { $CodexPath } else { '' }) -ExcludedDir $LocalBin
        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would pipe API key via stdin to: CODEX_HOME=`"$Lane2Home`" `"$($codexInfo.Path)`" login --with-api-key"
            Write-Info "[DRY-RUN] Would lock 2-step NTFS DACL on Lane2\auth.json and Lane2\config.toml"
            [void](Invoke-HistorySync -SourceHome $Lane1Home -TargetHome $Lane2Home -Bidirectional)
            return 0
        }

        $res = Invoke-CodexProcess -ExePath $codexInfo.Path -Arguments @('login', '--with-api-key') -TargetCodexHome $Lane2Home -StdinText $plainKey -TimeoutMs 30000
        $combinedOut = Redact-SecretsFromText -Text (($res.StdOut + "`n" + $res.StdErr).Trim()) -ExplicitSecrets @($plainKey)
        if (-not [string]::IsNullOrWhiteSpace($combinedOut)) {
            foreach ($ol in ($combinedOut -split "\r?\n")) {
                if (-not [string]::IsNullOrWhiteSpace($ol)) { Write-Host "    $ol" -ForegroundColor Gray }
            }
        }
        if ($res.TimedOut -or $res.ExitCode -ne 0) {
            Write-FailLine "codex login --with-api-key failed (exit=$($res.ExitCode), timed_out=$($res.TimedOut))."
            return 1
        }
        Write-Ok 'codex login --with-api-key succeeded for Sandbox 2.'

        # Step 3: Lock two-step NTFS DACLs on auth.json & config.toml
        $lane2Auth = Join-Path $Lane2Home 'auth.json'
        if (Test-Path -LiteralPath $lane2Auth -PathType Leaf) {
            Protect-SensitiveFileAcl $lane2Auth
            Write-Ok "Locked 2-step NTFS DACL: $lane2Auth"
        }
        if (Test-Path -LiteralPath $lane2Cfg -PathType Leaf) {
            Protect-SensitiveFileAcl $lane2Cfg
            Write-Ok "Locked 2-step NTFS DACL: $lane2Cfg"
        }

        # Step 4: Bidirectional chat history sync with GPT 1
        Write-Section 'Dong bo lich su chat 2 chieu (GPT 1 <-> Sandbox 2)...'
        [void](Invoke-HistorySync -SourceHome $Lane1Home -TargetHome $Lane2Home -Bidirectional)
        return 0
    } finally {
        $plainKey = $null
    }
}

# ============================================================================
# Action 1B: ApiOther -- Third-Party / Custom Provider (Direct Lane2\config.toml)
# ============================================================================

function Invoke-ActionApiOther {
    Write-Section '[1B] Cau hinh Ben thu 3 / Custom Provider (Mo truc tiep Lane2\config.toml)'
    if (-not (Test-Path -LiteralPath $Lane2Home)) {
        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would create directory: $Lane2Home"
        } else {
            [void][System.IO.Directory]::CreateDirectory($Lane2Home)
        }
    }

    $lane2Cfg = Join-Path $Lane2Home 'config.toml'
    Assert-NotReparsePoint -PathValue $lane2Cfg -Label 'Lane 2 config.toml'

    if (Test-Path -LiteralPath $lane2Cfg -PathType Leaf) {
        $bkp = New-TimestampedBackup -FilePath $lane2Cfg
        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would create backup: $bkp"
        } else {
            Write-Ok "Backup created & ACL-locked: $bkp"
        }
    } else {
        $starter = @(
            '# Sandbox 2 (Codex CLI) Custom Provider Configuration',
            '# SECURITY: Always use env_key = "<ENV_VAR>" instead of plaintext api_key / experimental_bearer_token.',
            'sandbox_mode = "workspace-write"',
            'approval_policy = "on-request"',
            '',
            '# Example custom provider (uncomment and customize):',
            '# model_provider = "custom_gw"',
            '# model = "your-model-id"',
            '#',
            '# [model_providers.custom_gw]',
            '# name = "Custom Gateway"',
            '# base_url = "https://your-gateway.example/v1"',
            '# wire_api = "responses"',
            '# env_key = "CUSTOM_GATEWAY_API_KEY"'
        ) -join "`r`n"
        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would create starter config.toml at: $lane2Cfg"
        } else {
            Write-Utf8NoBom -FilePath $lane2Cfg -Text ($starter + "`r`n")
            Protect-SensitiveFileAcl $lane2Cfg
            Write-Info "Created starter config.toml: $lane2Cfg"
        }
    }

    Write-Host ""
    Write-Host "    File config.toml Sandbox 2 : $lane2Cfg" -ForegroundColor White
    Write-Host "    Mau cau hinh env_key an toan (khong ghi plaintext key vao file):" -ForegroundColor DarkCyan
    Write-Host '      model_provider = "custom_gw"' -ForegroundColor DarkGray
    Write-Host '      [model_providers.custom_gw]' -ForegroundColor DarkGray
    Write-Host '      name = "Custom Gateway"' -ForegroundColor DarkGray
    Write-Host '      base_url = "https://your-gateway.example/v1"' -ForegroundColor DarkGray
    Write-Host '      wire_api = "responses"' -ForegroundColor DarkGray
    Write-Host '      env_key = "CUSTOM_GATEWAY_API_KEY"' -ForegroundColor DarkGray
    Write-Host ""

    $effectiveEditor = ''
    if (-not [string]::IsNullOrWhiteSpace($Editor)) {
        $effectiveEditor = $Editor.Trim()
    } elseif (-not $NonInteractive) {
        $effectiveEditor = if (-not [string]::IsNullOrWhiteSpace($env:EDITOR)) { $env:EDITOR.Trim() } else { 'notepad.exe' }
    }

    if (-not [string]::IsNullOrWhiteSpace($effectiveEditor)) {
        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would open '$lane2Cfg' with editor '$effectiveEditor' (wait until closed)."
        } else {
            Write-Info "Opening '$lane2Cfg' with '$effectiveEditor' (save & close editor to continue)..."
            $edExt = [System.IO.Path]::GetExtension($effectiveEditor).ToLowerInvariant()
            $prevPref = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                if ($edExt -eq '.ps1' -and (Test-Path -LiteralPath $effectiveEditor -PathType Leaf)) {
                    & $script:CurrentPsExe -NoProfile -ExecutionPolicy Bypass -File $effectiveEditor $lane2Cfg 2>&1 | ForEach-Object {
                        Write-Host ("    " + (Redact-SecretsFromText -Text ([string]$_)))
                    }
                    if ($LASTEXITCODE -ne 0) {
                        Write-FailLine "Editor script exited with code $LASTEXITCODE."
                        return 1
                    }
                } elseif (($edExt -eq '.cmd' -or $edExt -eq '.bat') -and (Test-Path -LiteralPath $effectiveEditor -PathType Leaf)) {
                    & $effectiveEditor $lane2Cfg 2>&1 | ForEach-Object {
                        Write-Host ("    " + (Redact-SecretsFromText -Text ([string]$_)))
                    }
                    if ($LASTEXITCODE -ne 0) {
                        Write-FailLine "Editor command exited with code $LASTEXITCODE."
                        return 1
                    }
                } elseif (Test-Path -LiteralPath $effectiveEditor -PathType Leaf) {
                    Start-Process -FilePath $effectiveEditor -ArgumentList @("`"$lane2Cfg`"") -Wait -ErrorAction Stop
                } elseif ($effectiveEditor -match '^(\S+)\s+(.+)$') {
                    Start-Process -FilePath $Matches[1] -ArgumentList @($Matches[2], "`"$lane2Cfg`"") -Wait -ErrorAction Stop
                } else {
                    Start-Process -FilePath $effectiveEditor -ArgumentList @("`"$lane2Cfg`"") -Wait -ErrorAction Stop
                }
            } finally {
                $ErrorActionPreference = $prevPref
                $global:LASTEXITCODE = 0
            }
        }
    } else {
        Write-Info "NonInteractive mode without -Editor: running post-edit validation directly on '$lane2Cfg'."
    }

    # Post-edit validation, plaintext secret warning, ACL re-lock, and bidirectional sync
    $exitCode = 0
    if (Test-Path -LiteralPath $lane2Cfg -PathType Leaf) {
        $tomlRes = Test-TomlSyntax -ConfigPath $lane2Cfg
        if (-not $tomlRes.Valid) {
            Write-FailLine "Invalid TOML syntax in '$lane2Cfg': $($tomlRes.Message)"
            $exitCode = 1
        } elseif ($tomlRes.Checked) {
            Write-Ok $tomlRes.Message
        } else {
            Write-Info $tomlRes.Message
        }

        $cfgRaw = [string](Get-Content -LiteralPath $lane2Cfg -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
        $badKeys = @(Find-PlaintextSecretsInToml -ConfigText $cfgRaw)
        if ($badKeys.Count -gt 0) {
            Write-WarnLine ("SECURITY WARNING: Plaintext secret key(s) detected in Lane2\config.toml: " + ($badKeys -join ', ') + ' (values redacted!). Please replace with env_key = "YOUR_ENV_VAR" and store the key in your User environment variable.')
        } else {
            Write-Ok 'Secret hygiene check passed: zero plaintext api_key / experimental_bearer_token in config.toml.'
        }

        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would re-lock 2-step NTFS DACL on: $lane2Cfg"
        } else {
            Protect-SensitiveFileAcl $lane2Cfg
            Write-Ok "Re-locked 2-step NTFS DACL: $lane2Cfg"
        }
    }

    Write-Section 'Dong bo lich su chat 2 chieu (GPT 1 <-> Sandbox 2)...'
    [void](Invoke-HistorySync -SourceHome $Lane1Home -TargetHome $Lane2Home -Bidirectional)
    return $exitCode
}

# ============================================================================
# Action 2: Login -- Official OpenAI / ChatGPT Login for Sandbox 2
# ============================================================================

function Invoke-ActionLogin {
    Write-Section '[2] Dang nhap Chinh thuc OpenAI / ChatGPT cho Sandbox 2 (Codex CLI)'
    Write-Info "Sandbox 2 (CLI): $Lane2Home"

    if (-not (Test-Path -LiteralPath $Lane2Home)) {
        if ($script:IsDryRun) {
            Write-Info "[DRY-RUN] Would create directory: $Lane2Home"
        } else {
            [void][System.IO.Directory]::CreateDirectory($Lane2Home)
        }
    }

    $lane2Cfg = Join-Path $Lane2Home 'config.toml'
    $cfgSummary = Get-TomlConfigSummary -ConfigPath $lane2Cfg
    if ($cfgSummary.IsThirdPartyActive) {
        $provLbl = if ($cfgSummary.ModelProvider) { $cfgSummary.ModelProvider } else { 'openai (custom override)' }
        $shouldClean = $false
        if ($Force) {
            $shouldClean = $true
        } elseif (-not $NonInteractive) {
            Write-WarnLine "Lane2\config.toml currently sets third-party model_provider='$provLbl', which may conflict with official OpenAI login."
            $ans = Read-Host 'Backup config.toml and clean third-party model_provider before login? [Y/n]'
            if ([string]::IsNullOrWhiteSpace($ans) -or $ans.Trim() -match '^(y|yes)$') {
                $shouldClean = $true
            }
        } else {
            Write-WarnLine "Lane2\config.toml sets third-party model_provider='$provLbl' (pass -Force to auto-backup & clean before official login)."
        }
        if ($shouldClean) {
            $cleanRes = Clear-ThirdPartyProviderFromConfig -ConfigPath $lane2Cfg
            if ($cleanRes.Modified -and -not $script:IsDryRun) {
                Write-Ok "Backed up config.toml -> $($cleanRes.BackupPath) and cleaned third-party model_provider '$($cleanRes.RemovedProvider)'."
            }
        }
    }

    $codexInfo = Resolve-CodexExecutable -ExplicitPath $(if ($script:ExplicitCodexPath) { $CodexPath } else { '' }) -ExcludedDir $LocalBin
    $loginArgs = if ($DeviceAuth) { @('login', '--device-auth') } else { @('login') }

    if ($script:IsDryRun) {
        Write-Info "[DRY-RUN] Would run: CODEX_HOME=`"$Lane2Home`" `"$($codexInfo.Path)`" $($loginArgs -join ' ')"
        Write-Info "[DRY-RUN] Would lock 2-step NTFS DACL on Lane2\auth.json"
        [void](Invoke-HistorySync -SourceHome $Lane1Home -TargetHome $Lane2Home -Bidirectional)
        return 0
    }

    Write-Info ("Launching official Codex login: " + ($loginArgs -join ' '))
    $loginExit = 0
    if ($NonInteractive) {
        $res = Invoke-CodexProcess -ExePath $codexInfo.Path -Arguments $loginArgs -TargetCodexHome $Lane2Home -TimeoutMs 30000
        $safeOut = Redact-SecretsFromText -Text (($res.StdOut + "`n" + $res.StdErr).Trim())
        if (-not [string]::IsNullOrWhiteSpace($safeOut)) {
            foreach ($ol in ($safeOut -split "\r?\n")) {
                if (-not [string]::IsNullOrWhiteSpace($ol)) { Write-Host "    $ol" -ForegroundColor Gray }
            }
        }
        $loginExit = if ($res.TimedOut) { 1 } else { $res.ExitCode }
    } else {
        $prevHome = $env:CODEX_HOME
        $prevPref = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $env:CODEX_HOME = $Lane2Home
            & $codexInfo.Path @loginArgs 2>&1 | ForEach-Object {
                Write-Host ("    " + (Redact-SecretsFromText -Text ([string]$_)))
            }
            $loginExit = $LASTEXITCODE
        } finally {
            if ($null -eq $prevHome) { Remove-Item Env:CODEX_HOME -ErrorAction SilentlyContinue } else { $env:CODEX_HOME = $prevHome }
            $ErrorActionPreference = $prevPref
            $global:LASTEXITCODE = 0
        }
    }

    if ($loginExit -ne 0) {
        Write-FailLine "codex $($loginArgs -join ' ') exited with code $loginExit."
        return 1
    }
    Write-Ok 'Official OpenAI / ChatGPT login completed for Sandbox 2.'

    $lane2Auth = Join-Path $Lane2Home 'auth.json'
    if (Test-Path -LiteralPath $lane2Auth -PathType Leaf) {
        Protect-SensitiveFileAcl $lane2Auth
        Write-Ok "Locked 2-step NTFS DACL: $lane2Auth"
    }
    if (Test-Path -LiteralPath $lane2Cfg -PathType Leaf) {
        Protect-SensitiveFileAcl $lane2Cfg
    }

    Write-Section 'Dong bo lich su chat 2 chieu (GPT 1 <-> Sandbox 2)...'
    [void](Invoke-HistorySync -SourceHome $Lane1Home -TargetHome $Lane2Home -Bidirectional)
    return 0
}

# ============================================================================
# Action 3: CheckApiKey -- Masked Local Inspection + Optional Live /models Probe
# ============================================================================

function Invoke-OnlineModelsProbe {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [string[]]$AllSecrets = @()
    )
    $endpoint = $BaseUrl.TrimEnd('/') + '/models'
    $parsedUri = $null
    if (-not [System.Uri]::TryCreate($endpoint, [System.UriKind]::Absolute, [ref]$parsedUri) -or ($parsedUri.Scheme -notin @('http', 'https'))) {
        Write-FailLine "Invalid probe URL: $endpoint"
        return 1
    }

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    } catch {}

    $redactList = @($ApiKey) + @($AllSecrets)
    try {
        $req = [System.Net.HttpWebRequest]::Create($endpoint)
        $req.Method = 'GET'
        $req.Timeout = 10000
        $req.ReadWriteTimeout = 10000
        $req.Accept = 'application/json'
        $req.UserAgent = 'codex-dual-lane-kit/1.4.0'
        $req.Headers['Authorization'] = "Bearer $ApiKey"

        $resp = $req.GetResponse()
        try {
            $httpResp = [System.Net.HttpWebResponse]$resp
            $statusCode = [int]$httpResp.StatusCode
            $sr = New-Object System.IO.StreamReader($httpResp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            try { $body = $sr.ReadToEnd() } finally { $sr.Dispose() }

            $modelCount = 0
            try {
                $json = $body | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $json) {
                    $dataProp = $json.PSObject.Properties['data']
                    if ($null -ne $dataProp -and $null -ne $dataProp.Value) {
                        $modelCount = @($dataProp.Value).Count
                    }
                }
            } catch {}
            Write-Ok "Online API Key Check: VALID (HTTP $statusCode, $modelCount models) | endpoint=$endpoint"
            return 0
        } finally {
            $resp.Dispose()
        }
    } catch [System.Net.WebException] {
        $wex = $_.Exception
        if ($null -ne $wex.Response) {
            try {
                $errResp = [System.Net.HttpWebResponse]$wex.Response
                $code = [int]$errResp.StatusCode
                if ($code -eq 401 -or $code -eq 403) {
                    Write-FailLine "Online API Key Check: INVALID/EXPIRED (HTTP $code) | endpoint=$endpoint"
                    return 1
                } elseif ($code -eq 429) {
                    Write-WarnLine "Online API Key Check: QUOTA/RATE_LIMITED (HTTP 429) | endpoint=$endpoint"
                    return 0
                } else {
                    Write-WarnLine "Online API Key Check: HTTP $code | endpoint=$endpoint"
                    return 1
                }
            } finally {
                try { $wex.Response.Dispose() } catch {}
            }
        }
        $safeMsg = Redact-SecretsFromText -Text $wex.Message -ExplicitSecrets $redactList
        Write-WarnLine "Online API Key Check: NETWORK_ERROR ($safeMsg) | endpoint=$endpoint"
        return 1
    } catch {
        $safeMsg = Redact-SecretsFromText -Text $_.Exception.Message -ExplicitSecrets $redactList
        Write-WarnLine "Online API Key Check: NETWORK_ERROR ($safeMsg) | endpoint=$endpoint"
        return 1
    }
}

function Invoke-ActionCheckApiKey {
    param([switch]$ForceOnline)
    Write-Section '[3] Check API Key -- Sandbox 2 (Codex CLI, Read-Only, Zero Secret Echo)'
    Write-Info "Sandbox 2 (CLI): $Lane2Home"

    $lane2Cfg  = Join-Path $Lane2Home 'config.toml'
    $lane2Auth = Join-Path $Lane2Home 'auth.json'
    $cfgSummary = Get-TomlConfigSummary -ConfigPath $lane2Cfg
    $authMeta   = Get-SafeAuthMetadata -AuthJsonPath $lane2Auth

    $allSecrets = New-Object 'System.Collections.Generic.List[string]'
    foreach ($s in $authMeta.SecretsToRedact) { $allSecrets.Add($s) }

    $envKeyInfo = [PSCustomObject]@{ Value = ''; Scope = 'None' }
    $openaiEnvInfo = Get-EnvVarValueAndScope -VarName 'OPENAI_API_KEY'
    if ($openaiEnvInfo.Value) { $allSecrets.Add($openaiEnvInfo.Value) }

    try {
        $provLabel = if ($cfgSummary.ModelProvider) { $cfgSummary.ModelProvider } else { 'openai (built-in default)' }
        Write-Host "    Active Provider   : $provLabel"
        Write-Host "    Active Base URL   : $($cfgSummary.ActiveBaseUrl)"

        if (-not [string]::IsNullOrWhiteSpace($cfgSummary.ActiveEnvKey) -and $cfgSummary.ActiveEnvKey -ne 'redacted-env-key') {
            $envKeyInfo = Get-EnvVarValueAndScope -VarName $cfgSummary.ActiveEnvKey
            if ($envKeyInfo.Value) { $allSecrets.Add($envKeyInfo.Value) }
            $scopeNote = if ($envKeyInfo.Scope -ne 'None') { " [$($envKeyInfo.Scope)]" } else { '' }
            Write-Host ("    config.toml env_key ($($cfgSummary.ActiveEnvKey)) : " + (Format-MaskedSecret $envKeyInfo.Value) + $scopeNote)
        } elseif ($cfgSummary.ActiveEnvKey -eq 'redacted-env-key') {
            Write-WarnLine 'config.toml env_key contains a non-standard/token-like value (redacted).'
        } else {
            Write-Host '    config.toml env_key : (not configured)'
        }

        $oaiScopeNote = if ($openaiEnvInfo.Scope -ne 'None') { " [$($openaiEnvInfo.Scope)]" } else { '' }
        Write-Host ("    Env OPENAI_API_KEY  : " + (Format-MaskedSecret $openaiEnvInfo.Value) + $oaiScopeNote)
        Write-Host ("    Lane2\auth.json     : auth_mode=$($authMeta.AuthMode) | OPENAI_API_KEY=$($authMeta.MaskedApiKey)")

        if ($cfgSummary.PlaintextSecretKeys.Count -gt 0) {
            Write-WarnLine ("Plaintext credential key(s) found in Lane2\config.toml: " + ($cfgSummary.PlaintextSecretKeys -join ', ') + ' (values redacted; migrate to env_key!).')
        } else {
            Write-Ok 'Secret Hygiene: Zero plaintext api_key / experimental_bearer_token in Lane2\config.toml.'
        }

        $cfgAcl  = Get-FileAclStatus $lane2Cfg
        $authAcl = Get-FileAclStatus $lane2Auth
        Write-Host "    NTFS DACL (config.toml) : $($cfgAcl.Label)"
        Write-Host "    NTFS DACL (auth.json)   : $($authAcl.Label)"

        # Pick active API key without ever sending OPENAI_API_KEY to a third-party provider that expects a custom env_key.
        $activeKey = ''
        $activeSource = ''
        $hasCustomEnvKey = (-not [string]::IsNullOrWhiteSpace($cfgSummary.ActiveEnvKey)) -and ($cfgSummary.ActiveEnvKey -ne 'redacted-env-key') -and ($cfgSummary.ActiveEnvKey -ne 'OPENAI_API_KEY')
        if ($hasCustomEnvKey) {
            if ($envKeyInfo.Value) {
                $activeKey = $envKeyInfo.Value.Trim()
                $activeSource = "env_key:$($cfgSummary.ActiveEnvKey)"
            }
        } else {
            if ($authMeta.HasApiKey) {
                $activeKey = $authMeta.ApiKeyRaw
                $activeSource = 'auth.json:OPENAI_API_KEY'
            } elseif ($openaiEnvInfo.Value) {
                $activeKey = $openaiEnvInfo.Value.Trim()
                $activeSource = 'env:OPENAI_API_KEY'
            }
        }

        if ($activeKey) {
            Write-Ok ("Active API Key Source: $activeSource -> " + (Format-MaskedSecret $activeKey))
        } elseif ($hasCustomEnvKey) {
            Write-WarnLine "Provider '$provLabel' requires env_key '$($cfgSummary.ActiveEnvKey)', which is currently NOT_SET."
        } elseif ($authMeta.HasOAuthTokens) {
            Write-Info 'No API key configured on Sandbox 2 (currently using OAuth/ChatGPT Login tokens in auth.json).'
        } else {
            Write-WarnLine 'No API key or OAuth session detected on Sandbox 2.'
        }

        $doOnline = $OnlineCheck.IsPresent -or $ForceOnline.IsPresent
        if (-not $doOnline -and -not $NonInteractive) {
            $ans = Read-Host "Probe API key online via GET $($cfgSummary.ActiveBaseUrl.TrimEnd('/'))/models? [y/N]"
            if ($ans -and $ans.Trim() -match '^(y|yes)$') { $doOnline = $true }
        }

        if ($doOnline) {
            if ([string]::IsNullOrWhiteSpace($activeKey)) {
                Write-FailLine 'Online API Key Check skipped: no active API key available to probe.'
                return 1
            }
            return (Invoke-OnlineModelsProbe -BaseUrl $cfgSummary.ActiveBaseUrl -ApiKey $activeKey -AllSecrets $allSecrets.ToArray())
        }
        return 0
    } finally {
        $authMeta.ApiKeyRaw = ''
        $authMeta.SecretsToRedact = @()
        $allSecrets.Clear()
    }
}

# ============================================================================
# Action 4: CheckAccounts -- Strictly 100% Read-Only Dual-Lane Account Inspector
# ============================================================================

function Invoke-ActionCheckAccounts {
    Write-Section '[4] Check Tai Khoan Hien Co -- GPT 1 (Desktop) & Sandbox 2 (CLI) [100% Read-Only]'
    $codexInfo = Resolve-CodexExecutable -ExplicitPath $(if ($script:ExplicitCodexPath) { $CodexPath } else { '' }) -ExcludedDir $LocalBin -AllowMissing

    $l1Auth = Get-SafeAuthMetadata -AuthJsonPath (Join-Path $Lane1Home 'auth.json')
    $l2Auth = Get-SafeAuthMetadata -AuthJsonPath (Join-Path $Lane2Home 'auth.json')
    $allSecrets = New-Object 'System.Collections.Generic.List[string]'
    foreach ($s in @($l1Auth.SecretsToRedact) + @($l2Auth.SecretsToRedact)) {
        if (-not [string]::IsNullOrWhiteSpace($s)) { $allSecrets.Add($s) }
    }
    foreach ($envName in @('OPENAI_API_KEY', 'CODEX_GATEWAY_API_KEY', 'CODEX_CLI_API_KEY')) {
        $ev = Get-EnvVarValueAndScope -VarName $envName
        if ($ev.Value) { $allSecrets.Add($ev.Value) }
    }

    try {
        $lanes = @(
            [PSCustomObject]@{ Label = 'GPT 1 (Codex Desktop)'; Home = $Lane1Home; Auth = $l1Auth },
            [PSCustomObject]@{ Label = 'Sandbox 2 (Codex CLI)'; Home = $Lane2Home; Auth = $l2Auth }
        )

        foreach ($lane in $lanes) {
            Write-Host "`n  --- $($lane.Label): $($lane.Home) ---" -ForegroundColor White
            if (-not (Test-Path -LiteralPath $lane.Home -PathType Container)) {
                Write-WarnLine "Directory does not exist: $($lane.Home)"
                continue
            }
            $cfgPath  = Join-Path $lane.Home 'config.toml'
            $authPath = Join-Path $lane.Home 'auth.json'
            $cfgSum   = Get-TomlConfigSummary -ConfigPath $cfgPath
            $am       = $lane.Auth

            # Run `codex login status` with isolated CODEX_HOME (read-only) and redact output
            if ($null -ne $codexInfo) {
                $stRes = Invoke-CodexProcess -ExePath $codexInfo.Path -Arguments @('login', 'status') -TargetCodexHome $lane.Home -TimeoutMs 10000
                $rawStatus = (($stRes.StdOut + ' ' + $stRes.StdErr) -replace '[\r\n]+', ' ').Trim()
                $safeStatus = Redact-SecretsFromText -Text $rawStatus -ExplicitSecrets $allSecrets.ToArray()
                if ([string]::IsNullOrWhiteSpace($safeStatus)) { $safeStatus = "(no output, exit=$($stRes.ExitCode))" }
                if ($safeStatus.Length -gt 160) { $safeStatus = $safeStatus.Substring(0, 160) + '...' }
                Write-Host "    codex login status : $safeStatus"
            } else {
                Write-Host '    codex login status : (codex binary not found; skipped)'
            }

            # Safe auth.json metadata (NEVER prints access_token / refresh_token / id_token / raw keys)
            $oauthLbl = if ($am.HasOAuthTokens) { 'present(redacted)' } else { 'absent' }
            $metaParts = New-Object 'System.Collections.Generic.List[string]'
            $metaParts.Add("auth_mode=$($am.AuthMode)")
            $metaParts.Add("oauth_tokens=$oauthLbl")
            $metaParts.Add("api_key=$($am.MaskedApiKey)")
            if ($am.MaskedAccountId) { $metaParts.Add("account_id=$($am.MaskedAccountId)") }
            if ($am.MaskedEmail)     { $metaParts.Add("email=$($am.MaskedEmail)") }
            if ($am.PlanLabel)       { $metaParts.Add("plan=$($am.PlanLabel)") }
            if ($am.LastRefresh)     { $metaParts.Add("last_refresh=$($am.LastRefresh)") }
            Write-Host ("    auth.json metadata : " + ($metaParts -join ' | '))

            # Safe config.toml summary
            $mpLbl = if ($cfgSum.ModelProvider) { $cfgSum.ModelProvider } else { 'openai(default)' }
            $ekLbl = if ($cfgSum.ActiveEnvKey)  { $cfgSum.ActiveEnvKey }  else { 'none' }
            $sbLbl = if ($cfgSum.SandboxMode)   { $cfgSum.SandboxMode }   else { 'unset(native)' }
            Write-Host "    config.toml        : model_provider=$mpLbl | env_key=$ekLbl | sandbox_mode=$sbLbl"
            if ($cfgSum.PlaintextSecretKeys.Count -gt 0) {
                Write-WarnLine ("Plaintext key(s) in config.toml: " + ($cfgSum.PlaintextSecretKeys -join ', ') + ' (values redacted)')
            }

            # Sessions & SQLite DB presence
            $sessCount = Get-SessionIndexCount -LaneHomePath $lane.Home
            $stateDb   = Get-LatestVersionedSqliteName -LaneHomePath $lane.Home -Prefix 'state'
            $goalsDb   = Get-LatestVersionedSqliteName -LaneHomePath $lane.Home -Prefix 'goals'
            $sessLbl   = if ($sessCount -lt 0) { 'unreadable' } else { "$sessCount" }
            Write-Host ("    Chat history       : session_index=$sessLbl | state_db=" + $(if ($stateDb) { $stateDb } else { 'none' }) + " | goals_db=" + $(if ($goalsDb) { $goalsDb } else { 'none' }))

            # NTFS DACL status
            $authAcl = Get-FileAclStatus $authPath
            $cfgAcl  = Get-FileAclStatus $cfgPath
            Write-Host "    NTFS DACL          : auth.json=$($authAcl.Label) | config.toml=$($cfgAcl.Label)"
        }

        # Shared Brain 6 NTFS Junctions status
        Write-Host "`n  --- Shared Brain NTFS Junctions (Sandbox 2 -> GPT 1) ---" -ForegroundColor White
        $sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
        $healthyCount = 0
        $issues = New-Object 'System.Collections.Generic.List[string]'
        foreach ($d in $sharedDirs) {
            $jPath = Join-Path $Lane2Home $d
            $expectedTarget = (Resolve-CanonicalLongPath -PathValue (Join-Path $Lane1Home $d)).TrimEnd('\').ToLowerInvariant()
            if (Test-Path -LiteralPath $jPath) {
                $it = Get-Item -LiteralPath $jPath -Force
                if ($it.LinkType -eq 'Junction') {
                    $rawT = (@($it.Target) | Select-Object -First 1)
                    $cleanT = if ($rawT) { $rawT -replace '^\\\?\?\\', '' } else { '' }
                    $normT  = if ($cleanT) { (Resolve-CanonicalLongPath -PathValue $cleanT).TrimEnd('\').ToLowerInvariant() } else { '' }
                    if ($normT -and ($normT -ne $expectedTarget)) {
                        $issues.Add("$d (target-mismatch)")
                    } elseif ($cleanT -and -not (Test-Path -LiteralPath $cleanT)) {
                        $issues.Add("$d (dangling)")
                    } else {
                        $healthyCount++
                    }
                } else {
                    $issues.Add("$d (local-dir)")
                }
            } else {
                $issues.Add("$d (missing)")
            }
        }
        if ($issues.Count -eq 0) {
            Write-Ok "$healthyCount/$($sharedDirs.Count) NTFS Junctions healthy & pointing to GPT 1."
        } else {
            Write-WarnLine "$healthyCount/$($sharedDirs.Count) NTFS Junctions healthy; details: $($issues -join ', ')"
        }
        return 0
    } finally {
        $l1Auth.ApiKeyRaw = ''
        $l2Auth.ApiKeyRaw = ''
        $l1Auth.SecretsToRedact = @()
        $l2Auth.SecretsToRedact = @()
        $allSecrets.Clear()
    }
}

# ============================================================================
# Action 5: SyncHistory -- Bidirectional Chat History Sync
# ============================================================================

function Invoke-ActionSyncHistory {
    Write-Section '[5] Dong bo Lich su Chat 2 Chieu (GPT 1 <-> Sandbox 2)'
    $ok = Invoke-HistorySync -SourceHome $Lane1Home -TargetHome $Lane2Home -Bidirectional -FailClosed
    if (-not $ok) { return 1 }
    return 0
}

# ============================================================================
# Action 6: RemoveSandbox2 -- History-Preserving Safe Uninstall of Sandbox 2
# ============================================================================

function Invoke-ActionRemoveSandbox2 {
    Write-Section '[6] Xoa Sandbox 2 (Codex CLI) An Toan -- KHONG Xoa Lich Su Chat GPT 1'
    Write-Host "    GPT 1 (GIU NGUYEN 100%): $Lane1Home" -ForegroundColor Green
    Write-Host "    Sandbox 2 (SE XOA)     : $Lane2Home" -ForegroundColor Yellow
    Write-Host "    CLI Wrappers           : $LocalBin"  -ForegroundColor Yellow

    if (-not $Force -and -not $script:IsDryRun) {
        if ($NonInteractive) {
            Write-FailLine 'RemoveSandbox2 requires -Force in -NonInteractive mode (or pass -DryRun to preview).'
            return 1
        }
        Write-Host ""
        Write-Host "    Quy trinh an toan 3 buoc:" -ForegroundColor Cyan
        Write-Host "      Buoc 1: Dong bo & cuu 100% lich su chat/Pinned/Goals tu Sandbox 2 ve GPT 1 (fail-closed)."
        Write-Host "      Buoc 2: Thao an toan toan bo NTFS Junction, xac minh 0 reparse point, roi xoa Sandbox 2 + CLI wrappers."
        Write-Host "      Buoc 3: Xac minh lich su chat cua GPT 1 con nguyen ven 100%."
        $confirm = Read-Host "Nhap 'DELETE' hoac 'XOA' de xac nhan xoa Sandbox 2 (de trong de huy)"
        if ([string]::IsNullOrWhiteSpace($confirm) -or ($confirm.Trim() -notmatch '^(DELETE|XOA)$')) {
            Write-Info '[CANCELLED] Huy thao tac xoa Sandbox 2. Khong co thay doi nao duoc thuc hien.'
            return 0
        }
    }

    # Step 1 (MANDATORY, FAIL-CLOSED): Rescue 100% of Sandbox 2 chats/pinned/goals/local rollout files into GPT 1
    Write-Section 'Buoc 1/3 (Bat buoc -- Fail-Closed): Cuu & dong bo 100% lich su chat tu Sandbox 2 ve GPT 1...'
    if (Test-Path -LiteralPath $Lane2Home -PathType Container) {
        if (-not (Test-Path -LiteralPath $Lane1Home -PathType Container)) {
            if ($script:IsDryRun) {
                Write-Info "[DRY-RUN] Would create GPT 1 target directory: $Lane1Home"
            } else {
                [void][System.IO.Directory]::CreateDirectory($Lane1Home)
            }
        }
        try {
            $rescueOk = Invoke-HistorySync -SourceHome $Lane2Home -TargetHome $Lane1Home -RescueSharedFiles -FailClosed
        } catch {
            Write-FailLine "Chat history rescue failed ($($_.Exception.Message)). REFUSING to delete Sandbox 2 ('$Lane2Home') to protect your chat history!"
            return 1
        }
        if (-not $rescueOk) {
            Write-FailLine "Chat history rescue did not succeed. REFUSING to delete Sandbox 2 ('$Lane2Home') to protect your chat history!"
            return 1
        }
    } else {
        Write-Info "Sandbox 2 directory ('$Lane2Home') does not exist; skipping Step 1 rescue."
    }

    # Step 2: Run restore-original.ps1 -RemoveLane2Home (detaches all Junctions first, verifies 0 reparse points, removes Lane2Home + CLI wrappers)
    Write-Section 'Buoc 2/3: Thao NTFS Junction an toan & xoa Sandbox 2 bang restore-original.ps1 -RemoveLane2Home...'
    $restoreScript = Join-Path $script:KitRoot 'scripts\restore-original.ps1'
    if (-not (Test-Path -LiteralPath $restoreScript -PathType Leaf)) {
        Write-FailLine "Required rollback script missing: $restoreScript"
        return 1
    }

    $restoreArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $restoreScript,
        '-Lane1Home', $Lane1Home,
        '-Lane2Home', $Lane2Home,
        '-LocalBin',  $LocalBin,
        '-RemoveLane2Home'
    )
    if ($SkipPathUpdate)  { $restoreArgs += '-SkipPathUpdate' }
    if ($script:IsDryRun) { $restoreArgs += '-DryRun' }

    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $script:CurrentPsExe @restoreArgs 2>&1 | ForEach-Object {
            Write-Host ("    " + (Redact-SecretsFromText -Text ([string]$_)))
        }
        $restoreExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevPref
        $global:LASTEXITCODE = 0
    }
    if ($restoreExit -ne 0) {
        Write-FailLine "restore-original.ps1 -RemoveLane2Home failed with exit code $restoreExit."
        return 1
    }

    # Step 3: Verify GPT 1 chat history remains 100% intact
    Write-Section 'Buoc 3/3: Xac minh lich su chat cua GPT 1 (~/.codex) con nguyen ven 100%...'
    if (-not (Test-Path -LiteralPath $Lane1Home -PathType Container)) {
        Write-FailLine "GPT 1 directory missing after uninstall: $Lane1Home"
        return 1
    }
    $l1SessionsDir = Join-Path $Lane1Home 'sessions'
    $l1MemoriesDir = Join-Path $Lane1Home 'memories'
    $l1SessFiles   = if (Test-Path -LiteralPath $l1SessionsDir -PathType Container) { @(Get-ChildItem -LiteralPath $l1SessionsDir -Recurse -File -ErrorAction SilentlyContinue).Count } else { 0 }
    $l1MemFiles    = if (Test-Path -LiteralPath $l1MemoriesDir -PathType Container) { @(Get-ChildItem -LiteralPath $l1MemoriesDir -Recurse -File -ErrorAction SilentlyContinue).Count } else { 0 }
    $l1IndexCount  = Get-SessionIndexCount -LaneHomePath $Lane1Home
    $l1StateDb     = Get-LatestVersionedSqliteName -LaneHomePath $Lane1Home -Prefix 'state'
    $l1GoalsDb     = Get-LatestVersionedSqliteName -LaneHomePath $Lane1Home -Prefix 'goals'

    Write-Ok ("GPT 1 verified intact: sessions_files=$l1SessFiles | memories_files=$l1MemFiles | session_index=$l1IndexCount | state_db=" + $(if ($l1StateDb) { $l1StateDb } else { 'none' }) + " | goals_db=" + $(if ($l1GoalsDb) { $l1GoalsDb } else { 'none' }))
    if (-not $script:IsDryRun) {
        if (Test-Path -LiteralPath $Lane2Home) {
            Write-WarnLine "Sandbox 2 directory still exists at '$Lane2Home' (check restore-original.ps1 output above)."
        } else {
            Write-Ok "Sandbox 2 removed cleanly: $Lane2Home"
        }
    } else {
        Write-Ok '[DRY-RUN] Preview completed with zero disk modifications.'
    }
    return 0
}

# ============================================================================
# Interactive Menu Loop (-Action Menu)
# ============================================================================

function Invoke-InteractiveMenu {
    if ($NonInteractive) {
        Write-FailLine 'Cannot run interactive Menu with -NonInteractive. Specify -Action ApiGpt|ApiOther|Login|CheckApiKey|CheckAccounts|SyncHistory|RemoveSandbox2.'
        return 1
    }
    while ($true) {
        Write-Host ""
        Write-Host "========================================================================" -ForegroundColor Cyan
        Write-Host "  CODEX DUAL-LANE CONTROL CENTER -- Quan ly Sandbox 2 (Codex CLI) v1.4.0" -ForegroundColor Cyan
        Write-Host "========================================================================" -ForegroundColor Cyan
        Write-Host "  GPT 1 (Codex Desktop) : $Lane1Home" -ForegroundColor Green
        Write-Host "  Sandbox 2 (Codex CLI) : $Lane2Home" -ForegroundColor Yellow
        if ($script:IsDryRun) {
            Write-Host "  [DRY-RUN MODE ACTIVE -- preview only, zero mutations]" -ForegroundColor Yellow
        }
        Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  [1]  Xac thuc API Key cho Sandbox 2 (Codex CLI)"
        Write-Host "       [1A] OpenAI / GPT chinh chu (nhap 1 API key -> codex login --with-api-key)"
        Write-Host "       [1B] Ben thu 3 / Custom Provider (mo truc tiep config.toml + khoa ACL)"
        Write-Host "  [2]  Dang nhap chinh thuc OpenAI / ChatGPT cho Sandbox 2 (codex login)"
        Write-Host "  [3]  Check API Key (kiem tra cuc bo + tuy chon probe /models truc tuyen)"
        Write-Host "  [4]  Check Tai khoan Hien co (chi-doc: GPT 1 Desktop + Sandbox 2 CLI)"
        Write-Host "  [5]  Dong bo Lich su Chat 2 chieu (GPT 1 <-> Sandbox 2)"
        Write-Host "  [6]  Xoa Sandbox 2 (Codex CLI) An toan -- KHONG xoa lich su chat GPT 1"
        Write-Host "  [0]  Thoat (Exit)"
        Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkGray

        $choice = Read-Host 'Chon chuc nang (1, 1A, 1B, 2, 3, 4, 5, 6, 0)'
        if ($null -eq $choice) { break }
        $c = $choice.Trim().ToUpperInvariant()

        switch ($c) {
            '1' {
                Write-Host "    [A] OpenAI / GPT chinh chu (nhap 1 API key)" -ForegroundColor Cyan
                Write-Host "    [B] Ben thu 3 / Custom Provider (mo truc tiep Lane2\config.toml)" -ForegroundColor Cyan
                $sub = Read-Host 'Chon [A/B]'
                if ($null -eq $sub) { continue }
                $sc = $sub.Trim().ToUpperInvariant()
                if ($sc -eq 'A' -or $sc -eq '1A') {
                    [void](Invoke-ActionApiGpt)
                } elseif ($sc -eq 'B' -or $sc -eq '1B') {
                    [void](Invoke-ActionApiOther)
                } else {
                    Write-WarnLine "Lua chon khong hop le: $sub"
                }
            }
            '1A' { [void](Invoke-ActionApiGpt) }
            '1B' { [void](Invoke-ActionApiOther) }
            '2' {
                if (-not $DeviceAuth) {
                    Write-Host "    [1] Dang nhap qua trinh duyet (codex login)" -ForegroundColor Cyan
                    Write-Host "    [2] Dang nhap bang Device Code (codex login --device-auth)" -ForegroundColor Cyan
                    $lSub = Read-Host 'Chon phuong thuc [1/2, mac dinh 1]'
                    $savedDeviceAuth = $DeviceAuth
                    try {
                        if ($lSub -and $lSub.Trim() -eq '2') { $DeviceAuth = [switch]$true }
                        [void](Invoke-ActionLogin)
                    } finally {
                        $DeviceAuth = $savedDeviceAuth
                    }
                } else {
                    [void](Invoke-ActionLogin)
                }
            }
            '3' { [void](Invoke-ActionCheckApiKey) }
            '4' { [void](Invoke-ActionCheckAccounts) }
            '5' { [void](Invoke-ActionSyncHistory) }
            '6' { [void](Invoke-ActionRemoveSandbox2) }
            '0' { Write-Info 'Da thoat Codex Dual-Lane Control Center.'; break }
            'Q' { Write-Info 'Da thoat Codex Dual-Lane Control Center.'; break }
            'EXIT' { Write-Info 'Da thoat Codex Dual-Lane Control Center.'; break }
            default { Write-WarnLine "Lua chon khong hop le: $choice" }
        }
        if ($c -in @('0', 'Q', 'EXIT')) { break }
    }
    return 0
}

# ============================================================================
# Entrypoint: Pre-Flight Path Validation & Action Dispatch
# ============================================================================

$script:KitRoot = Resolve-CanonicalLongPath -PathValue (Join-Path $PSScriptRoot '..')

$Lane1Home = Assert-SafeWindowsPath -PathValue $Lane1Home -ParamName 'Lane1Home' -DisallowRootOrProfile
$Lane2Home = Assert-SafeWindowsPath -PathValue $Lane2Home -ParamName 'Lane2Home' -DisallowRootOrProfile
$LocalBin  = Assert-SafeWindowsPath -PathValue $LocalBin  -ParamName 'LocalBin'  -DisallowRootOrProfile
$CodexPath = Assert-SafeWindowsPath -PathValue $CodexPath -ParamName 'CodexPath' -AllowEmpty
Assert-NoControlChars -Value $Editor -ParamName 'Editor'

if (Test-PathsOverlap -PathA $Lane1Home -PathB $Lane2Home) {
    throw "Invalid configuration: -Lane1Home ('$Lane1Home') and -Lane2Home ('$Lane2Home') must not be identical or nested inside each other."
}
foreach ($rootCheck in @(@('Lane1Home', $Lane1Home), @('Lane2Home', $Lane2Home), @('LocalBin', $LocalBin))) {
    Assert-NotReparsePoint -PathValue $rootCheck[1] -Label "-$($rootCheck[0])"
}

$rc = switch ($Action) {
    'Menu'           { Invoke-InteractiveMenu }
    'ApiGpt'         { Invoke-ActionApiGpt }
    'ApiOther'       { Invoke-ActionApiOther }
    'Login'          { Invoke-ActionLogin }
    'CheckApiKey'    { Invoke-ActionCheckApiKey }
    'CheckAccounts'  { Invoke-ActionCheckAccounts }
    'SyncHistory'    { Invoke-ActionSyncHistory }
    'RemoveSandbox2' { Invoke-ActionRemoveSandbox2 }
}

exit ([int]$rc)
