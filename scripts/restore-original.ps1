<#
.SYNOPSIS
    Deterministic, SHA-256 verified rollback & recovery tool for Codex Dual-Lane & Security Kit on Windows.

.DESCRIPTION
    Restores the system to its exact pre-install state using the transactional snapshot manifest
    (<Lane2Home>\.rollback\latest.json) recorded by setup-dual-lane.ps1:

      1. Safely detaches all 6 NTFS Directory Junctions in Lane 2 FIRST using Win32 non-recursive
         Directory.Delete(path, $false) (never touching Lane 1's target directories and avoiding
         cmd.exe metacharacter parsing issues on paths containing spaces, '&', '%', or Unicode),
         then restores any pre-install Lane 2 directory backups and verifies Lane 1 data is intact.
      2. Enforces strict caller-authorized path containment (canonicalized via Win32
         GetLongPathNameW so 8.3 short names such as RUNNER~1 / PROGRA~1 match their long forms
         consistently) and symlink/reparse-point rejection so a tampered snapshot manifest can
         NEVER read, overwrite, or delete files outside the caller's authorized Lane1Home,
         Lane2Home, and LocalBin directories.
      3. Supports both complete and partial/interrupted incremental manifests written mid-install:
         verifies every backup file's SHA-256 checksum BEFORE overwriting, performs an atomic
         staged restore with transient-lock retries, re-verifies SHA-256 after writing, only
         removes backups once integrity is proven, and never deletes untouched pre-existing user
         launchers when an install was interrupted before reaching wrapper installation.
      4. Removes CLI wrappers (codex.cmd, codex-official.cmd, codex-t3.cmd, codex-manage.cmd and
         extensionless Git Bash POSIX shims codex, codex-official, codex-t3, codex-manage) from
         LocalBin and cleans LocalBin from User PATH (unless -SkipPathUpdate is passed).
      5. Optionally removes Lane2Home (-RemoveLane2Home) ONLY after proving zero restore errors
         occurred, Lane2Home is not a dangerous OS/profile/Lane1 root, and zero NTFS Junctions or
         ReparsePoints remain anywhere inside Lane2Home (checked at all depths without following links).
      6. Supports both -DryRun and standard PowerShell -WhatIf to preview and verify all containment
         rules and SHA-256 checksums with zero modifications to disk or environment variables.

.PARAMETER Lane1Home
    Authorized CODEX_HOME root for Lane 1. Default: %USERPROFILE%\.codex.

.PARAMETER Lane2Home
    Authorized CODEX_HOME root for Lane 2. Default: %USERPROFILE%\.codex-official.

.PARAMETER LocalBin
    Authorized CLI wrapper directory containing codex.cmd, codex-official.cmd, codex-t3.cmd,
    codex-manage.cmd, and extensionless Git Bash POSIX shims.
    Default: %USERPROFILE%\.local\bin.

.PARAMETER SnapshotPath
    Optional explicit path to a rollback snapshot JSON manifest. Defaults to
    <Lane2Home>\.rollback\latest.json. Manifest entries are strictly contained within the caller's
    authorized Lane1Home, Lane2Home, and LocalBin roots.

.PARAMETER RemoveLane2Home
    Removes the entire Lane2Home directory after detaching all NTFS Junctions and proving zero
    reparse points remain at any depth inside Lane2Home.

.PARAMETER SkipPathUpdate
    Skips removing LocalBin from the Windows User PATH environment variable (ideal for CI/tests).

.PARAMETER DryRun
    Previews every rollback step and verifies all path containment rules and SHA-256 checksums
    without modifying disk, Junctions, or User PATH. Equivalent to PowerShell's -WhatIf switch.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -DryRun

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -WhatIf

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -RemoveLane2Home

.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
    License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
    Project   : Codex Dual-Lane & Security Kit
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
param(
    [string]$Lane1Home = (Join-Path $env:USERPROFILE '.codex'),
    [string]$Lane2Home = (Join-Path $env:USERPROFILE '.codex-official'),
    [string]$LocalBin  = (Join-Path $env:USERPROFILE '.local\bin'),
    [string]$SnapshotPath = '',
    [switch]$RemoveLane2Home,
    [switch]$SkipPathUpdate,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Unify -DryRun and standard PowerShell -WhatIf so .NET I/O and environment calls never mutate in preview mode.
# WHY reset $WhatIfPreference = $false right after capturing $script:IsDryRun:
# Every disk/Junction/PATH mutation below is explicitly gated by `if (-not $script:IsDryRun)`.
# Leaving $WhatIfPreference=$true in PowerShell 5.1 interferes with read-only cmdlets/module autoloading.
$script:IsDryRun = $DryRun.IsPresent -or [bool]$WhatIfPreference
$WhatIfPreference = $false
$script:WarningCount = 0
$script:ErrorCount = 0

# ============================================================================
# Helper Functions: Strict Containment, Reparse-Point Safety & Atomic Restore
# ============================================================================

function Write-Step([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Get-JsonProp {
    <#
    .SYNOPSIS
        StrictMode-safe property accessor for PSCustomObjects parsed from JSON.
    #>
    param(
        [object]$Obj,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Obj) { return $null }
    $prop = $Obj.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Resolve-CanonicalLongPath {
    <#
    .SYNOPSIS
        Canonicalizes a Windows filesystem path to its full long-name form (expanding 8.3 short
        segments such as RUNNER~1 or PROGRA~1) without dereferencing NTFS Junctions or symlinks.
        WHY:
          Ensures caller-authorized roots and manifest TargetPath/BackupPath entries compare
          consistently even when one side contains an 8.3 short path segment and the other uses
          the long name (e.g. Windows CI runners on PowerShell 7+ where GetFullPath does not
          expand 8.3 names), while preserving reparse points so symlink/junction guards remain intact.
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

function Get-NormalizedRoot([string]$PathValue, [string]$ParamName) {
    <#
    .SYNOPSIS
        Validates and canonicalizes a caller-provided root directory parameter (including 8.3 expansion).
        WHY: Ensures allowed-root prefix comparisons are unambiguous and free of control chars,
        Win32 device prefixes, or NTFS Alternate Data Stream syntax.
    #>
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw "Parameter -${ParamName} cannot be empty or whitespace."
    }
    if ($PathValue -match '[\x00-\x1F\x7F]') {
        throw "Invalid value for -${ParamName}: control characters are not permitted."
    }
    if ($PathValue -match '^(\\\\\?\\|\\\\\.\\|\\\?\?\\)') {
        throw "Invalid value for -${ParamName}: raw Win32 device namespace prefixes are not permitted."
    }
    $afterDrive = if ($PathValue.Length -ge 2 -and $PathValue[1] -eq ':') { $PathValue.Substring(2) } else { $PathValue }
    if ($afterDrive.IndexOf(':') -ge 0) {
        throw "Invalid value for -${ParamName}: NTFS alternate data stream syntax (':') is not permitted."
    }
    return (Resolve-CanonicalLongPath -PathValue $PathValue)
}

function Test-IsDangerousDeleteRoot([string]$DirPath, [string]$ProtectedLane1Home) {
    <#
    .SYNOPSIS
        Returns $true if deleting DirPath recursively would endanger OS, profile, or Lane 1 data.
        WHY: Defense-in-depth guard for -RemoveLane2Home so misconfigured paths (including 8.3
        short aliases) can never delete a drive root, %USERPROFILE%, C:\Windows, %TEMP%, or
        Lane1Home (or any ancestor of Lane1Home).
    #>
    $canon = Resolve-CanonicalLongPath -PathValue $DirPath
    $norm  = $canon.TrimEnd('\').ToLowerInvariant()
    $root  = [System.IO.Path]::GetPathRoot($canon).TrimEnd('\').ToLowerInvariant()
    if ($norm -eq $root) { return $true }

    foreach ($envDir in @($env:USERPROFILE, $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:TEMP)) {
        if (-not [string]::IsNullOrWhiteSpace($envDir)) {
            try {
                $blocked = (Resolve-CanonicalLongPath -PathValue $envDir).TrimEnd('\').ToLowerInvariant()
                if ($norm -eq $blocked) { return $true }
            } catch {}
        }
    }

    # Never allow deleting Lane1Home or an ancestor directory containing Lane1Home!
    $l1Norm = (Resolve-CanonicalLongPath -PathValue $ProtectedLane1Home).TrimEnd('\').ToLowerInvariant()
    if ($norm -eq $l1Norm -or $l1Norm.StartsWith("$norm\")) {
        return $true
    }
    return $false
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

function Test-PathInsideAllowedRoots {
    <#
    .SYNOPSIS
        Enforces strict path-traversal containment against an allowlist of caller-authorized roots.
        WHY: A tampered rollback manifest could attempt `..\` traversal, relative paths, ADS streams
        (`config.toml:stream`), device paths (`\\?\...`), or root-directory deletion. This check
        rejects all such patterns fail-closed before touching the filesystem.
    #>
    param(
        [AllowEmptyString()][string]$CandidatePath,
        [Parameter(Mandatory = $true)][string[]]$AllowedRoots,
        [switch]$AllowRootMatch
    )
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) { return $false }
    if ($CandidatePath -match '[\x00-\x1F\x7F]') { return $false }
    if ($CandidatePath -match '^(\\\\\?\\|\\\\\.\\|\\\?\?\\)') { return $false }
    if (-not [System.IO.Path]::IsPathRooted($CandidatePath)) { return $false }
    # Explicitly reject raw '..' path traversal segments even before canonicalization.
    if ($CandidatePath -match '(^|[\\/])\.\.([\\/]|$)') { return $false }
    # Reject NTFS Alternate Data Streams (any colon after drive prefix C:).
    $afterDrive = if ($CandidatePath.Length -ge 2 -and $CandidatePath[1] -eq ':') { $CandidatePath.Substring(2) } else { $CandidatePath }
    if ($afterDrive.IndexOf(':') -ge 0) { return $false }

    try {
        $full = (Resolve-CanonicalLongPath -PathValue $CandidatePath).TrimEnd('\').ToLowerInvariant()
    } catch {
        return $false
    }

    foreach ($root in $AllowedRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        try {
            $rFull = (Resolve-CanonicalLongPath -PathValue $root).TrimEnd('\').ToLowerInvariant()
        } catch {
            continue
        }
        if ($AllowRootMatch -and ($full -eq $rFull)) {
            return $true
        }
        if ($full.StartsWith("$rFull\")) {
            return $true
        }
    }
    return $false
}

function Assert-NoReparsePointInPath {
    <#
    .SYNOPSIS
        Verifies neither CandidatePath nor any existing parent directory inside its allowed root
        is a symbolic link or NTFS Junction (ReparsePoint).
        WHY: Prevents symlink-swap attacks where an attacker replaces `config.toml` or `rules\`
        with a symlink pointing outside the Codex directories before rollback runs.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CandidatePath,
        [Parameter(Mandatory = $true)][string[]]$AllowedRoots,
        [switch]$AllowRootMatch
    )
    $full = (Resolve-CanonicalLongPath -PathValue $CandidatePath).TrimEnd('\')
    $matchedRoot = $null
    foreach ($root in $AllowedRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $rFull = (Resolve-CanonicalLongPath -PathValue $root).TrimEnd('\')
        if ($AllowRootMatch -and [string]::Equals($full, $rFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            $matchedRoot = $rFull
            break
        }
        if ($full.StartsWith("$rFull\", [System.StringComparison]::OrdinalIgnoreCase)) {
            $matchedRoot = $rFull
            break
        }
    }
    if (-not $matchedRoot) {
        throw "Security violation: Path '$CandidatePath' is outside allowed Codex directories!"
    }

    if ([string]::Equals($full, $matchedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        try {
            $attrs = [System.IO.File]::GetAttributes($full)
            if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Security violation: Refusing to follow reparse point / symlink at '$full' during restore!"
            }
        } catch [System.IO.FileNotFoundException] {
            # Non-existent path is safe
        } catch [System.IO.DirectoryNotFoundException] {
            # Non-existent intermediate directory is safe
        }
        return
    }

    $cursor = $full
    while ($cursor.Length -gt $matchedRoot.Length) {
        # Call GetAttributes directly without gating on Test-Path so dangling symlinks and broken
        # junctions (where Test-Path can return $false on PowerShell 5.1) are still caught fail-closed!
        try {
            $attrs = [System.IO.File]::GetAttributes($cursor)
            if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Security violation: Refusing to follow reparse point / symlink at '$cursor' during restore!"
            }
        } catch [System.IO.FileNotFoundException] {
            # Non-existent leaf/intermediate path is safe
        } catch [System.IO.DirectoryNotFoundException] {
            # Non-existent intermediate directory is safe
        }
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent.TrimEnd('\')
    }
}

function Find-AnyReparsePointUnderDirectory([string]$RootDir) {
    <#
    .SYNOPSIS
        Iteratively scans RootDir at ALL depths for any NTFS Junction or symbolic link WITHOUT
        descending into any reparse point.
        WHY: Guarantees `-RemoveLane2Home` can NEVER recurse through a lingering or nested
        Junction into Lane 1's shared sessions, memories, skills, or plugins.
    #>
    $found = New-Object 'System.Collections.Generic.List[string]'
    if (-not (Test-Path -LiteralPath $RootDir -PathType Container)) { return @() }

    # Check the root itself first.
    $rootAttrs = [System.IO.File]::GetAttributes($RootDir)
    if ($rootAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
        $found.Add($RootDir)
        return @($found.ToArray())
    }

    $queue = New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($RootDir)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $entries = @()
        try {
            $entries = @([System.IO.Directory]::EnumerateFileSystemEntries($current))
        } catch {
            continue
        }
        foreach ($entry in $entries) {
            try {
                $attrs = [System.IO.File]::GetAttributes($entry)
                if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
                    $found.Add($entry)
                    # CRITICAL: Never descend into a reparse point!
                    continue
                }
                if ($attrs -band [System.IO.FileAttributes]::Directory) {
                    $queue.Enqueue($entry)
                }
            } catch {
                continue
            }
        }
    }
    return @($found.ToArray())
}

function Restore-FileAtomicallyWithRetry {
    <#
    .SYNOPSIS
        Stages a verified backup to a same-directory temp file, atomically swaps it over TargetPath
        with short retries for transient antivirus/process locks, and re-verifies SHA-256.
        WHY: Prevents half-written target files on crash and gracefully preserves the backup file
        if TargetPath is locked (e.g., Codex Desktop is still running).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BackupPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [AllowEmptyString()][string]$ExpectedSha256 = ''
    )
    $parentDir = [System.IO.Path]::GetDirectoryName($TargetPath)
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        [void][System.IO.Directory]::CreateDirectory($parentDir)
    }

    $tmpPath = "$TargetPath.restore-tmp.$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $maxAttempts = 3
    try {
        # Stage backup bytes first so TargetPath is never partially truncated if disk is full.
        Copy-Item -LiteralPath $BackupPath -Destination $tmpPath -Force
        if ($ExpectedSha256) {
            $stagedHash = Get-FileSha256 $tmpPath
            if (-not $stagedHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
                return [PSCustomObject]@{ Success = $false; Locked = $false; Reason = "Staged temp file SHA-256 mismatch (expected $ExpectedSha256, got $stagedHash)." }
            }
        }

        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                if (Test-Path -LiteralPath $TargetPath) {
                    try {
                        [System.IO.File]::Replace($tmpPath, $TargetPath, $null)
                    } catch [System.IO.IOException] {
                        throw
                    } catch [System.UnauthorizedAccessException] {
                        throw
                    } catch {
                        # Fallback when ReplaceFileW is unsupported on a virtualized filesystem
                        Copy-Item -LiteralPath $tmpPath -Destination $TargetPath -Force
                        Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
                    }
                } else {
                    [System.IO.File]::Move($tmpPath, $TargetPath)
                }

                # Post-write integrity verification
                if ($ExpectedSha256) {
                    $restoredHash = Get-FileSha256 $TargetPath
                    if (-not $restoredHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return [PSCustomObject]@{ Success = $false; Locked = $false; Reason = "Post-restore SHA-256 verification failed on '$TargetPath' (expected $ExpectedSha256, got $restoredHash)." }
                    }
                }
                return [PSCustomObject]@{ Success = $true; Locked = $false; Reason = '' }
            } catch [System.IO.IOException] {
                if ($attempt -lt $maxAttempts) { Start-Sleep -Milliseconds 250; continue }
                return [PSCustomObject]@{ Success = $false; Locked = $true; Reason = "File is locked or in use by another process: $($_.Exception.Message)" }
            } catch [System.UnauthorizedAccessException] {
                if ($attempt -lt $maxAttempts) { Start-Sleep -Milliseconds 250; continue }
                return [PSCustomObject]@{ Success = $false; Locked = $true; Reason = "Access denied (file may be locked or read-only): $($_.Exception.Message)" }
            }
        }
    } finally {
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
        }
    }
    return [PSCustomObject]@{ Success = $false; Locked = $false; Reason = 'Unexpected restore failure.' }
}

function Remove-FileGracefully {
    <#
    .SYNOPSIS
        Removes a file with retry handling for transient locks, reporting locked files cleanly
        instead of crashing mid-rollback.
    #>
    param([Parameter(Mandatory = $true)][string]$TargetPath)
    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $TargetPath -Force -ErrorAction Stop
            return [PSCustomObject]@{ Success = $true; Reason = '' }
        } catch [System.IO.IOException] {
            if ($attempt -lt $maxAttempts) { Start-Sleep -Milliseconds 250; continue }
            return [PSCustomObject]@{ Success = $false; Reason = "File is locked or in use: $($_.Exception.Message)" }
        } catch [System.UnauthorizedAccessException] {
            if ($attempt -lt $maxAttempts) { Start-Sleep -Milliseconds 250; continue }
            return [PSCustomObject]@{ Success = $false; Reason = "Access denied while removing file: $($_.Exception.Message)" }
        }
    }
    return [PSCustomObject]@{ Success = $false; Reason = 'Failed to remove file.' }
}

# ============================================================================
# Initialization: Lock Caller-Authorized Roots BEFORE Reading Untrusted JSON
# ============================================================================

$Lane1Home = Get-NormalizedRoot -PathValue $Lane1Home -ParamName 'Lane1Home'
$Lane2Home = Get-NormalizedRoot -PathValue $Lane2Home -ParamName 'Lane2Home'
$LocalBin  = Get-NormalizedRoot -PathValue $LocalBin  -ParamName 'LocalBin'

# Refuse symlink/reparse-point roots (including dangling symlinks / broken junctions where Test-Path
# may return $false on PS 5.1) BEFORE any operation (including -DryRun / -RemoveLane2Home).
foreach ($rootCheck in @(@('Lane1Home', $Lane1Home), @('Lane2Home', $Lane2Home), @('LocalBin', $LocalBin))) {
    $rName = $rootCheck[0]
    $rPath = $rootCheck[1]
    try {
        $rAttrs = [System.IO.File]::GetAttributes($rPath)
        if ($rAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Security violation: -${rName} ('$rPath') is a symlink/reparse point; refusing to roll back through a symlinked root."
        }
    } catch [System.IO.FileNotFoundException] {
    } catch [System.IO.DirectoryNotFoundException] {
    }
}

# SECURITY INVARIANT: Allowed restore roots are anchored EXCLUSIVELY to caller-provided/default
# parameters. An untrusted snapshot JSON is NEVER allowed to expand these roots!
$allowedRestoreRoots = @($Lane1Home, $Lane2Home, $LocalBin)

Write-Host "=== Codex Dual-Lane Deterministic Rollback & Recovery ===" -ForegroundColor Green
if ($script:IsDryRun) { Write-Host "[DRY-RUN MODE] Verifying snapshot and previewing rollback without modifying disk." -ForegroundColor Yellow }

$explicitSnapshot = -not [string]::IsNullOrWhiteSpace($SnapshotPath)
$manifestFile = if ($explicitSnapshot) {
    Get-NormalizedRoot -PathValue $SnapshotPath -ParamName 'SnapshotPath'
} else {
    Join-Path $Lane2Home '.rollback\latest.json'
}

$manifest = $null
if (Test-Path -LiteralPath $manifestFile -PathType Leaf) {
    try {
        # Explicit UTF-8 read prevents PowerShell 5.1 Windows-1252 mojibake on UTF-8 no-BOM JSON containing Unicode paths.
        $manifestRaw = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 -ErrorAction Stop
        $manifest = $manifestRaw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse snapshot manifest JSON at '$manifestFile': $($_.Exception.Message)"
    }
    $mTimestamp = Get-JsonProp -Obj $manifest -Name 'Timestamp'
    $mCompleted = Get-JsonProp -Obj $manifest -Name 'Completed'
    $mLastStage = Get-JsonProp -Obj $manifest -Name 'LastStage'
    $statusNote = if ($null -ne $mCompleted) { ", completed=$mCompleted, stage=$mLastStage" } else { '' }
    Write-Host "    Loaded snapshot manifest: $manifestFile (timestamp=$mTimestamp$statusNote)"

    # Verify any root directories declared inside the manifest stay strictly within caller-authorized roots.
    foreach ($rootKey in @('Lane1Home', 'Lane2Home', 'LocalBin')) {
        $declaredRoot = [string](Get-JsonProp -Obj $manifest -Name $rootKey)
        if (-not [string]::IsNullOrWhiteSpace($declaredRoot)) {
            if (-not (Test-PathInsideAllowedRoots -CandidatePath $declaredRoot -AllowedRoots $allowedRestoreRoots -AllowRootMatch)) {
                throw "Security violation: Snapshot manifest declares $rootKey='$declaredRoot' outside caller-authorized roots! If you installed to custom paths, pass -Lane1Home / -Lane2Home / -LocalBin explicitly."
            }
        }
    }
} elseif ($explicitSnapshot) {
    # Fail-closed when the caller explicitly pointed to a snapshot path that does not exist.
    throw "Specified -SnapshotPath does not exist: $manifestFile"
} else {
    $script:WarningCount++
    Write-Warning "No snapshot manifest found at $manifestFile; falling back to latest timestamped .backup-* files."
}

# Collect canonicalized wrapper paths recorded in the manifest (if any) so Step 3 never deletes
# an untouched pre-existing user launcher when rolling back a partial/interrupted install.
$manifestWrappers = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
if ($manifest) {
    foreach ($mw in @(Get-JsonProp -Obj $manifest -Name 'Wrappers')) {
        $mwStr = [string]$mw
        if (-not [string]::IsNullOrWhiteSpace($mwStr)) {
            if (-not (Test-PathInsideAllowedRoots -CandidatePath $mwStr -AllowedRoots $allowedRestoreRoots)) {
                throw "Security violation: Snapshot wrapper path '$mwStr' is outside allowed Codex directories!"
            }
            [void]$manifestWrappers.Add((Resolve-CanonicalLongPath -PathValue $mwStr))
        }
    }
}

# ============================================================================
# Preflight Security & Integrity Gate (Strictly Read-Only BEFORE Step 1)
# ============================================================================
# WHY: Validate ALL manifest entries (path containment, reparse-point checks, SHA-256 format,
# backup file/directory existence, and backup SHA-256 hashes) BEFORE detaching a single NTFS
# Junction in Step 1. If a manifest is tampered with OR any required backup is missing while
# the target is not already at its original state, rollback fails closed with ZERO disk side effects!
$hasSharedLinkRecordsProp = ($null -ne $manifest) -and ($null -ne $manifest.PSObject.Properties['SharedLinkRecords'])
$manifestLinkRecords = if ($hasSharedLinkRecordsProp) { @((Get-JsonProp -Obj $manifest -Name 'SharedLinkRecords') | Where-Object { $null -ne $_ }) } else { @() }
$hasSharedJunctionsProp = ($null -ne $manifest) -and ($null -ne $manifest.PSObject.Properties['SharedJunctions'])
$manifestJunctionNames = if ($hasSharedJunctionsProp) { @((Get-JsonProp -Obj $manifest -Name 'SharedJunctions') | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) } else { @() }

if ($hasSharedLinkRecordsProp -and $manifestLinkRecords.Count -gt 0) {
    foreach ($lr in $manifestLinkRecords) {
        $lrPath = [string](Get-JsonProp -Obj $lr -Name 'LinkPath')
        $lrPrior = [string](Get-JsonProp -Obj $lr -Name 'PriorState')
        $lrCreated = [bool](Get-JsonProp -Obj $lr -Name 'CreatedByKit')
        $lrBkp = [string](Get-JsonProp -Obj $lr -Name 'BackupDirPath')

        if ([string]::IsNullOrWhiteSpace($lrPath) -or -not (Test-PathInsideAllowedRoots -CandidatePath $lrPath -AllowedRoots $allowedRestoreRoots)) {
            throw "Security violation: Snapshot link path '$lrPath' is outside allowed Codex directories!"
        }
        $lrParent = Split-Path -Parent $lrPath
        if ($lrParent) {
            Assert-NoReparsePointInPath -CandidatePath $lrParent -AllowedRoots $allowedRestoreRoots -AllowRootMatch
        }
        if ($lrPrior -notin @('absent', 'preexisting_link', 'preexisting_dir')) {
            throw "Integrity violation: Snapshot link record for '$lrPath' has invalid PriorState '$lrPrior'."
        }
        if ($lrCreated -and $lrPrior -eq 'preexisting_dir') {
            if ([string]::IsNullOrWhiteSpace($lrBkp) -or -not (Test-PathInsideAllowedRoots -CandidatePath $lrBkp -AllowedRoots $allowedRestoreRoots)) {
                throw "Security violation: Snapshot directory backup path '$lrBkp' for '$lrPath' is missing or outside allowed Codex directories!"
            }
            Assert-NoReparsePointInPath -CandidatePath $lrBkp -AllowedRoots $allowedRestoreRoots
            if (-not (Test-Path -LiteralPath $lrBkp -PathType Container)) {
                # Idempotent re-run check: allow only if the target is ALREADY restored to a real non-reparse directory.
                $alreadyRestoredDir = $false
                try {
                    $tAttrs = [System.IO.File]::GetAttributes($lrPath)
                    if (($tAttrs -band [System.IO.FileAttributes]::Directory) -and -not ($tAttrs -band [System.IO.FileAttributes]::ReparsePoint)) {
                        $alreadyRestoredDir = $true
                    }
                } catch {}
                if (-not $alreadyRestoredDir) {
                    throw "Preflight failed: Required directory backup '$lrBkp' for '$lrPath' is missing and target is not restored to a real directory. Aborting before any disk changes."
                }
            }
        }
    }
}

$manifestFiles = if ($manifest) { @(Get-JsonProp -Obj $manifest -Name 'Files') } else { @() }
$manifestFiles = @($manifestFiles | Where-Object { $null -ne $_ })
if ($manifest -and $manifestFiles.Count -gt 0) {
    foreach ($entry in $manifestFiles) {
        $pfTarget = [string](Get-JsonProp -Obj $entry -Name 'TargetPath')
        if (-not (Test-PathInsideAllowedRoots -CandidatePath $pfTarget -AllowedRoots $allowedRestoreRoots)) {
            throw "Security violation: Snapshot target path '$pfTarget' is outside allowed Codex directories!"
        }
        Assert-NoReparsePointInPath -CandidatePath $pfTarget -AllowedRoots $allowedRestoreRoots

        if ([bool](Get-JsonProp -Obj $entry -Name 'ExistedPrior')) {
            $pfBkp = [string](Get-JsonProp -Obj $entry -Name 'BackupPath')
            $pfSha = [string](Get-JsonProp -Obj $entry -Name 'OriginalSha256')
            if (-not (Test-PathInsideAllowedRoots -CandidatePath $pfBkp -AllowedRoots $allowedRestoreRoots)) {
                throw "Security violation: Snapshot backup path '$pfBkp' is outside allowed Codex directories!"
            }
            Assert-NoReparsePointInPath -CandidatePath $pfBkp -AllowedRoots $allowedRestoreRoots
            if ($pfSha -notmatch '^[A-Fa-f0-9]{64}$') {
                throw "Integrity violation: Snapshot entry for '$pfTarget' is missing a valid 64-hex SHA-256 OriginalSha256 digest."
            }
            if (Test-Path -LiteralPath $pfBkp -PathType Leaf) {
                $pfActualHash = Get-FileSha256 $pfBkp
                if (-not $pfActualHash.Equals($pfSha, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "SHA-256 mismatch on backup '$pfBkp'! Expected $pfSha, got $pfActualHash. Aborting before any disk changes."
                }
            } else {
                # Missing backup file: allow ONLY for idempotent re-runs where target is ALREADY byte-exact
                # at OriginalSha256. Otherwise fail closed BEFORE Step 1 detaches any Junction or changes disk!
                $alreadyOriginalFile = $false
                if (Test-Path -LiteralPath $pfTarget -PathType Leaf) {
                    $pfTargetHash = Get-FileSha256 $pfTarget
                    if ($pfTargetHash.Equals($pfSha, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $alreadyOriginalFile = $true
                    }
                }
                if (-not $alreadyOriginalFile) {
                    throw "Preflight failed: Required backup file '$pfBkp' for '$pfTarget' is missing and target is not at original SHA-256 ($pfSha). Aborting before detaching any Junctions or modifying any files."
                }
            }
        }
    }
}

# ============================================================================
# Step 1: Safely Detach Kit-Created NTFS Directory Junctions & Restore Exact Dir Backups
# ============================================================================
# WHY: Always remove kit-created NTFS Junction reparse points via Win32 RemoveDirectoryW
# (`[System.IO.Directory]::Delete($jPath, $false)`) BEFORE any file restore or directory
# deletion so Lane 1's shared sessions/memories/skills/plugins are 100% untouched.
# Pre-existing user links (`CreatedByKit=$false`) are preserved intact, and directory backups
# are restored using the EXACT BackupDirPath recorded in the manifest (never wildcard guessing).
Write-Step "Step 1: Safely detaching kit-created NTFS Directory Junctions in $Lane2Home..."
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
if ($hasSharedLinkRecordsProp) {
    if ($manifestLinkRecords.Count -eq 0) {
        Write-Host "    Manifest records 0 shared link mutations (interrupted before Step 6); pre-existing links left untouched." -ForegroundColor DarkGray
    }
    foreach ($lr in $manifestLinkRecords) {
        $jPath = Resolve-CanonicalLongPath -PathValue ([string](Get-JsonProp -Obj $lr -Name 'LinkPath'))
        $lrPrior = [string](Get-JsonProp -Obj $lr -Name 'PriorState')
        $lrCreated = [bool](Get-JsonProp -Obj $lr -Name 'CreatedByKit')
        $lrBkpRaw = [string](Get-JsonProp -Obj $lr -Name 'BackupDirPath')

        if (-not $lrCreated) {
            # When -RemoveLane2Home is explicitly requested (e.g., RemoveSandbox2 after a 2nd/upgrade
            # setup run recorded the prior kit Junctions as preexisting_link), safely detach a
            # standard shared-dir Junction ONLY if its actual target points inside Lane1Home\<name>.
            $isLane1BridgeJunction = $false
            if ($RemoveLane2Home -and (Test-Path -LiteralPath $jPath)) {
                $leafName = Split-Path -Leaf $jPath
                if ($sharedDirs -contains $leafName) {
                    try {
                        $jItem = Get-Item -LiteralPath $jPath -Force -ErrorAction Stop
                        if ($jItem.LinkType -eq 'Junction' -or ($jItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                            $rawTargets = @($jItem.Target | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                            $expectedL1 = (Resolve-CanonicalLongPath -PathValue (Join-Path $Lane1Home $leafName)).TrimEnd('\')
                            foreach ($rt in $rawTargets) {
                                $normRt = ([string]$rt) -replace '^(\\\\\?\\|\\\?\?\\)', ''
                                try { $normRt = (Resolve-CanonicalLongPath -PathValue $normRt).TrimEnd('\') } catch { $normRt = $normRt.TrimEnd('\') }
                                if ($normRt.Equals($expectedL1, [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $isLane1BridgeJunction = $true
                                    break
                                }
                            }
                        }
                    } catch {
                        $isLane1BridgeJunction = $false
                    }
                }
            }
            if (-not $isLane1BridgeJunction) {
                if ($script:IsDryRun) {
                    Write-Host "    [DRY-RUN] Would preserve pre-existing Junction/link (not created by kit): $jPath" -ForegroundColor DarkGray
                } else {
                    Write-Host "    Preserved pre-existing Junction/link (not created by kit): $jPath" -ForegroundColor DarkGray
                }
                continue
            }
            Write-Host "    Detaching pre-existing Dual-Lane bridge Junction pointing to Lane 1 (-RemoveLane2Home): $jPath" -ForegroundColor Yellow
        }

        $junctionDetachedOrWouldDetach = $false
        if (Test-Path -LiteralPath $jPath) {
            $item = Get-Item -LiteralPath $jPath -Force
            if ($item.LinkType -eq 'Junction' -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                if (-not $script:IsDryRun) {
                    try {
                        [System.IO.Directory]::Delete($jPath, $false)
                    } catch {
                        throw "Failed to detach NTFS Junction at '$jPath' ($($_.Exception.Message)). Aborting to protect Lane 1 data."
                    }
                    if (Test-Path -LiteralPath $jPath) {
                        throw "Failed to detach NTFS Junction at '$jPath'. Aborting to protect Lane 1 data."
                    }
                }
                $junctionDetachedOrWouldDetach = $true
                if ($script:IsDryRun) {
                    Write-Host "    [DRY-RUN] Would detach kit-created NTFS Junction: $jPath (Lane 1 target untouched)"
                } else {
                    Write-Host "    Detached kit-created NTFS Junction: $jPath (Lane 1 target untouched)"
                }
            } else {
                Write-Host "    Skipped non-junction directory (already restored or real dir): $jPath" -ForegroundColor DarkGray
            }
        }

        if ($lrPrior -eq 'preexisting_dir' -and -not [string]::IsNullOrWhiteSpace($lrBkpRaw)) {
            $exactDirBackup = Resolve-CanonicalLongPath -PathValue $lrBkpRaw
            $targetVacantAfterDetach = $junctionDetachedOrWouldDetach -or (-not (Test-Path -LiteralPath $jPath))
            if ((Test-Path -LiteralPath $exactDirBackup -PathType Container) -and $targetVacantAfterDetach) {
                Assert-NoReparsePointInPath -CandidatePath $exactDirBackup -AllowedRoots $allowedRestoreRoots
                if (-not $script:IsDryRun) {
                    Move-Item -LiteralPath $exactDirBackup -Destination $jPath -Force
                    Write-Host "    Restored exact pre-existing directory from manifest: $exactDirBackup -> $jPath" -ForegroundColor Green
                } else {
                    Write-Host "    [DRY-RUN] Would restore exact pre-existing directory from manifest: $exactDirBackup -> $jPath" -ForegroundColor Green
                }
            }
        }
    }
} else {
    # Legacy v1 manifest (SharedJunctions name list only) or manifest-less fallback.
    $dirsToCheck = if ($hasSharedJunctionsProp) { $manifestJunctionNames } else { $sharedDirs }
    foreach ($name in $dirsToCheck) {
        $jPath = Join-Path $Lane2Home $name
        $junctionDetachedOrWouldDetach = $false

        if (Test-Path -LiteralPath $jPath) {
            $item = Get-Item -LiteralPath $jPath -Force
            if ($item.LinkType -eq 'Junction' -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                if (-not $script:IsDryRun) {
                    try {
                        [System.IO.Directory]::Delete($jPath, $false)
                    } catch {
                        throw "Failed to detach NTFS Junction at '$jPath' ($($_.Exception.Message)). Aborting to protect Lane 1 data."
                    }
                    if (Test-Path -LiteralPath $jPath) {
                        throw "Failed to detach NTFS Junction at '$jPath'. Aborting to protect Lane 1 data."
                    }
                }
                $junctionDetachedOrWouldDetach = $true
                if ($script:IsDryRun) {
                    Write-Host "    [DRY-RUN] Would detach NTFS Junction: $jPath (Lane 1 target untouched)"
                } else {
                    Write-Host "    Detached NTFS Junction: $jPath (Lane 1 target untouched)"
                }
            } else {
                Write-Host "    Skipped non-junction directory: $jPath" -ForegroundColor DarkGray
            }
        }

        if (Test-Path -LiteralPath $Lane2Home -PathType Container) {
            $dirBackups = @(Get-ChildItem -LiteralPath $Lane2Home -Filter "$name.backup-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
            $targetVacantAfterDetach = $junctionDetachedOrWouldDetach -or (-not (Test-Path -LiteralPath $jPath))
            if ($dirBackups.Count -gt 0 -and $targetVacantAfterDetach) {
                $latestDirBackup = $dirBackups[0].FullName
                Assert-NoReparsePointInPath -CandidatePath $latestDirBackup -AllowedRoots $allowedRestoreRoots
                if (-not $script:IsDryRun) {
                    Move-Item -LiteralPath $latestDirBackup -Destination $jPath -Force
                    Write-Host "    Restored pre-existing directory (legacy fallback): $latestDirBackup -> $jPath"
                } else {
                    Write-Host "    [DRY-RUN] Would restore pre-existing directory (legacy fallback): $latestDirBackup -> $jPath"
                }
            }
        }
    }
}

# Verify Lane 1 shared directories remain intact after Junction detachment.
foreach ($name in @('sessions', 'memories')) {
    $l1Path = Join-Path $Lane1Home $name
    if (Test-Path -LiteralPath $l1Path) {
        Write-Host "    Verified Lane 1 data intact: $l1Path" -ForegroundColor Green
    }
}

# ============================================================================
# Step 2: Restore Backed-Up Files with SHA-256 Verification (or Remove New Files)
# ============================================================================
Write-Step 'Step 2: Restoring files & verifying SHA-256 integrity...'
$manifestFiles = if ($manifest) { @(Get-JsonProp -Obj $manifest -Name 'Files') } else { @() }
# Filter out null elements in case Files was absent or empty
$manifestFiles = @($manifestFiles | Where-Object { $null -ne $_ })
$handledManifestTargets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

if ($manifest) {
    if ($manifestFiles.Count -eq 0) {
        Write-Host "    Manifest records 0 modified files (interrupted before file writes); nothing to restore in Step 2." -ForegroundColor DarkGray
    }
    foreach ($entry in $manifestFiles) {
        $rawTarget = [string](Get-JsonProp -Obj $entry -Name 'TargetPath')
        if (-not (Test-PathInsideAllowedRoots -CandidatePath $rawTarget -AllowedRoots $allowedRestoreRoots)) {
            throw "Security violation: Snapshot target path '$rawTarget' is outside allowed Codex directories!"
        }
        $target = Resolve-CanonicalLongPath -PathValue $rawTarget
        Assert-NoReparsePointInPath -CandidatePath $target -AllowedRoots $allowedRestoreRoots
        [void]$handledManifestTargets.Add($target)

        $existedPrior = [bool](Get-JsonProp -Obj $entry -Name 'ExistedPrior')
        if ($existedPrior) {
            $rawBkp = [string](Get-JsonProp -Obj $entry -Name 'BackupPath')
            $expectedSha = [string](Get-JsonProp -Obj $entry -Name 'OriginalSha256')

            if (-not (Test-PathInsideAllowedRoots -CandidatePath $rawBkp -AllowedRoots $allowedRestoreRoots)) {
                throw "Security violation: Snapshot backup path '$rawBkp' is outside allowed Codex directories!"
            }
            $bkp = Resolve-CanonicalLongPath -PathValue $rawBkp
            Assert-NoReparsePointInPath -CandidatePath $bkp -AllowedRoots $allowedRestoreRoots

            # Require a valid 64-character hex SHA-256 digest so a tampered manifest cannot omit verification.
            if ($expectedSha -notmatch '^[A-Fa-f0-9]{64}$') {
                throw "Integrity violation: Snapshot entry for '$target' is missing a valid 64-hex SHA-256 OriginalSha256 digest."
            }

            if (-not (Test-Path -LiteralPath $bkp -PathType Leaf)) {
                # Idempotent re-run check: if a prior rollback already restored the exact original
                # bytes and cleaned up the backup, verify SHA-256 and report cleanly without warning.
                if (Test-Path -LiteralPath $target -PathType Leaf) {
                    $curTargetHash = Get-FileSha256 $target
                    if ($curTargetHash.Equals($expectedSha, [System.StringComparison]::OrdinalIgnoreCase)) {
                        Write-Host "    Already at original state (SHA-256 verified): $target (SHA256=$($curTargetHash.Substring(0, 12))...)" -ForegroundColor DarkGray
                        continue
                    }
                }
                $script:ErrorCount++
                Write-Warning "Backup file missing: $bkp (cannot restore $target; original file left untouched)"
                continue
            }

            # Verify backup integrity BEFORE overwriting the target file (runs in both normal & DryRun/WhatIf).
            $bkpHash = Get-FileSha256 $bkp
            if (-not $bkpHash.Equals($expectedSha, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "SHA-256 mismatch on backup '$bkp'! Expected $expectedSha, got $bkpHash. Refusing to overwrite '$target'."
            }

            if (-not $script:IsDryRun) {
                $res = Restore-FileAtomicallyWithRetry -BackupPath $bkp -TargetPath $target -ExpectedSha256 $expectedSha
                if (-not $res.Success) {
                    $script:ErrorCount++
                    if ($res.Locked) {
                        Write-Warning "Could not restore '$target' because it is locked ($($res.Reason)). Close Codex Desktop/CLI and re-run restore-original.ps1. Backup preserved at: $bkp"
                    } else {
                        throw "Restore integrity failure for '$target': $($res.Reason)"
                    }
                    continue
                }
                # Only remove the backup AFTER post-restore SHA-256 verification succeeded!
                Remove-Item -LiteralPath $bkp -Force -ErrorAction SilentlyContinue
                Write-Host "    Restored & SHA-256 verified: $target (SHA256=$($bkpHash.Substring(0, 12))...)" -ForegroundColor Green
            } else {
                Write-Host "    [DRY-RUN] Would restore & SHA-256 verified: $target (SHA256=$($bkpHash.Substring(0, 12))...)" -ForegroundColor Green
            }
        } else {
            if (Test-Path -LiteralPath $target -PathType Leaf) {
                if (-not $script:IsDryRun) {
                    $rmRes = Remove-FileGracefully -TargetPath $target
                    if (-not $rmRes.Success) {
                        $script:ErrorCount++
                        Write-Warning "Could not remove newly created file '$target' ($($rmRes.Reason)). Close Codex Desktop/CLI and re-run."
                        continue
                    }
                    Write-Host "    Removed newly created file: $target"
                } else {
                    Write-Host "    [DRY-RUN] Would remove newly created file: $target"
                }
            }
        }
    }
} else {
    # Fallback restoration when no manifest file is present (e.g., manual cleanup after deleted .rollback).
    foreach ($homeDir in @($Lane1Home, $Lane2Home)) {
        foreach ($rel in @('config.toml', 'AGENTS.md', 'rules\default.rules')) {
            $full = Join-Path $homeDir $rel
            if (-not (Test-PathInsideAllowedRoots -CandidatePath $full -AllowedRoots $allowedRestoreRoots)) { continue }
            Assert-NoReparsePointInPath -CandidatePath $full -AllowedRoots $allowedRestoreRoots
            $parentDir = Split-Path -Parent $full
            $leaf = Split-Path -Leaf $full
            if (Test-Path -LiteralPath $parentDir -PathType Container) {
                $bkps = @(Get-ChildItem -LiteralPath $parentDir -Filter "$leaf.backup-*" -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                if ($bkps.Count -gt 0) {
                    $latestBkp = $bkps[0].FullName
                    Assert-NoReparsePointInPath -CandidatePath $latestBkp -AllowedRoots $allowedRestoreRoots
                    $bkpHash = Get-FileSha256 $latestBkp
                    if (-not $script:IsDryRun) {
                        $res = Restore-FileAtomicallyWithRetry -BackupPath $latestBkp -TargetPath $full -ExpectedSha256 $bkpHash
                        if (-not $res.Success) {
                            $script:ErrorCount++
                            Write-Warning "Could not restore '$full' from '$latestBkp' ($($res.Reason))."
                            continue
                        }
                        Write-Host "    Restored from latest backup: $latestBkp -> $full (SHA256=$($bkpHash.Substring(0, 12))...)"
                    } else {
                        Write-Host "    [DRY-RUN] Would restore from latest backup: $latestBkp -> $full (SHA256=$($bkpHash.Substring(0, 12))...)"
                    }
                }
            }
        }
    }
}

# ============================================================================
# Step 3: Reconcile CLI Wrappers (Restore Pre-Existing or Remove Newly Created) & Clean User PATH
# ============================================================================
Write-Step "Step 3: Reconciling CLI wrappers in $LocalBin..."
foreach ($w in @('codex.cmd', 'codex-official.cmd', 'codex-t3.cmd', 'codex-manage.cmd', 'codex', 'codex-official', 'codex-t3', 'codex-manage')) {
    $wp = Resolve-CanonicalLongPath -PathValue (Join-Path $LocalBin $w)
    # If Step 2 already restored (ExistedPrior=$true) or removed (ExistedPrior=$false) this wrapper
    # from the rollback manifest, do not touch it again in Step 3.
    if ($handledManifestTargets.Contains($wp)) {
        continue
    }
    Assert-NoReparsePointInPath -CandidatePath $wp -AllowedRoots $allowedRestoreRoots

    # Fallback mode (or legacy manifest without wrapper entries in Files): check for a timestamped
    # backup of a pre-existing launcher before deleting.
    $wrapperBkps = @()
    if (Test-Path -LiteralPath $LocalBin -PathType Container) {
        $wrapperBkps = @(Get-ChildItem -LiteralPath $LocalBin -Filter "$w.backup-*" -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    }
    if ($wrapperBkps.Count -gt 0) {
        $latestWrapperBkp = $wrapperBkps[0].FullName
        Assert-NoReparsePointInPath -CandidatePath $latestWrapperBkp -AllowedRoots $allowedRestoreRoots
        $bkpHash = Get-FileSha256 $latestWrapperBkp
        if (-not $script:IsDryRun) {
            $res = Restore-FileAtomicallyWithRetry -BackupPath $latestWrapperBkp -TargetPath $wp -ExpectedSha256 $bkpHash
            if (-not $res.Success) {
                $script:ErrorCount++
                Write-Warning "Could not restore pre-existing wrapper '$wp' from '$latestWrapperBkp' ($($res.Reason))."
                continue
            }
            Remove-Item -LiteralPath $latestWrapperBkp -Force -ErrorAction SilentlyContinue
            Write-Host "    Restored pre-existing wrapper: $latestWrapperBkp -> $wp (SHA256=$($bkpHash.Substring(0, 12))...)" -ForegroundColor Green
        } else {
            Write-Host "    [DRY-RUN] Would restore pre-existing wrapper: $latestWrapperBkp -> $wp (SHA256=$($bkpHash.Substring(0, 12))...)" -ForegroundColor Green
        }
    } elseif (Test-Path -LiteralPath $wp -PathType Leaf) {
        # Crash-safe interrupted-install guard: when a manifest is loaded and does NOT record this
        # wrapper in either Files or Wrappers, the interrupted install never touched it—preserve it!
        if ($manifest -and (-not $manifestWrappers.Contains($wp))) {
            Write-Host "    Preserved untouched launcher (not modified by interrupted install): $wp" -ForegroundColor DarkGray
            continue
        }
        if (-not $script:IsDryRun) {
            $rmRes = Remove-FileGracefully -TargetPath $wp
            if (-not $rmRes.Success) {
                $script:ErrorCount++
                Write-Warning "Could not remove wrapper '$wp' ($($rmRes.Reason))."
                continue
            }
            Write-Host "    Removed wrapper: $wp"
        } else {
            Write-Host "    [DRY-RUN] Would remove wrapper: $wp"
        }
    }
}

if (-not $SkipPathUpdate) {
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath) {
        $normBin = $LocalBin.TrimEnd('\').ToLowerInvariant()
        $remaining = New-Object 'System.Collections.Generic.List[string]'
        $removedAny = $false
        foreach ($entry in ($userPath -split ';')) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            $entryCanon = try { (Resolve-CanonicalLongPath -PathValue $entry).TrimEnd('\').ToLowerInvariant() } catch { $entry.TrimEnd('\').ToLowerInvariant() }
            if ($entryCanon -eq $normBin) {
                $removedAny = $true
                continue
            }
            $remaining.Add($entry)
        }
        # Only rewrite User PATH when LocalBin actually matched and was removed; never rewrite
        # merely because User PATH contained a trailing or empty ';' separator.
        if ($removedAny) {
            $cleanedPath = $remaining -join ';'
            if (-not $script:IsDryRun) {
                [System.Environment]::SetEnvironmentVariable('Path', $cleanedPath, 'User')
                Write-Host "    Removed $LocalBin from User PATH."
            } else {
                Write-Host "    [DRY-RUN] Would remove $LocalBin from User PATH."
            }
        }
    }
}

# ============================================================================
# Step 4: Optional Complete Removal of Lane2Home (Fail-Closed Multi-Guard)
# ============================================================================
if ($RemoveLane2Home -and (Test-Path -LiteralPath $Lane2Home)) {
    Write-Step "Step 4: Removing $Lane2Home (-RemoveLane2Home)..."
    if ($script:ErrorCount -gt 0) {
        throw "Refusing to remove '$Lane2Home' because $($script:ErrorCount) restore/removal error(s) occurred above. Preserving .rollback metadata and backups until locked files are closed and restore succeeds."
    }
    if (Test-IsDangerousDeleteRoot -DirPath $Lane2Home -ProtectedLane1Home $Lane1Home) {
        throw "Security violation: Refusing to delete unsafe root/profile/Lane1 path '$Lane2Home'!"
    }
    if (-not $script:IsDryRun) {
        # Scan ALL depths without following links to guarantee zero Junctions/Symlinks remain.
        $anyReparse = @(Find-AnyReparsePointUnderDirectory -RootDir $Lane2Home)
        if ($anyReparse.Count -gt 0) {
            throw "Refusing to remove '$Lane2Home' because $($anyReparse.Count) Junction/ReparsePoint(s) still exist: $($anyReparse -join ', ')"
        }
        try {
            Remove-Item -LiteralPath $Lane2Home -Recurse -Force -ErrorAction Stop
        } catch {
            $script:ErrorCount++
            Write-Warning "Could not completely remove '$Lane2Home' ($($_.Exception.Message)). Close any process using files inside it and re-run."
        }
        if ($script:ErrorCount -eq 0) {
            Write-Host "    Removed directory: $Lane2Home (Lane 1 data verified safe)"
        }
    } else {
        Write-Host "    [DRY-RUN] Would remove directory: $Lane2Home (after verifying zero Junctions/ReparsePoints remain)"
    }
}

if ($script:ErrorCount -gt 0) {
    Write-Host "`n[FAIL] Rollback finished with $($script:ErrorCount) error(s) and $($script:WarningCount) warning(s). Preserved backups remain on disk; close active Codex processes and re-run." -ForegroundColor Red
    exit 1
} elseif ($script:WarningCount -gt 0) {
    Write-Host "`n[WARN] Rollback completed with $($script:WarningCount) warning(s)." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "`n[OK] Deterministic rollback completed!" -ForegroundColor Green
    exit 0
}
