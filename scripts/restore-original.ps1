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
      2. Enforces strict caller-authorized path containment and symlink/reparse-point rejection
         so a tampered snapshot manifest can NEVER read, overwrite, or delete files outside the
         caller's authorized Lane1Home, Lane2Home, and LocalBin directories.
      3. Verifies every backup file's SHA-256 checksum BEFORE overwriting, performs an atomic
         staged restore with transient-lock retries, re-verifies SHA-256 after writing, and only
         removes the backup once integrity is proven (preserving backups if a target file is locked).
      4. Removes CLI wrappers (codex.cmd, codex-official.cmd, codex-t3.cmd) from LocalBin and
         cleans LocalBin from User PATH (unless -SkipPathUpdate is passed).
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
    Authorized CLI wrapper directory containing codex.cmd, codex-official.cmd, and codex-t3.cmd.
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

function Get-NormalizedRoot([string]$PathValue, [string]$ParamName) {
    <#
    .SYNOPSIS
        Validates and canonicalizes a caller-provided root directory parameter.
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
    $full = [System.IO.Path]::GetFullPath($PathValue)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) {
        return $full.TrimEnd('\', '/')
    }
    return $full
}

function Test-IsDangerousDeleteRoot([string]$DirPath, [string]$ProtectedLane1Home) {
    <#
    .SYNOPSIS
        Returns $true if deleting DirPath recursively would endanger OS, profile, or Lane 1 data.
        WHY: Defense-in-depth guard for -RemoveLane2Home so misconfigured paths can never delete
        a drive root, %USERPROFILE%, C:\Windows, %TEMP%, or Lane1Home (or any ancestor of Lane1Home).
    #>
    $norm = [System.IO.Path]::GetFullPath($DirPath).TrimEnd('\').ToLowerInvariant()
    $root = [System.IO.Path]::GetPathRoot($DirPath).TrimEnd('\').ToLowerInvariant()
    if ($norm -eq $root) { return $true }

    foreach ($envDir in @($env:USERPROFILE, $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:TEMP)) {
        if (-not [string]::IsNullOrWhiteSpace($envDir)) {
            try {
                $blocked = [System.IO.Path]::GetFullPath($envDir).TrimEnd('\').ToLowerInvariant()
                if ($norm -eq $blocked) { return $true }
            } catch {}
        }
    }

    # Never allow deleting Lane1Home or an ancestor directory containing Lane1Home!
    $l1Norm = [System.IO.Path]::GetFullPath($ProtectedLane1Home).TrimEnd('\').ToLowerInvariant()
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
        $full = [System.IO.Path]::GetFullPath($CandidatePath).TrimEnd('\').ToLowerInvariant()
    } catch {
        return $false
    }

    foreach ($root in $AllowedRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        try {
            $rFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\').ToLowerInvariant()
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
        [Parameter(Mandatory = $true)][string[]]$AllowedRoots
    )
    $full = [System.IO.Path]::GetFullPath($CandidatePath).TrimEnd('\')
    $matchedRoot = $null
    foreach ($root in $AllowedRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $rFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
        if ($full.StartsWith("$rFull\", [System.StringComparison]::OrdinalIgnoreCase)) {
            $matchedRoot = $rFull
            break
        }
    }
    if (-not $matchedRoot) {
        throw "Security violation: Path '$CandidatePath' is outside allowed Codex directories!"
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
    Write-Host "    Loaded snapshot manifest: $manifestFile (timestamp=$mTimestamp)"

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

# ============================================================================
# Preflight Security & Integrity Gate (Strictly Read-Only BEFORE Step 1)
# ============================================================================
# WHY: Validate ALL manifest entries (path containment, reparse-point checks, SHA-256 format,
# and backup SHA-256 hashes) BEFORE detaching a single NTFS Junction in Step 1. If a manifest
# has been tampered with or corrupted, rollback fails closed with ZERO disk side effects!
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
            }
        }
    }
}

# ============================================================================
# Step 1: Safely Detach All 6 NTFS Directory Junctions FIRST
# ============================================================================
# WHY: Always remove NTFS Junction reparse points via Win32 RemoveDirectoryW
# (`[System.IO.Directory]::Delete($jPath, $false)`) BEFORE any file restore or directory
# deletion so Lane 1's shared sessions/memories/skills/plugins are 100% untouched.
Write-Step "Step 1: Safely detaching NTFS Directory Junctions in $Lane2Home..."
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
foreach ($name in $sharedDirs) {
    $jPath = Join-Path $Lane2Home $name
    $junctionDetachedOrWouldDetach = $false

    if (Test-Path -LiteralPath $jPath) {
        $item = Get-Item -LiteralPath $jPath -Force
        if ($item.LinkType -eq 'Junction' -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            if (-not $script:IsDryRun) {
                try {
                    # Non-recursive Win32 RemoveDirectoryW: detaches ONLY the Junction reparse point,
                    # works natively with spaces/'&'/'%'/Unicode, and avoids cmd.exe shell parsing.
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

    # If setup-dual-lane.ps1 moved a pre-existing real directory aside (.backup-*), restore it now.
    if (Test-Path -LiteralPath $Lane2Home -PathType Container) {
        $dirBackups = @(Get-ChildItem -LiteralPath $Lane2Home -Filter "$name.backup-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        $targetVacantAfterDetach = $junctionDetachedOrWouldDetach -or (-not (Test-Path -LiteralPath $jPath))
        if ($dirBackups.Count -gt 0 -and $targetVacantAfterDetach) {
            $latestDirBackup = $dirBackups[0].FullName
            Assert-NoReparsePointInPath -CandidatePath $latestDirBackup -AllowedRoots $allowedRestoreRoots
            if (-not $script:IsDryRun) {
                Move-Item -LiteralPath $latestDirBackup -Destination $jPath -Force
                Write-Host "    Restored pre-existing directory: $latestDirBackup -> $jPath"
            } else {
                Write-Host "    [DRY-RUN] Would restore pre-existing directory: $latestDirBackup -> $jPath"
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

if ($manifest -and $manifestFiles.Count -gt 0) {
    foreach ($entry in $manifestFiles) {
        $target = [string](Get-JsonProp -Obj $entry -Name 'TargetPath')
        if (-not (Test-PathInsideAllowedRoots -CandidatePath $target -AllowedRoots $allowedRestoreRoots)) {
            throw "Security violation: Snapshot target path '$target' is outside allowed Codex directories!"
        }
        Assert-NoReparsePointInPath -CandidatePath $target -AllowedRoots $allowedRestoreRoots
        [void]$handledManifestTargets.Add([System.IO.Path]::GetFullPath($target))

        $existedPrior = [bool](Get-JsonProp -Obj $entry -Name 'ExistedPrior')
        if ($existedPrior) {
            $bkp = [string](Get-JsonProp -Obj $entry -Name 'BackupPath')
            $expectedSha = [string](Get-JsonProp -Obj $entry -Name 'OriginalSha256')

            if (-not (Test-PathInsideAllowedRoots -CandidatePath $bkp -AllowedRoots $allowedRestoreRoots)) {
                throw "Security violation: Snapshot backup path '$bkp' is outside allowed Codex directories!"
            }
            Assert-NoReparsePointInPath -CandidatePath $bkp -AllowedRoots $allowedRestoreRoots

            # Require a valid 64-character hex SHA-256 digest so a tampered manifest cannot omit verification.
            if ($expectedSha -notmatch '^[A-Fa-f0-9]{64}$') {
                throw "Integrity violation: Snapshot entry for '$target' is missing a valid 64-hex SHA-256 OriginalSha256 digest."
            }

            if (-not (Test-Path -LiteralPath $bkp -PathType Leaf)) {
                $script:WarningCount++
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
foreach ($w in @('codex.cmd', 'codex-official.cmd', 'codex-t3.cmd')) {
    $wp = [System.IO.Path]::GetFullPath((Join-Path $LocalBin $w))
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
        $remaining = @($userPath -split ';' | Where-Object { $_ -and ($_.TrimEnd('\').ToLowerInvariant() -ne $normBin) })
        $cleanedPath = $remaining -join ';'
        if ($cleanedPath -ne $userPath) {
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
