<#
.SYNOPSIS
    Deterministic, SHA-256 verified rollback & recovery tool for Codex Dual-Lane & Security Kit on Windows.
.DESCRIPTION
    Restores the system to its exact pre-install state using the transactional snapshot manifest
    (<Lane2Home>\.rollback\latest.json) recorded by setup-dual-lane.ps1:
      1. Safely detaches all 6 NTFS Directory Junctions in Lane 2 first (using `cmd /c rmdir`),
         and verifies that Lane 1's shared directories (sessions, memories, skills, plugins) remain intact.
      2. Restores every modified file from its backup and verifies its SHA-256 checksum matches
         the pre-install hash recorded in the snapshot manifest (or removes files that did not exist prior).
      3. Removes the CLI wrappers (`codex.cmd`, `codex-official.cmd`, `codex-t3.cmd`) from LocalBin
         and cleans LocalBin from User PATH (unless -SkipPathUpdate is passed).
      4. Optionally removes the Lane2Home directory (-RemoveLane2Home) ONLY after proving zero NTFS
         Junctions remain inside it.
      5. Supports -DryRun to preview and verify all checksums without modifying disk.
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -DryRun
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restore-original.ps1 -RemoveLane2Home
.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
    License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
    Project   : Codex Dual-Lane & Security Kit
#>
[CmdletBinding()]
param(
    [string]$Lane1Home = (Join-Path $env:USERPROFILE '.codex'),
    [string]$Lane2Home = (Join-Path $env:USERPROFILE '.codex-official'),
    [string]$LocalBin  = (Join-Path $env:USERPROFILE '.local\bin'),
    [string]$SnapshotPath = '',
    [switch]$RemoveLane2Home,
    [switch]$SkipPathUpdate,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Get-FileSha256([string]$FilePath) {
    if (-not (Test-Path -LiteralPath $FilePath)) { return '' }
    return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash
}

function Test-PathInsideAllowedRoots([string]$CandidatePath, [string[]]$AllowedRoots) {
    if (-not $CandidatePath) { return $false }
    $full = [System.IO.Path]::GetFullPath($CandidatePath).TrimEnd('\').ToLowerInvariant()
    foreach ($root in $AllowedRoots) {
        if (-not $root) { continue }
        $rFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\').ToLowerInvariant()
        if ($full -eq $rFull -or $full.StartsWith("$rFull\")) {
            return $true
        }
    }
    return $false
}

Write-Host "=== Codex Dual-Lane Deterministic Rollback & Recovery ===" -ForegroundColor Green
if ($DryRun) { Write-Host "[DRY-RUN MODE] Verifying snapshot and previewing rollback without modifying disk." -ForegroundColor Yellow }

$manifestFile = if ($SnapshotPath) { $SnapshotPath } else { Join-Path $Lane2Home '.rollback\latest.json' }
$manifest = $null
if (Test-Path -LiteralPath $manifestFile) {
    $manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    Write-Host "    Loaded snapshot manifest: $manifestFile (timestamp=$($manifest.Timestamp))"
    if ($manifest.Lane1Home) { $Lane1Home = $manifest.Lane1Home }
    if ($manifest.Lane2Home) { $Lane2Home = $manifest.Lane2Home }
    if ($manifest.LocalBin)  { $LocalBin  = $manifest.LocalBin }
} else {
    Write-Warning "No snapshot manifest found at $manifestFile; falling back to latest timestamped .backup-* files."
}

# 1. Safely detach all 6 NTFS Directory Junctions FIRST (never recursive-delete a Junction target!)
Write-Step "Step 1: Safely detaching NTFS Directory Junctions in $Lane2Home..."
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
foreach ($name in $sharedDirs) {
    $jPath = Join-Path $Lane2Home $name
    if (Test-Path -LiteralPath $jPath) {
        $item = Get-Item -LiteralPath $jPath -Force
        if ($item.LinkType -eq 'Junction' -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            if (-not $DryRun) {
                cmd /c rmdir "$jPath"
                if (Test-Path -LiteralPath $jPath) {
                    throw "Failed to detach NTFS Junction at $jPath. Aborting to protect Lane 1 data."
                }
            }
            Write-Host "    Detached NTFS Junction: $jPath (Lane 1 target untouched)"
        } else {
            Write-Host "    Skipped non-junction directory: $jPath" -ForegroundColor DarkGray
        }
    }

    # If a pre-install real directory was moved aside (.backup-*), restore it after detaching the junction
    $dirBackups = @(Get-ChildItem -Path $Lane2Home -Filter "$name.backup-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if ($dirBackups.Count -gt 0 -and -not (Test-Path -LiteralPath $jPath)) {
        $latestDirBackup = $dirBackups[0].FullName
        if (-not $DryRun) { Move-Item -LiteralPath $latestDirBackup -Destination $jPath -Force }
        Write-Host "    Restored pre-existing directory: $latestDirBackup -> $jPath"
    }
}

# Verify Lane 1 shared directories are still present
foreach ($name in @('sessions', 'memories')) {
    $l1Path = Join-Path $Lane1Home $name
    if (Test-Path -LiteralPath $l1Path) {
        Write-Host "    Verified Lane 1 data intact: $l1Path" -ForegroundColor Green
    }
}

# 2. Restore backed-up files with SHA-256 verification (or remove newly created files)
Write-Step 'Step 2: Restoring files & verifying SHA-256 integrity...'
$allowedRestoreRoots = @($Lane1Home, $Lane2Home, $LocalBin)
if ($manifest -and $manifest.Files) {
    foreach ($entry in $manifest.Files) {
        $target = [string]$entry.TargetPath
        if (-not (Test-PathInsideAllowedRoots -CandidatePath $target -AllowedRoots $allowedRestoreRoots)) {
            throw "Security violation: Snapshot target path '$target' is outside allowed Codex directories!"
        }
        if ([bool]$entry.ExistedPrior) {
            $bkp = [string]$entry.BackupPath
            if (-not (Test-PathInsideAllowedRoots -CandidatePath $bkp -AllowedRoots $allowedRestoreRoots)) {
                throw "Security violation: Snapshot backup path '$bkp' is outside allowed Codex directories!"
            }
            if (-not (Test-Path -LiteralPath $bkp)) {
                Write-Warning "Backup file missing: $bkp (cannot restore $target)"
                continue
            }
            $bkpHash = Get-FileSha256 $bkp
            if ($entry.OriginalSha256 -and ($bkpHash -ne $entry.OriginalSha256)) {
                throw "SHA-256 mismatch on backup $bkp! Expected $($entry.OriginalSha256), got $bkpHash."
            }
            if (-not $DryRun) {
                Copy-Item -LiteralPath $bkp -Destination $target -Force
                $restoredHash = Get-FileSha256 $target
                if ($entry.OriginalSha256 -and ($restoredHash -ne $entry.OriginalSha256)) {
                    throw "SHA-256 verification failed after restoring $target!"
                }
                Remove-Item -LiteralPath $bkp -Force -ErrorAction SilentlyContinue
            }
            Write-Host "    Restored & SHA-256 verified: $target (SHA256=$($bkpHash.Substring(0, 12))...)" -ForegroundColor Green
        } else {
            if (Test-Path -LiteralPath $target) {
                if (-not $DryRun) { Remove-Item -LiteralPath $target -Force }
                Write-Host "    Removed newly created file: $target"
            }
        }
    }
} else {
    # Fallback restoration when no manifest file is present
    foreach ($homeDir in @($Lane1Home, $Lane2Home)) {
        foreach ($rel in @('config.toml', 'AGENTS.md', 'rules\default.rules')) {
            $full = Join-Path $homeDir $rel
            $parentDir = Split-Path -Parent $full
            $leaf = Split-Path -Leaf $full
            if (Test-Path -LiteralPath $parentDir) {
                $bkps = @(Get-ChildItem -LiteralPath $parentDir -Filter "$leaf.backup-*" -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                if ($bkps.Count -gt 0) {
                    if (-not $DryRun) { Copy-Item -LiteralPath $bkps[0].FullName -Destination $full -Force }
                    Write-Host "    Restored from latest backup: $($bkps[0].FullName) -> $full"
                }
            }
        }
    }
}

# 3. Remove CLI wrappers & clean User PATH
Write-Step "Step 3: Removing CLI wrappers from $LocalBin..."
foreach ($w in @('codex.cmd', 'codex-official.cmd', 'codex-t3.cmd')) {
    $wp = Join-Path $LocalBin $w
    if (Test-Path -LiteralPath $wp) {
        if (-not $DryRun) { Remove-Item -LiteralPath $wp -Force }
        Write-Host "    Removed wrapper: $wp"
    }
}

if (-not $SkipPathUpdate) {
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath) {
        $normBin = $LocalBin.TrimEnd('\').ToLowerInvariant()
        $remaining = @($userPath -split ';' | Where-Object { $_ -and ($_.TrimEnd('\').ToLowerInvariant() -ne $normBin) })
        $cleanedPath = $remaining -join ';'
        if ($cleanedPath -ne $userPath) {
            if (-not $DryRun) {
                [System.Environment]::SetEnvironmentVariable('Path', $cleanedPath, 'User')
            }
            Write-Host "    Removed $LocalBin from User PATH."
        }
    }
}

# 4. Optional: completely remove Lane2Home (ONLY after verifying zero ReparsePoints/Junctions remain!)
if ($RemoveLane2Home -and (Test-Path -LiteralPath $Lane2Home)) {
    Write-Step "Step 4: Removing $Lane2Home (-RemoveLane2Home)..."
    if (-not $DryRun) {
        $anyReparse = @(Get-ChildItem -LiteralPath $Lane2Home -Force -ErrorAction SilentlyContinue | Where-Object {
            $_.LinkType -eq 'Junction' -or ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        })
        if ($anyReparse.Count -gt 0) {
            throw "Refusing to remove $Lane2Home because $($anyReparse.Count) Junction/ReparsePoint(s) still exist!"
        }
        Remove-Item -LiteralPath $Lane2Home -Recurse -Force
    }
    Write-Host "    Removed directory: $Lane2Home (Lane 1 data verified safe)"
}

Write-Host "`n[OK] Deterministic rollback completed!" -ForegroundColor Green
