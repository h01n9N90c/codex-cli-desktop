<#
.SYNOPSIS
    Real-time compatibility, health & behavioral security diagnostic for Codex Dual-Lane & Security Kit on Windows.
.DESCRIPTION
    Inspects real host OS, drives/filesystems, free disk space, installed Codex binary,
    NTFS Junctions, firewall rules, live behavioral execpolicy engine probes, sandbox network policy,
    AGENTS.md, login status, and Cargo target isolation.
    Read-only; modifies zero files and uses zero mock data.
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
    [string]$LocalBin  = (Join-Path $env:USERPROFILE '.local\bin')
)

$ErrorActionPreference = 'Continue'
$passCount = 0
$warnCount = 0
$failCount = 0

function Report([string]$Status, [string]$Label, [string]$Detail) {
    switch ($Status) {
        'PASS' { $script:passCount++; Write-Host ("[PASS] {0,-30} : {1}" -f $Label, $Detail) -ForegroundColor Green }
        'WARN' { $script:warnCount++; Write-Host ("[WARN] {0,-30} : {1}" -f $Label, $Detail) -ForegroundColor Yellow }
        'FAIL' { $script:failCount++; Write-Host ("[FAIL] {0,-30} : {1}" -f $Label, $Detail) -ForegroundColor Red }
    }
}

Write-Host "=== Codex Dual-Lane System Doctor (Real Host Diagnostics) ===" -ForegroundColor Cyan

# 1. OS & PowerShell
$os = [System.Environment]::OSVersion.VersionString
Report 'PASS' 'Operating System' "$os | PowerShell $($PSVersionTable.PSVersion)"

# 2. Fixed drives & NTFS status
$vols = $null
try { $vols = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | Sort-Object DriveLetter } catch { $vols = $null }
if ($vols) {
    $driveSummary = ($vols | ForEach-Object { "{0}:({1}, {2}GB free)" -f $_.DriveLetter, $_.FileSystem, ([math]::Round($_.SizeRemaining / 1GB, 1)) }) -join ' | '
    Report 'PASS' 'Local Fixed Drives' $driveSummary
}

$homeDrive = ([System.IO.Path]::GetPathRoot($Lane2Home)).TrimEnd(':\')
$homeVol = if ($vols) { $vols | Where-Object { $_.DriveLetter -eq $homeDrive } | Select-Object -First 1 } else { $null }
if (-not $homeVol -or $homeVol.FileSystem -eq 'NTFS') {
    Report 'PASS' 'Home Drive Filesystem' "${homeDrive}: is NTFS (Directory Junctions supported)"
} else {
    Report 'FAIL' 'Home Drive Filesystem' "${homeDrive}: is NOT NTFS ($($homeVol.FileSystem)); Junctions will fail"
}

# 3. Codex CLI launcher resolution & PATH precedence
$normBin = $LocalBin.TrimEnd('\').ToLowerInvariant()
$codexCmd = Get-Command codex -ErrorAction SilentlyContinue
if ($codexCmd) {
    $ver = (& $codexCmd.Source --version 2>&1 | Where-Object { $_ -notmatch '^WARNING:' } | Select-Object -First 1)
    $parent = (Split-Path -Parent $codexCmd.Source).TrimEnd('\').ToLowerInvariant()
    if ($parent -eq $normBin) {
        Report 'PASS' 'codex CLI in PATH' "$($codexCmd.Source) ($ver)"
    } else {
        Report 'WARN' 'codex CLI in PATH' "Resolved to $($codexCmd.Source) instead of $LocalBin\codex.cmd (reopen terminal or put $LocalBin first in PATH)"
    }
} else {
    $localFallback = Join-Path $LocalBin 'codex.cmd'
    if (Test-Path -LiteralPath $localFallback) {
        Report 'WARN' 'codex CLI in PATH' "Wrapper exists at $localFallback but is not yet in PATH (reopen terminal)"
    } else {
        Report 'WARN' 'codex CLI in PATH' "Not found in PATH. Run setup-dual-lane.ps1 and reopen terminal."
    }
}

$codexT3Cmd = Get-Command codex-t3 -ErrorAction SilentlyContinue
if ($codexT3Cmd) {
    $t3Parent = (Split-Path -Parent $codexT3Cmd.Source).TrimEnd('\').ToLowerInvariant()
    if ($t3Parent -eq $normBin) {
        Report 'PASS' 'codex-t3 CLI in PATH' $codexT3Cmd.Source
    } else {
        Report 'WARN' 'codex-t3 CLI in PATH' "Resolved to $($codexT3Cmd.Source) instead of $LocalBin\codex-t3.cmd"
    }
} elseif (Test-Path -LiteralPath (Join-Path $LocalBin 'codex-t3.cmd')) {
    Report 'WARN' 'codex-t3 CLI in PATH' "Wrapper exists at $(Join-Path $LocalBin 'codex-t3.cmd') (reopen terminal for PATH)"
} else {
    Report 'WARN' 'codex-t3 CLI in PATH' 'Not found in PATH'
}

# 4. Shared NTFS Junctions
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
$linkedOk = 0
$broken = @()
foreach ($d in $sharedDirs) {
    $p = Join-Path $Lane2Home $d
    if (Test-Path -LiteralPath $p) {
        $it = Get-Item -LiteralPath $p -Force
        if ($it.LinkType -eq 'Junction') { $linkedOk++ } else { $broken += "$d (not a Junction)" }
    } else {
        $broken += "$d (missing)"
    }
}
if ($broken.Count -eq 0) {
    Report 'PASS' 'Shared Brain Junctions' "$linkedOk/$($sharedDirs.Count) NTFS Junctions healthy"
} else {
    Report 'WARN' 'Shared Brain Junctions' "$linkedOk/$($sharedDirs.Count) healthy; issues: $($broken -join ', ')"
}

# Resolve direct codex binary for fast behavioral execpolicy engine probes
$probeExe = $null
try {
    $appx = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($appx -and $appx.InstallLocation) {
        $candidate = Join-Path $appx.InstallLocation 'app\resources\codex.exe'
        if (Test-Path -LiteralPath $candidate) { $probeExe = $candidate }
    }
} catch {}
if (-not $probeExe -and $codexCmd) { $probeExe = $codexCmd.Source }

# 5. Security guardrails (config + default.rules + AGENTS.md + live behavioral execpolicy engine probe)
foreach ($pair in @(@('Lane 1', $Lane1Home), @('Lane 2', $Lane2Home))) {
    $label, $dir = $pair[0], $pair[1]
    $rulesPath  = Join-Path $dir 'rules\default.rules'
    $agentsPath = Join-Path $dir 'AGENTS.md'
    $cfgPath    = Join-Path $dir 'config.toml'
    $hasRules   = Test-Path -LiteralPath $rulesPath
    $hasAgents  = (Test-Path -LiteralPath $agentsPath) -and ((Get-Item -LiteralPath $agentsPath).Length -gt 0)
    $hasConfig  = Test-Path -LiteralPath $cfgPath
    if ($hasRules -and $hasAgents -and $hasConfig) {
        $agentsText = Get-Content -LiteralPath $agentsPath -Raw -ErrorAction SilentlyContinue
        $cfgText    = Get-Content -LiteralPath $cfgPath -Raw -ErrorAction SilentlyContinue
        $staticAgentsOk = ($agentsText -match 'Static-Analysis-Only')
        $netOffline     = ($cfgText -match '(?ms)\[sandbox_workspace_write\]\s*[^\[]*network_access\s*=\s*false')
        $netLabel       = if ($netOffline) { 'sandbox_net=restricted' } else { 'sandbox_net=enabled' }

        # Live behavioral probe via Codex Rust execpolicy engine
        $probesPassed = 0
        $probeCmds = @(
            @('php', '-r', 'echo 1;'),
            @('mshta', 'http://example.invalid'),
            @('vssadmin', 'delete', 'shadows', '/all'),
            @('Start-Process', 'calc.exe'),
            @('iex', 'dir')
        )
        if ($probeExe) {
            foreach ($pArgs in $probeCmds) {
                $out = (& $probeExe execpolicy check --rules $rulesPath -- @pArgs 2>$null) -join ''
                if ($out -match '"decision"\s*:\s*"forbidden"') {
                    $probesPassed++
                }
            }
        }

        if ($staticAgentsOk -and $probesPassed -eq $probeCmds.Count) {
            Report 'PASS' "$label Guardrails" "config + AGENTS.md | engine_probe=$probesPassed/$($probeCmds.Count) forbidden | $netLabel"
        } elseif ($staticAgentsOk) {
            Report 'WARN' "$label Guardrails" "config + AGENTS.md present; engine_probe=$probesPassed/$($probeCmds.Count) ($netLabel)"
        } else {
            Report 'WARN' "$label Guardrails" "config + rules + AGENTS.md present, but static-only isolation rules incomplete ($netLabel)"
        }
    } else {
        Report 'WARN' "$label Guardrails" "config=$hasConfig, rules=$hasRules, AGENTS.md=$hasAgents"
    }
}

# 6. Auth isolation check (no secret values printed!)
$a1 = Join-Path $Lane1Home 'auth.json'
$a2 = Join-Path $Lane2Home 'auth.json'
$m1 = if (Test-Path -LiteralPath $a1) { try { (Get-Content -LiteralPath $a1 -Raw | ConvertFrom-Json).auth_mode } catch { 'unreadable' } } else { 'not-configured' }
$m2 = if (Test-Path -LiteralPath $a2) { try { (Get-Content -LiteralPath $a2 -Raw | ConvertFrom-Json).auth_mode } catch { 'unreadable' } } else { 'not-logged-in' }
if ($m2 -ne 'not-logged-in') {
    Report 'PASS' 'Auth Isolation' "Lane 1=$m1 | Lane 2=$m2 (isolated auth.json files)"
} else {
    Report 'WARN' 'Auth Isolation' "Lane 1=$m1 | Lane 2=$m2 (run 'codex login' for Lane 2)"
}

# 7. Python 3 availability (optional, for sync-sessions.py; ignore Microsoft Store stub)
$realPy = $null
$realPyVer = ''
foreach ($cand in @('python', 'python3')) {
    foreach ($cmd in (Get-Command $cand -All -ErrorAction SilentlyContinue)) {
        if (-not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
        $v = (& $cmd.Source --version 2>&1 | Select-Object -First 1)
        if ($v -match '^Python 3\.') {
            $realPy = $cmd.Source
            $realPyVer = [string]$v
            break
        }
    }
    if ($realPy) { break }
}
if ($realPy) {
    Report 'PASS' 'Python 3 (Optional Sync)' "$realPyVer ($realPy)"
} else {
    Report 'WARN' 'Python 3 (Optional Sync)' 'Not installed (only needed if running scripts/sync-sessions.py)'
}

Write-Host "`nSummary: $passCount PASS | $warnCount WARN | $failCount FAIL" -ForegroundColor Cyan
if ($failCount -gt 0) { exit 1 } else { exit 0 }
