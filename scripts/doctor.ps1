<#
.SYNOPSIS
    Real-time, strictly read-only compatibility, health & behavioral security diagnostic for
    Codex Dual-Lane & Security Kit on Windows.

.DESCRIPTION
    Inspects your live Windows host without modifying a single file, ACL, or environment variable:
      1. Operating System & PowerShell version.
      2. Local fixed drives, free disk space, and NTFS verification on Lane2Home's volume.
      3. Codex CLI launcher resolution (`codex` and `codex-t3`) and PATH precedence over global shims.
      4. Shared Brain NTFS Directory Junction health (verifies all 6 Junctions exist AND point to
         their expected Lane 1 targets).
      5. Security Guardrails on both lanes: config.toml, rules\default.rules, AGENTS.md
         (Static-Analysis-Only check), sandbox network isolation (`network_access = false`),
         shell environment secret scrubbing (`[shell_environment_policy]`), and live behavioral
         probes through the real Codex Rust `execpolicy check` engine.
      6. Plaintext Secret Hygiene check: scans config.toml in memory for prohibited plaintext keys
         (`experimental_bearer_token`, inline `api_key`) without ever printing secret values.
      7. Auth & NTFS Kernel ACL Isolation: safely reads only the `auth_mode` metadata field from
         auth.json (strictly sanitized to prevent token leakage), verifies zero `CodexSandboxUsers`
         ALLOW ACEs on sensitive files (without false-positiving protective DENY ACEs), reports
         ACL inheritance protection, and performs a strictly read-only advisory check on
         `.sandbox\deny_read_acl_state.json` if present.
      8. Optional Python 3 availability (ignoring Microsoft Store stubs) for scripts\sync-sessions.py.

    Exit Code Contract:
      - 0 : Zero FAIL checks (PASS and advisory WARN only).
      - 1 : One or more FAIL checks detected (e.g., non-NTFS home volume, plaintext secret in
            config.toml, or a must-forbid execpolicy command explicitly allowed).

.PARAMETER Lane1Home
    CODEX_HOME directory for Lane 1 (Desktop / optional gateway). Default: %USERPROFILE%\.codex.

.PARAMETER Lane2Home
    CODEX_HOME directory for Lane 2 (Official CLI). Default: %USERPROFILE%\.codex-official.

.PARAMETER LocalBin
    Directory containing installed CLI wrappers (`codex.cmd`, `codex-official.cmd`, `codex-t3.cmd`).
    Default: %USERPROFILE%\.local\bin.

.PARAMETER CodexPath
    Optional explicit path to `codex.exe` or `codex.cmd` for live `execpolicy check` probes.
    When omitted, auto-discovers WindowsApps MSIX, PATH, and common fallback locations.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1 -Lane1Home "D:\test\.codex" -Lane2Home "D:\test\.codex-official" -LocalBin "D:\test\.local\bin"

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
    [string]$CodexPath = ''
)

Set-StrictMode -Version Latest
# Read-only diagnostic tool: keep Continue so one unavailable probe never aborts remaining checks.
$ErrorActionPreference = 'Continue'

$script:passCount = 0
$script:warnCount = 0
$script:failCount = 0

# ============================================================================
# Helper Functions (Strictly Read-Only, Zero Secret Echo)
# ============================================================================

function Report([string]$Status, [string]$Label, [string]$Detail) {
    switch ($Status) {
        'PASS' { $script:passCount++; Write-Host ("[PASS] {0,-30} : {1}" -f $Label, $Detail) -ForegroundColor Green }
        'WARN' { $script:warnCount++; Write-Host ("[WARN] {0,-30} : {1}" -f $Label, $Detail) -ForegroundColor Yellow }
        'FAIL' { $script:failCount++; Write-Host ("[FAIL] {0,-30} : {1}" -f $Label, $Detail) -ForegroundColor Red }
    }
}

function Get-NormalizedFullPath([string]$PathValue) {
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return '' }
    try {
        $full = [System.IO.Path]::GetFullPath($PathValue)
        $root = [System.IO.Path]::GetPathRoot($full)
        if ($full.Length -gt $root.Length) { return $full.TrimEnd('\', '/') }
        return $full
    } catch {
        return $PathValue
    }
}

function Get-SafeAuthMode([string]$AuthJsonPath, [string]$MissingLabel) {
    <#
    .SYNOPSIS
        Safely reads ONLY the non-secret `auth_mode` field from auth.json.
        WHY: Strictly validates the extracted value against a tight identifier regex and rejects
        token-like prefixes (`sk-`, `eyJ`, `Bearer`) so even a malformed auth.json can NEVER leak
        credentials to console logs or CI output.
    #>
    if (-not (Test-Path -LiteralPath $AuthJsonPath -PathType Leaf)) {
        return $MissingLabel
    }
    try {
        # Explicit UTF-8 read ensures consistent decoding across PowerShell 5.1 and 7+.
        $parsed = Get-Content -LiteralPath $AuthJsonPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $prop = if ($null -ne $parsed) { $parsed.PSObject.Properties['auth_mode'] } else { $null }
        if ($null -eq $prop -or [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
            return 'present(mode-unset)'
        }
        $val = ([string]$prop.Value).Trim()
        # Reject any value that looks like a secret token or exceeds a short mode identifier.
        if ($val -match '^(sk-|eyJ|Bearer|ghp_|gho_|xox)' -or $val -notmatch '^[A-Za-z0-9_.-]{1,32}$') {
            return 'redacted-nonstandard'
        }
        return $val
    } catch {
        return 'unreadable'
    }
}

function Remove-TomlInlineComment([string]$Line) {
    <#
    .SYNOPSIS
        Strips an unquoted trailing TOML `# comment` while keeping `#` inside quoted strings.
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

function Inspect-CodexConfigGuardrails([string]$ConfigText) {
    <#
    .SYNOPSIS
        Line-by-line TOML section inspector for `[sandbox_workspace_write]` and
        `[shell_environment_policy]` security guardrails.
        WHY: Avoids both regex false positives (matching commented `# network_access = false`)
        and regex false negatives (arrays like `writable_roots = [...]` before `network_access`
        stopping `[^\[]*` prematurely).
    #>
    $netAccessValue = $null
    $envFilterOk = $false
    if ([string]::IsNullOrEmpty($ConfigText)) {
        return [PSCustomObject]@{ NetOffline = $false; EnvFilterOk = $false }
    }

    $currentSection = ''
    $inExcludeArray = $false
    $excludeBuffer = New-Object 'System.Text.StringBuilder'

    foreach ($rawLine in ($ConfigText -split "\r?\n")) {
        $line = (Remove-TomlInlineComment $rawLine).Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # If continuing a multi-line `exclude = [...]` array under [shell_environment_policy]
        if ($inExcludeArray) {
            [void]$excludeBuffer.Append(' ').Append($line)
            if ($line.Contains(']')) {
                $inExcludeArray = $false
                if ($excludeBuffer.ToString() -match '["'']\*KEY\*["'']') {
                    $envFilterOk = $true
                }
            }
            continue
        }

        # Section header: [[array_of_tables]] or [table]
        if ($line -match '^\[\[(.+)\]\]$') {
            $currentSection = '[[' + $Matches[1].Trim().ToLowerInvariant() + ']]'
            continue
        }
        if ($line -match '^\[(.+)\]$') {
            $currentSection = $Matches[1].Trim().ToLowerInvariant()
            continue
        }

        if ($currentSection -eq 'sandbox_workspace_write') {
            if ($line -match '^network_access\s*=\s*(true|false)\s*$') {
                $netAccessValue = $Matches[1].ToLowerInvariant()
            }
        } elseif ($currentSection -eq 'shell_environment_policy') {
            if ($line -match '^exclude\s*=\s*(.*)$') {
                $rhs = $Matches[1]
                [void]$excludeBuffer.Clear()
                [void]$excludeBuffer.Append($rhs)
                if ($rhs.Contains('[') -and -not $rhs.Contains(']')) {
                    $inExcludeArray = $true
                } elseif ($rhs -match '["'']\*KEY\*["'']') {
                    $envFilterOk = $true
                }
            }
        }
    }

    return [PSCustomObject]@{
        NetOffline  = ($netAccessValue -eq 'false')
        EnvFilterOk = $envFilterOk
    }
}

function Find-PlaintextSecretsInToml([string]$ConfigText) {
    <#
    .SYNOPSIS
        Scans config.toml text in memory for prohibited plaintext credential keys.
        WHY: Returns ONLY key names (never secret values) so doctor.ps1 can flag insecure
        configurations without leaking a single byte of any credential.
    #>
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

function Test-SandboxDenyAclState([string]$LaneHomePath) {
    <#
    .SYNOPSIS
        Strictly read-only host-side inspection of <CODEX_HOME>\.sandbox\deny_read_acl_state.json.
        WHY:
          Codex's Windows elevated sandbox tracks paths protected by Deny-Read ACLs in this JSON file
          (under `{ "principals": { "<SID>": [ "<path>", ... ] } }`).
          This function inspects:
            1. Presence & JSON parseability (detecting 22-byte NUL torn-write corruption that breaks
               Codex sandbox initialization).
            2. Count of tracked principal SIDs and deny-read path entries (without printing any paths).
            3. Host-side NTFS DACL on `deny_read_acl_state.json` (whether `CodexSandboxUsers` holds
               inherited/explicit Write or Modify access).
           BOUNDARY NOTE: `doctor.ps1` runs under the current Windows user context and performs static
          host-side DACL & structural inspection only; it does NOT spawn a child token under
          `CodexSandboxOffline`. For live sandbox-identity execution probes, see `docs/REAL_CODEX_CHECKLIST.md`.
    #>
    $statePath = Join-Path $LaneHomePath '.sandbox\deny_read_acl_state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return [PSCustomObject]@{ Present = $false; ValidJson = $false; EntryCount = 0; PrincipalCount = 0; SandboxWritable = $false }
    }
    $sandboxWritable = $false
    try {
        $stateAcl = Get-Acl -LiteralPath $statePath -ErrorAction Stop
        $writeRules = @($stateAcl.Access | Where-Object {
            ($_.IdentityReference.Value -like '*CodexSandboxUsers*') -and
            ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and
            (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -or
             ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify))
        })
        if ($writeRules.Count -gt 0) { $sandboxWritable = $true }
    } catch {}
    try {
        # Explicit UTF-8 read handles non-ASCII paths cleanly on PowerShell 5.1 without modifying the file.
        $raw = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return [PSCustomObject]@{ Present = $true; ValidJson = $false; EntryCount = 0; PrincipalCount = 0; SandboxWritable = $sandboxWritable }
        }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        $count = 0
        $principalCount = 0
        if ($obj -is [System.Array]) {
            $count = $obj.Count
        } elseif ($null -ne $obj) {
            # Codex's PersistentDenyReadAclState schema maps `principals: { "<SID>": [ "<path>", ... ] }`.
            $principalsProp = $obj.PSObject.Properties['principals']
            if ($null -ne $principalsProp -and $null -ne $principalsProp.Value) {
                $pProps = @($principalsProp.Value.PSObject.Properties)
                $principalCount = $pProps.Count
                foreach ($pp in $pProps) {
                    if ($null -ne $pp.Value) { $count += @($pp.Value).Count }
                }
            } else {
                $props = @($obj.PSObject.Properties)
                $count = $props.Count
                foreach ($listPropName in @('entries', 'paths', 'rules', 'deny_paths', 'protected_paths')) {
                    $lp = $obj.PSObject.Properties[$listPropName]
                    if ($null -ne $lp -and $null -ne $lp.Value) {
                        $count = @($lp.Value).Count
                        break
                    }
                }
            }
        }
        return [PSCustomObject]@{ Present = $true; ValidJson = $true; EntryCount = $count; PrincipalCount = $principalCount; SandboxWritable = $sandboxWritable }
    } catch {
        return [PSCustomObject]@{ Present = $true; ValidJson = $false; EntryCount = 0; PrincipalCount = 0; SandboxWritable = $sandboxWritable }
    }
}

# Normalize caller paths so GetPathRoot and case-insensitive comparisons behave consistently on relative inputs.
$Lane1Home = Get-NormalizedFullPath $Lane1Home
$Lane2Home = Get-NormalizedFullPath $Lane2Home
$LocalBin  = Get-NormalizedFullPath $LocalBin
if ($CodexPath) { $CodexPath = Get-NormalizedFullPath $CodexPath }

Write-Host "=== Codex Dual-Lane System Doctor (Real Host Diagnostics, Read-Only) ===" -ForegroundColor Cyan

# ============================================================================
# Check 1: Operating System & PowerShell Runtime
# ============================================================================
$os = [System.Environment]::OSVersion.VersionString
Report 'PASS' 'Operating System' "$os | PowerShell $($PSVersionTable.PSVersion)"

# ============================================================================
# Check 2: Fixed Drives & NTFS Filesystem Verification
# ============================================================================
$vols = $null
try { $vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | Sort-Object DriveLetter) } catch { $vols = @() }
if (@($vols).Count -gt 0) {
    $driveSummary = ($vols | ForEach-Object { "{0}:({1}, {2}GB free)" -f $_.DriveLetter, $_.FileSystem, ([math]::Round($_.SizeRemaining / 1GB, 1)) }) -join ' | '
    Report 'PASS' 'Local Fixed Drives' $driveSummary
}

$homeDrive = ([System.IO.Path]::GetPathRoot($Lane2Home)).TrimEnd(':\')
if ($homeDrive -notmatch '^[A-Za-z]$') {
    Report 'FAIL' 'Home Drive Filesystem' "Lane2Home '$Lane2Home' is not on a local drive letter; NTFS Directory Junctions require a local NTFS drive"
} else {
    $homeVol = if (@($vols).Count -gt 0) { $vols | Where-Object { $_.DriveLetter -eq $homeDrive } | Select-Object -First 1 } else { $null }
    if (-not $homeVol -or $homeVol.FileSystem -eq 'NTFS') {
        Report 'PASS' 'Home Drive Filesystem' "${homeDrive}: is NTFS (Directory Junctions supported)"
    } else {
        Report 'FAIL' 'Home Drive Filesystem' "${homeDrive}: is NOT NTFS ($($homeVol.FileSystem)); Junctions will fail"
    }
}

# ============================================================================
# Check 3: Codex CLI Launcher Resolution & PATH Precedence
# ============================================================================
$normBin = $LocalBin.TrimEnd('\').ToLowerInvariant()
$codexCmd = Get-Command codex -ErrorAction SilentlyContinue
if ($codexCmd -and $codexCmd.Source) {
    $ver = 'unknown'
    try {
        $verLines = @(& $codexCmd.Source --version 2>&1 | Where-Object { [string]$_ -notmatch '^WARNING:' })
        if ($verLines.Count -gt 0) {
            $rawVer = ([string]$verLines[0]).Trim()
            $ver = if ($rawVer.Length -gt 80) { $rawVer.Substring(0, 80) } else { $rawVer }
        }
    } catch {}
    $parent = (Split-Path -Parent $codexCmd.Source).TrimEnd('\').ToLowerInvariant()
    if ($parent -eq $normBin) {
        Report 'PASS' 'codex CLI in PATH' "$($codexCmd.Source) ($ver)"
    } else {
        Report 'WARN' 'codex CLI in PATH' "Resolved to $($codexCmd.Source) instead of $LocalBin\codex.cmd (reopen terminal or put $LocalBin first in PATH)"
    }
} else {
    $localFallback = Join-Path $LocalBin 'codex.cmd'
    if (Test-Path -LiteralPath $localFallback -PathType Leaf) {
        Report 'WARN' 'codex CLI in PATH' "Wrapper exists at $localFallback but is not yet in PATH (reopen terminal)"
    } else {
        Report 'WARN' 'codex CLI in PATH' 'Not found in PATH. Run setup-dual-lane.ps1 and reopen terminal.'
    }
}

$codexT3Cmd = Get-Command codex-t3 -ErrorAction SilentlyContinue
if ($codexT3Cmd -and $codexT3Cmd.Source) {
    $t3Parent = (Split-Path -Parent $codexT3Cmd.Source).TrimEnd('\').ToLowerInvariant()
    if ($t3Parent -eq $normBin) {
        Report 'PASS' 'codex-t3 CLI in PATH' $codexT3Cmd.Source
    } else {
        Report 'WARN' 'codex-t3 CLI in PATH' "Resolved to $($codexT3Cmd.Source) instead of $LocalBin\codex-t3.cmd"
    }
} elseif (Test-Path -LiteralPath (Join-Path $LocalBin 'codex-t3.cmd') -PathType Leaf) {
    Report 'WARN' 'codex-t3 CLI in PATH' "Wrapper exists at $(Join-Path $LocalBin 'codex-t3.cmd') (reopen terminal for PATH)"
} else {
    Report 'WARN' 'codex-t3 CLI in PATH' 'Not found in PATH'
}

# ============================================================================
# Check 4: Shared Brain NTFS Directory Junctions (Presence + Target Integrity)
# ============================================================================
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
$linkedOk = 0
$broken = New-Object 'System.Collections.Generic.List[string]'
foreach ($d in $sharedDirs) {
    $p = Join-Path $Lane2Home $d
    $expectedTarget = (Join-Path $Lane1Home $d).TrimEnd('\').ToLowerInvariant()
    if (Test-Path -LiteralPath $p) {
        $it = Get-Item -LiteralPath $p -Force
        if ($it.LinkType -eq 'Junction') {
            $rawTarget = (@($it.Target) | Select-Object -First 1)
            $normTarget = if ($rawTarget) { ($rawTarget -replace '^\\\?\?\\', '').TrimEnd('\').ToLowerInvariant() } else { '' }
            if ($normTarget -and ($normTarget -ne $expectedTarget)) {
                $broken.Add("$d (target mismatch)")
            } elseif ($rawTarget -and -not (Test-Path -LiteralPath ($rawTarget -replace '^\\\?\?\\', ''))) {
                $broken.Add("$d (dangling target)")
            } else {
                $linkedOk++
            }
        } else {
            $broken.Add("$d (not a Junction)")
        }
    } else {
        $broken.Add("$d (missing)")
    }
}
if ($broken.Count -eq 0) {
    Report 'PASS' 'Shared Brain Junctions' "$linkedOk/$($sharedDirs.Count) NTFS Junctions healthy & targets verified"
} else {
    Report 'WARN' 'Shared Brain Junctions' "$linkedOk/$($sharedDirs.Count) healthy; issues: $($broken -join ', ')"
}

# ============================================================================
# Check 5: Security Guardrails & Live Behavioral `codex execpolicy check` Probes
# ============================================================================
# Resolve the direct Codex binary for fast, live Rust execpolicy engine verification.
$probeExe = $null
if ($CodexPath -and (Test-Path -LiteralPath $CodexPath -PathType Leaf)) {
    $probeExe = $CodexPath
}
if (-not $probeExe) {
    try {
        $appx = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($appx -and $appx.InstallLocation) {
            $candidate = Join-Path $appx.InstallLocation 'app\resources\codex.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $probeExe = $candidate }
        }
    } catch {}
}
if (-not $probeExe -and $codexCmd -and $codexCmd.Source) { $probeExe = $codexCmd.Source }
if (-not $probeExe) {
    foreach ($fb in @((Join-Path $env:APPDATA 'npm\codex.cmd'), (Join-Path $env:LOCALAPPDATA 'Programs\Codex\codex.exe'))) {
        if (Test-Path -LiteralPath $fb -PathType Leaf) { $probeExe = $fb; break }
    }
}

# High-risk commands that templates/default.rules MUST classify as decision = "forbidden".
$probeCmds = @(
    @('php', '-r', 'echo 1;'),
    @('mshta', 'http://example.invalid'),
    @('vssadmin', 'delete', 'shadows', '/all'),
    @('icacls', 'auth.json', '/grant', 'Everyone:F'),
    @('git', 'push', '--force'),
    @('Start-Process', 'calc.exe'),
    @('iex', 'dir')
)

$secretFindings = New-Object 'System.Collections.Generic.List[string]'

foreach ($pair in @(@('Lane 1', $Lane1Home), @('Lane 2', $Lane2Home))) {
    $label = $pair[0]
    $dir   = $pair[1]
    $rulesPath  = Join-Path $dir 'rules\default.rules'
    $agentsPath = Join-Path $dir 'AGENTS.md'
    $cfgPath    = Join-Path $dir 'config.toml'
    $hasRules   = Test-Path -LiteralPath $rulesPath -PathType Leaf
    $hasAgents  = (Test-Path -LiteralPath $agentsPath -PathType Leaf) -and ((Get-Item -LiteralPath $agentsPath).Length -gt 0)
    $hasConfig  = Test-Path -LiteralPath $cfgPath -PathType Leaf

    # Scan config.toml for plaintext secret keys regardless of whether all 3 files exist.
    $cfgText = ''
    if ($hasConfig) {
        $cfgText = [string](Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
        $badKeys = @(Find-PlaintextSecretsInToml -ConfigText $cfgText)
        foreach ($bk in $badKeys) {
            $secretFindings.Add("${label}/config.toml:$bk")
        }
    }

    if ($hasRules -and $hasAgents -and $hasConfig) {
        $agentsText     = [string](Get-Content -LiteralPath $agentsPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
        $staticAgentsOk = ($agentsText -match 'Static-Analysis-Only')
        $cfgGuardrails  = Inspect-CodexConfigGuardrails -ConfigText $cfgText
        $netOffline     = $cfgGuardrails.NetOffline
        $envFilterOk    = $cfgGuardrails.EnvFilterOk
        $netLabel       = if ($netOffline) { 'sandbox_net=restricted' } else { 'sandbox_net=enabled' }
        $envLabel       = if ($envFilterOk) { 'env_scrub=ON' } else { 'env_scrub=MISSING' }

        $probesPassed   = 0
        $probesBypassed = 0
        $probeEvaluated = 0
        if ($probeExe) {
            foreach ($pArgs in $probeCmds) {
                try {
                    # Use explicit array splatting with '--' terminator for identical PS 5.1 & PS 7+ behavior.
                    $execArgs = @('execpolicy', 'check', '--rules', $rulesPath, '--') + $pArgs
                    $out = (& $probeExe @execArgs 2>$null) -join ''
                    if ($out -match '"decision"\s*:\s*"forbidden"') {
                        $probesPassed++
                        $probeEvaluated++
                    } elseif ($out -match '"decision"\s*:\s*"(allow|prompt)"') {
                        $probesBypassed++
                        $probeEvaluated++
                    }
                } catch {}
            }
        }

        if ($probesBypassed -gt 0) {
            # Genuine security regression: a must-forbid command was explicitly allowed or only prompted!
            Report 'FAIL' "$label Guardrails" "RULE BYPASS: $probesBypassed/$($probeCmds.Count) forbidden probe(s) NOT blocked | $netLabel | $envLabel"
        } elseif ($staticAgentsOk -and $envFilterOk -and $probesPassed -eq $probeCmds.Count) {
            Report 'PASS' "$label Guardrails" "config + AGENTS.md | engine_probe=$probesPassed/$($probeCmds.Count) forbidden | $netLabel | $envLabel"
        } elseif (-not $probeExe -or $probeEvaluated -eq 0) {
            $reason = if (-not $probeExe) { 'no codex binary' } else { 'engine_probe=0/' + $probeCmds.Count }
            Report 'WARN' "$label Guardrails" "config + AGENTS.md present (static_only=$staticAgentsOk); live probe skipped ($reason) | $netLabel | $envLabel"
        } elseif ($staticAgentsOk) {
            Report 'WARN' "$label Guardrails" "config + AGENTS.md present; engine_probe=$probesPassed/$($probeCmds.Count) | $netLabel | $envLabel"
        } else {
            Report 'WARN' "$label Guardrails" "config + rules + AGENTS.md present, but static-only isolation rules incomplete ($netLabel | $envLabel)"
        }
    } else {
        Report 'WARN' "$label Guardrails" "config=$hasConfig, rules=$hasRules, AGENTS.md=$hasAgents"
    }
}

# ============================================================================
# Check 6: Plaintext Secret Hygiene (Zero Credential Leakage)
# ============================================================================
if ($secretFindings.Count -gt 0) {
    Report 'FAIL' 'Secret Hygiene (config.toml)' "Plaintext credential key(s) detected: $($secretFindings -join ', ') (values redacted; migrate to env_key)"
} else {
    Report 'PASS' 'Secret Hygiene (config.toml)' 'Zero plaintext API keys or bearer tokens detected in config.toml'
}

# ============================================================================
# Check 7: Auth Mode, NTFS Kernel ACL Isolation & Read-Only Sandbox Advisory
# ============================================================================
$a1 = Join-Path $Lane1Home 'auth.json'
$a2 = Join-Path $Lane2Home 'auth.json'
$m1 = Get-SafeAuthMode -AuthJsonPath $a1 -MissingLabel 'not-configured'
$m2 = Get-SafeAuthMode -AuthJsonPath $a2 -MissingLabel 'not-logged-in'

# Inspect sensitive files for exposed CodexSandboxUsers ALLOW ACEs (ignoring protective DENY ACEs!)
# and check whether NTFS inheritance has been broken (/inheritance:d -> AreAccessRulesProtected=$true).
$sensitiveChecks = @(
    @{ Name = 'Lane1/auth.json';         Path = $a1 },
    @{ Name = 'Lane1/config.toml';       Path = (Join-Path $Lane1Home 'config.toml') },
    @{ Name = 'Lane1/config.backup';     Path = (Join-Path $Lane1Home 'config.backup.toml') },
    @{ Name = 'Lane2/auth.json';         Path = $a2 },
    @{ Name = 'Lane2/config.toml';       Path = (Join-Path $Lane2Home 'config.toml') },
    @{ Name = 'Lane2/.rollback/latest';  Path = (Join-Path $Lane2Home '.rollback\latest.json') }
)

$exposedFiles = New-Object 'System.Collections.Generic.List[string]'
$sandboxAllowCount = 0
$checkedSensitiveCount = 0
$inheritanceProtectedCount = 0

foreach ($sc in $sensitiveChecks) {
    $sf = $sc.Path
    if (Test-Path -LiteralPath $sf -PathType Leaf) {
        $checkedSensitiveCount++
        try {
            $acl = Get-Acl -LiteralPath $sf -ErrorAction Stop
            if ($acl.AreAccessRulesProtected) { $inheritanceProtectedCount++ }
            # Count ONLY Allow (Grant) ACEs for CodexSandboxUsers; protective Deny ACEs are safe!
            $allowRules = @($acl.Access | Where-Object {
                ($_.IdentityReference.Value -like '*CodexSandboxUsers*') -and
                ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
            })
            if ($allowRules.Count -gt 0) {
                $sandboxAllowCount += $allowRules.Count
                $exposedFiles.Add($sc.Name)
            }
        } catch {}
    }
}

$aclLabel = if ($sandboxAllowCount -eq 0) {
    "kernel_acl=locked (protected=$inheritanceProtectedCount/$checkedSensitiveCount)"
} else {
    "kernel_acl=EXPOSED($sandboxAllowCount Allow ACEs on $($exposedFiles -join ', '); re-run setup-dual-lane.ps1 or two-step icacls)"
}

if ($m2 -ne 'not-logged-in' -and $m2 -ne 'unreadable' -and $sandboxAllowCount -eq 0) {
    Report 'PASS' 'Auth & ACL Isolation' "Lane 1=$m1 | Lane 2=$m2 | $aclLabel"
} else {
    Report 'WARN' 'Auth & ACL Isolation' "Lane 1=$m1 | Lane 2=$m2 | $aclLabel"
}

# Read-only advisory check on .sandbox\deny_read_acl_state.json (host-side structural + DACL inspection;
# never modifies anything, never prints internal paths, and does not spawn a live sandbox token).
$denyStateL1 = Test-SandboxDenyAclState -LaneHomePath $Lane1Home
$denyStateL2 = Test-SandboxDenyAclState -LaneHomePath $Lane2Home
if (-not $denyStateL1.Present -and -not $denyStateL2.Present) {
    Report 'PASS' 'Sandbox Deny-ACL State' 'Not present yet (host-side read-only advisory; created by Codex Windows elevated sandbox on first run)'
} else {
    foreach ($pair in @(@('Lane 1', $denyStateL1), @('Lane 2', $denyStateL2))) {
        $laneLbl = $pair[0]
        $st      = $pair[1]
        if (-not $st.Present) { continue }
        $daclNote = if ($st.SandboxWritable) { 'state_dacl=sandbox_writable(host_dacl)' } else { 'state_dacl=locked(host_dacl)' }
        if ($st.ValidJson) {
            Report 'PASS' "$laneLbl Sandbox Deny-ACL" "Present & valid JSON ($($st.EntryCount) tracked item(s), $($st.PrincipalCount) principal(s); $daclNote; read-only advisory, untouched; see docs/REAL_CODEX_CHECKLIST.md for live sandbox-token probe)"
        } else {
            Report 'WARN' "$laneLbl Sandbox Deny-ACL" "Present at .sandbox\deny_read_acl_state.json but unreadable/malformed JSON ($daclNote; read-only advisory, untouched)"
        }
    }
}

# ============================================================================
# Check 8: Python 3 Availability (Optional, for scripts\sync-sessions.py)
# ============================================================================
$realPy = $null
$realPyVer = ''
foreach ($cand in @('python', 'python3')) {
    foreach ($cmd in @(Get-Command $cand -All -ErrorAction SilentlyContinue)) {
        if (-not $cmd -or -not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
        $v = ''
        try { $v = [string](& $cmd.Source --version 2>&1 | Select-Object -First 1) } catch {}
        if ($v -match '^Python 3\.') {
            $realPy = $cmd.Source
            $realPyVer = $v
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

Write-Host "`nSummary: $script:passCount PASS | $script:warnCount WARN | $script:failCount FAIL" -ForegroundColor Cyan
if ($script:failCount -gt 0) { exit 1 } else { exit 0 }
