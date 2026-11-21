<#
.SYNOPSIS
    Comprehensive automated security, integrity, AST, and end-to-end smoke test suite for
    Codex Dual-Lane & Security Kit on Windows.

.DESCRIPTION
    Exercises every end-user safety guarantee in isolated temporary directories (NEVER touches
    live %USERPROFILE%\.codex* or User PATH):
      1. PowerShell AST syntax & comment-based help validation on all *.ps1 scripts.
      2. Python bytecode compilation & unit/adversarial test suite (tests/test_sync_sessions.py).
      3. Starlark AST & security policy validation on templates/default.rules.
      4. Preview-mode (-DryRun and -WhatIf) zero-mutation verification on setup-dual-lane.ps1.
      5. Non-destructive TOML merge, zero plaintext API key enforcement (env_key only),
         UTF-8 no-BOM output, injection defense, Protect-SensitiveFileAcl two-step hardening,
         and wrapper execution inside paths containing spaces and '&'.
      6. Strictly read-only doctor.ps1 checks: healthy pass, zero secret/canary leakage,
         read-only deny_read_acl_state.json inspection, plaintext secret FAIL detection, and
         execpolicy bypass FAIL detection.
      7. Adversarial restore-original.ps1 preflight defense: path-traversal ('..\'), outside-root
         backup path, and SHA-256 tamper rejection with zero partial rollback side effects.
      8. Deterministic SHA-256 rollback & restore (-DryRun preview + live restore), proving
         byte-exact recovery and zero Lane 1 data loss across NTFS Directory Junctions.

.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
    License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
    Project   : Codex Dual-Lane & Security Kit
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$KitRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$SetupScript   = Join-Path $KitRoot 'scripts\setup-dual-lane.ps1'
$DoctorScript  = Join-Path $KitRoot 'scripts\doctor.ps1'
$RestoreScript = Join-Path $KitRoot 'scripts\restore-original.ps1'
$RulesFile     = Join-Path $KitRoot 'templates\default.rules'

# Use the currently running PowerShell host (powershell.exe on 5.1, pwsh.exe on 7+) so CI can
# validate both Windows PowerShell 5.1 and PowerShell 7+ with the exact same test script.
$CurrentPsExe = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { 'powershell' }
if ([string]::IsNullOrWhiteSpace($CurrentPsExe)) { $CurrentPsExe = 'powershell' }

function Assert-True {
    <#
    .SYNOPSIS
        Fails immediately with an actionable message if a safety assertion evaluates to false.
    #>
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Invoke-PsScript {
    <#
    .SYNOPSIS
        Runs a PowerShell script in an isolated child process and captures combined output + exit code.
        WHY: Child process isolation prevents script-scoped variables, strict mode, or exit calls
        from bleeding into the test harness and lets tests assert exact exit codes and stdout/stderr.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$Arguments = @()
    )
    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $CurrentPsExe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @Arguments 2>&1
        $code = $LASTEXITCODE
        return [PSCustomObject]@{
            ExitCode = $code
            Output   = (($output | ForEach-Object { [string]$_ }) -join "`n")
        }
    } finally {
        $ErrorActionPreference = $prevPref
    }
}

function Get-TreeSnapshot {
    <#
    .SYNOPSIS
        Captures a deterministic map of {relativePath -> SHA256 or 'DIR'} for zero-mutation checks.
    #>
    param([Parameter(Mandatory = $true)][string]$RootDir)
    $map = @{}
    if (-not (Test-Path -LiteralPath $RootDir)) { return $map }
    $rootFull = [System.IO.Path]::GetFullPath($RootDir).TrimEnd('\')
    foreach ($item in @(Get-ChildItem -LiteralPath $rootFull -Recurse -Force -ErrorAction SilentlyContinue)) {
        $rel = $item.FullName.Substring($rootFull.Length).TrimStart('\')
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            $map[$rel] = 'REPARSE'
        } elseif ($item.PSIsContainer) {
            $map[$rel] = 'DIR'
        } else {
            $map[$rel] = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
    }
    return $map
}

function Assert-SnapshotsEqual {
    param(
        [hashtable]$Before,
        [hashtable]$After,
        [string]$Context
    )
    $beforeKeys = @($Before.Keys | Sort-Object)
    $afterKeys  = @($After.Keys | Sort-Object)
    Assert-True ($beforeKeys.Count -eq $afterKeys.Count) "$Context changed entry count (before=$($beforeKeys.Count), after=$($afterKeys.Count))"
    foreach ($k in $beforeKeys) {
        Assert-True ($After.ContainsKey($k)) "$Context deleted entry '$k'"
        Assert-True ($Before[$k] -eq $After[$k]) "$Context modified '$k' (before=$($Before[$k]), after=$($After[$k]))"
    }
}

function Remove-TempTreeSafely {
    <#
    .SYNOPSIS
        Detaches any NTFS Junctions via non-recursive Win32 Directory.Delete before deleting a temp dir.
        WHY: Guarantees test cleanup never follows a Junction and works reliably on paths with spaces/'&'.
    #>
    param([string]$RootDir, [string]$Lane2Dir)
    if ($Lane2Dir -and (Test-Path -LiteralPath $Lane2Dir)) {
        foreach ($d in @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')) {
            $jp = Join-Path $Lane2Dir $d
            if (Test-Path -LiteralPath $jp) {
                try {
                    $attrs = [System.IO.File]::GetAttributes($jp)
                    if ($attrs -band [System.IO.FileAttributes]::ReparsePoint) {
                        [System.IO.Directory]::Delete($jp, $false)
                    }
                } catch {}
            }
        }
    }
    if ($RootDir -and (Test-Path -LiteralPath $RootDir)) {
        Remove-Item -LiteralPath $RootDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# TEST 1: PowerShell AST Parse Check & CRLF Hygiene on All .ps1 Scripts
# WHAT: Parses every .ps1 file in scripts/ and tests/ using the official
#       PowerShell Language Parser, verifies comment-based help, and checks CRLF.
# PREVENTS: Syntax regressions, PS 5.1/7+ parse failures, and broken LF-only
#           PowerShell scripts violating .gitattributes.
# ============================================================================
Write-Host "=== 1. PowerShell AST Parse Check & Line-Ending Hygiene (All .ps1 Scripts) ===" -ForegroundColor Cyan
$psFiles = @(
    @(Get-ChildItem -LiteralPath (Join-Path $KitRoot 'scripts') -Filter '*.ps1' -File) +
    @(Get-ChildItem -LiteralPath (Join-Path $KitRoot 'tests') -Filter '*.ps1' -File)
) | Sort-Object FullName
Assert-True ($psFiles.Count -ge 4) "Expected at least 4 .ps1 scripts, found $($psFiles.Count)"

foreach ($pf in $psFiles) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($pf.FullName, [ref]$tokens, [ref]$parseErrors)
    Assert-True ($null -ne $ast) "AST parser returned null for $($pf.Name)"
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $errSummary = ($parseErrors | ForEach-Object { "L$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
        throw "PowerShell AST parse error(s) in $($pf.FullName): $errSummary"
    }

    # Verify CRLF line endings per .gitattributes (*.ps1 text eol=crlf).
    $rawBytes = [System.IO.File]::ReadAllBytes($pf.FullName)
    $loneLf = 0
    for ($i = 0; $i -lt $rawBytes.Length; $i++) {
        if ($rawBytes[$i] -eq 0x0A -and ($i -eq 0 -or $rawBytes[$i - 1] -ne 0x0D)) {
            $loneLf++
        }
    }
    Assert-True ($loneLf -eq 0) "$($pf.Name) contains $loneLf lone LF line ending(s); .gitattributes requires CRLF"

    # Verify every production script in scripts\ has comment-based .SYNOPSIS help.
    if ($pf.DirectoryName -eq (Join-Path $KitRoot 'scripts')) {
        $helpText = Get-Content -LiteralPath $pf.FullName -Raw -Encoding UTF8
        Assert-True ($helpText -match '(?m)^\.SYNOPSIS\s*$') "$($pf.Name) is missing comment-based .SYNOPSIS help"
    }
    Write-Host "    [OK] $($pf.Name) (AST errors=0, lone-LF=0)" -ForegroundColor Green
}

# ============================================================================
# TEST 2: Python Compile & Unit/Adversarial Test Suite (sync-sessions.py)
# WHAT: Compiles Python sources and executes tests/test_sync_sessions.py with
#       bytecode writing disabled (-B) so working tree stays clean.
# PREVENTS: Regressions in read-only SQLite reads, UPSERT idempotency, atomic
#           JSONL writes, symlink/traversal rejection, and corrupt/locked DB handling.
# ============================================================================
Write-Host "`n=== 2. Running Python Syntax & Unit Tests (sync-sessions.py) ===" -ForegroundColor Cyan
$py = $null
foreach ($cand in @('python', 'python3')) {
    foreach ($cmd in @(Get-Command $cand -All -ErrorAction SilentlyContinue)) {
        if (-not $cmd -or -not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
        $prevPyPref = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $v = [string](& $cmd.Source --version 2>&1 | Select-Object -First 1)
        } finally {
            $ErrorActionPreference = $prevPyPref
        }
        if ($v -match '^Python 3\.') { $py = $cmd.Source; break }
    }
    if ($py) { break }
}
if (-not $py) { throw 'Python 3 not found for unit tests.' }

& $py -B -m unittest discover -s (Join-Path $KitRoot 'tests') -v
if ($LASTEXITCODE -ne 0) { throw "Python unit tests failed with exit code $LASTEXITCODE." }

# ============================================================================
# TEST 3: Starlark Syntax & Policy Validation on templates/default.rules
# WHAT: Parses templates/default.rules with Python's AST (Starlark subset),
#       checks LF-only/no-BOM hygiene, validates every prefix_rule() signature,
#       and asserts mandatory high-risk commands remain forbidden/prompted.
# PREVENTS: Broken Starlark syntax that would prevent Codex execpolicy from
#           loading rules, or accidental weakening/removal of core blocks.
# ============================================================================
Write-Host "`n=== 3. Validating templates/default.rules Starlark Syntax & Core Policy ===" -ForegroundColor Cyan
$rulesValidatorPy = @'
import ast, pathlib, sys

rules_path = pathlib.Path(sys.argv[1])
raw = rules_path.read_bytes()
assert not raw.startswith(b"\xef\xbb\xbf"), "default.rules must not contain UTF-8 BOM"
assert b"\r\n" not in raw, "default.rules must use LF line endings per .gitattributes"

tree = ast.parse(raw.decode("utf-8"), filename=str(rules_path))
assert len(tree.body) > 0, "default.rules must contain at least one rule"

rules = {}
for stmt in tree.body:
    assert isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call), (
        f"Unexpected statement on line {stmt.lineno}: only prefix_rule(...) calls allowed"
    )
    call = stmt.value
    assert isinstance(call.func, ast.Name) and call.func.id == "prefix_rule", (
        f"Unexpected function call on line {stmt.lineno}"
    )
    assert not call.args, f"prefix_rule on line {stmt.lineno} must use keyword arguments"
    kw = {k.arg: ast.literal_eval(k.value) for k in call.keywords}
    assert set(kw.keys()) == {"pattern", "decision"}, f"Unexpected kwargs on line {stmt.lineno}: {kw.keys()}"
    pat = kw["pattern"]
    dec = kw["decision"]
    assert isinstance(pat, list) and len(pat) > 0 and all(isinstance(x, str) and x for x in pat), (
        f"Invalid pattern on line {stmt.lineno}: {pat!r}"
    )
    assert dec in {"forbidden", "prompt", "allow"}, f"Invalid decision on line {stmt.lineno}: {dec!r}"
    rules[tuple(pat)] = dec

must_forbid = [
    ("vssadmin",), ("bcdedit",), ("icacls",), ("php",), ("mshta",),
    ("Start-Process",), ("Invoke-Expression",), ("iex",), ("git", "push", "--force"),
]
for pat in must_forbid:
    assert rules.get(pat) == "forbidden", f"Mandatory forbidden rule missing or weakened: {pat}"

must_prompt = [("git", "push"), ("git", "reset", "--hard"), ("git", "clean")]
for pat in must_prompt:
    assert rules.get(pat) == "prompt", f"Mandatory prompt rule missing or weakened: {pat}"

print(f"    [OK] templates/default.rules validated ({len(rules)} rules parsed, core forbidden/prompt invariants intact)")
'@
$rulesValidatorPy | & $py -B - $RulesFile
if ($LASTEXITCODE -ne 0) { throw "templates/default.rules validation failed with exit code $LASTEXITCODE." }

# ============================================================================
# Prepare Isolated Temp Workspace With Spaces & '&' (Tests 4 through 8)
# ============================================================================
$tmpRoot = Join-Path $env:TEMP ('codex kit & ci ' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$repoDir = Join-Path $tmpRoot 'My Repo & Space'
$l1      = Join-Path $tmpRoot 'lane 1 .codex'
$l2      = Join-Path $tmpRoot 'lane 2 .codex-official'
$bin     = Join-Path $tmpRoot 'local bin'
$cargo   = Join-Path $tmpRoot 'cargo target'
$fakeExe = Join-Path $tmpRoot 'fake codex.cmd'
$bypassExe = Join-Path $tmpRoot 'fake-bypass-codex.cmd'
$outsideVictim = Join-Path $tmpRoot 'outside-sensitive-file.txt'

New-Item -ItemType Directory -Path $tmpRoot, $repoDir, $l1, $l2 -Force | Out-Null
try {
    # Portable mock codex executable supporting --version, features, and execpolicy check.
    $fakeBat = @(
        '@echo off',
        'if "%~1"=="--version" echo codex-cli 0.171.0-test',
        'if "%~1"=="features" echo memories stable true',
        'if "%~1"=="execpolicy" echo {"decision":"forbidden"}',
        'exit /b 0'
    ) -join "`r`n"
    [System.IO.File]::WriteAllText($fakeExe, $fakeBat + "`r`n", [System.Text.Encoding]::ASCII)

    # Adversarial mock codex executable that returns "allow" for execpolicy checks to prove doctor.ps1 fails closed.
    $bypassBat = @(
        '@echo off',
        'if "%~1"=="--version" echo codex-cli 0.171.0-test',
        'if "%~1"=="execpolicy" echo {"decision":"allow"}',
        'exit /b 0'
    ) -join "`r`n"
    [System.IO.File]::WriteAllText($bypassExe, $bypassBat + "`r`n", [System.Text.Encoding]::ASCII)

    # External victim file outside Lane1/Lane2/LocalBin to prove restore-original.ps1 containment.
    $victimContent = 'EXTERNAL_VICTIM_MUST_NEVER_BE_TOUCHED'
    [System.IO.File]::WriteAllText($outsideVictim, $victimContent, (New-Object System.Text.UTF8Encoding($false)))
    $victimOrigHash = (Get-FileHash -LiteralPath $outsideVictim -Algorithm SHA256).Hash

    # Pre-seed Lane 2 config.toml with custom top-level settings (including multi-line array),
    # existing [projects.*], [mcp_servers.*], [tui] with inline comment, and [[array_of_tables]].
    $seedLane2 = @"
model = "user-custom-model"
notify = [
  "custom-notifier",
  "--quiet"
]

[projects."c:\\existing\\project"]
trust_level = "trusted"

[mcp_servers.custom_tool]
command = "node"
args = ["server.js"]

[tui] # keep user comment header
theme = "dark"

[[custom_hooks]]
name = "keep-array-table"
"@
    [System.IO.File]::WriteAllText((Join-Path $l2 'config.toml'), $seedLane2, (New-Object System.Text.UTF8Encoding($false)))
    $origLane2Hash = (Get-FileHash -LiteralPath (Join-Path $l2 'config.toml') -Algorithm SHA256).Hash

    # Pre-seed Lane 1 config.toml with a legacy plaintext experimental_bearer_token AND a custom [tui]
    # section to verify -ConfigureGateway purges plaintext secrets while preserving user sections.
    $legacyTokenCanary = 'sk-LEGACY-PLAINTEXT-MUST-BE-PURGED-112233'
    $seedLane1 = @"
model_provider = "OpenAI"

[model_providers.OpenAI]
name = "OpenAI"
base_url = "https://old.example.invalid/v1"
experimental_bearer_token = "$legacyTokenCanary"

[tui]
theme = "light"
"@
    [System.IO.File]::WriteAllText((Join-Path $l1 'config.toml'), $seedLane1, (New-Object System.Text.UTF8Encoding($false)))
    $origLane1Hash = (Get-FileHash -LiteralPath (Join-Path $l1 'config.toml') -Algorithm SHA256).Hash

    # Seed a critical Lane 1 session file to prove NTFS Junction creation & rollback NEVER lose Lane 1 data.
    New-Item -ItemType Directory -Path (Join-Path $l1 'sessions') -Force | Out-Null
    $criticalSessionFile = Join-Path $l1 'sessions\important-session.jsonl'
    [System.IO.File]::WriteAllText($criticalSessionFile, '{"id":"s-1","text":"important history"}', (New-Object System.Text.UTF8Encoding($false)))
    $origSessionHash = (Get-FileHash -LiteralPath $criticalSessionFile -Algorithm SHA256).Hash

    # Seed auth.json files in temp lanes with a secret token canary so Protect-SensitiveFileAcl
    # and doctor.ps1 zero-secret-leakage checks run against realistic credential files.
    $authSecretCanary = 'sk-CANARY-AUTH-SECRET-NEVER-ECHO-998877'
    $authLane1Json = '{"auth_mode":"apikey","OPENAI_API_KEY":"' + $authSecretCanary + '"}'
    $authLane2Json = '{"auth_mode":"chatgpt","tokens":{"access_token":"' + $authSecretCanary + '"}}'
    [System.IO.File]::WriteAllText((Join-Path $l1 'auth.json'), $authLane1Json, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $l2 'auth.json'), $authLane2Json, (New-Object System.Text.UTF8Encoding($false)))

    # Seed a pre-existing user launcher (codex-t3.cmd) in LocalBin (while leaving codex.cmd and
    # codex-official.cmd absent) to verify rollback restores pre-existing launchers byte-for-byte
    # instead of deleting them.
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $preExistingLauncher = Join-Path $bin 'codex-t3.cmd'
    [System.IO.File]::WriteAllText($preExistingLauncher, "@echo off`r`necho PRE_EXISTING_USER_LAUNCHER`r`n", (New-Object System.Text.UTF8Encoding($false)))
    $origLauncherHash = (Get-FileHash -LiteralPath $preExistingLauncher -Algorithm SHA256).Hash

    # ========================================================================
    # TEST 4: Dry-Run & -WhatIf Zero-Mutation Verification
    # WHAT: Runs setup-dual-lane.ps1 with -DryRun and -WhatIf (also testing
    #       the -ProjectRoot alias) and verifies every directory entry and file
    #       SHA-256 across Lane 1, Lane 2, LocalBin, and Repo is 100% unchanged.
    # PREVENTS: Preview runs accidentally creating directories, Junctions,
    #           backups, rollback manifests, or modifying config.toml.
    # ========================================================================
    Write-Host "`n=== 4. Dry-Run & -WhatIf Zero-Mutation Verification ===" -ForegroundColor Cyan
    $snapBeforeDryRun = Get-TreeSnapshot -RootDir $tmpRoot

    $resDry = Invoke-PsScript -ScriptPath $SetupScript -Arguments @(
        '-ProjectRoot', $repoDir, '-CodexPath', $fakeExe,
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CargoTargetDir', $cargo,
        '-ConfigureGateway', '-GatewayBaseUrl', 'https://gateway.example.invalid/v1',
        '-GatewayApiKeyEnv', 'CODEX_TEST_GW_KEY',
        '-InstallBridgeTemplate', '-SkipPathUpdate', '-DryRun'
    )
    Assert-True ($resDry.ExitCode -eq 0) "setup-dual-lane.ps1 -DryRun failed (exit=$($resDry.ExitCode)):`n$($resDry.Output)"
    Assert-SnapshotsEqual -Before $snapBeforeDryRun -After (Get-TreeSnapshot -RootDir $tmpRoot) -Context 'setup-dual-lane.ps1 -DryRun'

    $resWhatIf = Invoke-PsScript -ScriptPath $SetupScript -Arguments @(
        '-RepoPath', $repoDir, '-CodexPath', $fakeExe,
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CargoTargetDir', $cargo,
        '-InstallBridgeTemplate', '-SkipPathUpdate', '-WhatIf'
    )
    Assert-True ($resWhatIf.ExitCode -eq 0) "setup-dual-lane.ps1 -WhatIf failed (exit=$($resWhatIf.ExitCode)):`n$($resWhatIf.Output)"
    Assert-SnapshotsEqual -Before $snapBeforeDryRun -After (Get-TreeSnapshot -RootDir $tmpRoot) -Context 'setup-dual-lane.ps1 -WhatIf'
    Write-Host "    [OK] -DryRun and -WhatIf completed with zero filesystem mutations" -ForegroundColor Green

    # ========================================================================
    # TEST 5: Non-Destructive TOML Merge, Zero Plaintext Key, Safe ACL, Spaces/'&'
    # WHAT: Runs setup-dual-lane.ps1 end-to-end inside paths with spaces & '&',
    #       verifying non-destructive TOML preservation, env_key enforcement,
    #       legacy secret purging, UTF-8 no-BOM, Protect-SensitiveFileAcl
    #       two-step inheritance protection, input-injection rejection, and
    #       working CLI wrapper invocation.
    # PREVENTS: Clobbered user TOML sections, plaintext API keys persisted to
    #           disk/backups, BOM breakage in Rust TOML parser, broken NTFS ACLs
    #           on fresh machines without CodexSandboxUsers, and CMD quoting bugs.
    # ========================================================================
    Write-Host "`n=== 5. Non-Destructive TOML Merge, env_key, Safe ACL & Injection Defense ===" -ForegroundColor Cyan

    # Negative input-validation checks: invalid env var name and overlapping lanes must fail closed.
    $resBadEnv = Invoke-PsScript -ScriptPath $SetupScript -Arguments @(
        '-RepoPath', $repoDir, '-CodexPath', $fakeExe,
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin,
        '-ConfigureGateway', '-GatewayBaseUrl', 'https://gateway.example.invalid/v1',
        '-GatewayApiKeyEnv', 'BAD-ENV;NAME', '-SkipPathUpdate'
    )
    Assert-True ($resBadEnv.ExitCode -ne 0) 'Invalid -GatewayApiKeyEnv must be rejected'

    $resOverlap = Invoke-PsScript -ScriptPath $SetupScript -Arguments @(
        '-RepoPath', $repoDir, '-CodexPath', $fakeExe,
        '-Lane1Home', $l1, '-Lane2Home', $l1, '-LocalBin', $bin, '-SkipPathUpdate'
    )
    Assert-True ($resOverlap.ExitCode -ne 0) 'Overlapping Lane1Home == Lane2Home must be rejected'

    # Full install inside workspace containing spaces and '&'.
    $resInstall = Invoke-PsScript -ScriptPath $SetupScript -Arguments @(
        '-RepoPath', $repoDir, '-CodexPath', $fakeExe,
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CargoTargetDir', $cargo,
        '-ConfigureGateway', '-GatewayBaseUrl', 'https://gateway.example.invalid/v1',
        '-GatewayApiKeyEnv', 'CODEX_TEST_GW_KEY',
        '-InstallBridgeTemplate', '-SkipPathUpdate'
    )
    Assert-True ($resInstall.ExitCode -eq 0) "setup-dual-lane.ps1 failed (exit=$($resInstall.ExitCode)):`n$($resInstall.Output)"

    # Verify Lane 2 TOML merge & defaults.
    $merged2 = Get-Content -LiteralPath (Join-Path $l2 'config.toml') -Raw -Encoding UTF8
    Assert-True ($merged2 -match 'approval_policy = "on-request"') 'Default approval_policy must be on-request'
    Assert-True ($merged2 -match 'network_access = false') 'Default sandbox network_access must be false'
    Assert-True ($merged2 -match 'model = "user-custom-model"') 'Custom top-level model was lost during TOML merge'
    Assert-True ($merged2 -match 'custom-notifier') 'Custom multi-line top-level notify array was lost during TOML merge'
    Assert-True ($merged2 -match '\[mcp_servers\.custom_tool\]') 'Custom [mcp_servers.custom_tool] section was lost'
    Assert-True ($merged2 -match '\[tui\]') 'Custom [tui] section with inline comment was lost'
    Assert-True ($merged2 -match '\[\[custom_hooks\]\]') 'Custom [[custom_hooks]] array-of-tables was lost'
    Assert-True ($merged2 -match 'c:\\\\existing\\\\project') 'Existing trusted project was lost during TOML merge'

    # Verify Lane 1 gateway config enforces env_key and purges legacy plaintext token.
    $merged1 = Get-Content -LiteralPath (Join-Path $l1 'config.toml') -Raw -Encoding UTF8
    Assert-True ($merged1 -match 'env_key = "CODEX_TEST_GW_KEY"') 'Lane 1 config.toml must use env_key'
    Assert-True ($merged1 -notmatch 'experimental_bearer_token') 'Lane 1 config.toml must NEVER contain experimental_bearer_token'
    Assert-True ($merged1 -notmatch [regex]::Escape($legacyTokenCanary)) 'Legacy plaintext token leaked into merged Lane 1 config.toml'
    Assert-True ($merged1 -match '\[tui\]') 'Custom Lane 1 [tui] section was lost during gateway merge'

    # Verify UTF-8 NO-BOM on generated config.toml in both lanes.
    foreach ($cfgFile in @((Join-Path $l1 'config.toml'), (Join-Path $l2 'config.toml'))) {
        $bytes = [System.IO.File]::ReadAllBytes($cfgFile)
        Assert-True (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) "Generated $cfgFile contains a UTF-8 BOM"
    }

    # Verify Protect-SensitiveFileAcl broke inheritance (Step 1 /inheritance:d) and left zero CodexSandboxUsers Allow ACEs.
    $manifestPath = Join-Path $l2 '.rollback\latest.json'
    Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'Rollback snapshot manifest (.rollback\latest.json) was not created'
    foreach ($aclFile in @(
        (Join-Path $l1 'auth.json'),
        (Join-Path $l1 'config.toml'),
        (Join-Path $l2 'auth.json'),
        (Join-Path $l2 'config.toml'),
        $manifestPath
    )) {
        $acl = Get-Acl -LiteralPath $aclFile
        Assert-True ([bool]$acl.AreAccessRulesProtected) "Protect-SensitiveFileAcl did not disable NTFS inheritance (/inheritance:d) on $aclFile"
        $sandboxAllow = @($acl.Access | Where-Object {
            ($_.IdentityReference.Value -like '*CodexSandboxUsers*') -and
            ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
        })
        Assert-True ($sandboxAllow.Count -eq 0) "CodexSandboxUsers Allow ACE still present on $aclFile"
    }

    # Verify generated codex.cmd wrapper executes cleanly despite spaces and '&' in paths.
    $wrapperCmd = Join-Path $bin 'codex.cmd'
    Assert-True (Test-Path -LiteralPath $wrapperCmd -PathType Leaf) 'codex.cmd wrapper was not created'
    $wrapperOut = (& $wrapperCmd --version 2>&1) -join "`n"
    Assert-True ($LASTEXITCODE -eq 0 -and $wrapperOut -match 'codex-cli 0\.171\.0-test') "codex.cmd wrapper failed on path with spaces/'&': $wrapperOut"
    Write-Host "    [OK] TOML merge, env_key secret purge, UTF-8 no-BOM, Protect-SensitiveFileAcl, and wrapper verified" -ForegroundColor Green

    # ========================================================================
    # TEST 6: doctor.ps1 Health Checks, Read-Only Advisory & Zero Secret Leakage
    # WHAT: Runs doctor.ps1 against the configured temp lanes with realistic
    #       secret canaries in auth.json and .sandbox\deny_read_acl_state.json,
    #       then tests failure detection on plaintext secrets and execpolicy bypass.
    # PREVENTS: Secret/token printing in diagnostic logs, accidental mutation of
    #           .sandbox\deny_read_acl_state.json, and silent pass on rule bypasses.
    # ========================================================================
    Write-Host "`n=== 6. doctor.ps1 Diagnostics, Read-Only Integrity & Zero Secret Leakage ===" -ForegroundColor Cyan
    $sandboxDir = Join-Path $l2 '.sandbox'
    New-Item -ItemType Directory -Path $sandboxDir -Force | Out-Null
    $denyAclPath = Join-Path $sandboxDir 'deny_read_acl_state.json'
    $denyCanary = 'CANARY_PRIVATE_DENY_PATH_7711'
    [System.IO.File]::WriteAllText($denyAclPath, '{"protected_paths":["C:\\' + $denyCanary + '"]}', (New-Object System.Text.UTF8Encoding($false)))
    $denyOrigHash = (Get-FileHash -LiteralPath $denyAclPath -Algorithm SHA256).Hash

    # 6a) Healthy doctor run must exit 0 and never echo auth or deny-ACL canaries.
    $resDocOk = Invoke-PsScript -ScriptPath $DoctorScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CodexPath', $fakeExe
    )
    Assert-True ($resDocOk.ExitCode -eq 0) "doctor.ps1 failed on healthy setup (exit=$($resDocOk.ExitCode)):`n$($resDocOk.Output)"
    Assert-True ($resDocOk.Output -match 'engine_probe=7/7 forbidden') "doctor.ps1 did not report 7/7 forbidden probes:`n$($resDocOk.Output)"
    Assert-True ($resDocOk.Output -match 'kernel_acl=locked') "doctor.ps1 did not report kernel_acl=locked:`n$($resDocOk.Output)"
    Assert-True ($resDocOk.Output -match 'Sandbox Deny-ACL') "doctor.ps1 did not report Sandbox Deny-ACL advisory:`n$($resDocOk.Output)"
    Assert-True (-not $resDocOk.Output.Contains($authSecretCanary)) 'CRITICAL: doctor.ps1 leaked auth.json secret canary!'
    Assert-True (-not $resDocOk.Output.Contains($denyCanary)) 'CRITICAL: doctor.ps1 leaked deny_read_acl_state.json internal path!'
    Assert-True ((Get-FileHash -LiteralPath $denyAclPath -Algorithm SHA256).Hash -eq $denyOrigHash) 'doctor.ps1 modified deny_read_acl_state.json!'

    # 6b) Malformed token-like auth_mode in auth.json must be redacted, never echoed.
    $tokenLikeAuthMode = 'sk-AUTH-MODE-CANARY-LEAK-334455'
    [System.IO.File]::WriteAllText((Join-Path $l2 'auth.json'), '{"auth_mode":"' + $tokenLikeAuthMode + '"}', (New-Object System.Text.UTF8Encoding($false)))
    $resDocRedact = Invoke-PsScript -ScriptPath $DoctorScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CodexPath', $fakeExe
    )
    Assert-True (-not $resDocRedact.Output.Contains($tokenLikeAuthMode)) 'CRITICAL: doctor.ps1 echoed token-like auth_mode!'
    Assert-True ($resDocRedact.Output -match 'redacted-nonstandard') 'doctor.ps1 did not redact token-like auth_mode'
    # Restore clean auth.json for subsequent steps.
    [System.IO.File]::WriteAllText((Join-Path $l2 'auth.json'), $authLane2Json, (New-Object System.Text.UTF8Encoding($false)))

    # 6c) Plaintext secret in config.toml must trigger FAIL (exit 1) WITHOUT echoing the secret value.
    $cfgLeakCanary = 'sk-CONFIG-PLAINTEXT-CANARY-667788'
    $savedMerged2 = Get-Content -LiteralPath (Join-Path $l2 'config.toml') -Raw -Encoding UTF8
    try {
        [System.IO.File]::WriteAllText(
            (Join-Path $l2 'config.toml'),
            $savedMerged2 + "`r`nexperimental_bearer_token = `"$cfgLeakCanary`"`r`n",
            (New-Object System.Text.UTF8Encoding($false))
        )
        $resDocSecret = Invoke-PsScript -ScriptPath $DoctorScript -Arguments @(
            '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CodexPath', $fakeExe
        )
        Assert-True ($resDocSecret.ExitCode -eq 1) "doctor.ps1 must exit 1 when config.toml contains plaintext secret"
        Assert-True ($resDocSecret.Output -match '\[FAIL\]\s+Secret Hygiene') "doctor.ps1 did not report Secret Hygiene FAIL"
        Assert-True (-not $resDocSecret.Output.Contains($cfgLeakCanary)) 'CRITICAL: doctor.ps1 leaked plaintext config.toml secret!'
    } finally {
        [System.IO.File]::WriteAllText((Join-Path $l2 'config.toml'), $savedMerged2, (New-Object System.Text.UTF8Encoding($false)))
    }

    # 6d) Execpolicy bypass ("decision":"allow") must trigger FAIL (exit 1).
    $resDocBypass = Invoke-PsScript -ScriptPath $DoctorScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-CodexPath', $bypassExe
    )
    Assert-True ($resDocBypass.ExitCode -eq 1) 'doctor.ps1 must exit 1 when execpolicy allows a forbidden probe'
    Assert-True ($resDocBypass.Output -match 'RULE BYPASS') 'doctor.ps1 did not report RULE BYPASS on allowed probe'
    Write-Host "    [OK] doctor.ps1 passed healthy, redaction, plaintext-secret FAIL, and rule-bypass FAIL checks" -ForegroundColor Green

    # ========================================================================
    # TEST 7: Path-Traversal & Tamper Rejection in restore-original.ps1
    # WHAT: Feeds 3 adversarial manifests to restore-original.ps1:
    #         (a) '..' path traversal targeting an external file outside roots
    #         (b) outside-root BackupPath attempting arbitrary file read/copy
    #         (c) tampered OriginalSha256 mismatch
    #       Asserts every attack fails closed with ZERO partial side effects
    #       (external victim untouched AND Lane 2 Junctions still attached).
    # PREVENTS: Arbitrary file deletion/overwrite via poisoned rollback manifests
    #           and partial rollback state on corrupted backups.
    # ========================================================================
    Write-Host "`n=== 7. Path-Traversal & Manifest-Tamper Rejection in restore-original.ps1 ===" -ForegroundColor Cyan

    # 7a) '..' traversal targeting external file (ExistedPrior = false -> attempts deletion outside root)
    $traversalManifest = Join-Path $tmpRoot 'malicious-traversal.json'
    $traversalTarget = Join-Path $l2 '..\outside-sensitive-file.txt'
    $malObj1 = [PSCustomObject]@{
        SchemaVersion = 1
        Timestamp     = '20260101-000000'
        Lane1Home     = $l1
        Lane2Home     = $l2
        LocalBin      = $bin
        Files         = @(
            [PSCustomObject]@{
                TargetPath     = $traversalTarget
                ExistedPrior   = $false
                BackupPath     = ''
                OriginalSha256 = ''
            }
        )
    } | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($traversalManifest, $malObj1, (New-Object System.Text.UTF8Encoding($false)))

    $resTrav = Invoke-PsScript -ScriptPath $RestoreScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin,
        '-SnapshotPath', $traversalManifest, '-SkipPathUpdate'
    )
    Assert-True ($resTrav.ExitCode -ne 0) 'restore-original.ps1 MUST reject path-traversal TargetPath'
    Assert-True (Test-Path -LiteralPath $outsideVictim -PathType Leaf) 'CRITICAL: External victim file was deleted via path traversal!'
    Assert-True ((Get-FileHash -LiteralPath $outsideVictim -Algorithm SHA256).Hash -eq $victimOrigHash) 'External victim hash changed!'
    Assert-True (((Get-Item -LiteralPath (Join-Path $l2 'sessions') -Force).LinkType) -eq 'Junction') 'Preflight failure must NOT detach Junctions!'

    # 7b) Outside-root BackupPath attempting to copy an unauthorized file into Lane2Home
    $outsideBkpManifest = Join-Path $tmpRoot 'malicious-backup.json'
    $malObj2 = [PSCustomObject]@{
        SchemaVersion = 1
        Timestamp     = '20260101-000000'
        Lane1Home     = $l1
        Lane2Home     = $l2
        LocalBin      = $bin
        Files         = @(
            [PSCustomObject]@{
                TargetPath     = (Join-Path $l2 'config.toml')
                ExistedPrior   = $true
                BackupPath     = $outsideVictim
                OriginalSha256 = $victimOrigHash
            }
        )
    } | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($outsideBkpManifest, $malObj2, (New-Object System.Text.UTF8Encoding($false)))

    $resOutBkp = Invoke-PsScript -ScriptPath $RestoreScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin,
        '-SnapshotPath', $outsideBkpManifest, '-SkipPathUpdate'
    )
    Assert-True ($resOutBkp.ExitCode -ne 0) 'restore-original.ps1 MUST reject outside-root BackupPath'
    Assert-True (((Get-Item -LiteralPath (Join-Path $l2 'sessions') -Force).LinkType) -eq 'Junction') 'Preflight failure on outside BackupPath must NOT detach Junctions!'

    # 7c) Tampered SHA-256 hash in manifest must abort before mutating anything
    $tamperManifest = Join-Path $tmpRoot 'malicious-hash.json'
    $realManifestObj = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($entry in $realManifestObj.Files) {
        if ($entry.ExistedPrior -and $entry.OriginalSha256) {
            $entry.OriginalSha256 = '0000000000000000000000000000000000000000000000000000000000000000'
            break
        }
    }
    [System.IO.File]::WriteAllText($tamperManifest, ($realManifestObj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))

    $resTamper = Invoke-PsScript -ScriptPath $RestoreScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin,
        '-SnapshotPath', $tamperManifest, '-SkipPathUpdate'
    )
    Assert-True ($resTamper.ExitCode -ne 0) 'restore-original.ps1 MUST abort on SHA-256 hash mismatch'
    Assert-True (((Get-Item -LiteralPath (Join-Path $l2 'sessions') -Force).LinkType) -eq 'Junction') 'SHA-256 preflight failure must NOT detach Junctions!'
    Write-Host "    [OK] Path traversal, outside-root backup, and SHA-256 tamper all blocked fail-closed with zero side effects" -ForegroundColor Green

    # ========================================================================
    # TEST 8: Deterministic SHA-256 Rollback & Restore (-DryRun + Live)
    # WHAT: Runs restore-original.ps1 -DryRun (asserting zero mutation), then
    #       runs real restore-original.ps1 inside paths with spaces & '&',
    #       verifying exact pre-install SHA-256 on both lanes' config.toml,
    #       removal of new files & wrappers, clean Junction detachment, and
    #       byte-identical survival of Lane 1's critical session file.
    # PREVENTS: Broken rollback on paths with spaces/'&', incomplete cleanup,
    #           or catastrophic Lane 1 data deletion when detaching Junctions.
    # ========================================================================
    Write-Host "`n=== 8. Deterministic SHA-256 Rollback & Recovery (Spaces/'&' Path) ===" -ForegroundColor Cyan

    # 8a) restore-original.ps1 -DryRun and -WhatIf must verify manifest and mutate zero files/Junctions.
    $snapBeforeRestoreDry = Get-TreeSnapshot -RootDir $tmpRoot
    $resRestoreDry = Invoke-PsScript -ScriptPath $RestoreScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-SkipPathUpdate', '-DryRun'
    )
    Assert-True ($resRestoreDry.ExitCode -eq 0) "restore-original.ps1 -DryRun failed (exit=$($resRestoreDry.ExitCode)):`n$($resRestoreDry.Output)"
    Assert-SnapshotsEqual -Before $snapBeforeRestoreDry -After (Get-TreeSnapshot -RootDir $tmpRoot) -Context 'restore-original.ps1 -DryRun'

    $resRestoreWhatIf = Invoke-PsScript -ScriptPath $RestoreScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-SkipPathUpdate', '-WhatIf'
    )
    Assert-True ($resRestoreWhatIf.ExitCode -eq 0) "restore-original.ps1 -WhatIf failed (exit=$($resRestoreWhatIf.ExitCode)):`n$($resRestoreWhatIf.Output)"
    Assert-SnapshotsEqual -Before $snapBeforeRestoreDry -After (Get-TreeSnapshot -RootDir $tmpRoot) -Context 'restore-original.ps1 -WhatIf'

    # 8b) Real rollback restores byte-exact original files and detaches all Junctions safely.
    $resRestore = Invoke-PsScript -ScriptPath $RestoreScript -Arguments @(
        '-Lane1Home', $l1, '-Lane2Home', $l2, '-LocalBin', $bin, '-SkipPathUpdate'
    )
    Assert-True ($resRestore.ExitCode -eq 0) "restore-original.ps1 failed (exit=$($resRestore.ExitCode)):`n$($resRestore.Output)"

    $restoredLane2Hash = (Get-FileHash -LiteralPath (Join-Path $l2 'config.toml') -Algorithm SHA256).Hash
    Assert-True ($restoredLane2Hash -eq $origLane2Hash) "Rollback SHA-256 mismatch on Lane 2 config.toml! Expected $origLane2Hash, got $restoredLane2Hash"

    $restoredLane1Hash = (Get-FileHash -LiteralPath (Join-Path $l1 'config.toml') -Algorithm SHA256).Hash
    Assert-True ($restoredLane1Hash -eq $origLane1Hash) "Rollback SHA-256 mismatch on Lane 1 config.toml! Expected $origLane1Hash, got $restoredLane1Hash"

    Assert-True (-not (Test-Path -LiteralPath (Join-Path $l2 'AGENTS.md'))) 'Newly created Lane 2 AGENTS.md should have been removed by rollback'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $bin 'codex.cmd'))) 'Newly created wrapper codex.cmd should have been removed by rollback'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $bin 'codex-official.cmd'))) 'Newly created wrapper codex-official.cmd should have been removed by rollback'
    Assert-True (Test-Path -LiteralPath $preExistingLauncher -PathType Leaf) 'Pre-existing user launcher codex-t3.cmd MUST be restored by rollback (not deleted!)'
    $restoredLauncherHash = (Get-FileHash -LiteralPath $preExistingLauncher -Algorithm SHA256).Hash
    Assert-True ($restoredLauncherHash -eq $origLauncherHash) "Rollback SHA-256 mismatch on pre-existing codex-t3.cmd! Expected $origLauncherHash, got $restoredLauncherHash"
    foreach ($d in @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')) {
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $l2 $d))) "NTFS Junction Lane2\$d was not detached by rollback"
    }

    Assert-True (Test-Path -LiteralPath $criticalSessionFile -PathType Leaf) 'CRITICAL: Lane 1 session file was lost during rollback!'
    $afterSessionHash = (Get-FileHash -LiteralPath $criticalSessionFile -Algorithm SHA256).Hash
    Assert-True ($afterSessionHash -eq $origSessionHash) 'CRITICAL: Lane 1 session file hash changed during rollback!'

    Write-Host "`n[PASS] All 8 Windows test stages passed cleanly (AST, Python, default.rules, DryRun/WhatIf, TOML/env_key/ACL, doctor, traversal defense, SHA-256 rollback)!" -ForegroundColor Green
} finally {
    Remove-TempTreeSafely -RootDir $tmpRoot -Lane2Dir $l2
}
