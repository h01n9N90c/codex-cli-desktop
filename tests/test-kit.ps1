<#
.SYNOPSIS
    Automated smoke, TOML-merge, UTF-8 no-BOM, secret-isolation, and Python unit test runner.
.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    License   : Apache-2.0
#>
$ErrorActionPreference = 'Stop'
$KitRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

Write-Host "=== 1. Running Python Unit Tests (sync-sessions UPSERT & schema drift) ===" -ForegroundColor Cyan
$py = $null
foreach ($cand in @('python', 'python3')) {
    foreach ($cmd in (Get-Command $cand -All -ErrorAction SilentlyContinue)) {
        if (-not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
        $v = (& $cmd.Source --version 2>&1 | Select-Object -First 1)
        if ($v -match '^Python 3\.') { $py = $cmd.Source; break }
    }
    if ($py) { break }
}
if (-not $py) { throw "Python 3 not found for unit tests." }
& $py -m unittest discover -s (Join-Path $KitRoot 'tests') -v
if ($LASTEXITCODE -ne 0) { throw "Python unit tests failed." }

Write-Host "`n=== 2. Running Non-Destructive TOML Merge & Zero-Plaintext-Key Smoke Test ===" -ForegroundColor Cyan
$tmpRoot = Join-Path $env:TEMP ('codex-kit-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$l1 = Join-Path $tmpRoot '.codex'
$l2 = Join-Path $tmpRoot '.codex-official'
$bin = Join-Path $tmpRoot '.local\bin'
$cargo = Join-Path $tmpRoot 'cargo-target'
$fakeExe = Join-Path $tmpRoot 'fake-codex.cmd'

New-Item -ItemType Directory -Path $tmpRoot, $l1, $l2 -Force | Out-Null
try {
    # Create a minimal portable mock codex executable so CI runners without Codex installed can still test installer logic
    Set-Content -LiteralPath $fakeExe -Value "@echo off`r`nif `"%1`"==`"--version`" echo codex-cli 0.171.0-test`r`nif `"%1`"==`"features`" echo memories stable true`r`nexit /b 0" -Encoding ASCII

    # Pre-seed Lane 2 config.toml with custom user sections ([mcp_servers.custom], [tui]) and custom top-level notify
    $seedLane2 = @"
model = "user-custom-model"
notify = ["custom-notifier"]

[projects."c:\\existing\\project"]
trust_level = "trusted"

[mcp_servers.custom_tool]
command = "node"
args = ["server.js"]

[tui]
theme = "dark"
"@
    [System.IO.File]::WriteAllText((Join-Path $l2 'config.toml'), $seedLane2, (New-Object System.Text.UTF8Encoding($false)))
    $origLane2Hash = (Get-FileHash -LiteralPath (Join-Path $l2 'config.toml') -Algorithm SHA256).Hash

    # Seed a critical session file in Lane 1 to prove rollback NEVER loses Lane 1 data through Junctions
    New-Item -ItemType Directory -Path (Join-Path $l1 'sessions') -Force | Out-Null
    $criticalSessionFile = Join-Path $l1 'sessions\important-session.jsonl'
    [System.IO.File]::WriteAllText($criticalSessionFile, '{"id":"s-1","text":"important history"}', (New-Object System.Text.UTF8Encoding($false)))
    $origSessionHash = (Get-FileHash -LiteralPath $criticalSessionFile -Algorithm SHA256).Hash

    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot 'scripts\setup-dual-lane.ps1') `
        -RepoPath $tmpRoot -CodexPath $fakeExe -Lane1Home $l1 -Lane2Home $l2 -LocalBin $bin -CargoTargetDir $cargo `
        -ConfigureGateway -GatewayBaseUrl 'https://gateway.example.invalid/v1' -GatewayApiKeyEnv 'CODEX_TEST_GW_KEY' `
        -InstallBridgeTemplate -SkipPathUpdate

    $merged2 = Get-Content -LiteralPath (Join-Path $l2 'config.toml') -Raw
    if ($merged2 -notmatch 'approval_policy = "on-request"') { throw 'Default approval_policy should be on-request' }
    if ($merged2 -notmatch 'network_access = false') { throw 'Default sandbox network_access should be false' }
    if ($merged2 -notmatch 'model = "user-custom-model"') { throw 'Custom top-level model was lost during TOML merge' }
    if ($merged2 -notmatch '\[mcp_servers\.custom_tool\]') { throw 'Custom [mcp_servers.custom_tool] section was lost during TOML merge' }
    if ($merged2 -notmatch '\[tui\]') { throw 'Custom [tui] section was lost during TOML merge' }
    if ($merged2 -notmatch 'c:\\\\existing\\\\project') { throw 'Existing trusted project was lost during TOML merge' }

    $merged1 = Get-Content -LiteralPath (Join-Path $l1 'config.toml') -Raw
    if ($merged1 -notmatch 'env_key = "CODEX_TEST_GW_KEY"') { throw 'Lane 1 config.toml must use env_key' }
    if ($merged1 -match 'experimental_bearer_token') { throw 'Lane 1 config.toml must NEVER contain experimental_bearer_token' }

    # Verify UTF-8 no-BOM on generated config.toml
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $l2 'config.toml'))
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw 'Generated config.toml contains a UTF-8 BOM!'
    }

    # Verify rollback snapshot manifest was generated
    $manifestPath = Join-Path $l2 '.rollback\latest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw 'Rollback snapshot manifest (.rollback\latest.json) was not created!'
    }

    Write-Host "`n=== 3. Running Deterministic SHA-256 Rollback & Recovery Test ===" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot 'scripts\restore-original.ps1') `
        -Lane1Home $l1 -Lane2Home $l2 -LocalBin $bin -SkipPathUpdate

    $restoredLane2Hash = (Get-FileHash -LiteralPath (Join-Path $l2 'config.toml') -Algorithm SHA256).Hash
    if ($restoredLane2Hash -ne $origLane2Hash) {
        throw "Rollback SHA-256 mismatch on Lane 2 config.toml! Expected $origLane2Hash, got $restoredLane2Hash"
    }
    if (Test-Path -LiteralPath (Join-Path $l2 'AGENTS.md')) {
        throw 'Newly created Lane 2 AGENTS.md should have been removed by rollback!'
    }
    if (Test-Path -LiteralPath (Join-Path $bin 'codex.cmd')) {
        throw 'Wrapper codex.cmd should have been removed by rollback!'
    }
    if (-not (Test-Path -LiteralPath $criticalSessionFile)) {
        throw 'CRITICAL: Lane 1 session file was lost during rollback!'
    }
    $afterSessionHash = (Get-FileHash -LiteralPath $criticalSessionFile -Algorithm SHA256).Hash
    if ($afterSessionHash -ne $origSessionHash) {
        throw 'CRITICAL: Lane 1 session file hash changed during rollback!'
    }

    Write-Host "[PASS] All TOML merge, default on-request policy, env_key secret isolation, UTF-8 no-BOM, and deterministic SHA-256 rollback assertions passed!" -ForegroundColor Green
} finally {
    foreach ($d in @('memories','memories_v2','sessions','archived_sessions','skills','plugins')) {
        $jp = Join-Path $l2 $d
        if (Test-Path -LiteralPath $jp) { cmd /c rmdir "$jp" 2>$null }
    }
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
