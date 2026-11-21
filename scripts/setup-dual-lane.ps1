<#
.SYNOPSIS
    Universal, hardware-adaptive one-click installer for Codex Dual-Lane & Security Kit on Windows.
.DESCRIPTION
    Works on ANY Windows 10/11 machine (single-drive C:\ or multi-drive C:\D:\E:\, any username,
    paths with spaces/Unicode/'&', WindowsApps Codex Desktop OR standalone/npm Codex CLI).

    Zero hardcoded mock data, zero hardcoded model tiers, zero hardcoded secrets:
      - Auto-detects real Codex executable (WindowsApps MSIX, PATH, npm global, or explicit -CodexPath)
      - Dynamically probes real supported feature flags via `codex features list`
      - Checks NTFS filesystem support before creating Directory Junctions
      - Checks real free disk space on the Cargo target drive and warns if low (< 10 GB)
      - Preserves existing trusted [projects.'...'] entries and creates timestamped backups before editing
      - Supports -DryRun to preview every action without modifying disk
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app" -DryRun
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app" -InstallBridgeTemplate
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-dual-lane.ps1 -RepoPath "C:\Projects\my-app" -OfficialModel "gpt-6.2-sol" -SyncSessions
.NOTES
    Author    : Lê Hoàng Ngọc Tươi
    Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
    License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
    Project   : Codex Dual-Lane & Security Kit
#>
[CmdletBinding()]
param(
    [string]$RepoPath = (Get-Location).Path,
    [string]$CodexPath = '',
    [string]$Lane1Home = (Join-Path $env:USERPROFILE '.codex'),
    [string]$Lane2Home = (Join-Path $env:USERPROFILE '.codex-official'),
    [string]$LocalBin  = (Join-Path $env:USERPROFILE '.local\bin'),
    [string]$CargoTargetDir = (Join-Path $env:TEMP 'codex-lane2-target'),
    [string]$OfficialModel = '',
    [string]$OfficialReasoning = '',
    [string]$OfficialServiceTier = '',
    [ValidateSet('never', 'on-request')]
    [string]$ApprovalPolicy = 'never',
    [switch]$AllowSandboxNetwork,
    [switch]$ConfigureGateway,
    [string]$GatewayProviderName = 'OpenAI',
    [string]$GatewayBaseUrl = '',
    [string]$GatewayModel = '',
    [string]$GatewayApiKey = '',
    [switch]$SyncSessions,
    [switch]$InstallBridgeTemplate,
    [switch]$SkipPathUpdate,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Escape-TomlBasicString([string]$Value) {
    return ($Value -replace '\\', '\\' -replace '"', '\"')
}

function Write-Utf8NoBom([string]$FilePath, [string]$Text) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($FilePath, $Text, $utf8NoBom)
}

function Backup-IfExists([string]$FilePath) {
    if (Test-Path -LiteralPath $FilePath) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backup = "$FilePath.backup-$stamp"
        if (-not $DryRun) {
            Copy-Item -LiteralPath $FilePath -Destination $backup -Force
        }
        Write-Host "    Backup saved: $backup" -ForegroundColor DarkGray
    }
}

function Resolve-CodexExecutable([string]$ExplicitPath, [string]$ExcludedDir) {
    # 1. Explicit user path
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "Specified -CodexPath does not exist: $ExplicitPath"
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
        if (Test-Path -LiteralPath $msixExe) {
            return [PSCustomObject]@{ Path = $msixExe; Source = 'WindowsApps' }
        }
    }

    # 3. Existing codex binary in PATH (strictly excluding our own ~/.local/bin wrapper and non-cmd .ps1 shims)
    $excludedNorm = $ExcludedDir.TrimEnd('\').ToLowerInvariant()
    $cmdCandidates = Get-Command codex -All -ErrorAction SilentlyContinue
    $exeMatch = $null
    $batchMatch = $null
    foreach ($cmd in $cmdCandidates) {
        if (-not $cmd.Source) { continue }
        $src = $cmd.Source
        $parent = (Split-Path -Parent $src).TrimEnd('\').ToLowerInvariant()
        if ($parent -eq $excludedNorm) { continue }
        $ext = [System.IO.Path]::GetExtension($src).ToLowerInvariant()
        # On Windows, npm creates codex.ps1 alongside codex.cmd; cmd.exe wrappers cannot execute .ps1 directly
        if ($ext -eq '.ps1' -or $ext -eq '') {
            $siblingExe = Join-Path (Split-Path -Parent $src) 'codex.exe'
            $siblingCmd = Join-Path (Split-Path -Parent $src) 'codex.cmd'
            if ((Test-Path -LiteralPath $siblingExe) -and -not $exeMatch) { $exeMatch = $siblingExe }
            elseif ((Test-Path -LiteralPath $siblingCmd) -and -not $batchMatch) { $batchMatch = $siblingCmd }
            continue
        }
        if ($ext -eq '.exe' -and (Test-Path -LiteralPath $src) -and -not $exeMatch) {
            $exeMatch = $src
        } elseif (($ext -eq '.cmd' -or $ext -eq '.bat') -and (Test-Path -LiteralPath $src) -and -not $batchMatch) {
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
        if (Test-Path -LiteralPath $fb) {
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
    $supported = @{}
    $prevHome = $env:CODEX_HOME
    $prevPref = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $env:CODEX_HOME = $ProbeHome
        $lines = & $ExePath features list 2>$null
        foreach ($line in $lines) {
            $text = [string]$line
            if ($text -match '^([a-z0-9_]+)\s+(stable|experimental|under development|deprecated)\s+') {
                $supported[$Matches[1]] = $Matches[2]
            }
        }
    } catch {
        # Older CLI builds may not have `features list`; return empty map safely
    } finally {
        $ErrorActionPreference = $prevPref
        $env:CODEX_HOME = $prevHome
    }
    return $supported
}

function Get-ExistingTrustedProjects([string[]]$ConfigPaths) {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($cfg in $ConfigPaths) {
        if (-not (Test-Path -LiteralPath $cfg)) { continue }
        $content = Get-Content -LiteralPath $cfg -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        $matches = [regex]::Matches($content, '(?m)^\[projects\.''([^'']+)''\]|^\[projects\."([^"]+)"\]')
        foreach ($m in $matches) {
            $raw = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value -replace '\\\\', '\' }
            if ($raw -and $seen.Add($raw)) {
                $list.Add($raw)
            }
        }
    }
    return , $list
}

$KitRoot  = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path

Write-Host "=== Codex Dual-Lane & Security Kit Installer ===" -ForegroundColor Green
if ($DryRun) { Write-Host "[DRY-RUN MODE] No files on disk will be modified." -ForegroundColor Yellow }

# 1. Detect real Codex executable & version
Write-Step 'Detecting real Codex installation on this machine...'
$resolvedCodex = Resolve-CodexExecutable -ExplicitPath $CodexPath -ExcludedDir $LocalBin
$CodexExe = $resolvedCodex.Path
$CodexSource = $resolvedCodex.Source
$prevVerPref = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $codexVersion = (& $CodexExe --version 2>&1 | Where-Object { $_ -notmatch '^WARNING:' } | Select-Object -First 1)
} finally {
    $ErrorActionPreference = $prevVerPref
}
Write-Host "    Source  : $CodexSource"
Write-Host "    Binary  : $CodexExe"
Write-Host "    Version : $codexVersion"

# 2. Check NTFS & free disk space on user home and Cargo target drives
Write-Step 'Checking filesystem compatibility (NTFS) and free disk space...'
$homeDrive = ([System.IO.Path]::GetPathRoot($Lane2Home)).TrimEnd(':\')
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
try { $targetVol = Get-Volume -DriveLetter $targetDrive -ErrorAction SilentlyContinue } catch { $targetVol = $null }
if ($targetVol) {
    $freeGB = [math]::Round($targetVol.SizeRemaining / 1GB, 2)
    Write-Host ("    Build drive {0}: Free={1} GB (CARGO_TARGET_DIR={2})" -f $targetDrive, $freeGB, $CargoTargetDir)
    if ($freeGB -lt 10) {
        Write-Warning "Drive ${targetDrive}: has less than 10 GB free ($freeGB GB). For large Rust projects, pass -CargoTargetDir on a drive with more space."
    }
}

# 3. Dynamically probe supported Codex feature flags
Write-Step 'Probing supported Codex feature flags from your installed binary...'
$probeDir = Join-Path $env:TEMP ('codex-feature-probe-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
try {
    $supportedFeatures = Get-SupportedCodexFeatures -ExePath $CodexExe -ProbeHome $probeDir
} finally {
    Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ("    Detected {0} feature flags (daemon_auto_start={1}, goals={2}, memories={3})" -f `
    $supportedFeatures.Count, `
    $supportedFeatures.ContainsKey('daemon_auto_start'), `
    $supportedFeatures.ContainsKey('goals'), `
    $supportedFeatures.ContainsKey('memories'))

# 4. Prepare directories
Write-Step "Preparing directories: $Lane1Home, $Lane2Home, $LocalBin..."
foreach ($dir in @($Lane1Home, (Join-Path $Lane1Home 'rules'), $Lane2Home, (Join-Path $Lane2Home 'rules'), $LocalBin)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        if (-not $DryRun) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Write-Host "    Create dir: $dir"
    }
}

# 5. Create NTFS Directory Junctions for shared memories, sessions, skills, plugins
Write-Step 'Linking shared memories, sessions, skills, and plugins via NTFS Junctions...'
$sharedDirs = @('memories', 'memories_v2', 'sessions', 'archived_sessions', 'skills', 'plugins')
foreach ($name in $sharedDirs) {
    $src = Join-Path $Lane1Home $name
    $dst = Join-Path $Lane2Home $name
    if (-not (Test-Path -LiteralPath $src)) {
        if (-not $DryRun) { New-Item -ItemType Directory -Path $src -Force | Out-Null }
    }
    if (Test-Path -LiteralPath $dst) {
        $item = Get-Item -LiteralPath $dst -Force
        if ($item.LinkType -eq 'Junction') {
            Write-Host "    Already linked: $name -> $($item.Target)"
            continue
        }
        $dirBackup = "$dst.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        if (-not $DryRun) { Move-Item -LiteralPath $dst -Destination $dirBackup -Force }
        Write-Host "    Moved existing directory safely to: $dirBackup" -ForegroundColor DarkGray
    }
    if (-not $DryRun) { New-Item -ItemType Junction -Path $dst -Target $src | Out-Null }
    Write-Host "    Linked: $dst -> $src"
}

# 6. Install Starlark command firewall (rules/default.rules) into both lanes
Write-Step 'Installing Starlark command firewall (rules/default.rules) into both lanes...'
$rulesTemplate = Join-Path $KitRoot 'templates\default.rules'
foreach ($homeDir in @($Lane1Home, $Lane2Home)) {
    $targetRule = Join-Path $homeDir 'rules\default.rules'
    Backup-IfExists $targetRule
    if (-not $DryRun) { Copy-Item -LiteralPath $rulesTemplate -Destination $targetRule -Force }
    Write-Host "    Installed: $targetRule"
}

# 7. Install lane-specific global AGENTS.md guardrails
Write-Step 'Installing anti-prompt-injection & dual-lane AGENTS.md guardrails...'
$lane1AgentsDst = Join-Path $Lane1Home 'AGENTS.md'
$lane2AgentsDst = Join-Path $Lane2Home 'AGENTS.md'
Backup-IfExists $lane1AgentsDst
Backup-IfExists $lane2AgentsDst
if (-not $DryRun) {
    Copy-Item -LiteralPath (Join-Path $KitRoot 'templates\AGENTS.lane1.md') -Destination $lane1AgentsDst -Force
    Copy-Item -LiteralPath (Join-Path $KitRoot 'templates\AGENTS.lane2.md') -Destination $lane2AgentsDst -Force
}
Write-Host "    Installed: $lane1AgentsDst"
Write-Host "    Installed: $lane2AgentsDst"

# 8. Build & write Lane 2 Official OpenAI config.toml (preserving existing trusted projects!)
Write-Step 'Writing Lane 2 Official OpenAI config.toml...'
$lane2ConfigPath = Join-Path $Lane2Home 'config.toml'
$trustedProjects = Get-ExistingTrustedProjects -ConfigPaths @((Join-Path $Lane1Home 'config.toml'), $lane2ConfigPath)
$normRepo = $RepoPath.ToLowerInvariant()
if (-not ($trustedProjects | Where-Object { $_.ToLowerInvariant() -eq $normRepo })) {
    $trustedProjects.Add($normRepo)
}

$optionalModelLines = New-Object 'System.Collections.Generic.List[string]'
if ($OfficialModel)       { $optionalModelLines.Add("model = `"$(Escape-TomlBasicString $OfficialModel)`"") }
if ($OfficialReasoning)   { $optionalModelLines.Add("model_reasoning_effort = `"$(Escape-TomlBasicString $OfficialReasoning)`"") }
if ($OfficialServiceTier) { $optionalModelLines.Add("service_tier = `"$(Escape-TomlBasicString $OfficialServiceTier)`"") }

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
    "[projects.`"$(Escape-TomlBasicString $_)`"]`ntrust_level = `"trusted`""
}) -join "`n`n"

$sandboxNetworkValue = if ($AllowSandboxNetwork) { 'true' } else { 'false' }

$lane2Config = @"
# Official OpenAI / ChatGPT Codex CLI configuration (LANE 2)
# Leave model/service_tier unset unless overridden so Codex uses your account's real defaults.
sandbox_mode = "workspace-write"
approval_policy = "$ApprovalPolicy"
windows_wsl_setup_acknowledged = true
$($optionalModelLines -join "`n")

[windows]
sandbox = "elevated"

$projectsBlock

[features]
$($featureLines -join "`n")

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

Backup-IfExists $lane2ConfigPath
if (-not $DryRun) { Write-Utf8NoBom -FilePath $lane2ConfigPath -Text $lane2Config }
Write-Host "    Wrote: $lane2ConfigPath (preserved $($trustedProjects.Count) trusted project(s))"

# 9. Optional: configure Lane 1 third-party gateway ONLY if explicitly requested
if ($ConfigureGateway) {
    if (-not $GatewayBaseUrl -or -not $GatewayApiKey) {
        throw '-ConfigureGateway requires both -GatewayBaseUrl and -GatewayApiKey.'
    }
    Write-Step 'Configuring Lane 1 third-party gateway in ~/.codex/config.toml...'
    $lane1ConfigPath = Join-Path $Lane1Home 'config.toml'
    $lane1CleanBackup = Join-Path $Lane1Home 'config.backup.toml'
    if ((Test-Path -LiteralPath $lane1ConfigPath) -and -not (Test-Path -LiteralPath $lane1CleanBackup)) {
        if (-not $DryRun) { Copy-Item -LiteralPath $lane1ConfigPath -Destination $lane1CleanBackup -Force }
        Write-Host "    Saved clean original backup: $lane1CleanBackup"
    }
    Backup-IfExists $lane1ConfigPath

    $modelsUrl = $GatewayBaseUrl.TrimEnd('/') + '/models'
    $gwModelLines = if ($GatewayModel) {
        "model = `"$(Escape-TomlBasicString $GatewayModel)`"`nreview_model = `"$(Escape-TomlBasicString $GatewayModel)`""
    } else { '' }

    $gwFeatureLines = New-Object 'System.Collections.Generic.List[string]'
    if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('memories')) { $gwFeatureLines.Add('memories = true') }
    if ($supportedFeatures.Count -eq 0 -or $supportedFeatures.ContainsKey('js_repl')) { $gwFeatureLines.Add('js_repl = false') }
    if ($supportedFeatures.ContainsKey('api_key_model_discovery')) { $gwFeatureLines.Add('api_key_model_discovery = true') }
    if ($supportedFeatures.ContainsKey('image_generation')) { $gwFeatureLines.Add('image_generation = true') }
    if ($supportedFeatures.ContainsKey('goals')) { $gwFeatureLines.Add('goals = true') }

    $lane1Config = @"
# Lane 1 Codex configuration (Third-Party Gateway + Security Guardrails)
model_provider = "$(Escape-TomlBasicString $GatewayProviderName)"
$gwModelLines
web_search = "live"
disable_response_storage = true
network_access = "enabled"
sandbox_mode = "workspace-write"
approval_policy = "$ApprovalPolicy"
windows_wsl_setup_acknowledged = true

[model_providers."$(Escape-TomlBasicString $GatewayProviderName)"]
name = "$(Escape-TomlBasicString $GatewayProviderName)"
base_url = "$(Escape-TomlBasicString $GatewayBaseUrl)"
model_catalog_url = "$(Escape-TomlBasicString $modelsUrl)"
wire_api = "responses"
requires_openai_auth = false
experimental_bearer_token = "$(Escape-TomlBasicString $GatewayApiKey)"

[windows]
sandbox = "elevated"

$projectsBlock

[features]
$($gwFeatureLines -join "`n")

[sandbox_workspace_write]
network_access = $sandboxNetworkValue

[shell_environment_policy]
exclude = ["*KEY*", "*SECRET*", "*TOKEN*", "*PASSWORD*", "*CREDENTIAL*"]

[shell_environment_policy.set]
CODEX_ACTIVE_LANE = "LANE_1"
"@
    if (-not $DryRun) { Write-Utf8NoBom -FilePath $lane1ConfigPath -Text $lane1Config }
    Write-Host "    Wrote: $lane1ConfigPath"
}

# 10. Install self-healing CLI wrappers into ~/.local/bin
Write-Step 'Installing codex.cmd, codex-official.cmd, and codex-t3.cmd into ~/.local/bin...'
$isBatchTarget = $CodexExe.ToLowerInvariant().EndsWith('.cmd') -or $CodexExe.ToLowerInvariant().EndsWith('.bat')
$invokePrefix  = if ($isBatchTarget) { 'call ' } else { '' }
$windowsAppsRefresh = if ($CodexSource -eq 'WindowsApps') {
@"
if not exist "%CODEX_EXE%" (
    for /f "usebackq delims=" %%I in (``powershell -NoProfile -Command "(Get-AppxPackage OpenAI.Codex | Select-Object -First 1).InstallLocation"``) do (
        set "CODEX_EXE=%%I\app\resources\codex.exe"
    )
)
"@
} else { '' }

$needsUtf8Codepage = ($Lane1Home -match '[^\x00-\x7F]') -or ($Lane2Home -match '[^\x00-\x7F]') -or ($CargoTargetDir -match '[^\x00-\x7F]') -or ($CodexExe -match '[^\x00-\x7F]')
$utf8Header = if ($needsUtf8Codepage) { "chcp 65001 >nul`r`n" } else { '' }

$officialWrapper = @"
@echo off
setlocal
${utf8Header}set "CODEX_HOME=$Lane2Home"
set "CODEX_ACTIVE_LANE=LANE_2"
set "CARGO_TARGET_DIR=$CargoTargetDir"
set "CODEX_EXE=$CodexExe"
$windowsAppsRefresh
${invokePrefix}"%CODEX_EXE%" %*
exit /b %ERRORLEVEL%
"@

$t3Wrapper = @"
@echo off
setlocal
${utf8Header}set "CODEX_HOME=$Lane1Home"
set "CODEX_ACTIVE_LANE=LANE_1"
set "CODEX_EXE=$CodexExe"
$windowsAppsRefresh
${invokePrefix}"%CODEX_EXE%" %*
exit /b %ERRORLEVEL%
"@

if (-not $DryRun) {
    Write-Utf8NoBom -FilePath (Join-Path $LocalBin 'codex.cmd') -Text $officialWrapper
    Write-Utf8NoBom -FilePath (Join-Path $LocalBin 'codex-official.cmd') -Text $officialWrapper
    Write-Utf8NoBom -FilePath (Join-Path $LocalBin 'codex-t3.cmd') -Text $t3Wrapper
}
Write-Host "    Installed wrappers in: $LocalBin"

# Prepend ~/.local/bin to User PATH so our wrappers take precedence over npm/global codex shims
if (-not $SkipPathUpdate) {
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $pathEntries = @()
    if ($userPath) {
        $pathEntries = $userPath -split ';' | Where-Object { $_ -and $_.Trim() -ne '' }
    }
    $normLocalBin = $LocalBin.TrimEnd('\').ToLowerInvariant()
    $firstIsLocalBin = ($pathEntries.Count -gt 0) -and ($pathEntries[0].TrimEnd('\').ToLowerInvariant() -eq $normLocalBin)
    if (-not $firstIsLocalBin) {
        $filtered = @($pathEntries | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -ne $normLocalBin })
        $newPath = (@($LocalBin) + $filtered) -join ';'
        if (-not $DryRun) {
            [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        }
        Write-Host "    Prepended $LocalBin to User PATH (highest priority). Open a new terminal window to pick up PATH changes." -ForegroundColor Yellow
    }
} else {
    Write-Host "    Skipped User PATH modification (-SkipPathUpdate)." -ForegroundColor DarkGray
}

# 11. Optional: copy DUAL_LANE_BRIDGE.md into target repository
if ($InstallBridgeTemplate) {
    $bridgeDir = Join-Path $RepoPath 'artifacts\dual-lane'
    $bridgeDst = Join-Path $bridgeDir 'DUAL_LANE_BRIDGE.md'
    Write-Step "Ensuring bridge template at $bridgeDst..."
    if (-not (Test-Path -LiteralPath $bridgeDst)) {
        if (-not $DryRun) {
            if (-not (Test-Path -LiteralPath $bridgeDir)) { New-Item -ItemType Directory -Path $bridgeDir -Force | Out-Null }
            Copy-Item -LiteralPath (Join-Path $KitRoot 'templates\DUAL_LANE_BRIDGE.md') -Destination $bridgeDst
        }
        Write-Host "    Created: $bridgeDst"
    } else {
        Write-Host "    Kept existing: $bridgeDst"
    }
}

# 12. Optional: sync session metadata & pinned threads
if ($SyncSessions) {
    Write-Step 'Syncing session index, pinned threads, and goals via sync-sessions.py...'
    $pythonExe = $null
    foreach ($cand in @('python', 'python3')) {
        foreach ($cmd in (Get-Command $cand -All -ErrorAction SilentlyContinue)) {
            if (-not $cmd.Source -or ($cmd.Source -like '*\WindowsApps\*')) { continue }
            $prevPyPref = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $v = (& $cmd.Source --version 2>&1 | Select-Object -First 1)
            } finally {
                $ErrorActionPreference = $prevPyPref
            }
            if ($v -match '^Python 3\.') { $pythonExe = $cmd.Source; break }
        }
        if ($pythonExe) { break }
    }
    if (-not $pythonExe) {
        Write-Warning 'Real Python 3 was not found in PATH (ignoring Microsoft Store stub); skipping SQLite session sync.'
    } else {
        $pyArgs = @((Join-Path $KitRoot 'scripts\sync-sessions.py'), '--lane1', $Lane1Home, '--lane2', $Lane2Home, '--repo', $RepoPath, '--approval-mode', $ApprovalPolicy)
        if ($DryRun) { $pyArgs += '--dry-run' }
        & $pythonExe @pyArgs
    }
}

if (-not $DryRun) {
    Write-Step 'Running post-install verification...'
    & (Join-Path $LocalBin 'codex.cmd') --version
}

Write-Host "`n[OK] Setup completed!" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Run health check anytime:   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\doctor.ps1"
Write-Host "  2. Sign in to Lane 2 (once):   codex login"
Write-Host "  3. Start Lane 2 Official CLI:  codex"
Write-Host "  4. Start Lane 1 (Desktop/T3):  codex-t3 (or open Codex Desktop App)"
