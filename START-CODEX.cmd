@echo off
setlocal
REM ============================================================================
REM START-CODEX.cmd -- 1-Click / 1-Touch Launcher for Codex Dual-Lane Control Center
REM Author    : Le Hoang Ngoc Tuoi
REM Copyright : Copyright 2026 Le Hoang Ngoc Tuoi
REM License   : Apache-2.0
REM ============================================================================
set "KIT_DIR=%~dp0"
if "%KIT_DIR:~-1%"=="\" set "KIT_DIR=%KIT_DIR:~0,-1%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT_DIR%\scripts\codex-manager.ps1" %*
set "RC=%ERRORLEVEL%"
exit /b %RC%
