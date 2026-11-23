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

if "%~1"=="" goto :interactive
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT_DIR%\scripts\codex-manager.ps1" %*
exit /b %ERRORLEVEL%

:interactive
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT_DIR%\scripts\codex-manager.ps1"
set "RC=%ERRORLEVEL%"

REM Interactive double-click mode: drop into an interactive PowerShell terminal
REM locked into the user's selected project directory (from .recent_projects.txt)
REM with ~/.local/bin on PATH so `codex` and `codex-manage` are ready immediately!
set "LANE2_DIR=%CODEX_LANE2_HOME%"
if "%LANE2_DIR%"=="" set "LANE2_DIR=%USERPROFILE%\.codex-official"
set "LOCAL_BIN=%CODEX_LOCAL_BIN%"
if "%LOCAL_BIN%"=="" set "LOCAL_BIN=%USERPROFILE%\.local\bin"
set "PATH=%LOCAL_BIN%;%PATH%"

set "ACTIVE_PROJ="
if exist "%LANE2_DIR%\.recent_projects.txt" (
    for /f "usebackq delims=" %%P in ("%LANE2_DIR%\.recent_projects.txt") do (
        if not defined ACTIVE_PROJ if exist "%%~P\" set "ACTIVE_PROJ=%%~P"
    )
)
if not defined ACTIVE_PROJ set "ACTIVE_PROJ=%CD%"

echo.
echo ========================================================================
setlocal EnableDelayedExpansion
echo   Terminal lam viec da mo san tai du an: !ACTIVE_PROJ!
endlocal
echo   Go 'codex' de chay Sandbox 2 CLI  ^|  Go 'codex-manage' de mo lai Menu
echo ========================================================================
echo.
cd /d "%ACTIVE_PROJ%"
powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass
exit /b %RC%
