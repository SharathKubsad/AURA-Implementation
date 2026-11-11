@echo off
setlocal enabledelayedexpansion
rem ==============================================================================
rem One-Click Launcher for Windows Evidence Collection
rem Project: Real-Time Fileless Malware Detection
rem ==============================================================================
title FMD Custom Evidence Collector (Windows)

rem 1. Detect Python launcher (prefer py -3 over python to bypass Windows Store alias)
set "PYTHON_CMD="

py -3 -c "import sys; sys.exit(0)" >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_CMD=py -3"
    goto :python_detected
)

py -c "import sys; sys.exit(0)" >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_CMD=py"
    goto :python_detected
)

python -c "import sys; sys.exit(0)" >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_CMD=python"
    goto :python_detected
)

rem Search standard installation directories if launcher not on PATH
for /d %%D in ("%LocalAppData%\Programs\Python\Python3*" "C:\Program Files\Python3*" "C:\Python3*") do (
    if exist "%%D\python.exe" (
        set "PYTHON_CMD=%%D\python.exe"
        goto :python_detected
    )
)

:python_detected
if defined PYTHON_CMD (
    echo [+] Detected Python interpreter: !PYTHON_CMD!
    set "PYTHON_LAUNCHER=!PYTHON_CMD!"
) else (
    echo [*] Note: No working Python command detected. Running PowerShell collector directly.
)

rem If invoked with --test-launcher, print detection and exit cleanly without starting collection
if "%~1"=="--test-launcher" (
    echo [TEST] Launcher test successful: PYTHON_CMD=!PYTHON_CMD!
    exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect_run_windows.ps1" -PythonCmd "!PYTHON_CMD!" %*

echo.
echo ==============================================================================
pause
