@echo off
setlocal enabledelayedexpansion

rem Anchor working directory to script location
cd /d "%~dp0"

title Real-Time Fileless Malware Detection and Analysis System
color 0A

echo ===============================================================================
echo     REAL-TIME FILELESS MALWARE DETECTION AND ANALYSIS SYSTEM
echo ===============================================================================
echo.
echo [*] Working Directory: %CD%
echo.
echo [1/5] Detecting Python Runtime:

set "PYTHON_EXEC="

rem 1. Check local virtual environments first
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXEC=%~dp0.venv\Scripts\python.exe"
    echo [*] Found Python in .venv: !PYTHON_EXEC!
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXEC=%~dp0venv\Scripts\python.exe"
    echo [*] Found Python in venv: !PYTHON_EXEC!
)

rem 2. Check system PATH python
if not defined PYTHON_EXEC (
    python -c "import sys; sys.exit(0)" >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%I in ('python -c "import sys; print(sys.executable)" 2^>nul') do (
            if not defined PYTHON_EXEC set "PYTHON_EXEC=%%I"
        )
        if defined PYTHON_EXEC (
            echo [*] Found system Python: !PYTHON_EXEC!
        ) else (
            set "PYTHON_EXEC=python"
            echo [*] Using system python in PATH
        )
    )
)

rem 3. Check py launcher
if not defined PYTHON_EXEC (
    py -3 -c "import sys; sys.exit(0)" >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%I in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
            if not defined PYTHON_EXEC set "PYTHON_EXEC=%%I"
        )
        if defined PYTHON_EXEC (
            echo [*] Found Python via py launcher: !PYTHON_EXEC!
        )
    )
)

rem 4. Check standard AppData and Program Files directories
if not defined PYTHON_EXEC (
    if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
        set "PYTHON_EXEC=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        echo [*] Found Python 3.13 at: !PYTHON_EXEC!
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PYTHON_EXEC=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        echo [*] Found Python 3.12 at: !PYTHON_EXEC!
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_EXEC=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
        echo [*] Found Python 3.11 at: !PYTHON_EXEC!
    )
)

rem 5. Fail if no valid runtime was found
if not defined PYTHON_EXEC (
    color 0C
    echo [!] ERROR: Python 3.11+ runtime was not found on this machine.
    echo [!] Please install Python 3.11 or newer from https://www.python.org/
    pause
    exit /b 1
)

set "PYTHONPATH=%CD%"

echo.
echo [2/5] Checking and Updating Python Dependencies:
echo [*] Verifying all required package versions...
"!PYTHON_EXEC!" -m pip install -r requirements.txt --quiet
if !errorlevel! neq 0 (
    echo [*] Updating dependencies to ensure version compatibility...
    "!PYTHON_EXEC!" -m pip install -r requirements.txt
    if !errorlevel! neq 0 (
        color 0C
        echo [!] ERROR: Failed to install or update dependencies.
        pause
        exit /b 1
    )
)
echo [*] All dependencies verified and up to date.

echo.
echo [3/5] Verifying Unified Benchmark Dataset and ML Artifacts:

if not exist "data\processed\unified\unified_dataset.jsonl" (
    echo [*] Building dataset from authentic sandbox runs...
    "!PYTHON_EXEC!" tools\build_unified_dataset.py
)

if not exist "models\artifacts\process\model.json" (
    echo [*] Training Process XGBoost...
    "!PYTHON_EXEC!" -m models.process.train --dataset data\processed\unified\unified_dataset.jsonl --output-dir models\artifacts\process
)

if not exist "models\artifacts\memory\model.cbm" (
    echo [*] Training Memory CatBoost...
    "!PYTHON_EXEC!" -m models.memory.train --dataset data\processed\unified\unified_dataset.jsonl --output-dir models\artifacts\memory
)

if not exist "models\artifacts\command\model.joblib" (
    if not exist "models\artifacts\command\model.safetensors" (
        echo [*] Training Command Model...
        "!PYTHON_EXEC!" -m models.command.train --dataset data\processed\unified\unified_dataset.jsonl --output-dir models\artifacts\command
    )
)

if not exist "models\artifacts\network\model.joblib" (
    echo [*] Training Network LightGBM...
    "!PYTHON_EXEC!" -m models.network.train --dataset data\processed\unified\unified_dataset.jsonl --output-dir models\artifacts\network
)

if not exist "models\multiclass\artifacts\multiclass_model.ubj" (
    echo [*] Training Multiclass XGBoost...
    "!PYTHON_EXEC!" -m models.multiclass.train_on_custom --data-path data\processed\unified\unified_dataset.jsonl --output-dir models\multiclass\artifacts
)

echo [*] All model artifacts verified successfully.

echo.
"!PYTHON_EXEC!" tools\free_port.py 8000

echo.
echo [4/5] Preparing Web Dashboard Auto-Launcher:
echo [*] The dashboard will automatically open in your default browser once the ML server is initialized.
start /b powershell -WindowStyle Hidden -NoProfile -Command "$url = 'http://127.0.0.1:8000'; for ($i=0; $i -lt 40; $i++) { Start-Sleep -Seconds 1; try { $res = Invoke-WebRequest -Uri ($url + '/health') -UseBasicParsing -TimeoutSec 1; if ($res.StatusCode -eq 200) { Start-Process $url; break } } catch { } }"

echo.
echo [5/5] Starting Real-Time FastAPI Detection Backend:
echo ===============================================================================
echo [*] Server URL: http://127.0.0.1:8000
echo [*] Interactive API Docs: http://127.0.0.1:8000/docs
echo [*] Live Host Status: http://127.0.0.1:8000/system/status
echo [*] Live Telemetry Detection: http://127.0.0.1:8000/detection
echo [*] Press CTRL+C in this terminal window to stop the server.
echo ===============================================================================
echo.

"!PYTHON_EXEC!" -m uvicorn framework.api.main:app --host 127.0.0.1 --port 8000

if !errorlevel! neq 0 (
    color 0C
    echo.
    echo [!] Server stopped with error code !errorlevel!.
    pause
)

