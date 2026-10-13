@echo off
setlocal enabledelayedexpansion

title IoT Security Assessment Platform v2.0
echo =============================================================================
echo   Starting IoT Security Assessment and Automated Response Platform...
echo =============================================================================
echo.

:: 1. Check Python installation
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set PY_CMD=python
) else (
    where py >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        set PY_CMD=py
    ) else (
        echo [ERROR] Python is not installed or not in your system PATH!
        echo Please install Python 3.9+ from https://www.python.org/downloads/
        echo Make sure to check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
)

echo [*] Using Python: %PY_CMD%

:: 2. Setup Virtual Environment
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment (.venv)...
    %PY_CMD% -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [!] Warning: Could not create virtual environment. Running with global python.
    )
)

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [*] Virtual environment activated.
)

:: 3. Install/Verify Dependencies
echo [*] Checking required dependencies...
python -m pip install -r requirements.txt --quiet --disable-pip-version-check
if %ERRORLEVEL% neq 0 (
    echo [!] Warning: Some dependencies failed to install. Attempting launch anyway...
)

:: 4. Launch Platform
echo [*] Launching IoT Risk Platform...
echo.
python run.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Platform stopped with an error code: %ERRORLEVEL%
    pause
)
