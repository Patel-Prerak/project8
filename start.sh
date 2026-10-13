#!/usr/bin/env bash
# ==============================================================================
# IoT Security Assessment Platform - Linux / macOS Launcher
# ==============================================================================

set -e

echo "============================================================================="
echo "  Starting IoT Security Assessment and Automated Response Platform..."
echo "============================================================================="

# 1. Locate Python 3
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "[ERROR] Python 3 is not installed or not in PATH!"
    echo "Please install Python 3.9+ using your package manager (e.g. apt, dnf, brew)."
    exit 1
fi

echo "[*] Using Python: $($PY_CMD --version)"

# 2. Setup Virtual Environment
if [ ! -f ".venv/bin/activate" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    $PY_CMD -m venv .venv || {
        echo "[!] Warning: python3-venv might be missing. Try: sudo apt install python3-venv"
        echo "[!] Proceeding with system python..."
    }
fi

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "[*] Virtual environment activated."
fi

# 3. Install/Verify Dependencies
echo "[*] Checking dependencies from requirements.txt..."
python -m pip install -r requirements.txt --quiet --disable-pip-version-check || {
    echo "[!] Warning: Some dependencies failed to install cleanly."
}

# 4. Launch Application
echo "[*] Launching IoT Risk Platform..."
python run.py "$@"
