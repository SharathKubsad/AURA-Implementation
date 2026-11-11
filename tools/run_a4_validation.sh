#!/usr/bin/env bash
# ==============================================================================
# One-Click A4 Real-Evidence Validation Workflow for Kali Linux
# ==============================================================================
# Automatically locates ~/fmd-results/custom/RUN-001/ and executes the full
# semantic validation suite against authentic Volatility 3 output files.
#
# Supports:
# - Double-click from Kali File Manager (Thunar/XFCE)
# - Direct command line execution: ./tools/run_a4_validation.sh [optional_dir]
# ==============================================================================
set -euo pipefail

# 1. Double-click GUI terminal wrapper:
# If stdout is not connected to a terminal and an X display is available,
# launch inside a terminal window so the operator sees the real-time output.
if [ ! -t 1 ] && [ -n "${DISPLAY:-}" ]; then
    if command -v xfce4-terminal >/dev/null 2>&1; then
        exec xfce4-terminal --title="A4 Real-Evidence Validation" --hold -e "$0"
    elif command -v x-terminal-emulator >/dev/null 2>&1; then
        exec x-terminal-emulator -e "$0"
    elif command -v gnome-terminal >/dev/null 2>&1; then
        exec gnome-terminal -- "$0"
    elif command -v xterm >/dev/null 2>&1; then
        exec xterm -hold -e "$0"
    fi
fi

# 2. Resolve repository directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# 3. Environment and Python interpreter detection
if [ -f "$REPO_DIR/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$REPO_DIR/.venv/bin/activate"
elif [ -f "$HOME/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.venv/bin/activate"
fi

PYTHON_BIN="python3"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "[-] Error: Python 3 was not found in PATH or virtual environment."
    echo ""
    read -r -p "Press [Enter] to exit..." || true
    exit 1
fi

# 4. Locate RUN-001 evidence directory
TARGET_DIR="${1:-}"
if [ -z "$TARGET_DIR" ]; then
    if [ -d "$HOME/fmd-results/custom/RUN-001" ]; then
        TARGET_DIR="$HOME/fmd-results/custom/RUN-001"
    elif [ -d "$REPO_DIR/data/raw/custom/RUN-001" ]; then
        TARGET_DIR="$REPO_DIR/data/raw/custom/RUN-001"
    elif [ -d "$REPO_DIR/tests/fixtures/volatility/RUN-001" ]; then
        TARGET_DIR="$REPO_DIR/tests/fixtures/volatility/RUN-001"
    else
        TARGET_DIR="$HOME/fmd-results/custom/RUN-001"
    fi
fi

echo "============================================================"
echo " Starting A4 Real-Evidence Validation"
echo " Target Evidence: $TARGET_DIR"
echo " Repository Root: $REPO_DIR"
echo " Python Binary:   $("$PYTHON_BIN" -c "import sys; print(sys.executable)")"
echo "============================================================"

export PYTHONPATH="$REPO_DIR${PYTHONPATH:+:$PYTHONPATH}"

EXIT_CODE=0
"$PYTHON_BIN" "$SCRIPT_DIR/validate_a4_evidence.py" "$TARGET_DIR" --sample-id "RUN-001" || EXIT_CODE=$?

echo ""
read -r -p "Validation complete. Press [Enter] to exit..." || true
exit $EXIT_CODE
