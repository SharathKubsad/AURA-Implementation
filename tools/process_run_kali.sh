#!/usr/bin/env bash
# ==============================================================================
# A6: Kali Processing Controller
# Project: Real-Time Fileless Malware Detection
# Usage:
#   ./tools/process_run_kali.sh RUN-XXX
#   ./tools/process_run_kali.sh /path/to/RUN-XXX
#   Double-click in GUI file manager (opens terminal automatically)
# ==============================================================================
set -euo pipefail

# 1. GUI double-click detection: If not attached to a terminal, re-launch in terminal emulator
if [ ! -t 1 ] && [ -n "${DISPLAY:-}" ]; then
    for term in xfce4-terminal x-terminal-emulator konsole gnome-terminal xterm; do
        if command -v "$term" >/dev/null 2>&1; then
            if [ "$term" = "xfce4-terminal" ]; then
                exec "$term" --hold -T "FMD Processing Controller" -e "$0 $*"
            elif [ "$term" = "gnome-terminal" ]; then
                exec "$term" -- bash -c "$0 $*; echo; read -p 'Press enter to exit...'"
            else
                exec "$term" -e bash -c "$0 $*; echo; read -p 'Press enter to exit...'"
            fi
        fi
    done
fi

# Resolve script directory and repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================================================"
echo "          FMD A6: KALI EXPERIMENT PROCESSING CONTROLLER                 "
echo "========================================================================"

# Find Python 3
PYTHON_BIN=""
for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
        PYTHON_BIN="$py"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[-] Error: Python 3 not found on system PATH."
    exit 1
fi

TARGET_RUN="${1:-}"

# If no target specified, prompt interactively or list candidate directories
if [ -z "$TARGET_RUN" ]; then
    echo "[*] No RUN specified. Searching for incoming RUN directories..."
    echo ""
    CANDIDATES=()
    
    # Check common incoming directories
    SEARCH_PATHS=(
        "$HOME/fmd-results/custom"
        "$REPO_ROOT/data/raw/custom"
        "$PWD"
    )
    
    for spath in "${SEARCH_PATHS[@]}"; do
        if [ -d "$spath" ]; then
            while IFS= read -r -d '' d; do
                bname="$(basename "$d")"
                if [[ "$bname" =~ ^RUN-[0-9]+$ ]]; then
                    CANDIDATES+=("$d")
                fi
            done < <(find "$spath" -mindepth 1 -maxdepth 2 -type d -print0 2>/dev/null)
        fi
    done
    
    if [ ${#CANDIDATES[@]} -gt 0 ]; then
        echo "Found candidate RUN directories:"
        for i in "${!CANDIDATES[@]}"; do
            echo "  [$((i + 1))] ${CANDIDATES[$i]}"
        done
        echo ""
        read -r -p "Select number or enter RUN ID (e.g. RUN-002): " USER_INPUT
        if [[ "$USER_INPUT" =~ ^[0-9]+$ ]] && [ "$USER_INPUT" -ge 1 ] && [ "$USER_INPUT" -le ${#CANDIDATES[@]} ]; then
            TARGET_RUN="${CANDIDATES[$((USER_INPUT - 1))]}"
        else
            TARGET_RUN="$USER_INPUT"
        fi
    else
        read -r -p "Enter RUN ID (e.g. RUN-002) or directory path: " TARGET_RUN
    fi
fi

if [ -z "$TARGET_RUN" ]; then
    echo "[-] Error: No RUN target specified."
    exit 1
fi

echo "[+] Target RUN: $TARGET_RUN"
echo "[*] Launching processing engine..."
echo ""

# Execute python processing controller
"$PYTHON_BIN" "$SCRIPT_DIR/process_run_kali.py" "$TARGET_RUN"

echo ""
echo "[+] Processing script finished."
