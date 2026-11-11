#!/usr/bin/env bash
# ============================================================
# FMD - GENERIC CUSTOM BATCH PROCESSOR
#
# Use for each malware family/category.
#
# Usage:
#   ./tools/process_custom_batch.sh <category> <input_dir> <output_dir>
#
# Example:
#   ./tools/process_custom_batch.sh \
#     powershell_fileless \
#     /home/fmd/fmd-results/custom/powershell_fileless \
#     data/processed/custom_powershell_fileless
#
# This is based directly on the known-good benign batch workflow:
#   memory.raw
#      -> Volatility 3
#      -> A4 Process + Memory extraction
#      -> JSON validation
#      -> Windows-ready package
#
# Raw evidence is NEVER deleted.
# Command/Network evidence is preserved for Track B.
# This script does NOT fabricate Command/Network features.
# ============================================================

set -u
set -o pipefail

REPO="$HOME/Real-Time-Fileless-Malware-Detection"

CATEGORY="${1:-}"
EVIDENCE_ROOT="${2:-}"
PACKAGE="${3:-}"

if [[ -z "$CATEGORY" || -z "$EVIDENCE_ROOT" || -z "$PACKAGE" ]]; then
    echo
    echo "Usage:"
    echo "  $0 <category> <input_dir> <output_dir>"
    echo
    echo "Example:"
    echo "  $0 powershell_fileless \\"
    echo "    /home/fmd/fmd-results/custom/powershell_fileless \\"
    echo "    data/processed/custom_powershell_fileless"
    echo
    exit 1
fi

# Resolve paths.
if [[ "$PACKAGE" = /* ]]; then
    PACKAGE="$(realpath -m "$PACKAGE")"
else
    PACKAGE="$(realpath -m "$REPO/$PACKAGE")"
fi

EVIDENCE_ROOT="$(realpath "$EVIDENCE_ROOT")"

VOLATILITY="$HOME/volatility3-2.28.0/vol.py"
SYMBOLS="$HOME/volatility3-2.28.0/symbols"

# Keep each category's intermediate files separate so runs from
# different families cannot overwrite one another.
INTERIM="$REPO/data/interim/custom_$CATEGORY"

VOL_OUT="$INTERIM/volatility"
PROCESS_OUT="$INTERIM/process"
MEMORY_OUT="$INTERIM/memory"

PACKAGE_VOL="$PACKAGE/volatility"
PACKAGE_PROCESS="$PACKAGE/process"
PACKAGE_MEMORY="$PACKAGE/memory"
PACKAGE_METADATA="$PACKAGE/metadata"
PACKAGE_SOURCE="$PACKAGE/source_evidence"

SUMMARY="$PACKAGE/batch_summary.csv"
MANIFEST="$PACKAGE/manifest.json"
CHECKSUMS="$PACKAGE/checksums.sha256"

ARCHIVE="${PACKAGE}.tar.gz"

# ------------------------------------------------------------
# Required Volatility plugins: EXACT same set as benign batch.
# ------------------------------------------------------------

PLUGINS=(
    "windows.pslist"
    "windows.psscan"
    "windows.psxview"
    "windows.pstree"
    "windows.threads"
    "windows.handles"
    "windows.dlllist"
    "windows.malfind"
    "windows.privileges"
    "windows.ldrmodules"
    "windows.vadinfo"
)

# ------------------------------------------------------------
# Prepare directories.
# ------------------------------------------------------------

mkdir -p \
    "$VOL_OUT" \
    "$PROCESS_OUT" \
    "$MEMORY_OUT" \
    "$PACKAGE_VOL" \
    "$PACKAGE_PROCESS" \
    "$PACKAGE_MEMORY" \
    "$PACKAGE_METADATA" \
    "$PACKAGE_SOURCE"

cd "$REPO" || exit 1

echo
echo "============================================================"
echo " FMD GENERIC CUSTOM BATCH PROCESSOR"
echo "============================================================"
echo
echo "Category:"
echo "  $CATEGORY"
echo
echo "Evidence:"
echo "  $EVIDENCE_ROOT"
echo
echo "Repository:"
echo "  $REPO"
echo
echo "Volatility:"
echo "  $VOLATILITY"
echo
echo "Symbols:"
echo "  $SYMBOLS"
echo
echo "Package:"
echo "  $PACKAGE"
echo
echo "============================================================"

# ------------------------------------------------------------
# Checks.
# ------------------------------------------------------------

if [[ ! -f "$VOLATILITY" ]]; then
    echo "[FATAL] Volatility 3 was not found:"
    echo "        $VOLATILITY"
    exit 1
fi

if [[ ! -d "$SYMBOLS" ]]; then
    echo "[FATAL] Volatility symbols were not found:"
    echo "        $SYMBOLS"
    exit 1
fi

if [[ ! -d "$EVIDENCE_ROOT" ]]; then
    echo "[FATAL] Evidence directory was not found:"
    echo "        $EVIDENCE_ROOT"
    exit 1
fi

# ------------------------------------------------------------
# Discover RUN-* directories dynamically.
# ------------------------------------------------------------

mapfile -t RUNS < <(
    find "$EVIDENCE_ROOT" \
        -mindepth 1 \
        -maxdepth 1 \
        -type d \
        -name 'RUN-*' \
        -printf '%f\n' |
    sort -V
)

if [[ "${#RUNS[@]}" -eq 0 ]]; then
    echo "[FATAL] No RUN-* directories found in:"
    echo "        $EVIDENCE_ROOT"
    exit 1
fi

echo
echo "Runs discovered:"
printf '  %s\n' "${RUNS[@]}"
echo

# ------------------------------------------------------------
# Summary.
# ------------------------------------------------------------

echo "sample_id,memory_exists,memory_size_bytes,volatility_status,extraction_status,validation_status,notes" \
    > "$SUMMARY"

# ------------------------------------------------------------
# Initial manifest.
# ------------------------------------------------------------

python3 - "$MANIFEST" "$CATEGORY" <<'PY'
import json
import sys
from datetime import datetime, timezone

manifest_path = sys.argv[1]
category = sys.argv[2]

manifest = {
    "dataset": f"custom_{category}",
    "label": 1,
    "family": category,
    "source_type": "controlled_windows_vm",
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "runs": [],
    "pipeline": {
        "volatility": True,
        "process_features": True,
        "memory_features": True,
        "command_features": False,
        "network_features": False
    },
    "notes": [
        "Process and Memory features generated using the existing A4 pipeline.",
        "Command and Network source evidence preserved for Track-B processing.",
        "Raw memory dumps are not included in the Windows-ready package.",
        "No unsupported feature values are fabricated."
    ]
}

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
PY

# ------------------------------------------------------------
# Run one Volatility plugin.
# Same behavior as the known-good benign processor.
# ------------------------------------------------------------

run_plugin() {
    local run="$1"
    local raw="$2"
    local plugin="$3"

    local plugin_name="${plugin#windows.}"
    local output_dir="$VOL_OUT/$run"
    local output_file="$output_dir/${plugin_name}.txt"
    local stderr_file="$output_dir/${plugin_name}.stderr.log"

    echo
    echo "------------------------------------------------------------"
    echo "[$run] Running $plugin"
    echo "------------------------------------------------------------"

    rm -f "$output_file" "$stderr_file"

    python3 "$VOLATILITY" \
        -s "$SYMBOLS" \
        -f "$raw" \
        "$plugin" \
        > "$output_file" \
        2> "$stderr_file"

    local rc=$?

    if [[ -s "$output_file" && $rc -eq 0 ]]; then
        echo "[OK] $plugin"
        return 0
    fi

    # Preserve usable output for the known harmless cleanup error.
    if [[ -s "$output_file" && $rc -ne 0 ]]; then
        if grep -qiE \
            "MagicDetect|cleanup|Uncleanable|exception during cleanup" \
            "$stderr_file"
        then
            echo "[WARN] $plugin produced output."
            echo "       Volatility returned rc=$rc."
            echo "       Cleanup-related stderr detected; output retained."
            return 0
        fi
    fi

    echo "[FAIL] $plugin"
    echo
    echo "---- STDERR ----"
    if [[ -s "$stderr_file" ]]; then
        tail -30 "$stderr_file"
    else
        echo "(no stderr output)"
    fi
    echo "----------------"
    echo

    return 1
}

# ------------------------------------------------------------
# Process one run.
# ------------------------------------------------------------

process_run() {
    local run="$1"

    local run_dir="$EVIDENCE_ROOT/$run"
    local raw="$run_dir/memory.raw"

    local output_dir="$VOL_OUT/$run"

    local volatility_status="PASS"
    local extraction_status="NOT_RUN"
    local validation_status="NOT_RUN"
    local notes=""

    echo
    echo
    echo "============================================================"
    echo " PROCESSING $run"
    echo "============================================================"

    if [[ ! -d "$run_dir" ]]; then
        echo "[FAIL] Run directory does not exist:"
        echo "       $run_dir"

        echo "$run,NO,0,FAIL,NOT_RUN,FAIL,run_directory_missing" \
            >> "$SUMMARY"

        return 1
    fi

    if [[ ! -f "$raw" ]]; then
        echo "[FAIL] memory.raw does not exist:"
        echo "       $raw"

        echo "$run,NO,0,FAIL,NOT_RUN,FAIL,memory_raw_missing" \
            >> "$SUMMARY"

        return 1
    fi

    local memory_size
    memory_size=$(stat -c '%s' "$raw")

    echo
    echo "[+] Memory dump:"
    echo "    $raw"
    echo
    echo "[+] Size:"
    echo "    $memory_size bytes"
    echo

    mkdir -p "$output_dir"

    # --------------------------------------------------------
    # Run all Volatility plugins.
    # --------------------------------------------------------

    for plugin in "${PLUGINS[@]}"; do
        if ! run_plugin "$run" "$raw" "$plugin"; then
            volatility_status="FAIL"
            notes="${notes}${plugin}_failed;"
        fi
    done

    if [[ "$volatility_status" != "PASS" ]]; then
        echo
        echo "[FAIL] Volatility stage failed for $run"
        echo
        echo "Raw evidence has NOT been touched."
        echo

        echo "$run,YES,$memory_size,FAIL,NOT_RUN,FAIL,$notes" \
            >> "$SUMMARY"

        return 1
    fi

    echo
    echo "[PASS] All Volatility outputs generated for $run"

    echo
    echo "Generated Volatility files:"
    ls -lh "$output_dir"/*.txt 2>/dev/null || true

    # --------------------------------------------------------
    # EXACT A4 invocation used by the successful benign batch.
    # --------------------------------------------------------

    echo
    echo "------------------------------------------------------------"
    echo "[$run] Running A4 Process + Memory extraction"
    echo "------------------------------------------------------------"

    if python3 -m forensics.extraction.pipeline \
        --input-dir "$output_dir" \
        --sample-id "$run" \
        --output-dir "$INTERIM"
    then
        extraction_status="PASS"
        echo
        echo "[PASS] A4 extraction completed for $run"
    else
        extraction_status="FAIL"

        echo
        echo "[FAIL] A4 extraction failed for $run"

        echo "$run,YES,$memory_size,PASS,FAIL,FAIL,a4_extraction_failed" \
            >> "$SUMMARY"

        return 1
    fi

    # --------------------------------------------------------
    # Expected JSON files.
    # --------------------------------------------------------

    local process_json="$PROCESS_OUT/${run}.json"
    local memory_json="$MEMORY_OUT/${run}.json"

    echo
    echo "Checking generated feature files..."

    if [[ ! -s "$process_json" ]]; then
        echo "[FAIL] Process feature JSON missing:"
        echo "       $process_json"

        echo "$run,YES,$memory_size,PASS,FAIL,FAIL,process_json_missing" \
            >> "$SUMMARY"

        return 1
    fi

    if [[ ! -s "$memory_json" ]]; then
        echo "[FAIL] Memory feature JSON missing:"
        echo "       $memory_json"

        echo "$run,YES,$memory_size,PASS,FAIL,FAIL,memory_json_missing" \
            >> "$SUMMARY"

        return 1
    fi

    echo "[OK] Process JSON exists"
    echo "[OK] Memory JSON exists"

    # --------------------------------------------------------
    # JSON validation: same validation behavior as benign batch.
    # --------------------------------------------------------

    echo
    echo "Validating JSON..."

    if python3 - "$process_json" "$memory_json" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise SystemExit(f"Invalid JSON object: {path}")

    print(f"[OK] {path}")

print("JSON VALIDATION PASS")
PY
    then
        validation_status="PASS"
    else
        validation_status="FAIL"

        echo
        echo "[FAIL] JSON validation failed."

        echo "$run,YES,$memory_size,PASS,PASS,FAIL,json_validation_failed" \
            >> "$SUMMARY"

        return 1
    fi

    # --------------------------------------------------------
    # Copy Process + Memory features.
    # --------------------------------------------------------

    cp "$process_json" "$PACKAGE_PROCESS/"
    cp "$memory_json" "$PACKAGE_MEMORY/"

    # --------------------------------------------------------
    # Copy metadata.
    # --------------------------------------------------------

    if [[ -f "$run_dir/metadata.json" ]]; then
        cp "$run_dir/metadata.json" "$PACKAGE_METADATA/${run}.json"
    else
        echo "[WARN] metadata.json missing for $run"
        notes="${notes}metadata_missing;"
    fi

    # --------------------------------------------------------
    # Preserve Track-B source evidence.
    # --------------------------------------------------------

    mkdir -p "$PACKAGE_SOURCE/$run"

    for source_file in \
        powershell.evtx \
        sysmon.evtx \
        network_connections.csv \
        process_snapshot.csv \
        network.pcap
    do
        if [[ -f "$run_dir/$source_file" ]]; then
            cp "$run_dir/$source_file" "$PACKAGE_SOURCE/$run/"
        fi
    done

    # Also preserve any other small metadata/evidence files,
    # but NEVER copy memory.raw into the processed package.
    while IFS= read -r -d '' source_file; do
        base="$(basename "$source_file")"

        case "$base" in
            memory.raw|*.dmp|*.mem)
                continue
                ;;
            metadata.json|powershell.evtx|sysmon.evtx|network_connections.csv|process_snapshot.csv|network.pcap)
                continue
                ;;
        esac

        # Keep only ordinary files reasonably suitable for the
        # structured package.
        size="$(stat -c '%s' "$source_file" 2>/dev/null || echo 0)"
        if [[ "$size" -le 52428800 ]]; then
            cp -n "$source_file" "$PACKAGE_SOURCE/$run/" 2>/dev/null || true
        fi
    done < <(find "$run_dir" -maxdepth 1 -type f -print0)

    # --------------------------------------------------------
    # Copy Volatility outputs.
    # --------------------------------------------------------

    mkdir -p "$PACKAGE_VOL/$run"

    for file in "$output_dir"/*.txt; do
        if [[ -f "$file" ]]; then
            cp "$file" "$PACKAGE_VOL/$run/"
        fi
    done

    # --------------------------------------------------------
    # Record success.
    # --------------------------------------------------------

    echo "$run,YES,$memory_size,PASS,PASS,PASS,$notes" \
        >> "$SUMMARY"

    echo
    echo "============================================================"
    echo " $run COMPLETE"
    echo "============================================================"

    return 0
}

# ============================================================
# Process all discovered runs.
# ============================================================

TOTAL=0
PASSED=0
FAILED=0

for run in "${RUNS[@]}"; do
    TOTAL=$((TOTAL + 1))

    if process_run "$run"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

# ============================================================
# Update manifest.
# ============================================================

python3 - "$MANIFEST" "$SUMMARY" <<'PY'
import csv
import json
import sys
from datetime import datetime, timezone

manifest_path = sys.argv[1]
summary_path = sys.argv[2]

with open(summary_path, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)

manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
manifest["runs"] = rows

manifest["statistics"] = {
    "total": len(rows),
    "passed": sum(r["validation_status"] == "PASS" for r in rows),
    "failed": sum(r["validation_status"] != "PASS" for r in rows)
}

with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
PY

# ============================================================
# Generate checksums.
# ============================================================

echo
echo "============================================================"
echo " GENERATING PACKAGE CHECKSUMS"
echo "============================================================"

(
    cd "$PACKAGE" || exit 1

    find . \
        -type f \
        ! -name "checksums.sha256" \
        -print0 |
    sort -z |
    xargs -0 sha256sum
) > "$CHECKSUMS"

echo
echo "Checksums created:"
echo "$CHECKSUMS"

# ============================================================
# Create archive.
# ============================================================

echo
echo "============================================================"
echo " CREATING WINDOWS TRANSFER ARCHIVE"
echo "============================================================"

rm -f "$ARCHIVE"

tar -czf "$ARCHIVE" \
    -C "$(dirname "$PACKAGE")" \
    "$(basename "$PACKAGE")"

echo
echo "[OK] Archive created:"
echo "$ARCHIVE"

# ============================================================
# Final report.
# ============================================================

echo
echo
echo "============================================================"
echo " FMD CUSTOM BATCH COMPLETE"
echo "============================================================"
echo
echo "Category    : $CATEGORY"
echo "Total runs  : $TOTAL"
echo "Passed      : $PASSED"
echo "Failed      : $FAILED"
echo
echo "Summary:"
echo "  $SUMMARY"
echo
echo "Manifest:"
echo "  $MANIFEST"
echo
echo "Package:"
echo "  $PACKAGE"
echo
echo "Archive:"
echo "  $ARCHIVE"
echo
echo "Raw evidence was NOT deleted."
echo "============================================================"

if [[ "$FAILED" -eq 0 ]]; then
    echo
    echo "ALL DISCOVERED RUNS PASSED."
    echo
    exit 0
else
    echo
    echo "SOME RUNS FAILED."
    echo "DO NOT DELETE RAW EVIDENCE."
    echo
    exit 2
fi
