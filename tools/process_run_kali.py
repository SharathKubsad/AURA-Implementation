"""A6 Kali Processing Controller.

Processes an incoming completed RUN directory:
1. Detects and resolves RUN directory location.
2. Verifies metadata schema and evidence files.
3. Checks evidence integrity.
4. Runs Volatility 3 forensic plugins if memory dump is present and outputs are missing.
5. Invokes existing A4 extraction pipeline (Process + Memory).
6. Preserves Command + Network evidence for Track B.
7. Generates machine-readable validation report.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.collection_orchestrator import (  # noqa: E402
    process_run_pipeline,
    verify_run_evidence,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("process_kali")

VOLATILITY_PLUGINS = [
    ("windows.pslist", "pslist.txt"),
    ("windows.psscan", "psscan.txt"),
    ("windows.pstree", "pstree.txt"),
    ("windows.threads", "threads.txt"),
    ("windows.handles", "handles.txt"),
    ("windows.dlllist", "dlllist.txt"),
    ("windows.psxview", "psxview.txt"),
    ("windows.malfind", "malfind.txt"),
    ("windows.privileges", "privileges.txt"),
    ("windows.vadinfo", "vadinfo.txt"),
    ("windows.ldrmodules", "ldrmodules.txt"),
]


def resolve_run_directory(target: str | Path, search_dirs: list[Path] | None = None) -> Path:
    """Find and resolve a RUN directory by name or path."""
    p = Path(target)
    if p.is_dir():
        return p.resolve()

    target_name = p.name if not p.suffix else p.stem

    candidate_locations = [
        Path.cwd() / target_name,
        _REPO_ROOT / "data" / "raw" / "custom" / target_name,
        Path.home() / "fmd-results" / "custom" / target_name,
        Path("/home/kali/fmd-results/custom") / target_name,
        Path("C:/FMD-Transfer") / target_name,
    ]

    if search_dirs:
        for sdir in search_dirs:
            candidate_locations.insert(0, sdir / target_name)
            if sdir.is_dir():
                for sub in sdir.iterdir():
                    if sub.is_dir():
                        candidate_locations.append(sub / target_name)

    # Also search subdirectories under data/raw/custom
    custom_root = _REPO_ROOT / "data" / "raw" / "custom"
    if custom_root.is_dir():
        for category_dir in custom_root.iterdir():
            if category_dir.is_dir():
                candidate_locations.append(category_dir / target_name)

    for cand in candidate_locations:
        if cand.is_dir():
            return cand.resolve()

    raise FileNotFoundError(
        f"Could not locate RUN directory for '{target}'. Checked candidates: "
        f"{[str(c) for c in candidate_locations]}"
    )


def find_volatility_cmd() -> list[str] | None:
    """Locate Volatility 3 executable in system."""
    for cmd in ["vol.py", "vol", "volatility3"]:
        if shutil.which(cmd):
            return [cmd]

    # Check python -m volatility3.cli
    try:
        res = subprocess.run(
            [sys.executable, "-m", "volatility3.cli", "-h"],
            capture_output=True,
            timeout=5,
        )
        if res.returncode == 0:
            return [sys.executable, "-m", "volatility3.cli"]
    except Exception:
        pass

    return None


def run_volatility_extraction(run_dir: Path) -> dict[str, str]:
    """Execute Volatility 3 plugins against memory dump if raw dump is present and outputs missing."""
    mem_dump = None
    for candidate in ["memory.raw", "memory.dmp"]:
        target = run_dir / candidate
        if target.is_file() and target.stat().st_size > 0:
            mem_dump = target
            break

    results: dict[str, str] = {}
    if not mem_dump:
        logger.info(
            "No raw memory dump found in %s; using existing Volatility text files if present.",
            run_dir,
        )
        return results

    vol_cmd = find_volatility_cmd()
    if not vol_cmd:
        logger.warning("Volatility 3 not detected on PATH. Skipping on-demand memory parsing.")
        return results

    logger.info("Starting Volatility 3 extraction on %s using %s...", mem_dump.name, vol_cmd)
    for plugin, outfile in VOLATILITY_PLUGINS:
        out_path = run_dir / outfile
        if out_path.is_file() and out_path.stat().st_size > 0:
            logger.info("Plugin output %s already exists. Skipping.", outfile)
            results[plugin] = "SKIPPED_EXISTS"
            continue

        full_cmd = vol_cmd + ["-f", str(mem_dump), plugin]
        logger.info("Running: %s > %s", " ".join(full_cmd), outfile)
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                sub_res = subprocess.run(
                    full_cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=300
                )
            if sub_res.returncode == 0:
                results[plugin] = "SUCCESS"
            else:
                logger.warning(
                    "Plugin %s returned code %d: %s", plugin, sub_res.returncode, sub_res.stderr
                )
                results[plugin] = f"FAILED_EXIT_{sub_res.returncode}"
        except Exception as ex:
            logger.error("Error executing %s: %s", plugin, ex)
            results[plugin] = f"ERROR_{ex}"

    return results


def process_run(
    target_run: str | Path,
    output_dir: Path | None = None,
    skip_volatility: bool = False,
) -> dict[str, Any]:
    """Main processing workflow for an incoming completed RUN."""
    run_dir = resolve_run_directory(target_run)
    logger.info("=" * 72)
    logger.info("PROCESSING RUN DIRECTORY: %s", run_dir)
    logger.info("=" * 72)

    # 1. Verify evidence and metadata
    is_valid, errors = verify_run_evidence(run_dir)
    if not is_valid:
        logger.error("Evidence verification failed for %s: %s", run_dir, errors)
        raise ValueError(f"Evidence verification failed: {errors}")

    logger.info("Verification PASSED for metadata and evidence files.")

    # 2. Run Volatility 3 if required
    if not skip_volatility:
        run_volatility_extraction(run_dir)

    # 3. Check Track B evidence preservation
    track_b_evidence: dict[str, bool] = {}
    for evidence_name in [
        "sysmon.evtx",
        "powershell.evtx",
        "process_snapshot.csv",
        "network_connections.csv",
        "network.pcap",
    ]:
        ev_file = run_dir / evidence_name
        track_b_evidence[evidence_name] = ev_file.is_file()

    logger.info("Track B Evidence Preserved: %s", track_b_evidence)

    # 4. Invoke existing A4 extraction pipeline (reusing run_track_a_extraction)
    report = process_run_pipeline(run_dir, output_base_dir=output_dir)

    # Add Track B preserved evidence list into report
    report["track_b_evidence"] = track_b_evidence
    report_file = run_dir / "validation_report.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    logger.info("Processing complete. Status: %s", report["status"])
    logger.info("Validation Report: %s", report_file)
    return report


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Kali Processing Controller for Completed RUN")
    parser.add_argument("run_target", help="RUN directory name (e.g. RUN-002) or directory path")
    parser.add_argument(
        "--output-dir", type=Path, default=None, help="Base directory for interim features"
    )
    parser.add_argument("--skip-volatility", action="store_true", help="Skip running Volatility 3")
    args = parser.parse_args()

    try:
        report = process_run(
            target_run=args.run_target,
            output_dir=args.output_dir,
            skip_volatility=args.skip_volatility,
        )
        print("\n" + "=" * 72)
        print("A6 KALI PROCESSING SUMMARY:")
        print(f"Status           : {report.get('status')}")
        print(f"Sample ID        : {report.get('sample_id')}")
        print(f"Label            : {report.get('label')}")
        print(f"Family           : {report.get('family')}")
        print(f"Process Features : {report.get('process_features')}")
        print(f"Memory Features  : {report.get('memory_features')}")
        print(f"Validation Report: {report.get('run_dir')}/validation_report.json")
        print("=" * 72 + "\n")
        return 0 if report.get("status") == "PASS" else 1
    except Exception as ex:
        logger.error("Processing failed: %s", ex)
        return 1


if __name__ == "__main__":
    sys.exit(main())
