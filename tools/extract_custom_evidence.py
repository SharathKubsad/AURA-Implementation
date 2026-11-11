"""Batch extractor for custom dataset archives and evidence directories (Track B).

Extracts Command and Network forensic features from custom dataset archives
(in C:\\FMD-Dataset\\archives) or local source_evidence folders into data/interim/.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tarfile
import tempfile
from pathlib import Path

# Ensure repo root is on sys.path for direct execution
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from forensics.command.command_extractor import extract_command_features  # noqa: E402
from forensics.network.network_extractor import extract_network_features  # noqa: E402
from forensics.schemas.memory import MemoryFeatures  # noqa: E402
from forensics.schemas.process import ProcessFeatures  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def extract_from_directory(
    evidence_dir: Path,
    sample_id: str,
    output_dir: Path = Path("data/interim"),
) -> tuple[Path, Path]:
    """Extract Command and Network features from a single evidence directory."""
    cmd_dir = output_dir / "command"
    net_dir = output_dir / "network"
    cmd_dir.mkdir(parents=True, exist_ok=True)
    net_dir.mkdir(parents=True, exist_ok=True)

    cmd_feat = extract_command_features(evidence_dir, sample_id=sample_id)
    net_feat = extract_network_features(evidence_dir, sample_id=sample_id)

    cmd_path = cmd_dir / f"{sample_id}.json"
    net_path = net_dir / f"{sample_id}.json"

    cmd_path.write_text(cmd_feat.model_dump_json(indent=2), encoding="utf-8")
    net_path.write_text(net_feat.model_dump_json(indent=2), encoding="utf-8")

    return cmd_path, net_path


def extract_from_archive(
    archive_path: Path,
    output_dir: Path = Path("data/interim"),
) -> list[tuple[str, Path, Path, Path | None, Path | None]]:
    """Extract Command, Network, Process, and Memory features from a batch archive.

    Unpacks source evidence for Track B command/network extraction, and extracts/copies
    pre-existing validated Track A process and memory JSONs with canonical sample IDs.

    Args:
        archive_path: Path to tar.gz batch archive.
        output_dir: Root directory for interim files (default: data/interim).

    Returns:
        List of tuples (sample_id, cmd_path, net_path, proc_path, mem_path).
    """
    results: list[tuple[str, Path, Path, Path | None, Path | None]] = []
    if not archive_path.is_file():
        logger.error("Archive not found: %s", archive_path)
        return results

    cmd_dir = output_dir / "command"
    net_dir = output_dir / "network"
    proc_dir = output_dir / "process"
    mem_dir = output_dir / "memory"
    for d in (cmd_dir, net_dir, proc_dir, mem_dir):
        d.mkdir(parents=True, exist_ok=True)

    logger.info("Processing archive: %s", archive_path.name)
    with tempfile.TemporaryDirectory(prefix="fmd_ext_") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        with tarfile.open(archive_path, "r:*") as tf:
            # 1. First, extract and standardize existing Process & Memory feature JSONs
            proc_paths: dict[str, Path] = {}
            mem_paths: dict[str, Path] = {}

            for member in tf.getmembers():
                norm_name = member.name.replace("\\", "/")
                if norm_name.endswith(".json"):
                    if "/process/RUN-" in norm_name:
                        run_id = Path(norm_name).stem
                        sample_id = f"EXEC_{run_id}"
                        extracted_f = tf.extractfile(member)
                        if extracted_f:
                            raw_dict = json.loads(extracted_f.read().decode("utf-8-sig"))
                            raw_dict["sample_id"] = sample_id
                            proc_obj = ProcessFeatures.model_validate(raw_dict)
                            out_p = proc_dir / f"{sample_id}.json"
                            out_p.write_text(proc_obj.model_dump_json(indent=2), encoding="utf-8")
                            proc_paths[run_id] = out_p

                    elif "/memory/RUN-" in norm_name:
                        run_id = Path(norm_name).stem
                        sample_id = f"EXEC_{run_id}"
                        extracted_f = tf.extractfile(member)
                        if extracted_f:
                            raw_dict = json.loads(extracted_f.read().decode("utf-8-sig"))
                            raw_dict["sample_id"] = sample_id
                            mem_obj = MemoryFeatures.model_validate(raw_dict)
                            out_p = mem_dir / f"{sample_id}.json"
                            out_p.write_text(mem_obj.model_dump_json(indent=2), encoding="utf-8")
                            mem_paths[run_id] = out_p

            # 2. Locate all source_evidence/RUN-xxx directories for Track B extraction
            run_dirs: set[str] = set()
            for member in tf.getmembers():
                parts = member.name.replace("\\", "/").split("/")
                if "source_evidence" in parts:
                    idx = parts.index("source_evidence")
                    if idx + 1 < len(parts):
                        run_id = parts[idx + 1]
                        if run_id.startswith("RUN-"):
                            run_dirs.add(run_id)

            logger.info(
                "Found %d RUNs in %s: %s (Process=%d, Memory=%d)",
                len(run_dirs),
                archive_path.name,
                sorted(run_dirs),
                len(proc_paths),
                len(mem_paths),
            )

            # 3. Extract source evidence for each RUN and extract Command + Network features
            for run_id in sorted(run_dirs):
                run_members = [
                    m
                    for m in tf.getmembers()
                    if f"source_evidence/{run_id}" in m.name.replace("\\", "/")
                ]
                for m in run_members:
                    tf.extract(
                        m, path=tmp_dir, filter="data" if hasattr(tarfile, "data_filter") else None
                    )

                extracted_run_path = None
                for candidate in tmp_dir.rglob(run_id):
                    if candidate.is_dir() and "source_evidence" in candidate.parts:
                        extracted_run_path = candidate
                        break

                if extracted_run_path and extracted_run_path.is_dir():
                    sample_id = f"EXEC_{run_id}"
                    cmd_p, net_p = extract_from_directory(
                        extracted_run_path, sample_id=sample_id, output_dir=output_dir
                    )
                    proc_p = proc_paths.get(run_id)
                    mem_p = mem_paths.get(run_id)
                    results.append((sample_id, cmd_p, net_p, proc_p, mem_p))
                    logger.info(
                        "  [+] Assembled %s -> cmd=%s, net=%s, proc=%s, mem=%s",
                        sample_id,
                        cmd_p.name,
                        net_p.name,
                        proc_p.name if proc_p else "None",
                        mem_p.name if mem_p else "None",
                    )

    return results


def process_all_archives(
    archives_dir: Path = Path(r"C:\FMD-Dataset\archives"),
    output_dir: Path = Path("data/interim"),
) -> int:
    """Process all tar.gz custom dataset archives in directory."""
    if not archives_dir.is_dir():
        logger.error("Archives directory does not exist: %s", archives_dir)
        return 0

    tar_files = sorted(list(archives_dir.glob("*.tar.gz")) + list(archives_dir.glob("*.tgz")))
    logger.info("Found %d archives in %s", len(tar_files), archives_dir)

    total_runs = 0
    for archive in tar_files:
        run_results = extract_from_archive(archive, output_dir=output_dir)
        total_runs += len(run_results)

    logger.info(
        "Successfully extracted features for %d total RUNs across %d archives",
        total_runs,
        len(tar_files),
    )
    return total_runs


def main() -> None:
    """CLI entry point for extracting features from custom dataset evidence."""
    parser = argparse.ArgumentParser(
        description="Extract Track B features from custom archives or directories"
    )
    parser.add_argument(
        "--input-archive",
        "-a",
        type=Path,
        default=None,
        help="Path to a single .tar.gz custom batch archive",
    )
    parser.add_argument(
        "--all-archives",
        action="store_true",
        help="Process all archives in C:\\FMD-Dataset\\archives",
    )
    parser.add_argument(
        "--archives-dir",
        type=Path,
        default=Path(r"C:\FMD-Dataset\archives"),
        help="Directory containing custom batch archives (default: C:\\FMD-Dataset\\archives)",
    )
    parser.add_argument(
        "--evidence-dir",
        "-d",
        type=Path,
        default=None,
        help="Path to an individual RUN source evidence folder",
    )
    parser.add_argument(
        "--sample-id",
        "-s",
        type=str,
        default="EXEC_RUN-001",
        help="Sample identifier for individual evidence directory",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("data/interim"),
        help="Interim output directory (default: data/interim)",
    )
    args = parser.parse_args()

    if args.all_archives:
        count = process_all_archives(archives_dir=args.archives_dir, output_dir=args.output_dir)
        print(f"[+] Finished processing all archives: {count} runs extracted.")
    elif args.input_archive:
        results = extract_from_archive(args.input_archive, output_dir=args.output_dir)
        print(f"[+] Finished archive {args.input_archive.name}: {len(results)} runs extracted.")
    elif args.evidence_dir:
        cmd_p, net_p = extract_from_directory(
            args.evidence_dir, sample_id=args.sample_id, output_dir=args.output_dir
        )
        print(f"[+] Extracted {args.sample_id}:")
        print(f"    Command: {cmd_p}")
        print(f"    Network: {net_p}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
