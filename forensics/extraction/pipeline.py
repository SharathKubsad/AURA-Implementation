"""Track A forensic extraction pipeline coordinator."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import NamedTuple

from forensics.command.command_extractor import extract_command_features
from forensics.extraction.memory_extractor import extract_memory_features
from forensics.extraction.process_extractor import extract_process_features
from forensics.network.network_extractor import extract_network_features
from forensics.schemas.command import CommandFeatures
from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.network import NetworkFeatures
from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger(__name__)


class ExtractionResult(NamedTuple):
    """Container for Track A extraction output."""

    sample_id: str
    process_features: ProcessFeatures
    memory_features: MemoryFeatures
    process_output_path: Path
    memory_output_path: Path


class TrackBExtractionResult(NamedTuple):
    """Container for Track B extraction output."""

    sample_id: str
    command_features: CommandFeatures
    network_features: NetworkFeatures
    command_output_path: Path
    network_output_path: Path


class FullExtractionResult(NamedTuple):
    """Container for full 4-modality extraction output."""

    sample_id: str
    process_features: ProcessFeatures
    memory_features: MemoryFeatures
    command_features: CommandFeatures
    network_features: NetworkFeatures
    process_output_path: Path
    memory_output_path: Path
    command_output_path: Path
    network_output_path: Path


def run_track_a_extraction(
    input_dir: Path,
    sample_id: str = "EXEC_RUN-001",
    output_base_dir: Path = Path("data/interim"),
) -> ExtractionResult:
    """Execute Track A extraction (Process and Memory) on a Volatility 3 output directory.

    Args:
        input_dir: Directory containing plugin output files (pslist, vadinfo, etc.).
        sample_id: Canonical sample identifier (default: 'EXEC_RUN-001').
        output_base_dir: Root directory for interim feature storage.

    Returns:
        ExtractionResult: NamedTuple containing validated feature objects and write paths.
    """
    input_path = Path(input_dir)
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    # 1. Extract Process Features
    process_features = extract_process_features(input_path, sample_id=sample_id)
    proc_dir = Path(output_base_dir) / "process"
    proc_dir.mkdir(parents=True, exist_ok=True)
    proc_path = proc_dir / f"{sample_id}.json"
    proc_path.write_text(process_features.model_dump_json(indent=2), encoding="utf-8")

    # 2. Extract Memory Features
    memory_features = extract_memory_features(input_path, sample_id=sample_id)
    mem_dir = Path(output_base_dir) / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    mem_path = mem_dir / f"{sample_id}.json"
    mem_path.write_text(memory_features.model_dump_json(indent=2), encoding="utf-8")

    return ExtractionResult(
        sample_id=sample_id,
        process_features=process_features,
        memory_features=memory_features,
        process_output_path=proc_path,
        memory_output_path=mem_path,
    )


def run_track_b_extraction(
    input_dir: Path,
    sample_id: str = "EXEC_RUN-001",
    output_base_dir: Path = Path("data/interim"),
) -> TrackBExtractionResult:
    """Execute Track B extraction (Command and Network) on an evidence directory.

    Args:
        input_dir: Directory containing command and network evidence (EVTX, CSVs).
        sample_id: Canonical sample identifier.
        output_base_dir: Root directory for interim feature storage.

    Returns:
        TrackBExtractionResult: NamedTuple containing feature objects and write paths.
    """
    input_path = Path(input_dir)
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    # 1. Extract Command Features
    command_features = extract_command_features(input_path, sample_id=sample_id)
    cmd_dir = Path(output_base_dir) / "command"
    cmd_dir.mkdir(parents=True, exist_ok=True)
    cmd_path = cmd_dir / f"{sample_id}.json"
    cmd_path.write_text(command_features.model_dump_json(indent=2), encoding="utf-8")

    # 2. Extract Network Features
    network_features = extract_network_features(input_path, sample_id=sample_id)
    net_dir = Path(output_base_dir) / "network"
    net_dir.mkdir(parents=True, exist_ok=True)
    net_path = net_dir / f"{sample_id}.json"
    net_path.write_text(network_features.model_dump_json(indent=2), encoding="utf-8")

    return TrackBExtractionResult(
        sample_id=sample_id,
        command_features=command_features,
        network_features=network_features,
        command_output_path=cmd_path,
        network_output_path=net_path,
    )


def run_full_extraction(
    input_dir: Path,
    sample_id: str = "EXEC_RUN-001",
    output_base_dir: Path = Path("data/interim"),
) -> FullExtractionResult:
    """Execute full 4-modality extraction across Process, Memory, Command, and Network.

    Args:
        input_dir: Directory containing Volatility outputs and source evidence.
        sample_id: Canonical sample identifier.
        output_base_dir: Root directory for interim feature storage.

    Returns:
        FullExtractionResult: Container with all 4 extracted modalities.
    """
    res_a = run_track_a_extraction(input_dir, sample_id=sample_id, output_base_dir=output_base_dir)
    res_b = run_track_b_extraction(input_dir, sample_id=sample_id, output_base_dir=output_base_dir)

    return FullExtractionResult(
        sample_id=sample_id,
        process_features=res_a.process_features,
        memory_features=res_a.memory_features,
        command_features=res_b.command_features,
        network_features=res_b.network_features,
        process_output_path=res_a.process_output_path,
        memory_output_path=res_a.memory_output_path,
        command_output_path=res_b.command_output_path,
        network_output_path=res_b.network_output_path,
    )


def main() -> None:
    """CLI interface for running forensic extraction."""
    parser = argparse.ArgumentParser(
        description="Run forensic extraction pipeline for Track A, Track B, or All modalities"
    )
    parser.add_argument(
        "--input-dir",
        "-i",
        type=Path,
        required=True,
        help="Directory containing evidence or Volatility 3 output files",
    )
    parser.add_argument(
        "--sample-id",
        "-s",
        type=str,
        default="EXEC_RUN-001",
        help="Canonical sample ID (default: EXEC_RUN-001)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("data/interim"),
        help="Interim output directory (default: data/interim)",
    )
    parser.add_argument(
        "--track",
        "-t",
        choices=["a", "b", "all"],
        default="a",
        help="Extraction track to execute: 'a' (Process+Memory), 'b' (Command+Network), 'all' (Unified)",
    )
    args = parser.parse_args()

    if args.track == "a":
        res_a = run_track_a_extraction(
            input_dir=args.input_dir,
            sample_id=args.sample_id,
            output_base_dir=args.output_dir,
        )
        print(f"Track A extraction complete for {res_a.sample_id}")
        print(f"  Process Features: {res_a.process_output_path}")
        print(f"  Memory Features:  {res_a.memory_output_path}")
    elif args.track == "b":
        res_b = run_track_b_extraction(
            input_dir=args.input_dir,
            sample_id=args.sample_id,
            output_base_dir=args.output_dir,
        )
        print(f"Track B extraction complete for {res_b.sample_id}")
        print(f"  Command Features: {res_b.command_output_path}")
        print(f"  Network Features: {res_b.network_output_path}")
    else:
        res_all = run_full_extraction(
            input_dir=args.input_dir,
            sample_id=args.sample_id,
            output_base_dir=args.output_dir,
        )
        print(f"Full extraction complete for {res_all.sample_id}")
        print(f"  Process Features: {res_all.process_output_path}")
        print(f"  Memory Features:  {res_all.memory_output_path}")
        print(f"  Command Features: {res_all.command_output_path}")
        print(f"  Network Features: {res_all.network_output_path}")


if __name__ == "__main__":
    main()
