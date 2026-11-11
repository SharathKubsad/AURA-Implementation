"""Memory feature extraction engine for Volatility 3 outputs (Track A)."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from forensics.extraction.parser_utils import (
    calculate_shannon_entropy,
    find_plugin_file,
    parse_ldrmodules_output,
    parse_malfind_output,
    parse_volatility_file,
)
from forensics.schemas.memory import MemoryFeatures

logger = logging.getLogger(__name__)

EXECUTABLE_PROTECTIONS = {
    "page_execute",
    "page_execute_read",
    "page_execute_readwrite",
    "page_execute_writecopy",
    "execute",
    "execute_read",
    "execute_readwrite",
    "execute_writecopy",
}

RWX_PROTECTIONS = {
    "page_execute_readwrite",
    "execute_readwrite",
}


def extract_memory_features(
    input_dir: Path,
    sample_id: str,
    raw_memory_bytes: bytes | None = None,
) -> MemoryFeatures:
    """Extract MemoryFeatures from Volatility 3 plugin outputs in the specified directory.

    Derives features based on true Volatility 3 output semantics:
    - rwx_page_count: actual RWX VAD regions from vadinfo
    - injected_code_regions: actual findings from malfind
    - unmapped_executable_pages: executable memory pages not backed by a disk image
    - vad_protection_anomaly_count: discrepancies between initial allocation and current protection
    - ldrmodules_inconsistencies: unlinked DLL indicators in ldrmodules (InLoad or InMem False)
    - yara_shellcode_matches: actual signature match hits from yarascan/vadyarascan
    - mean/max_memory_entropy: None (unsupported/missing) when only text output is available,
      or calculated if actual raw memory bytes are provided.

    Args:
        input_dir: Directory containing Volatility 3 plugin outputs.
        sample_id: Canonical sample identifier (e.g. 'EXEC_RUN-001').
        raw_memory_bytes: Optional raw byte payload for calculating page entropy.

    Returns:
        MemoryFeatures: Validated Pydantic model conforming to canonical schema.
    """
    # 1. Parse vadinfo
    vadinfo_file = find_plugin_file(input_dir, "vadinfo")
    vadinfo_records = parse_volatility_file(vadinfo_file) if vadinfo_file else []

    rwx_page_count = 0
    unmapped_executable_pages = 0
    vad_protection_anomaly_count = 0

    for row in vadinfo_records:
        pid_val = row.get("pid")
        if pid_val is None:
            continue

        prot = str(row.get("protection") or "").lower().strip()
        init_prot = str(row.get("initprotection") or "").lower().strip()

        # RWX protection check: committed memory region with PAGE_EXECUTE_READWRITE
        if any(rwx in prot for rwx in RWX_PROTECTIONS):
            rwx_page_count += 1

        # Check if region is executable
        is_exec = any(ep in prot for ep in EXECUTABLE_PROTECTIONS)

        # Unmapped executable pages: executable region with no backing image file
        file_val = str(row.get("file") or row.get("filename") or row.get("mapping") or "").strip()
        tag_val = str(row.get("tag") or "").strip()
        private_mem = str(row.get("privatememory") or row.get("private") or "").strip()

        is_unmapped = (
            (not file_val or file_val.lower() in ("n/a", "none", "null", "-"))
            and (private_mem in ("1", "true", "yes") or tag_val.startswith("Vad"))
            and not tag_val.startswith("VadImage")
        )

        if is_exec and is_unmapped:
            unmapped_executable_pages += 1

        # Protection anomaly: initial allocation protection differs from current protection
        # (e.g. VirtualAlloc PAGE_READWRITE modified via VirtualProtect to PAGE_EXECUTE_READWRITE)
        if init_prot and prot and (init_prot != prot) and init_prot not in ("n/a", "-", "none"):
            vad_protection_anomaly_count += 1

    # 2. Parse malfind (injected code regions)
    malfind_file = find_plugin_file(input_dir, "malfind")
    malfind_records = parse_malfind_output(malfind_file) if malfind_file else []
    injected_code_regions = len(malfind_records)

    # 3. Parse ldrmodules (reflective loading inconsistencies)
    ldrmodules_file = find_plugin_file(input_dir, "ldrmodules")
    ldrmodules_records = parse_ldrmodules_output(ldrmodules_file) if ldrmodules_file else []
    ldrmodules_inconsistencies = sum(
        1 for r in ldrmodules_records if (not r.get("inload", True)) or (not r.get("inmem", True))
    )

    # 4. Parse YARA shellcode matches (vadyarascan or yarascan)
    yara_file = find_plugin_file(input_dir, "yarascan") or find_plugin_file(
        input_dir, "vadyarascan"
    )
    yara_records = parse_volatility_file(yara_file) if yara_file else []
    yara_shellcode_matches = 0

    for row in yara_records:
        rule_val = str(row.get("rule") or "").strip()
        # Only count genuine rule match hits (not header or banner rows)
        if rule_val and rule_val.lower() not in ("rule", "n/a", "none"):
            yara_shellcode_matches += 1

    # 5. Compute memory entropy
    # Rule: Entropy must NOT be reported as successfully calculated from ordinary Volatility text output.
    # If raw bytes are unavailable, represent the feature as unsupported/missing (None/null)
    # according to the canonical schema rather than inventing 0.0.
    mean_memory_entropy: float | None = None
    max_memory_entropy: float | None = None

    if raw_memory_bytes and len(raw_memory_bytes) > 0:
        entropy_val = calculate_shannon_entropy(raw_memory_bytes)
        mean_memory_entropy = entropy_val
        max_memory_entropy = entropy_val

    return MemoryFeatures(
        sample_id=sample_id,
        rwx_page_count=rwx_page_count,
        injected_code_regions=injected_code_regions,
        unmapped_executable_pages=unmapped_executable_pages,
        vad_protection_anomaly_count=vad_protection_anomaly_count,
        ldrmodules_inconsistencies=ldrmodules_inconsistencies,
        yara_shellcode_matches=yara_shellcode_matches,
        mean_memory_entropy=mean_memory_entropy,
        max_memory_entropy=max_memory_entropy,
    )


def main() -> None:
    """CLI entrypoint for memory feature extraction."""
    parser = argparse.ArgumentParser(description="Extract Memory features from Volatility 3 output")
    parser.add_argument(
        "--input-dir", "-i", type=Path, required=True, help="Input directory of Volatility outputs"
    )
    parser.add_argument(
        "--sample-id", "-s", type=str, required=True, help="Canonical sample identifier"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("data/interim/memory"),
        help="Output directory",
    )
    parser.add_argument(
        "--raw-bytes-file",
        "-r",
        type=Path,
        default=None,
        help="Optional path to raw memory bytes file for true entropy calculation",
    )
    args = parser.parse_args()

    raw_bytes = None
    if args.raw_bytes_file and args.raw_bytes_file.is_file():
        raw_bytes = args.raw_bytes_file.read_bytes()

    features = extract_memory_features(args.input_dir, args.sample_id, raw_memory_bytes=raw_bytes)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_file = args.output_dir / f"{args.sample_id}.json"
    out_file.write_text(features.model_dump_json(indent=2), encoding="utf-8")
    print(f"Memory features extracted successfully to: {out_file}")


if __name__ == "__main__":
    main()
