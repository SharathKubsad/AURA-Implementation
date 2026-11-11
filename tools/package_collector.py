"""Build script for C:/FMD-Transfer/FMD-Windows-Collector.zip.

Creates a self-contained ZIP package for the hardened A6 Windows collector.
Preserves required relative directory structure.
Strictly excludes .git, virtual environments, tests, malware, payloads,
dumps, PCAPs, EVTX files, and temporary artifacts.
"""

import sys
import zipfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

TARGET_ZIP = Path("C:/FMD-Transfer/FMD-Windows-Collector.zip")

FILES_TO_INCLUDE = [
    # Windows & Kali Tooling
    "tools/collect_run_windows.bat",
    "tools/collect_run_windows.ps1",
    "tools/collection_orchestrator.py",
    "tools/process_run_kali.py",
    "tools/process_run_kali.sh",
    # Forensics extraction pipeline & semantic parsers
    "forensics/extraction/__init__.py",
    "forensics/extraction/pipeline.py",
    "forensics/extraction/process_extractor.py",
    "forensics/extraction/memory_extractor.py",
    "forensics/extraction/parser_utils.py",
    # Forensics Pydantic schemas
    "forensics/schemas/__init__.py",
    "forensics/schemas/custom_collection.py",
    "forensics/schemas/metadata.py",
    "forensics/schemas/process.py",
    "forensics/schemas/memory.py",
    "forensics/schemas/command.py",
    "forensics/schemas/network.py",
    # Custom dataset metadata, allocation ledger & categories
    "data/raw/custom/categories.json",
    "data/raw/custom/allocated_runs.json",
    "data/raw/custom/RUN_CONVENTIONS.md",
    # Shared JSON schemas
    "data/schemas/command_features.schema.json",
    "data/schemas/custom_collection_metadata.schema.json",
    "data/schemas/labels.schema.json",
    "data/schemas/memory_features.schema.json",
    "data/schemas/network_features.schema.json",
    "data/schemas/process_features.schema.json",
    "data/schemas/sample_metadata.schema.json",
    "data/schemas/schema_version.json",
    # Documentation & Specifications
    "docs/CUSTOM_COLLECTION_WORKFLOW.md",
    "docs/DATA_SCHEMA.md",
    "pyproject.toml",
    "README.md",
    "PROJECT_MANUAL.md",
    "AGENTS.md",
]


def build_collector_package(dest_path: Path = TARGET_ZIP) -> Path:
    """Pack all necessary collector files into a zip archive."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists():
        dest_path.unlink()

    missing: list[str] = []
    added: list[str] = []

    with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Guarantee forensics/__init__.py is present
        zf.writestr("forensics/__init__.py", '"""Forensics package root."""\n')
        added.append("forensics/__init__.py")

        for rel_str in FILES_TO_INCLUDE:
            src = _REPO_ROOT / rel_str
            if not src.is_file():
                missing.append(rel_str)
                continue
            zf.write(src, arcname=rel_str)
            added.append(rel_str)

    if missing:
        print(f"WARNING: Missing {len(missing)} files: {missing}", file=sys.stderr)

    print(f"Successfully created {dest_path}")
    print(f"Total files packaged: {len(added)}")
    print(f"Total archive size  : {dest_path.stat().st_size:,} bytes")
    return dest_path


if __name__ == "__main__":
    build_collector_package()
