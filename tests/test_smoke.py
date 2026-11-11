"""Smoke tests verifying repository environment and structure."""

import sys
from pathlib import Path


def test_python_version() -> None:
    """Ensure Python runtime is 3.11 or greater."""
    assert sys.version_info >= (3, 11), f"Python 3.11+ required, found: {sys.version}"


def test_core_directories_exist() -> None:
    """Verify that essential project directories are present."""
    root = Path(__file__).resolve().parent.parent
    expected_dirs = [
        "data/raw",
        "data/processed",
        "data/schemas",
        "models/process",
        "models/memory",
        "models/command",
        "models/network",
        "models/multiclass",
        "forensics/process",
        "forensics/memory",
        "forensics/command",
        "forensics/network",
        "live_collectors",
        "framework/fusion",
        "framework/api",
        "sandbox",
        "preprocessing",
        "evaluation",
        "configs",
        "docs",
    ]
    for rel_dir in expected_dirs:
        dir_path = root / rel_dir
        assert dir_path.is_dir(), f"Expected directory missing: {rel_dir}"


def test_core_files_exist() -> None:
    """Verify that required bootstrap files exist."""
    root = Path(__file__).resolve().parent.parent
    expected_files = [
        "README.md",
        "requirements.txt",
        "pyproject.toml",
        ".gitignore",
        ".env.example",
        "configs/thresholds.yaml",
        "configs/settings.yaml",
    ]
    for rel_file in expected_files:
        file_path = root / rel_file
        assert file_path.is_file(), f"Expected file missing: {rel_file}"
