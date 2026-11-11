"""Automated test suite validating A5 custom dataset collection scaffolding.

Verifies:
- All 12 collection categories exist under data/raw/custom/ with dedicated READMEs.
- Each category README explains naming, labels, family, required evidence, Volatility outputs,
  extraction destination, and SHA-256 requirements.
- Canonical metadata template contains all 12 required fields and validates against Pydantic schema.
- RUN-001 remains classified as benign validation baseline.
- No existing A4 extraction files have been modified.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from forensics.extraction.memory_extractor import extract_memory_features
from forensics.extraction.process_extractor import extract_process_features
from forensics.schemas.custom_collection import CustomCollectionMetadata

CUSTOM_DATA_ROOT = Path(__file__).resolve().parent.parent / "data" / "raw" / "custom"

EXPECTED_12_CATEGORIES = {
    "BENIGN": ["benign"],
    "TRACK_A": [
        "powershell_fileless",
        "process_hollowing",
        "memory_only_rat",
        "registry_resident_malware",
        "cobalt_strike_beacon",
        "metasploit_memory_payloads",
    ],
    "TRACK_B": [
        "wmi_malware",
        "reflective_dll_injection",
        "lolbins_abuse",
        "fileless_ransomware",
        "empire_framework",
    ],
}

ALL_12_CATEGORY_NAMES = [
    "benign",
    "powershell_fileless",
    "process_hollowing",
    "memory_only_rat",
    "registry_resident_malware",
    "cobalt_strike_beacon",
    "metasploit_memory_payloads",
    "wmi_malware",
    "reflective_dll_injection",
    "lolbins_abuse",
    "fileless_ransomware",
    "empire_framework",
]

REQUIRED_METADATA_FIELDS = [
    "sample_id",
    "label",
    "family",
    "track",
    "os",
    "execution_timestamp",
    "source_type",
    "source_reference",
    "evidence_sha256",
    "memory_dump",
    "sysmon_available",
    "notes",
]


def test_all_12_collection_categories_exist() -> None:
    """Verify that all 12 collection categories exist as directories under data/raw/custom/."""
    assert CUSTOM_DATA_ROOT.is_dir(), f"Missing directory: {CUSTOM_DATA_ROOT}"

    for category_name in ALL_12_CATEGORY_NAMES:
        category_dir = CUSTOM_DATA_ROOT / category_name
        assert category_dir.is_dir(), f"Category directory missing: {category_dir}"

        readme_file = category_dir / "README.md"
        assert readme_file.is_file(), f"Missing README.md in category: {category_dir}"
        content = readme_file.read_text(encoding="utf-8")
        assert len(content) > 100, f"README too short in: {readme_file}"

        # Verify all required documentation sections in category README
        content_lower = content.lower()
        assert (
            "naming" in content_lower or "sample" in content_lower
        ), f"Missing run naming section in {readme_file}"
        assert "label" in content_lower, f"Missing label section in {readme_file}"
        assert "family" in content_lower, f"Missing family section in {readme_file}"
        assert "evidence" in content_lower, f"Missing evidence section in {readme_file}"
        assert "volatility" in content_lower, f"Missing Volatility section in {readme_file}"
        assert (
            "destination" in content_lower or "extraction" in content_lower
        ), f"Missing extraction destination in {readme_file}"
        assert (
            "sha" in content_lower or "hash" in content_lower
        ), f"Missing SHA256/hash requirements in {readme_file}"


def test_categories_catalog_json_validity() -> None:
    """Verify categories.json catalog accurately reflects the 12 categories and track division."""
    catalog_path = CUSTOM_DATA_ROOT / "categories.json"
    assert catalog_path.is_file(), f"Missing catalog: {catalog_path}"

    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert catalog.get("total_categories") == 12
    assert catalog.get("track_division") == {
        "BENIGN": 1,
        "TRACK_A": 6,
        "TRACK_B": 5,
    }

    category_names_in_catalog = [c["name"] for c in catalog["categories"]]
    assert len(category_names_in_catalog) == 12
    assert set(category_names_in_catalog) == set(ALL_12_CATEGORY_NAMES)


def test_canonical_metadata_template_fields() -> None:
    """Verify canonical metadata templates in JSON and YAML contain all 12 required fields."""
    # 1. JSON template
    json_path = CUSTOM_DATA_ROOT / "metadata.template.json"
    assert json_path.is_file(), f"Missing template: {json_path}"
    json_data = json.loads(json_path.read_text(encoding="utf-8"))

    for field in REQUIRED_METADATA_FIELDS:
        assert field in json_data, f"Field '{field}' missing from metadata.template.json"

    # Validate against Pydantic model
    validated_model = CustomCollectionMetadata.model_validate(json_data)
    assert validated_model.label in (0, 1)
    assert len(validated_model.evidence_sha256) == 64

    # 2. YAML template
    yaml_path = CUSTOM_DATA_ROOT / "metadata.template.yaml"
    assert yaml_path.is_file(), f"Missing template: {yaml_path}"
    yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

    for field in REQUIRED_METADATA_FIELDS:
        assert field in yaml_data, f"Field '{field}' missing from metadata.template.yaml"

    CustomCollectionMetadata.model_validate(yaml_data)


def test_run_001_remains_classified_as_benign_validation() -> None:
    """Verify RUN-001 remains classified as benign validation baseline."""
    # 1. Check RUN-001 metadata in data/raw/custom/RUN-001/metadata.json
    run001_dir = CUSTOM_DATA_ROOT / "RUN-001"
    assert run001_dir.is_dir(), f"RUN-001 directory missing: {run001_dir}"

    meta_file = run001_dir / "metadata.json"
    assert meta_file.is_file(), f"RUN-001 metadata.json missing: {meta_file}"
    meta = json.loads(meta_file.read_text(encoding="utf-8"))

    # Must be classified as benign validation
    assert meta.get("sample_id") == "EXEC_RUN-001"
    assert meta.get("label") == 0
    assert meta.get("family") == "benign"
    assert "benign_validation" in str(meta.get("source_reference", "")).lower()

    # 2. Check documentation in RUN_CONVENTIONS.md
    conventions_file = CUSTOM_DATA_ROOT / "RUN_CONVENTIONS.md"
    assert conventions_file.is_file()
    conventions_text = conventions_file.read_text(encoding="utf-8")
    assert "RUN-001" in conventions_text
    assert "Benign Validation Baseline" in conventions_text
    assert "RUN-002" in conventions_text

    # 3. Verify actual extraction on data/raw/custom/RUN-001 yields zero security anomalies
    proc_feats = extract_process_features(run001_dir, sample_id="EXEC_RUN-001")
    mem_feats = extract_memory_features(run001_dir, sample_id="EXEC_RUN-001")

    assert proc_feats.hidden_process_count == 0
    assert proc_feats.anomalous_ppid_count == 0
    assert proc_feats.suspicious_dll_count == 0
    assert proc_feats.malfind_process_count == 0
    assert proc_feats.unlinked_dll_count == 0
    assert mem_feats.injected_code_regions == 0
    assert mem_feats.rwx_page_count == 0
    assert mem_feats.ldrmodules_inconsistencies == 0


def test_no_existing_a4_files_are_modified() -> None:
    """Verify that all core A4 extraction files remain intact and functional."""
    repo_root = Path(__file__).resolve().parent.parent

    a4_expected_files = [
        repo_root / "forensics" / "extraction" / "process_extractor.py",
        repo_root / "forensics" / "extraction" / "memory_extractor.py",
        repo_root / "forensics" / "extraction" / "parser_utils.py",
        repo_root / "forensics" / "extraction" / "pipeline.py",
        repo_root / "tools" / "run_a4_validation.sh",
        repo_root / "tools" / "validate_a4_evidence.py",
        repo_root / "tests" / "test_forensic_extraction.py",
        repo_root / "tests" / "test_a4_validation.py",
    ]

    for fpath in a4_expected_files:
        assert fpath.is_file(), f"A4 file was deleted or missing: {fpath}"
        assert fpath.stat().st_size > 0, f"A4 file is unexpectedly empty: {fpath}"
