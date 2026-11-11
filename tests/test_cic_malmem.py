"""Unit and integration tests for CIC-MalMem-2022 ingestion and audit."""

from __future__ import annotations

import json
from pathlib import Path

from forensics.schemas.memory import MemoryFeatures
from forensics.schemas.process import ProcessFeatures
from tools.audit_cic_malmem import MalMemAuditor

_REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_CSV_PATH = (
    _REPO_ROOT / "data" / "raw" / "public" / "cic_malmem_2022" / "Obfuscated-MalMem2022.csv"
)
MANIFEST_PATH = _REPO_ROOT / "data" / "processed" / "public" / "cic_malmem_2022_manifest.json"
INTERIM_DIR = _REPO_ROOT / "data" / "interim" / "public" / "cic_malmem_2022"
EXPECTED_SHA256 = "624ecb6c9229cf62bd3b8f65d23a2b132760e6bada458aa46eee134a313840c4"


class TestCICMalMemIngestion:
    """Tests for verifying CIC-MalMem-2022 data integrity, schemas, and isolation."""

    def test_raw_csv_exists_and_verified(self) -> None:
        """Verify the raw CSV exists with exact size and checksum."""
        assert RAW_CSV_PATH.exists(), f"Raw CSV missing at {RAW_CSV_PATH}"
        assert RAW_CSV_PATH.stat().st_size == 18979873

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        assert manifest["source_file_sha256"] == EXPECTED_SHA256

    def test_manifest_sample_and_class_counts(self) -> None:
        """Verify exact sample counts and class balance in manifest."""
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        assert manifest["raw_sample_count"] == 58596
        assert manifest["valid_process_count"] == 58596
        assert manifest["valid_memory_count"] == 58596
        assert manifest["benign_count"] == 29298
        assert manifest["malware_count"] == 29298
        assert manifest["provenance_completeness"] == 100.0
        assert len(manifest["family_distribution"]) == 16
        assert manifest["adapter_version"] == "1.0.0"

    def test_interim_jsonl_schema_validation(self) -> None:
        """Verify sample records conform to ProcessFeatures, MemoryFeatures, and no-fabrication rule."""
        samples_file = INTERIM_DIR / "samples.jsonl"
        assert samples_file.exists()

        # Test first 100 sample lines
        with open(samples_file, encoding="utf-8") as f:
            for _ in range(100):
                line = f.readline()
                if not line:
                    break
                rec = json.loads(line)

                # ProcessFeatures validation
                assert rec["process"] is not None
                proc = ProcessFeatures.model_validate(rec["process"])
                assert proc.sample_id.startswith("MALMEM_")
                assert proc.total_process_count >= 0

                # MemoryFeatures validation
                assert rec["memory"] is not None
                mem = MemoryFeatures.model_validate(rec["memory"])
                assert mem.sample_id.startswith("MALMEM_")

                # No Command or Network fabrication
                assert rec["command"] is None
                assert rec["network"] is None

                # Provenance verification
                prov = rec["provenance"]
                assert prov["original_dataset"] == "CIC-MalMem-2022"
                assert prov["available_modalities"] == ["process", "memory"]

    def test_unmeasured_features_preserved_as_none(self) -> None:
        """Verify unmeasured features are preserved as None rather than synthetic zeros."""
        samples_file = INTERIM_DIR / "samples.jsonl"
        with open(samples_file, encoding="utf-8") as f:
            for _ in range(20):
                line = f.readline()
                rec = json.loads(line)
                proc = rec["process"]
                mem = rec["memory"]

                # Process unmeasured fields
                assert proc["anomalous_ppid_count"] is None
                assert proc["max_threads_in_single_process"] is None
                assert proc["suspicious_dll_count"] is None
                assert proc["elevated_privilege_count"] is None

                # Memory unmeasured fields
                assert mem["yara_shellcode_matches"] is None
                assert mem["mean_memory_entropy"] is None
                assert mem["max_memory_entropy"] is None

    def test_audit_cic_malmem_run(self) -> None:
        """Verify MalMemAuditor audits full dataset cleanly."""
        auditor = MalMemAuditor(
            interim_dir=INTERIM_DIR, processed_dir=_REPO_ROOT / "data" / "processed" / "public"
        )
        report = auditor.audit()

        assert report["audit_passed"] is True
        assert report["total_samples"] == 58596
        assert report["class_distribution"]["Benign"] == 29298
        assert report["class_distribution"]["Malware"] == 29298
        assert report["duplicate_sample_count"] == 0
        assert report["custom_dataset_isolation"]["status"] == "ISOLATED"
        assert report["schema_validity"]["process_schema_errors"] == 0
        assert report["schema_validity"]["memory_schema_errors"] == 0
        assert report["invalid_numeric_values"] == 0
        assert report["provenance_completeness"]["completeness_pct"] == 100.0

    def test_custom_dataset_zero_collision(self) -> None:
        """Ensure no collision between 45 custom samples and 58,596 MalMem samples."""
        custom_file = _REPO_ROOT / "data" / "processed" / "unified" / "unified_dataset.jsonl"
        if custom_file.exists():
            custom_ids = set()
            with open(custom_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        custom_ids.add(json.loads(line)["sample_id"])

            samples_file = INTERIM_DIR / "samples.jsonl"
            with open(samples_file, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        s_id = json.loads(line)["sample_id"]
                        assert s_id not in custom_ids
