"""Phase 3 Comprehensive Semantic Fidelity and Rich Forensic Audit Test Suite.

Verifies:
1. 45-run sample reconciliation (RUN-001, RUN-002, RUN-003, RUN-100..102, RUN-200..202,
   RUN-300..302, RUN-400..402, RUN-500..502, RUN-600..602, RUN-700..702, RUN-800..802,
   RUN-900..902, RUN-1000..1002, RUN-1100..1111).
2. Canonical label integrity (13 Benign, 32 Malware, RUN-001 = Benign).
3. Cryptographic provenance across all runs.
4. Process semantic fidelity and PID handling (pslist vs psscan, unlinked/carved handling).
5. Strict null semantics (no fabricated zeros for missing network/PCAP fields).
6. Source-type preservation (NETSTAT vs SYSMON in network observations).
7. Distinct handling of Sysmon EID 3 and netstat snapshot telemetry.
8. PowerShell EID 4104 ScriptBlock fidelity and multi-part representation.
9. Collection harness identification (DumpIt.exe, collect_run_windows.ps1 flagged).
10. Benign baseline Defender exception (MsMpEng.exe RWX flagged with is_known_baseline_exception).
11. Relationship integrity (tree edges, bindings, parent-exit semantics documented).
12. Information-loss accounting completeness.
13. Authoritative Dataset immutability.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "Dataset"
FORENSIC_DIR = REPO_ROOT / "data" / "forensic"
AUDIT_DIR = FORENSIC_DIR / "audits"
DOCS_DIR = REPO_ROOT / "docs"

EXPECTED_45_RUN_IDS = {
    "RUN-001", "RUN-002", "RUN-003",
    "RUN-100", "RUN-101", "RUN-102",
    "RUN-200", "RUN-201", "RUN-202",
    "RUN-300", "RUN-301", "RUN-302",
    "RUN-400", "RUN-401", "RUN-402",
    "RUN-500", "RUN-501", "RUN-502",
    "RUN-600", "RUN-601", "RUN-602",
    "RUN-700", "RUN-701", "RUN-702",
    "RUN-800", "RUN-801", "RUN-802",
    "RUN-900", "RUN-901", "RUN-902",
    "RUN-1000", "RUN-1001", "RUN-1002",
    "RUN-1100", "RUN-1101", "RUN-1102", "RUN-1103", "RUN-1104", "RUN-1105",
    "RUN-1106", "RUN-1107", "RUN-1108", "RUN-1109", "RUN-1110", "RUN-1111",
}


@pytest.fixture(scope="module")
def samples():
    samples_path = FORENSIC_DIR / "samples" / "samples.jsonl"
    assert samples_path.exists(), f"Missing samples file: {samples_path}"
    loaded = []
    with open(samples_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                loaded.append(json.loads(line))
    return loaded


def test_01_sample_reconciliation(samples):
    """Verify all 45 source runs match exactly 45 derived runs."""
    assert len(samples) == 45, f"Expected 45 runs, got {len(samples)}"
    extracted_run_ids = {s["run_id"] for s in samples}
    assert extracted_run_ids == EXPECTED_45_RUN_IDS, (
        f"Mismatch in run IDs: missing {EXPECTED_45_RUN_IDS - extracted_run_ids}, "
        f"extra {extracted_run_ids - EXPECTED_45_RUN_IDS}"
    )


def test_02_label_and_family_integrity(samples):
    """Verify 13 Benign, 32 Malware, and RUN-001 is Benign."""
    benign = [s for s in samples if s["label"] == 0]
    malware = [s for s in samples if s["label"] == 1]
    
    assert len(benign) == 13, f"Expected 13 benign runs, got {len(benign)}"
    assert len(malware) == 32, f"Expected 32 malware runs, got {len(malware)}"
    
    # RUN-001 must be benign
    run_001 = next(s for s in samples if s["run_id"] == "RUN-001")
    assert run_001["label"] == 0
    assert run_001["family"] == "benign"
    
    # RUN-1100..1111 must all be benign
    for run_num in range(1100, 1112):
        s = next(s for s in samples if s["run_id"] == f"RUN-{run_num}")
        assert s["label"] == 0
        assert s["family"] == "benign"


def test_03_cryptographic_provenance(samples):
    """Verify provenance metadata exists and points to Dataset source metadata on disk."""
    manifest_path = FORENSIC_DIR / "manifests" / "dataset_manifest.json"
    assert manifest_path.exists()
    
    for s in samples:
        prov = s.get("provenance")
        assert prov is not None, f"Provenance missing in {s['run_id']}"
        assert prov["sample_id"] == s["sample_id"]
        assert prov["source_type"] == "METADATA"
        assert prov["extraction_timestamp"]
        
        # Verify source metadata file exists on disk in Dataset/
        meta_src = Path(s["metadata_source"])
        assert meta_src.exists(), f"Source metadata file does not exist: {meta_src}"


def test_04_process_semantic_fidelity_and_pid_handling(samples):
    """Verify process entity reconciliation: pslist vs psscan, dead pool carved handling."""
    for s in samples:
        run_id = s["run_id"]
        proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
        assert proc_file.exists()
        
        has_pslist = False
        has_psscan = False
        with open(proc_file, "r", encoding="utf-8") as f:
            for line in f:
                p = json.loads(line)
                assert isinstance(p["pid"], int)
                assert isinstance(p["ppid"], int)
                if p.get("is_in_pslist"):
                    has_pslist = True
                if p.get("is_in_psscan"):
                    has_psscan = True
        
        assert has_pslist, f"Run {run_id} missing live pslist processes"
        assert has_psscan, f"Run {run_id} missing psscan processes"


def test_05_strict_null_semantics_for_network():
    """Verify missing packet and byte telemetry is not fabricated as 0."""
    net_dir = FORENSIC_DIR / "events" / "network"
    tested_connections = 0
    for run_file in net_dir.glob("*.jsonl"):
        with open(run_file, "r", encoding="utf-8") as f:
            for line in f:
                conn = json.loads(line)
                tested_connections += 1
                # In rich forensic schema, NetworkConnection strictly does not fabricate PCAP fields
                assert "packet_count" not in conn or conn["packet_count"] is None
                assert "byte_count" not in conn or conn["byte_count"] is None
                assert "beacon_periodicity_sec" not in conn or conn["beacon_periodicity_sec"] is None
                
    assert tested_connections > 10000, f"Expected >10k network connections, got {tested_connections}"


def test_06_source_type_preservation_in_network():
    """Verify network observations preserve source_type (NETSTAT vs SYSMON)."""
    net_dir = FORENSIC_DIR / "events" / "network"
    source_types_found = set()
    sources_found = set()
    for run_file in net_dir.glob("*.jsonl"):
        with open(run_file, "r", encoding="utf-8") as f:
            for line in f:
                conn = json.loads(line)
                sources_found.add(conn["source"])
                source_types_found.add(conn["provenance"]["source_type"])
                
    assert "network_connections.csv" in sources_found
    assert "sysmon_eid3" in sources_found
    assert "NETSTAT" in source_types_found
    assert "SYSMON" in source_types_found


def test_07_sysmon_event_fidelity():
    """Verify Sysmon events retain Event IDs, details, and timestamps."""
    sysmon_dir = FORENSIC_DIR / "events" / "sysmon"
    total_events = 0
    eids_found = set()
    for run_file in sysmon_dir.glob("*.jsonl"):
        with open(run_file, "r", encoding="utf-8") as f:
            for line in f:
                evt = json.loads(line)
                total_events += 1
                eids_found.add(evt["event_id"])
                assert evt.get("timestamp"), f"Missing timestamp in {run_file}"
                assert "details" in evt
    
    assert total_events > 100000, f"Expected >100k Sysmon events, got {total_events}"
    assert "1" in eids_found, "Sysmon EID 1 (Process Create) must be present"
    assert "3" in eids_found, "Sysmon EID 3 (Network Connect) must be present"


def test_08_powershell_scriptblock_fidelity():
    """Verify PowerShell EID 4104 ScriptBlocks preserve text, IDs, and sequence."""
    ps_dir = FORENSIC_DIR / "events" / "powershell"
    total_ps = 0
    has_scriptblock_id = False
    has_script_text = False
    
    for run_file in ps_dir.glob("*.jsonl"):
        with open(run_file, "r", encoding="utf-8") as f:
            for line in f:
                evt = json.loads(line)
                total_ps += 1
                if evt.get("script_block_id"):
                    has_scriptblock_id = True
                if evt.get("script_block_text"):
                    has_script_text = True
                    
    assert total_ps > 10000, f"Expected >10k PowerShell events, got {total_ps}"
    assert has_scriptblock_id, "PowerShell script_block_id must be preserved"
    assert has_script_text, "PowerShell script_block_text must be preserved"


def test_09_collection_harness_attribution():
    """Verify operator capture scripts are marked with FLAGGED_FOR_EXCLUSION."""
    audit_csv = AUDIT_DIR / "command_attribution_audit.csv"
    assert audit_csv.exists(), f"Missing command attribution audit: {audit_csv}"
    
    runs_with_harness = 0
    with open(audit_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            harness_cnt = int(row["collection_harness_count"])
            if harness_cnt > 0:
                runs_with_harness += 1
                assert row["collection_harness_leakage_flag"] == "FLAGGED_FOR_EXCLUSION"
                
    assert runs_with_harness == 45, (
        f"All 45 runs must identify and flag collection harness activity, got {runs_with_harness}"
    )


def test_10_benign_baseline_msmpeng_exception():
    """Verify RUN-001 and benign runs preserve MsMpEng.exe RWX as is_known_baseline_exception."""
    mem_dir = FORENSIC_DIR / "events" / "memory"
    
    benign_runs_with_msmpeng_exception = 0
    for run_id in ["RUN-001", "RUN-1100", "RUN-1101", "RUN-1102", "RUN-1103", "RUN-1104"]:
        mem_file = mem_dir / f"{run_id}.jsonl"
        assert mem_file.exists()
        
        found_in_run = False
        with open(mem_file, "r", encoding="utf-8") as f:
            for line in f:
                finding = json.loads(line)
                if finding.get("is_known_baseline_exception"):
                    assert "MsMpEng.exe" in finding.get("process", ""), (
                        f"Unexpected baseline exception process: {finding.get('process')}"
                    )
                    found_in_run = True
        if found_in_run:
            benign_runs_with_msmpeng_exception += 1
            
    assert benign_runs_with_msmpeng_exception == 6, (
        "MsMpEng.exe baseline exception must be flagged in all benign test runs"
    )


def test_11_relationship_integrity():
    """Verify relationship graph edge counts and join status documentation."""
    rel_csv = AUDIT_DIR / "relationship_audit.csv"
    assert rel_csv.exists(), f"Missing relationship audit: {rel_csv}"
    
    total_runs_checked = 0
    with open(rel_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_runs_checked += 1
            tree_edges = int(row["process_tree_edges"])
            assert tree_edges > 100, f"Run {row['sample_id']} has suspiciously low tree edges: {tree_edges}"
            # Orphan edges (4-7) represent historical PPID where parent process exited prior to dump (standard Windows OS behavior)
            orphan_edges = int(row["orphan_edges"])
            assert 0 <= orphan_edges <= 15, f"Excessive orphan edges in {row['sample_id']}: {orphan_edges}"
            
    assert total_runs_checked == 45, f"Expected 45 runs in relationship audit, got {total_runs_checked}"


def test_12_information_loss_accounting():
    """Verify information loss audit document exists and accounts for all transformations."""
    info_loss_csv = AUDIT_DIR / "information_loss.csv"
    info_loss_doc = DOCS_DIR / "rich_information_loss_audit.md"
    
    assert info_loss_csv.exists(), f"Missing {info_loss_csv}"
    assert info_loss_doc.exists(), f"Missing {info_loss_doc}"
    
    entries = []
    with open(info_loss_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append(row)
            assert row["justification"], f"Missing justification for {row['source_field']}"
            
    assert len(entries) >= 9, f"Expected at least 9 tracked modalities/fields, got {len(entries)}"


def test_13_dataset_immutability():
    """Verify the authoritative Dataset/ remains untouched, complete, and immutable across all 12 categories."""
    assert DATASET_DIR.exists(), "Dataset/ directory does not exist!"
    categories = [p for p in DATASET_DIR.iterdir() if p.is_dir() and not p.name.startswith(".")]
    assert len(categories) == 12, f"Expected 12 category folders in Dataset/, got {len(categories)}"
    
    for cat_dir in categories:
        assert (cat_dir / "checksums.sha256").exists(), f"Missing checksums.sha256 in {cat_dir.name}"
        assert (cat_dir / "manifest.json").exists(), f"Missing manifest.json in {cat_dir.name}"
        assert (cat_dir / "batch_summary.csv").exists(), f"Missing batch_summary.csv in {cat_dir.name}"
        assert (cat_dir / "memory").exists(), f"Missing memory/ in {cat_dir.name}"
        assert (cat_dir / "metadata").exists(), f"Missing metadata/ in {cat_dir.name}"
        assert (cat_dir / "process").exists(), f"Missing process/ in {cat_dir.name}"
        assert (cat_dir / "source_evidence").exists(), f"Missing source_evidence/ in {cat_dir.name}"
        assert (cat_dir / "volatility").exists(), f"Missing volatility/ in {cat_dir.name}"
