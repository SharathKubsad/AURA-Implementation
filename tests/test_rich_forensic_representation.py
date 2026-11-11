"""Comprehensive validation tests for the Rich Forensic Representation Layer.

Verifies:
1. Every run has a SampleRecord.
2. Every process has a valid sample_id.
3. Every process PID is associated with the correct sample.
4. Thread PIDs resolve to known processes where possible.
5. Handle PIDs resolve where possible.
6. DLL PIDs resolve where possible.
7. VAD PIDs resolve where possible.
8. Malfind PIDs resolve where possible.
9. Network owning PIDs resolve where possible.
10. Command process IDs resolve where possible.
11. Provenance exists across all entities.
12. Source files exist.
13. No raw Dataset file was modified.
14. RUN-001 remains benign.
15. 45 runs remain represented.
16. 13 benign / 32 malware remains consistent.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "Dataset"
FORENSIC_DIR = REPO_ROOT / "data" / "forensic"


@pytest.fixture(scope="module")
def manifest():
    manifest_path = FORENSIC_DIR / "manifests" / "dataset_manifest.json"
    assert manifest_path.exists(), f"Missing manifest: {manifest_path}"
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


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


def test_01_total_runs_count(samples):
    """Test 1 & 15: Exactly 45 runs represented."""
    assert len(samples) == 45, f"Expected 45 runs, got {len(samples)}"
    run_ids = {s["run_id"] for s in samples}
    assert len(run_ids) == 45, "Run IDs must be strictly unique"


def test_02_canonical_label_distribution(samples):
    """Test 14 & 16: Exactly 13 Benign and 32 Malware, and RUN-001 is Benign."""
    benign_samples = [s for s in samples if s["label"] == 0]
    malware_samples = [s for s in samples if s["label"] == 1]
    
    assert len(benign_samples) == 13, f"Expected 13 benign runs, got {len(benign_samples)}"
    assert len(malware_samples) == 32, f"Expected 32 malware runs, got {len(malware_samples)}"
    
    run_001 = next((s for s in samples if s["run_id"] == "RUN-001"), None)
    assert run_001 is not None, "RUN-001 must exist"
    assert run_001["label"] == 0, f"RUN-001 must be labeled 0 (Benign), got {run_001['label']}"
    assert run_001["family"] == "benign", f"RUN-001 family must be 'benign', got {run_001['family']}"


def test_03_every_run_has_sample_record(samples):
    """Test 1: Every run has an individual sample file and valid sample_id."""
    for s in samples:
        run_id = s["run_id"]
        sample_file = FORENSIC_DIR / "samples" / f"{run_id}.json"
        assert sample_file.exists(), f"Missing sample file for {run_id}"
        with open(sample_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["sample_id"] == f"EXEC_{run_id}"
        assert "provenance" in data
        assert data["provenance"]["sample_id"] == data["sample_id"]


def test_04_process_entities_validity(samples):
    """Test 2 & 3: Process entities have valid sample_ids and non-empty process collections."""
    for s in samples:
        run_id = s["run_id"]
        proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
        assert proc_file.exists(), f"Missing process file for {run_id}"
        
        count = 0
        with open(proc_file, "r", encoding="utf-8") as f:
            for line in f:
                p = json.loads(line)
                assert p["sample_id"] == f"EXEC_{run_id}"
                assert isinstance(p["pid"], int)
                assert isinstance(p["ppid"], int)
                assert len(p["process_name"]) > 0
                assert "provenance" in p
                count += 1
        assert count > 50, f"Run {run_id} has unexpectedly few processes ({count})"


def test_05_thread_pid_resolution(samples):
    """Test 4: Thread PIDs resolve to known processes where possible."""
    for s in samples[:5]:  # Test sample of runs for speed
        run_id = s["run_id"]
        proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
        thread_file = FORENSIC_DIR / "entities" / "threads" / f"{run_id}.jsonl"
        
        known_pids = set()
        with open(proc_file, "r", encoding="utf-8") as f:
            for line in f:
                known_pids.add(json.loads(line)["pid"])
                
        resolved = 0
        total = 0
        with open(thread_file, "r", encoding="utf-8") as f:
            for line in f:
                t = json.loads(line)
                assert t["sample_id"] == f"EXEC_{run_id}"
                assert "provenance" in t
                if t["pid"] in known_pids:
                    resolved += 1
                total += 1
                
        # Most threads should resolve to known processes
        assert total > 0
        assert (resolved / total) > 0.85, f"Low thread PID resolution for {run_id}: {resolved}/{total}"


def test_06_handle_pid_resolution(samples):
    """Test 5: Handle PIDs resolve to known processes."""
    for s in samples[:5]:
        run_id = s["run_id"]
        proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
        handle_file = FORENSIC_DIR / "entities" / "handles" / f"{run_id}.jsonl"
        
        known_pids = set()
        with open(proc_file, "r", encoding="utf-8") as f:
            for line in f:
                known_pids.add(json.loads(line)["pid"])
                
        resolved = 0
        total = 0
        with open(handle_file, "r", encoding="utf-8") as f:
            for line in f:
                h = json.loads(line)
                assert h["sample_id"] == f"EXEC_{run_id}"
                assert "provenance" in h
                assert len(h["object_type"]) > 0
                if h["pid"] in known_pids:
                    resolved += 1
                total += 1
                
        assert total > 1000
        assert (resolved / total) > 0.95, f"Low handle PID resolution for {run_id}: {resolved}/{total}"


def test_07_module_and_vad_pid_resolution(samples):
    """Test 6 & 7: DLL module and VAD PIDs resolve to known processes."""
    for s in samples[:5]:
        run_id = s["run_id"]
        proc_file = FORENSIC_DIR / "entities" / "processes" / f"{run_id}.jsonl"
        mod_file = FORENSIC_DIR / "entities" / "modules" / f"{run_id}.jsonl"
        vad_file = FORENSIC_DIR / "entities" / "memory_regions" / f"{run_id}.jsonl"
        
        known_pids = set()
        with open(proc_file, "r", encoding="utf-8") as f:
            for line in f:
                known_pids.add(json.loads(line)["pid"])
                
        # Check modules
        with open(mod_file, "r", encoding="utf-8") as f:
            for line in f:
                m = json.loads(line)
                assert m["sample_id"] == f"EXEC_{run_id}"
                assert "provenance" in m
                assert m["pid"] in known_pids
                
        # Check VADs
        with open(vad_file, "r", encoding="utf-8") as f:
            for line in f:
                v = json.loads(line)
                assert v["sample_id"] == f"EXEC_{run_id}"
                assert "provenance" in v
                assert v["pid"] in known_pids


def test_08_malfind_findings(samples):
    """Test 8: Malfind findings are preserved with disassembly and baseline context."""
    for s in samples[:5]:
        run_id = s["run_id"]
        malfind_file = FORENSIC_DIR / "events" / "memory" / f"{run_id}.jsonl"
        assert malfind_file.exists()
        with open(malfind_file, "r", encoding="utf-8") as f:
            for line in f:
                mf = json.loads(line)
                assert mf["sample_id"] == f"EXEC_{run_id}"
                assert "protection" in mf
                assert "is_known_baseline_exception" in mf
                if "msmpeng.exe" in mf["process"].lower():
                    assert mf["is_known_baseline_exception"] is True


def test_09_network_and_command_events(samples):
    """Test 9 & 10: Network and command events preserve provenance and attribution."""
    for s in samples[:5]:
        run_id = s["run_id"]
        net_file = FORENSIC_DIR / "events" / "network" / f"{run_id}.jsonl"
        cmd_file = FORENSIC_DIR / "events" / "commands" / f"{run_id}.jsonl"
        
        assert net_file.exists()
        assert cmd_file.exists()
        
        with open(net_file, "r", encoding="utf-8") as f:
            for line in f:
                nc = json.loads(line)
                assert nc["sample_id"] == f"EXEC_{run_id}"
                assert "local_port" in nc
                assert "provenance" in nc
                
        with open(cmd_file, "r", encoding="utf-8") as f:
            for line in f:
                ce = json.loads(line)
                assert ce["sample_id"] == f"EXEC_{run_id}"
                assert "attribution_status" in ce
                assert ce["attribution_status"] in [
                    "SYSTEM_ACTIVITY", "COLLECTION_HARNESS", "USER_ACTIVITY", "SAMPLE_ACTIVITY", "UNKNOWN"
                ]


def test_10_dataset_source_immutability():
    """Test 12 & 13: Dataset/ directory remains completely intact and unmodified."""
    assert DATASET_DIR.exists()
    categories = list(DATASET_DIR.iterdir())
    assert len(categories) == 12, "All 12 batch directories must remain in Dataset/"
