"""Benchmark dataset generator for fileless malware detection.

Generates realistic telemetry traces across 11 malware families and benign profiles,
conforming to forensics.schemas (ProcessFeatures, CommandFeatures, NetworkFeatures,
MemoryFeatures, SampleMetadata).
Safe token representations used to prevent OS heuristic quarantine.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from forensics.schemas import (
    BinaryLabel,
    CommandFeatures,
    EnvironmentType,
    MemoryFeatures,
    NetworkFeatures,
    OperatingSystem,
    ProcessFeatures,
    SampleMetadata,
    SourceType,
)

# Canonical family directory mapping
MALWARE_FAMILY_SPECS: dict[int, dict[str, Any]] = {
    1: {
        "name": "PowerShell Fileless",
        "tokens": ["pwsh_cradle", "reflection_load", "b64_exec"],
        "entropy_range": (5.2, 6.8),
        "proc_bias": {
            "suspicious_dll": 2,
            "malfind": 1,
            "unlinked": 1,
            "hidden_proc": 0,
            "anom_ppid": 1,
        },
        "mem_bias": {"rwx": 3, "injected": 2, "unmapped": 1, "vad_anom": 2, "entropy": (5.5, 7.2)},
        "net_bias": {"beacon": 0.4, "outbound": 3, "dns": 5, "bytes_sent": (5000, 25000)},
    },
    2: {
        "name": "WMI Malware",
        "tokens": ["wmi_subscription", "wmi_process_call", "event_consumer"],
        "entropy_range": (4.6, 5.9),
        "proc_bias": {
            "suspicious_dll": 1,
            "malfind": 1,
            "unlinked": 0,
            "hidden_proc": 1,
            "anom_ppid": 2,
        },
        "mem_bias": {"rwx": 2, "injected": 1, "unmapped": 1, "vad_anom": 1, "entropy": (4.8, 6.5)},
        "net_bias": {"beacon": 0.3, "outbound": 2, "dns": 3, "bytes_sent": (2000, 15000)},
    },
    3: {
        "name": "Process Hollowing",
        "tokens": ["unmap_target", "thread_hijack", "hollow_svchost"],
        "entropy_range": (3.8, 5.2),
        "proc_bias": {
            "suspicious_dll": 4,
            "malfind": 3,
            "unlinked": 3,
            "hidden_proc": 1,
            "anom_ppid": 3,
        },
        "mem_bias": {"rwx": 5, "injected": 4, "unmapped": 3, "vad_anom": 4, "entropy": (6.0, 7.6)},
        "net_bias": {"beacon": 0.5, "outbound": 2, "dns": 2, "bytes_sent": (4000, 30000)},
    },
    4: {
        "name": "Reflective DLL Injection",
        "tokens": ["reflective_loader", "rundll_hook", "regsvr_scriptlet"],
        "entropy_range": (4.8, 6.2),
        "proc_bias": {
            "suspicious_dll": 5,
            "malfind": 3,
            "unlinked": 4,
            "hidden_proc": 0,
            "anom_ppid": 1,
        },
        "mem_bias": {"rwx": 6, "injected": 3, "unmapped": 4, "vad_anom": 5, "entropy": (6.2, 7.8)},
        "net_bias": {"beacon": 0.6, "outbound": 4, "dns": 4, "bytes_sent": (8000, 45000)},
    },
    5: {
        "name": "Registry Malware",
        "tokens": ["run_key_persistence", "winlogon_helper", "activex_reg"],
        "entropy_range": (4.5, 6.0),
        "proc_bias": {
            "suspicious_dll": 1,
            "malfind": 1,
            "unlinked": 0,
            "hidden_proc": 0,
            "anom_ppid": 1,
        },
        "mem_bias": {"rwx": 2, "injected": 1, "unmapped": 1, "vad_anom": 1, "entropy": (4.5, 6.2)},
        "net_bias": {"beacon": 0.2, "outbound": 1, "dns": 2, "bytes_sent": (1500, 8000)},
    },
    6: {
        "name": "Cobalt Strike Beacon",
        "tokens": ["named_pipe_beacon", "http_stager", "jitter_heartbeat"],
        "entropy_range": (5.8, 7.2),
        "proc_bias": {
            "suspicious_dll": 3,
            "malfind": 4,
            "unlinked": 3,
            "hidden_proc": 1,
            "anom_ppid": 2,
        },
        "mem_bias": {"rwx": 7, "injected": 5, "unmapped": 4, "vad_anom": 6, "entropy": (6.8, 7.9)},
        "net_bias": {"beacon": 0.88, "outbound": 6, "dns": 8, "bytes_sent": (12000, 60000)},
    },
    7: {
        "name": "Metasploit Memory Payloads",
        "tokens": ["meterpreter_rev_tcp", "mshta_stage", "in_memory_dll"],
        "entropy_range": (5.5, 7.0),
        "proc_bias": {
            "suspicious_dll": 3,
            "malfind": 4,
            "unlinked": 2,
            "hidden_proc": 1,
            "anom_ppid": 2,
        },
        "mem_bias": {"rwx": 6, "injected": 4, "unmapped": 3, "vad_anom": 5, "entropy": (6.5, 7.7)},
        "net_bias": {"beacon": 0.75, "outbound": 5, "dns": 6, "bytes_sent": (10000, 50000)},
    },
    8: {
        "name": "LOLBins Abuse",
        "tokens": ["certutil_download", "bitsadmin_job", "mshta_vbs"],
        "entropy_range": (4.2, 5.8),
        "proc_bias": {
            "suspicious_dll": 2,
            "malfind": 1,
            "unlinked": 1,
            "hidden_proc": 0,
            "anom_ppid": 2,
        },
        "mem_bias": {"rwx": 3, "injected": 2, "unmapped": 1, "vad_anom": 2, "entropy": (5.0, 6.8)},
        "net_bias": {"beacon": 0.45, "outbound": 3, "dns": 5, "bytes_sent": (4000, 22000)},
    },
    9: {
        "name": "Fileless Ransomware",
        "tokens": ["memory_key_gen", "shadow_inhibit", "rapid_crypto_stream"],
        "entropy_range": (4.9, 6.4),
        "proc_bias": {
            "suspicious_dll": 4,
            "malfind": 2,
            "unlinked": 1,
            "hidden_proc": 1,
            "anom_ppid": 1,
        },
        "mem_bias": {"rwx": 4, "injected": 2, "unmapped": 2, "vad_anom": 3, "entropy": (6.1, 7.8)},
        "net_bias": {"beacon": 0.5, "outbound": 3, "dns": 3, "bytes_sent": (8000, 35000)},
    },
    10: {
        "name": "Memory-only RAT",
        "tokens": ["stealth_agent", "encrypted_traffic", "dll_unlinked_hook"],
        "entropy_range": (5.4, 6.9),
        "proc_bias": {
            "suspicious_dll": 3,
            "malfind": 3,
            "unlinked": 2,
            "hidden_proc": 1,
            "anom_ppid": 2,
        },
        "mem_bias": {"rwx": 5, "injected": 4, "unmapped": 3, "vad_anom": 4, "entropy": (6.3, 7.6)},
        "net_bias": {"beacon": 0.82, "outbound": 5, "dns": 7, "bytes_sent": (11000, 48000)},
    },
    11: {
        "name": "Empire Framework",
        "tokens": ["empire_stager", "rest_c2_comm", "powershell_agent"],
        "entropy_range": (5.6, 7.1),
        "proc_bias": {
            "suspicious_dll": 3,
            "malfind": 3,
            "unlinked": 2,
            "hidden_proc": 1,
            "anom_ppid": 2,
        },
        "mem_bias": {"rwx": 6, "injected": 4, "unmapped": 3, "vad_anom": 5, "entropy": (6.4, 7.8)},
        "net_bias": {"beacon": 0.85, "outbound": 5, "dns": 6, "bytes_sent": (10000, 52000)},
    },
}

BENIGN_TOKENS = [
    "svchost_localservice",
    "powershell_backup_script",
    "git_status_check",
    "vscode_main_worker",
    "python_test_runner",
    "cmd_system_info",
    "curl_telemetry_get",
    "tasklist_query",
    "npm_build_worker",
    "dotnet_host_engine",
]


def _synthesize_command_line(family_id: int, is_malware: bool) -> tuple[str, int, int, int, int]:
    """Safely synthesize command line text and binary telemetry flags."""
    if not is_malware:
        token = random.choice(BENIGN_TOKENS)
        cmd_text = f"C:\\Windows\\System32\\service_host.exe --context={token} --session={random.randint(100, 999)}"
        return cmd_text, 0, 0, 0, 0

    spec = MALWARE_FAMILY_SPECS[family_id]
    token = random.choice(spec["tokens"])
    b64_flag = 1 if family_id in (1, 6, 7, 10, 11) else 0
    cradle_flag = 1 if family_id in (1, 6, 7, 8, 11) else 0
    bypass_flag = 1 if family_id in (1, 8, 11) else 0
    hidden_flag = 1 if family_id in (1, 2, 6, 10, 11) else 0

    cmd_text = f"powershell_host -NoProfile -ExecutionProfile Suspended --token={token} --b64={'AQIDBAUG' if b64_flag else 'none'}"
    return cmd_text, b64_flag, cradle_flag, bypass_flag, hidden_flag


def generate_sample(
    sample_idx: int,
    family_id: int,
    source_prefix: str = "EXEC",
) -> tuple[SampleMetadata, ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures]:
    """Generate a single cohesive sample conforming to all schemas."""
    sample_id = f"{source_prefix}_{datetime.now(UTC).strftime('%Y%m%d')}_{sample_idx:04d}"
    is_malware = family_id > 0
    binary_label = BinaryLabel.MALWARE if is_malware else BinaryLabel.BENIGN
    family_name = MALWARE_FAMILY_SPECS.get(family_id, {}).get("name", "Benign")

    timestamp = datetime.now(UTC) - timedelta(minutes=random.randint(1, 10000))
    os_choice = random.choice([OperatingSystem.WINDOWS_11, OperatingSystem.WINDOWS_10])
    env_choice = random.choice([EnvironmentType.VMWARE_WORKSTATION, EnvironmentType.VIRTUALBOX])

    metadata = SampleMetadata(
        sample_id=sample_id,
        source_type=(
            SourceType.CUSTOM_SANDBOX if source_prefix == "EXEC" else SourceType.PUBLIC_DATASET
        ),
        source_id=f"sha256_mock_{sample_idx:08x}",
        execution_id=f"RUN_{os_choice.value.upper()}_{sample_idx:04d}",
        timestamp=timestamp,
        operating_system=os_choice,
        environment=env_choice,
        binary_label=binary_label,
        family_label=family_id,
        family_name=family_name,
        operator="Automated Benchmark Harness",
        notes=f"Telemetry profile for {family_name}",
    )

    cmd_text, b64_flag, cradle_flag, bypass_flag, hidden_flag = _synthesize_command_line(
        family_id, is_malware
    )

    if not is_malware:
        cmd_feat = CommandFeatures(
            sample_id=sample_id,
            raw_command_text=cmd_text,
            command_length=len(cmd_text),
            shannon_entropy=round(random.uniform(2.8, 4.2), 2),
            is_base64_encoded=0,
            has_download_cradle=0,
            has_bypass_execution_policy=0,
            has_hidden_window=0,
            uses_lolbins=0,
            registry_persistence_count=0,
        )

        proc_feat = ProcessFeatures(
            sample_id=sample_id,
            total_process_count=random.randint(90, 140),
            hidden_process_count=0,
            anomalous_ppid_count=random.choice([0, 0, 0, 1]),
            avg_threads_per_process=round(random.uniform(9.0, 16.0), 2),
            max_threads_in_single_process=random.randint(35, 75),
            total_handle_count=random.randint(3500, 9500),
            suspicious_dll_count=0,
            malfind_process_count=0,
            elevated_privilege_count=random.randint(0, 2),
            unlinked_dll_count=0,
        )

        net_feat = NetworkFeatures(
            sample_id=sample_id,
            active_connection_count=random.randint(2, 12),
            listening_port_count=random.randint(6, 18),
            outbound_connection_count=random.randint(1, 5),
            dns_query_count=random.randint(1, 8),
            unique_remote_ips=random.randint(1, 4),
            avg_interpacket_interval_ms=round(random.uniform(80.0, 650.0), 2),
            beacon_regularity_score=round(random.uniform(0.02, 0.25), 3),
            total_bytes_sent=random.randint(1024, 25000),
            total_bytes_received=random.randint(4096, 95000),
            suspicious_port_usage=0,
        )

        mem_feat = MemoryFeatures(
            sample_id=sample_id,
            rwx_page_count=random.choice([0, 0, 0, 1]),
            injected_code_regions=0,
            unmapped_executable_pages=0,
            vad_protection_anomaly_count=0,
            ldrmodules_inconsistencies=0,
            yara_shellcode_matches=0,
            mean_memory_entropy=round(random.uniform(2.8, 4.4), 2),
            max_memory_entropy=round(random.uniform(4.0, 5.8), 2),
        )
    else:
        spec = MALWARE_FAMILY_SPECS[family_id]
        ent_low, ent_high = spec["entropy_range"]
        uses_lb = 1 if family_id in (4, 8) else 0

        cmd_feat = CommandFeatures(
            sample_id=sample_id,
            raw_command_text=cmd_text,
            command_length=len(cmd_text),
            shannon_entropy=round(random.uniform(ent_low, ent_high), 2),
            is_base64_encoded=b64_flag,
            has_download_cradle=cradle_flag,
            has_bypass_execution_policy=bypass_flag,
            has_hidden_window=hidden_flag,
            uses_lolbins=uses_lb,
            registry_persistence_count=(
                random.randint(1, 3) if family_id in (2, 5) else random.choice([0, 1])
            ),
        )

        pb = spec["proc_bias"]
        proc_feat = ProcessFeatures(
            sample_id=sample_id,
            total_process_count=random.randint(110, 160),
            hidden_process_count=pb["hidden_proc"] + random.choice([0, 1]),
            anomalous_ppid_count=pb["anom_ppid"] + random.choice([0, 1]),
            avg_threads_per_process=round(random.uniform(14.0, 26.0), 2),
            max_threads_in_single_process=random.randint(55, 120),
            total_handle_count=random.randint(7000, 18000),
            suspicious_dll_count=pb["suspicious_dll"] + random.choice([0, 1]),
            malfind_process_count=pb["malfind"] + random.choice([0, 1]),
            elevated_privilege_count=random.randint(2, 5),
            unlinked_dll_count=pb["unlinked"] + random.choice([0, 1]),
        )

        nb = spec["net_bias"]
        min_bytes, max_bytes = nb["bytes_sent"]
        net_feat = NetworkFeatures(
            sample_id=sample_id,
            active_connection_count=random.randint(8, 28),
            listening_port_count=random.randint(10, 30),
            outbound_connection_count=nb["outbound"] + random.randint(1, 4),
            dns_query_count=nb["dns"] + random.randint(2, 6),
            unique_remote_ips=random.randint(2, 7),
            avg_interpacket_interval_ms=round(random.uniform(40.0, 280.0), 2),
            beacon_regularity_score=round(
                min(max(nb["beacon"] + random.uniform(-0.06, 0.06), 0.1), 0.98), 3
            ),
            total_bytes_sent=random.randint(min_bytes, max_bytes),
            total_bytes_received=random.randint(min_bytes * 2, max_bytes * 3),
            suspicious_port_usage=1 if random.random() < 0.65 else 0,
        )

        mb = spec["mem_bias"]
        mem_low, mem_high = mb["entropy"]
        mem_feat = MemoryFeatures(
            sample_id=sample_id,
            rwx_page_count=mb["rwx"] + random.choice([0, 1, 2]),
            injected_code_regions=mb["injected"] + random.choice([0, 1]),
            unmapped_executable_pages=mb["unmapped"] + random.choice([0, 1]),
            vad_protection_anomaly_count=mb["vad_anom"] + random.choice([0, 1, 2]),
            ldrmodules_inconsistencies=(
                random.randint(1, 3) if family_id in (3, 4) else random.choice([0, 1])
            ),
            yara_shellcode_matches=(
                random.randint(1, 3) if family_id in (6, 7, 10) else random.choice([0, 1])
            ),
            mean_memory_entropy=round(random.uniform(mem_low - 0.4, mem_high - 0.4), 2),
            max_memory_entropy=round(random.uniform(mem_high, 7.92), 2),
        )

    return metadata, proc_feat, cmd_feat, net_feat, mem_feat


def generate_benchmark_dataset(
    total_samples: int = 1500,
    benign_ratio: float = 0.40,
    output_dir: Path | str = "data/processed",
) -> Path:
    """Generate full benchmark dataset and save as CSV and Parquet."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    records = []
    num_benign = int(total_samples * benign_ratio)
    num_malware = total_samples - num_benign

    sample_counter = 1
    # 1. Generate Benign samples
    for _ in range(num_benign):
        meta, proc, cmd, net, mem = generate_sample(
            sample_counter, family_id=0, source_prefix="PUB"
        )
        row = {
            **meta.model_dump(),
            **proc.model_dump(exclude={"sample_id"}),
            **cmd.model_dump(exclude={"sample_id"}),
            **net.model_dump(exclude={"sample_id"}),
            **mem.model_dump(exclude={"sample_id"}),
        }
        records.append(row)
        sample_counter += 1

    # 2. Generate Malware samples across 11 families
    families = list(MALWARE_FAMILY_SPECS.keys())
    for _ in range(num_malware):
        fam_id = random.choice(families)
        src_prefix = "EXEC" if random.random() < 0.6 else "PUB"
        meta, proc, cmd, net, mem = generate_sample(
            sample_counter, family_id=fam_id, source_prefix=src_prefix
        )
        row = {
            **meta.model_dump(),
            **proc.model_dump(exclude={"sample_id"}),
            **cmd.model_dump(exclude={"sample_id"}),
            **net.model_dump(exclude={"sample_id"}),
            **mem.model_dump(exclude={"sample_id"}),
        }
        records.append(row)
        sample_counter += 1

    df = pd.DataFrame(records)
    csv_file = output_path / "benchmark_dataset.csv"
    parquet_file = output_path / "benchmark_dataset.parquet"

    df.to_csv(csv_file, index=False)
    df.to_parquet(parquet_file, index=False)

    print(f"[BenchmarkGenerator] Successfully generated {len(df)} records -> {csv_file}")
    return csv_file


if __name__ == "__main__":
    generate_benchmark_dataset()
