import json
import random
import numpy as np
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from framework.detection_service import DetectionService
from forensics.schemas import ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures

svc = DetectionService()

with open("data/processed/unified/unified_dataset.jsonl", "r", encoding="utf-8") as f:
    records = [json.loads(line) for line in f if line.strip()]

benign_records = [r for r in records if r["binary_label"] == 0]
malware_records = [r for r in records if r["binary_label"] == 1]

print(f"Loaded {len(benign_records)} benign records and {len(malware_records)} malware records.")

rng = random.Random(42)
num_samples = 200

# ROBUSTNESS EXPERIMENT
y_true_rob = []
y_pred_rob = []
y_prob_rob = []

for i in range(num_samples):
    is_malware = (i % 2 == 1)
    if is_malware:
        base = rng.choice(malware_records)
    else:
        base = rng.choice(benign_records)
        
    sid = f"ROB_{base['sample_id']}_{i:03d}"
    
    proc = ProcessFeatures(
        sample_id=sid,
        total_process_count=base.get("total_process_count", 140),
        hidden_process_count=base.get("hidden_process_count", 0),
        anomalous_ppid_count=base.get("anomalous_ppid_count", 0),
        avg_threads_per_process=base.get("avg_threads_per_process", 12.0),
        max_threads_in_single_process=base.get("max_threads_in_single_process", 80),
        total_handle_count=base.get("total_handle_count", 50000),
        suspicious_dll_count=base.get("suspicious_dll_count", 0),
        malfind_process_count=base.get("malfind_process_count", 0),
        elevated_privilege_count=base.get("elevated_privilege_count", 0),
        unlinked_dll_count=base.get("unlinked_dll_count", 0),
    )
    
    cmd_text = base.get("raw_command_text", "")
    cmd = CommandFeatures(
        sample_id=sid,
        raw_command_text=cmd_text,
        command_length=len(cmd_text),
        shannon_entropy=base.get("shannon_entropy", 4.0),
        is_base64_encoded=base.get("is_base64_encoded", 0),
        has_download_cradle=base.get("has_download_cradle", 0),
        has_bypass_execution_policy=base.get("has_bypass_execution_policy", 0),
        has_hidden_window=base.get("has_hidden_window", 0),
        uses_lolbins=base.get("uses_lolbins", 0),
        registry_persistence_count=base.get("registry_persistence_count", 0),
    )
    
    net = NetworkFeatures(
        sample_id=sid,
        active_connection_count=base.get("active_connection_count", 0),
        listening_port_count=base.get("listening_port_count", 0),
        outbound_connection_count=base.get("outbound_connection_count", 0),
        dns_query_count=base.get("dns_query_count") or 0,
        unique_remote_ips=base.get("unique_remote_ips", 0),
        avg_interpacket_interval_ms=base.get("avg_interpacket_interval_ms") or 0.0,
        beacon_regularity_score=base.get("beacon_regularity_score") or 0.0,
        total_bytes_sent=base.get("total_bytes_sent") or 0,
        total_bytes_received=base.get("total_bytes_received") or 0,
        suspicious_port_usage=base.get("suspicious_port_usage", 0),
    )
    
    mem = MemoryFeatures(
        sample_id=sid,
        rwx_page_count=base.get("rwx_page_count", 0),
        injected_code_regions=base.get("injected_code_regions", 0),
        unmapped_executable_pages=base.get("unmapped_executable_pages", 0),
        vad_protection_anomaly_count=base.get("vad_protection_anomaly_count", 0),
        ldrmodules_inconsistencies=base.get("ldrmodules_inconsistencies", 0),
        yara_shellcode_matches=base.get("yara_shellcode_matches", 0),
        mean_memory_entropy=base.get("mean_memory_entropy") or 0.0,
        max_memory_entropy=base.get("max_memory_entropy") or 0.0,
    )
    
    if is_malware:
        # Adversarial perturbations to evade detection:
        # 1. Obfuscation stripping in command text
        if len(cmd.raw_command_text) > 20:
            cmd.raw_command_text = f"powershell.exe -w 1 {cmd.raw_command_text[20:]}"
        cmd.has_download_cradle = 0
        cmd.uses_lolbins = 0
        # 2. Beacon jitter & legitimate port evasion
        net.beacon_regularity_score = float(max(net.beacon_regularity_score - 0.35, 0.05))
        net.avg_interpacket_interval_ms = float(rng.uniform(300, 1200))
        net.suspicious_port_usage = 0
        # 3. Stealth process tree (mask anomalous PPID and reduce thread spike)
        proc.anomalous_ppid_count = 0
        proc.max_threads_in_single_process = int(proc.max_threads_in_single_process * 0.7)
    else:
        # Minor benign jitter
        proc.total_process_count += rng.randint(-5, 5)
        proc.total_handle_count += rng.randint(-500, 500)
        
    res = svc.detect(proc, cmd, net, mem)
    
    t = 1 if is_malware else 0
    p = 1 if res["is_malware"] else 0
    c = res["confidence"]
    
    y_true_rob.append(t)
    y_pred_rob.append(p)
    y_prob_rob.append(c)

print("=== REAL-BASED ROBUSTNESS RESULTS (200 SAMPLES) ===")
print("Accuracy: ", round(float(accuracy_score(y_true_rob, y_pred_rob)), 4))
print("Precision:", round(float(precision_score(y_true_rob, y_pred_rob, zero_division=0)), 4))
print("Recall:   ", round(float(recall_score(y_true_rob, y_pred_rob, zero_division=0)), 4))
print("F1-Score: ", round(float(f1_score(y_true_rob, y_pred_rob, zero_division=0)), 4))
print("ROC-AUC:  ", round(float(roc_auc_score(y_true_rob, y_prob_rob)), 4))
print("Confusion Matrix:")
print(confusion_matrix(y_true_rob, y_pred_rob))
print(f"Mean conf Malware: {np.mean([c for t, c in zip(y_true_rob, y_prob_rob) if t == 1]):.4f}")
print(f"Mean conf Benign:  {np.mean([c for t, c in zip(y_true_rob, y_prob_rob) if t == 0]):.4f}")
