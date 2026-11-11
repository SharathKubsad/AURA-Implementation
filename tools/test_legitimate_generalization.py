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

rng = random.Random(42)
num_samples = 200

y_true_gen = []
y_pred_gen = []
y_prob_gen = []

for i in range(num_samples):
    is_malware = (i % 2 == 1)
    if is_malware:
        base = rng.choice(malware_records)
    else:
        base = rng.choice(benign_records)
        
    sid = f"GEN_{base['sample_id']}_{i:03d}"
    
    # Blinding: suppress handles, mask network volume and regularity, suppress command flags
    proc = ProcessFeatures(
        sample_id=sid,
        total_process_count=base.get("total_process_count", 140),
        hidden_process_count=0,  # Blinded
        anomalous_ppid_count=base.get("anomalous_ppid_count", 0),
        avg_threads_per_process=base.get("avg_threads_per_process", 12.0),
        max_threads_in_single_process=base.get("max_threads_in_single_process", 80),
        total_handle_count=int(base.get("total_process_count", 140) * 350),  # Blinded to normal ratio
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
        is_base64_encoded=0,  # Blinded
        has_download_cradle=0,  # Blinded
        has_bypass_execution_policy=0,  # Blinded
        has_hidden_window=0,  # Blinded
        uses_lolbins=0,  # Blinded
        registry_persistence_count=0,  # Blinded
    )
    
    net = NetworkFeatures(
        sample_id=sid,
        active_connection_count=0,  # Blinded
        listening_port_count=base.get("listening_port_count", 0),
        outbound_connection_count=0,  # Blinded
        dns_query_count=0,  # Blinded
        unique_remote_ips=0,  # Blinded
        avg_interpacket_interval_ms=0.0,  # Blinded
        beacon_regularity_score=0.0,  # Blinded
        total_bytes_sent=0,  # Blinded
        total_bytes_received=0,  # Blinded
        suspicious_port_usage=0,  # Blinded
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
    
    res = svc.detect(proc, cmd, net, mem)
    
    t = 1 if is_malware else 0
    p = 1 if res["is_malware"] else 0
    c = res["confidence"]
    
    y_true_gen.append(t)
    y_pred_gen.append(p)
    y_prob_gen.append(c)

print("=== REAL-BASED GENERALIZATION RESULTS (200 SAMPLES) ===")
print("Accuracy: ", round(float(accuracy_score(y_true_gen, y_pred_gen)), 4))
print("Precision:", round(float(precision_score(y_true_gen, y_pred_gen, zero_division=0)), 4))
print("Recall:   ", round(float(recall_score(y_true_gen, y_pred_gen, zero_division=0)), 4))
print("F1-Score: ", round(float(f1_score(y_true_gen, y_pred_gen, zero_division=0)), 4))
print("ROC-AUC:  ", round(float(roc_auc_score(y_true_gen, y_prob_gen)), 4))
print("Confusion Matrix:")
print(confusion_matrix(y_true_gen, y_pred_gen))
print(f"Mean conf Malware: {np.mean([c for t, c in zip(y_true_gen, y_prob_gen) if t == 1]):.4f}")
print(f"Mean conf Benign:  {np.mean([c for t, c in zip(y_true_gen, y_prob_gen) if t == 0]):.4f}")
