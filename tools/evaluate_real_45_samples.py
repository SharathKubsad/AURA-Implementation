import json
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from framework.detection_service import DetectionService
from forensics.schemas import ProcessFeatures, CommandFeatures, NetworkFeatures, MemoryFeatures

svc = DetectionService()

with open("data/processed/unified/unified_dataset.jsonl", "r", encoding="utf-8") as f:
    rows = [json.loads(line) for line in f if line.strip()]

print(f"Loaded {len(rows)} authentic unified samples.")

y_true = []
y_pred = []
y_conf = []

print(f"{'sample_id':<14} | {'family':<25} | {'t':<2} | {'p':<2} | {'conf':<7} | {'proc':<6} | {'cmd':<6} | {'net':<6} | {'mem':<6}")
print("-" * 95)

for r in rows:
    t = r["binary_label"]
    sample_id = r["sample_id"]
    family = r.get("family", "unknown")
    
    proc = ProcessFeatures(
        sample_id=sample_id,
        total_process_count=r.get("total_process_count", 0),
        hidden_process_count=r.get("hidden_process_count", 0),
        anomalous_ppid_count=r.get("anomalous_ppid_count", 0),
        avg_threads_per_process=r.get("avg_threads_per_process", 0.0),
        max_threads_in_single_process=r.get("max_threads_in_single_process", 0),
        total_handle_count=r.get("total_handle_count", 0),
        suspicious_dll_count=r.get("suspicious_dll_count", 0),
        malfind_process_count=r.get("malfind_process_count", 0),
        elevated_privilege_count=r.get("elevated_privilege_count", 0),
        unlinked_dll_count=r.get("unlinked_dll_count", 0),
    )
    
    cmd = CommandFeatures(
        sample_id=sample_id,
        raw_command_text=r.get("raw_command_text", ""),
        command_length=r.get("command_length", 0),
        shannon_entropy=r.get("shannon_entropy", 0.0),
        is_base64_encoded=r.get("is_base64_encoded", 0),
        has_download_cradle=r.get("has_download_cradle", 0),
        has_bypass_execution_policy=r.get("has_bypass_execution_policy", 0),
        has_hidden_window=r.get("has_hidden_window", 0),
        uses_lolbins=r.get("uses_lolbins", 0),
        registry_persistence_count=r.get("registry_persistence_count", 0),
    )
    
    net = NetworkFeatures(
        sample_id=sample_id,
        active_connection_count=r.get("active_connection_count", 0),
        listening_port_count=r.get("listening_port_count", 0),
        outbound_connection_count=r.get("outbound_connection_count", 0),
        dns_query_count=r.get("dns_query_count") or 0,
        unique_remote_ips=r.get("unique_remote_ips", 0),
        avg_interpacket_interval_ms=r.get("avg_interpacket_interval_ms") or 0.0,
        beacon_regularity_score=r.get("beacon_regularity_score") or 0.0,
        total_bytes_sent=r.get("total_bytes_sent") or 0,
        total_bytes_received=r.get("total_bytes_received") or 0,
        suspicious_port_usage=r.get("suspicious_port_usage", 0),
    )
    
    mem = MemoryFeatures(
        sample_id=sample_id,
        rwx_page_count=r.get("rwx_page_count", 0),
        injected_code_regions=r.get("injected_code_regions", 0),
        unmapped_executable_pages=r.get("unmapped_executable_pages", 0),
        vad_protection_anomaly_count=r.get("vad_protection_anomaly_count", 0),
        ldrmodules_inconsistencies=r.get("ldrmodules_inconsistencies", 0),
        yara_shellcode_matches=r.get("yara_shellcode_matches", 0),
        mean_memory_entropy=r.get("mean_memory_entropy") or 0.0,
        max_memory_entropy=r.get("max_memory_entropy") or 0.0,
    )
    
    res = svc.detect(proc, cmd, net, mem)
    p = 1 if res["is_malware"] else 0
    c = res["confidence"]
    
    y_true.append(t)
    y_pred.append(p)
    y_conf.append(c)
    
    pm = res["per_model"]
    print(f"{sample_id:<14} | {family:<25} | {t:<2} | {p:<2} | {c:<7.4f} | {pm.get('process', 0):<6.4f} | {pm.get('command', 0):<6.4f} | {pm.get('network', 0):<6.4f} | {pm.get('memory', 0):<6.4f}")

print("\n=== OVERALL DETECTION PERFORMANCE ON AUTHENTIC 45 SAMPLES ===")
print("Accuracy: ", round(float(accuracy_score(y_true, y_pred)), 4))
print("Precision:", round(float(precision_score(y_true, y_pred, zero_division=0)), 4))
print("Recall:   ", round(float(recall_score(y_true, y_pred, zero_division=0)), 4))
print("F1-Score: ", round(float(f1_score(y_true, y_pred, zero_division=0)), 4))
print("ROC-AUC:  ", round(float(roc_auc_score(y_true, y_conf)), 4))
print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))

mean_mal = np.mean([c for t, c in zip(y_true, y_conf) if t == 1])
mean_ben = np.mean([c for t, c in zip(y_true, y_conf) if t == 0])
print(f"\nMean confidence Malware: {mean_mal:.4f}")
print(f"Mean confidence Benign:  {mean_ben:.4f}")
