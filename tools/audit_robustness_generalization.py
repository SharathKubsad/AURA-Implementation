import json
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from framework.detection_service import DetectionService
from preprocessing.benchmark_generator import generate_sample

svc = DetectionService()

print("=== PHASE 1 AUDIT: ROBUSTNESS & GENERALIZATION ORIENTATION ===")
print(f"{'sample_id':<12} | {'true':<5} | {'pred':<5} | {'p_malware':<10} | {'p_benign':<10} | {'proc':<6} | {'cmd':<6} | {'net':<6} | {'mem':<6}")
print("-" * 88)

y_true = []
y_pred = []
y_conf = []

for i in range(20):
    is_malware = i % 2 == 1
    family_id = (i % 11) + 1 if is_malware else 0
    meta, proc, cmd, net, mem = generate_sample(10000 + i, family_id=family_id)
    
    if is_malware:
        cmd.raw_command_text = f"powershell.exe -w 1 {cmd.raw_command_text[30:]}"
        cmd.has_download_cradle = 0
        cmd.uses_lolbins = 0
        net.beacon_regularity_score = float(max(net.beacon_regularity_score - 0.35, 0.15))
        net.suspicious_port_usage = 0
    
    res = svc.detect(proc, cmd, net, mem)
    
    t = 1 if is_malware else 0
    p = 1 if res["is_malware"] else 0
    p_malware = res["confidence"]
    p_benign = 1.0 - p_malware
    
    y_true.append(t)
    y_pred.append(p)
    y_conf.append(p_malware)
    
    pm = res["per_model"]
    print(f"{meta.sample_id:<12} | {t:<5} | {p:<5} | {p_malware:<10.4f} | {p_benign:<10.4f} | {pm.get('process', 0):<6.4f} | {pm.get('command', 0):<6.4f} | {pm.get('network', 0):<6.4f} | {pm.get('memory', 0):<6.4f}")

print("\n--- Summary Metrics (First 20 Samples) ---")
print("Accuracy: ", accuracy_score(y_true, y_pred))
print("Precision:", precision_score(y_true, y_pred, zero_division=0))
print("Recall:   ", recall_score(y_true, y_pred, zero_division=0))
print("F1:       ", f1_score(y_true, y_pred, zero_division=0))
print("ROC-AUC:  ", roc_auc_score(y_true, y_conf) if len(set(y_true)) > 1 else "N/A")

# Compare mean probabilities for true benign vs true malware
mean_malware_conf = np.mean([c for t, c in zip(y_true, y_conf) if t == 1])
mean_benign_conf = np.mean([c for t, c in zip(y_true, y_conf) if t == 0])
print(f"\nMean confidence for True Malware: {mean_malware_conf:.4f}")
print(f"Mean confidence for True Benign:  {mean_benign_conf:.4f}")
