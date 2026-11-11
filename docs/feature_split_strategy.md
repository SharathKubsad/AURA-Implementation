# Run-Level Stratified Train / Validation / Test Split Strategy
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** 2026-09-24  
**Split Level:** Strict Execution RUN Level (Disjoint Partition)  

---

## 1. Split Philosophy & Leakage Prevention Rules

1. **Strict Run Disjointness:** No telemetry records or extracted features from any execution run appear in more than one partition.
2. **Family Stratification:** Every one of the 11 malware families is represented in the training set to establish multi-class and binary discernment baselines.
3. **Purity of Final Test Set:** The test set represents unseen execution runs across both benign operating states and multiple malware families. It remains strictly locked until final model evaluation.
4. **No Cross-Run Batch Bleed:** Validation and Test sets contain zero sample-ID, timing, or operational overlaps with the Training set.

---

## 2. Partition Summary Table

| Partition | Total Runs | Benign Runs (Label 0) | Malware Runs (Label 1) | Percentage of Dataset | Purpose |
|---|:---:|:---:|:---:|:---:|---|
| **Train** | **28** | 8 | 20 | 62.2% | Primary model weight optimization |
| **Validation** | **9** | 3 | 6 | 20.0% | Early stopping, validation threshold tuning |
| **Test** | **8** | 2 | 6 | 17.8% | Held-out benchmark evaluation |
| **Total** | **45** | **13** | **32** | **100.0%** | Full canonical custom dataset |

---

## 3. Explicit Run Assignment

### A. Training Runs (28)
`["RUN-001", "RUN-002", "RUN-100", "RUN-1000", "RUN-1001", "RUN-101", "RUN-1100", "RUN-1101", "RUN-1102", "RUN-1103", "RUN-1104", "RUN-1105", "RUN-1106", "RUN-200", "RUN-201", "RUN-300", "RUN-301", "RUN-400", "RUN-500", "RUN-501", "RUN-600", "RUN-601", "RUN-700", "RUN-701", "RUN-800", "RUN-801", "RUN-900", "RUN-901"]`

### B. Validation Runs (9)
`["RUN-003", "RUN-102", "RUN-1107", "RUN-1108", "RUN-1109", "RUN-202", "RUN-302", "RUN-402", "RUN-502"]`

### C. Test Runs (8)
`["RUN-1002", "RUN-1110", "RUN-1111", "RUN-401", "RUN-602", "RUN-702", "RUN-802", "RUN-902"]`
