# Legacy Artifact Inventory (Phase 3 Audit)
**Project:** Real-Time AI-Based Fileless Malware Detection and Classification System  
**Date:** 2026-09-24  
**Total Obsolete Artifacts Tagged for Deletion:** 117 (774.54 MB)  
**Total Ambiguous / Reference Artifacts Retained (KEEP):** 23 (0.47 MB)  

---

## 1. Candidate Artifacts for Controlled Deletion (DELETE)

| Relative Path | Size (KB) | Reason for Deletion | Dependency Check |
|---|:---:|---|---|
| `data/processed/unified/dataset_manifest.json` | 2.7 KB | Obsolete artifact inside legacy directory data/processed/unified | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/unified/feature_statistics.json` | 10.1 KB | Obsolete artifact inside legacy directory data/processed/unified | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/unified/unified_dataset.csv` | 6.9 KB | Obsolete artifact inside legacy directory data/processed/unified | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/unified/unified_dataset.jsonl` | 55.1 KB | Obsolete artifact inside legacy directory data/processed/unified | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/unified/unified_dataset_audit.csv` | 2.1 KB | Obsolete artifact inside legacy directory data/processed/unified | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/unified/unified_dataset_audit.json` | 22.3 KB | Obsolete artifact inside legacy directory data/processed/unified | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/process_dataset.jsonl` | 33.4 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/command_dataset.jsonl` | 1398.5 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/network_dataset.jsonl` | 24.2 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/memory_dataset.jsonl` | 25.4 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/process_rich_v3_candidate.jsonl` | 21.8 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/command_rich_v3_candidate.jsonl` | 1361.1 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/network_rich_v3_candidate.jsonl` | 13.2 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/memory_rich_v3_candidate.jsonl` | 17.7 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/benchmark_dataset.csv` | 606.2 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `data/processed/benchmark_dataset.parquet` | 150.0 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command/config.json` | 0.6 KB | Obsolete artifact inside legacy directory models/artifacts/command | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command/features.json` | 0.1 KB | Obsolete artifact inside legacy directory models/artifacts/command | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command/metadata.json` | 1.4 KB | Obsolete artifact inside legacy directory models/artifacts/command | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command/model.safetensors` | 261555.2 KB | Obsolete artifact inside legacy directory models/artifacts/command | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command/tokenizer.json` | 2.9 KB | Obsolete artifact inside legacy directory models/artifacts/command | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command/tokenizer_config.json` | 0.4 KB | Obsolete artifact inside legacy directory models/artifacts/command | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/config.json` | 0.7 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/cv_metrics.json` | 2.1 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/feature_names.json` | 0.0 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/metadata.json` | 0.8 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/model.safetensors` | 261555.2 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/tokenizer.json` | 695.0 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/command_v2/tokenizer_config.json` | 0.4 KB | Obsolete artifact inside legacy directory models/artifacts/command_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory/features.json` | 0.3 KB | Obsolete artifact inside legacy directory models/artifacts/memory | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory/metadata.json` | 1.5 KB | Obsolete artifact inside legacy directory models/artifacts/memory | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory/model.cbm` | 27.8 KB | Obsolete artifact inside legacy directory models/artifacts/memory | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory_v2/cv_metrics.json` | 2.4 KB | Obsolete artifact inside legacy directory models/artifacts/memory_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory_v2/feature_names.json` | 0.1 KB | Obsolete artifact inside legacy directory models/artifacts/memory_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory_v2/metadata.json` | 0.9 KB | Obsolete artifact inside legacy directory models/artifacts/memory_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/memory_v2/model.cbm` | 19.8 KB | Obsolete artifact inside legacy directory models/artifacts/memory_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network/features.json` | 0.5 KB | Obsolete artifact inside legacy directory models/artifacts/network | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network/metadata.json` | 2.0 KB | Obsolete artifact inside legacy directory models/artifacts/network | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network/model.joblib` | 7.1 KB | Obsolete artifact inside legacy directory models/artifacts/network | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network_v2/cv_metrics.json` | 2.3 KB | Obsolete artifact inside legacy directory models/artifacts/network_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network_v2/feature_names.json` | 0.1 KB | Obsolete artifact inside legacy directory models/artifacts/network_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network_v2/metadata.json` | 0.9 KB | Obsolete artifact inside legacy directory models/artifacts/network_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/network_v2/model.txt` | 24.3 KB | Obsolete artifact inside legacy directory models/artifacts/network_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process/features.json` | 0.4 KB | Obsolete artifact inside legacy directory models/artifacts/process | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process/metadata.json` | 1.6 KB | Obsolete artifact inside legacy directory models/artifacts/process | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process/model.json` | 53.3 KB | Obsolete artifact inside legacy directory models/artifacts/process | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process/scaler.joblib` | 0.8 KB | Obsolete artifact inside legacy directory models/artifacts/process | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process_v2/cv_metrics.json` | 2.5 KB | Obsolete artifact inside legacy directory models/artifacts/process_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process_v2/feature_names.json` | 0.2 KB | Obsolete artifact inside legacy directory models/artifacts/process_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process_v2/metadata.json` | 1.1 KB | Obsolete artifact inside legacy directory models/artifacts/process_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process_v2/model.json` | 65.4 KB | Obsolete artifact inside legacy directory models/artifacts/process_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/process_v2/scaler.joblib` | 0.7 KB | Obsolete artifact inside legacy directory models/artifacts/process_v2 | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/command/config.json` | 0.6 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/command/metadata.json` | 0.7 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/command/model.safetensors` | 261555.2 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/command/tokenizer.json` | 2.9 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/command/tokenizer_config.json` | 0.6 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/network/features.json` | 0.2 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/network/metadata.json` | 0.9 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cape_sandbox/network/model.joblib` | 70.1 KB | Obsolete artifact inside legacy directory models/artifacts/public_cape_sandbox | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/memory/catboost_model.cbm` | 98.5 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/memory/features_used.json` | 0.8 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/memory/training_metadata.json` | 2.5 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/process/features_used.json` | 0.7 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/process/scaler.joblib` | 0.7 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/process/training_metadata.json` | 2.4 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/public_cic_malmem/process/xgboost_model.json` | 279.0 KB | Obsolete artifact inside legacy directory models/artifacts/public_cic_malmem | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/scaler.joblib` | 2.7 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/artifacts/selected_features.json` | 0.9 KB | Obsolete legacy scalar ML feature dataset / model artifact / evaluation output | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/process/artifacts/features.json` | 0.3 KB | Obsolete artifact inside legacy directory models/process/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/process/artifacts/metrics.json` | 0.1 KB | Obsolete artifact inside legacy directory models/process/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/process/artifacts/process_model.xgb` | 179.2 KB | Obsolete artifact inside legacy directory models/process/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/memory/artifacts/features.json` | 0.3 KB | Obsolete artifact inside legacy directory models/memory/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/memory/artifacts/memory_model.xgb` | 218.2 KB | Obsolete artifact inside legacy directory models/memory/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/memory/artifacts/metrics.json` | 0.1 KB | Obsolete artifact inside legacy directory models/memory/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/network/artifacts/features.json` | 0.3 KB | Obsolete artifact inside legacy directory models/network/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/network/artifacts/metrics.json` | 0.1 KB | Obsolete artifact inside legacy directory models/network/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/network/artifacts/network_model.joblib` | 856.3 KB | Obsolete artifact inside legacy directory models/network/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/network/artifacts/network_model.txt` | 859.1 KB | Obsolete artifact inside legacy directory models/network/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/command/artifacts/command_model.joblib` | 196.4 KB | Obsolete artifact inside legacy directory models/command/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/command/artifacts/features.json` | 0.2 KB | Obsolete artifact inside legacy directory models/command/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/command/artifacts/metrics.json` | 0.1 KB | Obsolete artifact inside legacy directory models/command/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/family_label_map.json` | 0.3 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/features.json` | 1.1 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/label_mapping.json` | 0.3 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/loo_predictions.json` | 4.1 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/metrics.json` | 2.6 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/multiclass_model.ubj` | 409.0 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `models/multiclass/artifacts/multiclass_model.xgb` | 409.0 KB | Obsolete artifact inside legacy directory models/multiclass/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/binary/command_evaluation.json` | 2.3 KB | Obsolete artifact inside legacy directory evaluation/binary | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/binary/consolidated_report.json` | 2.8 KB | Obsolete artifact inside legacy directory evaluation/binary | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/binary/memory_evaluation.json` | 2.5 KB | Obsolete artifact inside legacy directory evaluation/binary | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/binary/network_evaluation.json` | 3.0 KB | Obsolete artifact inside legacy directory evaluation/binary | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/binary/process_evaluation.json` | 2.6 KB | Obsolete artifact inside legacy directory evaluation/binary | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/consolidated_audit_report.md` | 14.0 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/correlation_matrix.csv` | 3.0 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/correlation_report.json` | 2.3 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/current_model_reproduction.csv` | 0.5 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/current_model_reproduction.json` | 3.9 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/dataset_integrity.csv` | 2.9 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/dataset_integrity.json` | 14.5 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/feature_statistics.csv` | 5.9 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/feature_statistics.json` | 23.9 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/leakage_audit.json` | 3.6 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/manual_trace_6_samples.json` | 4.5 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/modality_score_analysis.csv` | 0.7 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/modality_score_analysis.json` | 5.4 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/model_artifact_audit.json` | 4.6 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/provenance_45_table.json` | 35.0 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/split_audit.json` | 3.7 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/threshold_sweep.csv` | 3.6 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/threshold_sweep.json` | 22.8 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/custom_audit/volatility3_extraction_audit.json` | 21.2 KB | Obsolete artifact inside legacy directory evaluation/custom_audit | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/generalization/artifacts/generalization_metrics.json` | 0.1 KB | Obsolete artifact inside legacy directory evaluation/generalization/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/robustness/artifacts/robustness_metrics.json` | 0.1 KB | Obsolete artifact inside legacy directory evaluation/robustness/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/xai/artifacts/lime_summary.json` | 1.0 KB | Obsolete artifact inside legacy directory evaluation/xai/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |
| `evaluation/xai/artifacts/shap_summary.json` | 2.2 KB | Obsolete artifact inside legacy directory evaluation/xai/artifacts | Obsolete scalar pipeline artifact; replaced by `data/forensic/` |

---

## 2. Retained Reference Artifacts (KEEP)

| Relative Path | Size (KB) | Classification Rationale |
|---|:---:|---|
| `data/processed/public/cic_malmem_2022_audit.json` | 2.9 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cic_malmem_2022_manifest.json` | 7.2 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cross_dataset_compatibility.json` | 47.1 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/public_benchmark_dataset.jsonl` | 14.3 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/public_compatibility_report.json` | 8.2 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/public_dataset_audit.json` | 1.2 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/public_dataset_manifest.json` | 2.8 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cape_sandbox/audit.csv` | 33.3 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cape_sandbox/audit.json` | 0.9 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cape_sandbox/compatibility.json` | 23.6 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cape_sandbox/dataset_decision.json` | 0.9 KB | Public benchmark metadata or baseline dataset inventory |
| `data/processed/public/cape_sandbox/schema_inventory.json` | 8.8 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/dataset_inventory/all_models_metadata.json` | 9.7 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/dataset_inventory/dataset_files_inventory.json` | 238.1 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/dataset_inventory/metadata_analysis.json` | 13.3 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/dataset_inventory/runs_inventory.json` | 58.9 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cape_sandbox/command_evaluation.json` | 0.7 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cape_sandbox/consolidated_report.json` | 1.1 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cape_sandbox/leakage_report.json` | 0.9 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cape_sandbox/network_evaluation.json` | 0.9 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cic_malmem/consolidated_report.json` | 2.4 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cic_malmem/memory_evaluation.json` | 3.4 KB | Public benchmark metadata or baseline dataset inventory |
| `evaluation/public_cic_malmem/process_evaluation.json` | 3.3 KB | Public benchmark metadata or baseline dataset inventory |