# Multiclass Model Data Requirements & Architecture Analysis

**Date:** 2026-09-22  
**Purpose:** Formal scientific evaluation of multiclass malware family classification under extreme low-sample constraints (N=33 total malware runs across 11 families).  
**Status:** SPECIFICATION ONLY — NO CODE OR DATA MODIFIED.

---

## 1. The Fundamental Statistical Challenge

The custom dataset in `Dataset/` contains exactly 11 malware families with **3 execution runs per family**:

| Family Name | Batch Directory | Execution Run IDs | Sample Support ($N_k$) |
|---|---|---|---|
| `powershell_fileless` | `custom_powershell_fileless/` | `RUN-001`, `RUN-002`, `RUN-003` | 3 |
| `process_hollowing` | `custom_process_hollowing/` | `RUN-100`, `RUN-101`, `RUN-102` | 3 |
| `memory_only_rat` | `custom_memory_only_rat/` | `RUN-200`, `RUN-201`, `RUN-202` | 3 |
| `registry_resident_malware`| `custom_registry_resident_malware/`| `RUN-300`, `RUN-301`, `RUN-302` | 3 |
| `cobalt_strike_beacon` | `custom_cobalt_strike_beacon/` | `RUN-400`, `RUN-401`, `RUN-402` | 3 |
| `metasploit_memory_payloads`| `custom_metasploit_memory_payloads/`| `RUN-500`, `RUN-501`, `RUN-502` | 3 |
| `wmi_malware` | `custom_wmi_malware/` | `RUN-600`, `RUN-601`, `RUN-602` | 3 |
| `reflective_dll_injection` | `custom_reflective_dll_injection/` | `RUN-700`, `RUN-701`, `RUN-702` | 3 |
| `lolbins_abuse` | `custom_lolbins_abuse/` | `RUN-800`, `RUN-801`, `RUN-802` | 3 |
| `fileless_ransomware` | `custom_fileless_ransomware/` | `RUN-900`, `RUN-901`, `RUN-902` | 3 |
| `empire_framework` | `custom_empire_framework/` | `RUN-1000`, `RUN-1001`, `RUN-1002`| 3 |
| **Total** | **11 Families** | **33 Malware Runs** | **33 Total** |

### 1.1 The Statistical Reality
- A 33-sample dataset evaluated across 11 classes has an expected random chance accuracy of:
  $$P(\text{Random}) = \frac{1}{11} \approx 9.09\%$$
- In standard 5-fold cross-validation, each fold test set would contain approximately 6.6 samples, meaning 4 to 5 classes would have **zero representation in the test fold**, while the training folds would have only 2 samples per class.
- In Leave-One-Out Cross-Validation (LOO-CV), exactly 1 sample is held out and 32 are used for training (leaving 2 samples for the target class).
- When the previous model was trained on corrupted features (fallback strings and constant network features), LOO-CV accuracy was **9.38%**, perfectly matching random guessing!

---

## 2. Architecture Comparison: Direct Raw Features vs. Stacked/Fusion Model

We evaluated two architectural approaches for Objective 3 (Multiclass Extension):

### Approach A: Direct Raw/Evidence-Derived Multiclass Model
In this approach, the multiclass classifier is trained directly on a concatenated vector of all genuine engineered features from the four modalities ($X_{\text{process}} \cup X_{\text{memory}} \cup X_{\text{command\_heuristics}} \cup X_{\text{network}}$).

- **Dimensionality:** ~29 features.
- **Sample Size:** $N = 33$ samples.
- **Ratio of Samples to Dimensions:** $33 / 29 \approx 1.14$.
- **Risk:** Extreme curse of dimensionality. Gradient boosted trees with depth 3 will easily overfit on individual VM artifacts (e.g. slight timing variations) rather than generalizable family behaviors.
- **Advantage:** Preserves fine-grained differences that may be lost in modality aggregation.

### Approach B: Stacked / Confidence-Fusion Multiclass Model
In this approach, the multiclass classifier takes the **4 posterior probability scores / logits** from the binary detectors ($P_{\text{process}}, P_{\text{command}}, P_{\text{network}}, P_{\text{memory}}$) plus a small set of high-leverage family discriminators (e.g. `uses_lolbins`, `ldrmodules_inconsistencies`, `has_download_cradle`, `c2_port`).

- **Dimensionality:** 4 probabilities + 4 categorical flags = 8 dimensions.
- **Sample Size:** $N = 33$ samples.
- **Ratio of Samples to Dimensions:** $33 / 8 \approx 4.1$.
- **Advantage:** Substantially more constrained parameter space. Regularized linear models (Logistic Regression with L2) or shallow Random Forests can achieve stable convergence without memorizing run-specific noise.
- **Risk:** Relies heavily on the binary models being well-calibrated.

---

## 3. Recommended Multiclass Strategy & Requirements

To achieve statistically defensible, honest results for Objective 3 without data fabrication:

1. **Feature Set:**
   Use a **Compact Discriminator Vector (10 to 12 features)** consisting of features that have direct causal links to specific malware mechanics:
   - `uses_lolbins` (Flags `lolbins_abuse`)
   - `anomalous_ppid_wmi` (Flags `wmi_malware`)
   - `unlinked_dll_count` (Flags `reflective_dll_injection`)
   - `hidden_process_count` (Flags `process_hollowing`)
   - `named_pipe_count` (Flags `cobalt_strike_beacon`)
   - `c2_nonstandard_port` (Flags `metasploit_memory_payloads` / `empire_framework`)
   - `shannon_entropy_command` (Flags `powershell_fileless`)
   - `vad_protection_anomaly_count` (Flags in-memory reflective loaders)
   - Binary detector confidence scores ($P_{\text{proc}}, P_{\text{mem}}, P_{\text{cmd}}, P_{\text{net}}$).

2. **Validation Strategy:**
   - Must use **Leave-One-Out Cross-Validation (LOO-CV)** over the 33 samples.
   - All evaluation documentation must explicitly publish the per-class confusion matrix, precision, recall, and state that $N=3$ per family represents an experimental prototype proof-of-concept rather than an enterprise-scale classifier.
   - If enterprise-grade statistical power is required, the custom runs must be merged with external benchmark public corpora (e.g. CIC-MalMem2022).
