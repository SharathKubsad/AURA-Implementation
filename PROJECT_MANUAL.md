# PROJECT MANUAL — Hybrid ML Framework for Fileless Malware Detection
### Full build plan, 2-person work division, and step-by-step execution guide
This document is self-contained. It restates the requirements in working form, assigns every task to an owner, and gives exact steps/commands for each phase. Pair it with `AGENTS.md` if an AI coding agent is doing implementation work alongside you.

---

## 0. Executive Summary — What You're Building

Four objectives, one pipeline:

- **Objective 1 — Benchmark Dataset:** Merge public fileless-malware datasets with a custom dataset you generate yourself (run real fileless malware families in isolated VMs, capture memory dumps, extract Process/Command/Network/Memory features with Volatility3), producing one standardized, labeled dataset.
- **Objective 2 — Real-Time Hybrid Detector:** Four independent binary models (Process=XGBoost, Command=RoBERTa/DistilBERT, Network=LightGBM, Memory=CatBoost). Live telemetry is scored by the first three continuously; if any flags suspicion, a **partial** memory dump is pulled and scored by the Memory model; all four confidence scores are averaged and compared to a **0.60 threshold** for the final Benign/Malware call.
- **Objective 3 — Multi-Class Family Classification:** When Objective 2 says "Malware," reuse the same four feature vectors (no new extraction), fuse them into one vector, and classify the malware family with a multi-class XGBoost model.
- **Objective 4 — Assurance Layer:** Prove the framework generalizes (test on unseen malware variants and unseen feature subsets) and is explainable (SHAP global/local + LIME per-sample).

Everything below turns this into buildable work, split fairly across two people.

---

## 1. Ground Rules Before You Start

1. **One shared dataset schema, decided jointly, before either of you writes a training script.** See §3.7.
2. **All malware execution happens in isolated VMs, never on a host machine, never bridged to a real network.** See §4.3 — this is non-negotiable and applies to both of you equally.
3. **Git from day one**, with the branch/ownership rules in `AGENTS.md`. Two people editing a notebook by emailing `.ipynb` files back and forth is how this kind of project quietly falls apart — don't do that.
4. **Track experiments in MLflow from the first training run.** "Production grade" is judged on reproducibility as much as accuracy — you want to be able to say exactly which run produced which number, months from now.

---

## 2. Two-Person Work Division

### 2.1 Why split this way
The four feature domains (Process, Command, Network, Memory) naturally form two pairs of similar engineering character:
- **Process + Memory** are both tabular/structured, forensic-artifact-driven, and tie directly into systems engineering (live collectors, the FastAPI service, deployment).
- **Command + Network** are both sequence/log-driven (Command needs NLP tokenization; Network is tabular but log-heavy) and tie directly into the evaluation/assurance layer (both objectives 3 and 4 consume outputs from these two more than the others, since malware-family signal is strongest in command text and beaconing patterns).

Splitting by these two pairs means **each person owns exactly two of the four models end-to-end** (data → features → training → live collector), which is the fairest atomic unit of work here. On top of their two models, each person owns one "extra" workstream sized to balance total effort:
- Track A's extra is **systems/DevSecOps work** (the real-time framework backbone, fusion engine, API, deployment, CI).
- Track B's extra is **Objective 3 + Objective 4** (multi-class classifier, robustness/generalization testing, SHAP/LIME, final metrics reporting).

Both extras are comparable in size (roughly 3–4 weeks of focused work each — see the timeline in §9).

### 2.2 Suggested assignment
Given your cybersecurity-honours + DevOps/DevSecOps direction, **you're the natural fit for Track A** (you already have the systems/security background this track leans on) and your teammate takes **Track B** (modeling + evaluation depth). This is a suggestion, not a requirement — the split is symmetric enough to swap wholesale if your teammate prefers the systems side.

### 2.3 Track A — "Core Detection Engine" (Structured Signals + Systems)

| # | Task | Deliverable |
|---|---|---|
| A1 | Sandbox infrastructure setup (Windows 10, Windows 11, one Linux VM) | Reusable VM images + snapshot workflow, documented in `sandbox/vm-configs/` |
| A2 | Execute malware set 1 (6 families, §2.5) inside the sandboxes | Raw memory dumps + execution metadata logged |
| A3 | Memory acquisition tooling (DumpIt / WinPMEM / LiME) | Repeatable acquisition scripts |
| A4 | Volatility3 extraction pipeline — **Process + Memory** plugins | `forensics/extraction/process_extractor.py`, `memory_extractor.py` |
| A5 | Public dataset sub-collection: CIC-MalMem-2022, EMBER | Cleaned pull scripts + raw files in `data/raw/public/` |
| A6 | Train **Process Model (XGBoost)** | Serialized model + MLflow run + metrics |
| A7 | Train **Memory Model (CatBoost)** | Serialized model + MLflow run + metrics |
| A8 | Live collectors: process + memory-trigger | `framework/live_collectors/process_collector.py`, `memory_trigger.py` |
| A9 | Confidence fusion engine + threshold decision | `framework/fusion/fuse.py` |
| A10 | FastAPI detection service | `framework/api/main.py` |
| A11 | Docker Compose, CI pipeline, repo scaffolding | `docker-compose.yml`, `.github/workflows/ci.yml` |

### 2.4 Track B — "Modeling, Language Signals & Assurance" (Command/Network + Objectives 3–4)

| # | Task | Deliverable |
|---|---|---|
| B1 | Execute malware set 2 (5 families, §2.5) inside the sandboxes | Raw memory dumps + execution metadata logged |
| B2 | Network capture tooling (tshark alongside every run) + command/log capture (PowerShell transcript + ScriptBlock logging, Bash history, WMI event logs) | Repeatable capture scripts |
| B3 | Volatility3 extraction pipeline — **Command + Network** plugins/log parsers | `forensics/extraction/command_extractor.py`, `network_extractor.py` |
| B4 | Public dataset sub-collection: SOREL-20M, MalwareBazaar, VX-Underground, Any.Run, VirusShare, Hybrid Analysis | Cleaned pull scripts + raw files in `data/raw/public/` |
| B5 | Preprocessing pipeline: dedup, missing values, normalization, one-hot encoding, SMOTE/ADASYN balancing, feature scaling/engineering, feature selection (MI, RFE, SHAP) | `preprocessing/pipeline.py` |
| B6 | Train **Command Model (DistilBERT, upgrade path to RoBERTa)** | Serialized model + MLflow run + metrics |
| B7 | Train **Network Model (LightGBM)** | Serialized model + MLflow run + metrics |
| B8 | Live collectors: command + network | `framework/live_collectors/command_collector.py`, `network_collector.py` |
| B9 | Objective 3: feature fusion vector + multi-class XGBoost + API integration | `models/multiclass/`, extended API response schema |
| B10 | Objective 4: robustness + generalization test design and execution | `evaluation/robustness/`, `evaluation/generalization/` |
| B11 | Objective 4: SHAP (global + local) and LIME integration + final metrics report | `evaluation/xai/`, `docs/final_report.md` |

### 2.5 Malware execution split (11 families from the requirements doc)

| Owner | Families |
|---|---|
| Track A (set 1, 6 families) | PowerShell Malware, Process Hollowing, Memory-only RAT, Registry-resident Malware, Cobalt Strike Beacon, Metasploit Memory Payloads |
| Track B (set 2, 5 families) | WMI Malware, Reflective DLL Injection, LOLBins Abuse, Fileless Ransomware, Empire Framework |

Note: whoever runs a sample captures **all four** feature categories from that one run (a single execution produces one row with process + command + network + memory columns) — this split is only about dividing the manual sandbox labor evenly, not about which model "gets" which malware family.

### 2.6 Joint work (do these together, not solo)
- Phase 0 environment/repo bootstrap (§3)
- Dataset schema & labeling convention (§3.7) — get this wrong and both of your pipelines produce incompatible outputs
- Dataset merge (Public + Custom → Standardized Benchmark Dataset)
- End-to-end integration testing (§8)
- Final report, demo recording, and defense/viva prep (§10)

---

## 3. Phase 0 — Repository & Environment Bootstrap (Joint, do this first)

1. Create the repo with the exact folder structure in `AGENTS.md` §2. Commit `AGENTS.md`, this manual, and an empty structure with `.gitkeep` files first.
2. Write `.gitignore` immediately, before any data exists:
   ```
   data/raw/
   *.raw
   *.mem
   *.vmem
   *.dmp
   *.lime
   *.pcap
   *.pcapng
   .venv/
   mlruns/
   *.env
   ```
3. Create `pyproject.toml` / `requirements.txt` with (minimum set — add as needed):
   ```
   pandas numpy scikit-learn imbalanced-learn
   xgboost lightgbm catboost
   transformers torch
   shap lime
   fastapi uvicorn pydantic
   psutil pyshark scapy
   mlflow dvc
   pytest black ruff pre-commit
   ```
4. `python3.11 -m venv .venv && pip install -r requirements.txt`
5. `pre-commit install` with hooks for `black`, `ruff`, and a basic secret/large-file scan.
6. `docker compose up -d mlflow` — confirm the MLflow UI loads at `localhost:5000`.
7. Set up branch protection on `main`: require 1 review, require CI to pass.
8. Both of you do a "hello world" PR (any trivial doc fix) to confirm the CI + review flow works before real work starts.

**Acceptance criteria:** repo exists with full folder tree, CI runs green on an empty PR, both people can push branches and open PRs.

---

## 4. Phase 1 — Objective 1: Benchmark Dataset Engineering

### 4.1 Public dataset collection

| Source | Owner | What to keep |
|---|---|---|
| CIC-MalMem-2022 | Track A | Process + memory-relevant columns only |
| EMBER | Track A | Static/process-adjacent features that map to your schema |
| SOREL-20M | Track B | Metadata + behavioral fields usable for command/network mapping |
| MalwareBazaar samples | Track B | Sample metadata (hash, family tag) — do not download live binaries to a host machine |
| VX-Underground | Track B | Reference/metadata only |
| Any.Run Reports | Track B | Behavioral report exports (process/command/network trees) |
| VirusShare | Track B | Metadata/hash lists |
| Hybrid Analysis | Track B | Behavioral report exports |

For every source: **discard disk-based/static-file features** — the project is scoped to process, command, network, and memory behavior only. Log what you kept and why in `data/raw/public/<source>/NOTES.md`.

### 4.2 Sandbox environment setup (Track A leads infra, both use it)

Use a **two-role VM topology**, not one all-in-one VM — this matters because Network features (DNS beaconing, C2 traffic, packet timing) only exist if traffic actually crosses a wire between two machines. Running a payload entirely inside a single VM against itself gives you almost no real network signal to extract.

1. Install a hypervisor: VMware Workstation/Fusion, VirtualBox, or Hyper-V (pick one consistently across the team). VMware is a perfectly standard choice for this.
2. Create:
   - **One Attacker/C2 VM — Kali Linux.** This is the right use for Kali here: it ships with Metasploit preinstalled and is a clean launch point for Empire, Cobalt Strike trial/community edition, and PowerSploit-style techniques against a target.
   - **Target/Victim VMs** — Windows 10, Windows 11 (preferred where a choice exists), and one separate Ubuntu VM for the Linux-targeted families (e.g., LOLBins abuse on Linux). **These target VMs are what you dump memory from** — Kali itself is not sampled.
3. Put the Attacker VM and every Target VM on the **same isolated host-only/internal virtual network**, with no route to the internet or your real LAN. This gives you genuine C2/beaconing traffic to capture (needed for §4.5's Network features) while staying fully contained.
4. Disable shared folders, clipboard sharing, and drag-and-drop between host and every guest.
5. Fully patch and configure each Target VM once, then take a **clean baseline snapshot** of it — this is what you revert to after every single execution. (Kali doesn't need reverting between runs; it isn't the machine being forensically sampled.)
6. Inside each Target VM, install: Sysmon (Windows, with a process-creation + network-connection config), PowerShell Script Block + Transcript logging (via registry/GPO), Volatility3-compatible symbol tables, and (on the VM being dumped) DumpIt or WinPMEM; on the Ubuntu Target VM install LiME (built as a kernel module) and auditd.
7. Document this exact setup once in `sandbox/vm-configs/README.md`: the Attacker VM config, each Target VM's baseline, and the internal network name/subnet — so it's reproducible without repeating the work.

**Where an agentic coding tool (Antigravity, Claude Code, etc.) fits:** use it to write and maintain the *scripts around* this setup — the Volatility wrapper scripts, the snapshot/revert helper, the log-parsing pipeline, the FastAPI service — not to autonomously decide when to trigger a malware run. VMware+Kali and an agentic coding assistant aren't alternatives to each other; they sit at different layers. The hypervisor is where the malware actually runs, in isolation; the agentic tool is a developer aid for the code you write around it. Step 2 of §4.3 below — verifying network isolation before every single run — is a manual, per-run judgment call by a person. That's the actual safety control here, and it's the one step to keep manual regardless of which coding agent you use for everything else.

### 4.3 Malware execution protocol (safety-critical — read before running anything)

For **every single sample**, in this exact order:
1. Revert the VM to the clean baseline snapshot.
2. Confirm network adapter is Host-Only/isolated (check every time — this is the step people skip and regret).
3. Start Sysmon/logging, start a `tshark` capture on the VM's virtual interface, start PowerShell transcript logging if applicable.
4. From the **Attacker/Kali VM**, launch the malware family's known behavior against the Target VM using an already-existing, named, publicly documented framework or technique appropriate to that family (e.g., Metasploit modules for Metasploit Memory Payloads, the Empire framework for Empire-based execution, PowerSploit-style scripts for PowerShell/reflective-DLL techniques, Cobalt Strike trial/community edition for Beacon behavior). Use samples/frameworks from the public sources in §4.1 — do not write new payload code.
5. Let it run for a fixed observation window (recommend 3–5 minutes) to generate realistic process/command/network activity.
6. Acquire the memory dump (see §4.4) **before** reverting.
7. Stop all captures, export the `.pcap`, transcript logs, and Sysmon event export.
8. Record one row in `sandbox/execution-logs/log.csv`: `sample_id, family, vm, os, timestamp, operator, sample_sha256, notes`.
9. Revert to the clean snapshot immediately. Never run a second sample on a "dirty" VM.
10. Store any retained sample file as a password-protected zip (password: `infected`) outside the git repo; log only its path.

Repeat this for all 11 families per §2.5, ideally 2–3 runs per family (more samples = a more robust dataset, and you need enough volume for the train/test splits in Objective 4).

### 4.4 Memory acquisition

- **Windows:** `DumpIt.exe` (preferred, run as Administrator, produces a raw memory image) or `winpmem_mini_x64.exe output.raw` as a fallback.
- **Linux:** build and load LiME: `insmod lime.ko "path=/mnt/evidence/<sample_id>.lime format=lime"`.
- Acquire **immediately** after the observation window in §4.3, before the malware's in-memory footprint changes or gets cleaned up.

### 4.5 Forensic feature extraction (Volatility3)

Run these plugins against every dump and parse the output into your feature schema (§3.7). Suggested plugin-to-feature mapping:

**Process features** (Track A): `windows.pslist`, `windows.psscan`, `windows.pstree` (parent-child + PID/PPID), `windows.threads` (thread count), `windows.handles` (handle count), `windows.dlllist` (DLL loading), `windows.malfind` (injection indicators), `windows.psxview` (hidden processes), `windows.privileges` (privilege level/tokens). Linux equivalents: `linux.pslist`, `linux.pstree`, `linux.psaux`.

**Memory features** (Track A): `windows.malfind` (injected code + RWX regions), `windows.vadinfo` (memory regions), `windows.ldrmodules` (reflective loading indicators), `windows.dlllist` cross-referenced for anomalies, plus a YARA scan (`windows.vadyarascan`) for known shellcode signatures, and a memory-entropy calculation you write yourself over the raw pages.

**Command features** (Track B): `windows.cmdline` (command lines per process), `windows.registry.printkey`/`hivelist` for registry execution artifacts, plus parsing of the PowerShell transcript/ScriptBlock logs and Sysmon Event ID 1 for encoded-command and LOLBins detection. Linux: `linux.bash` for shell history.

**Network features** (Track B): `windows.netscan`/`windows.netstat` for connection state at dump time, cross-referenced with the `tshark` `.pcap` for DNS/HTTP/HTTPS requests, beacon-interval timing (inter-packet gaps to the same remote IP), and bytes transmitted. Linux: `linux.netstat` (or `linux.sockstat`).

Each extractor script should output one row per sample into `data/interim/<category>/<sample_id>.json`, conforming to the pydantic schema for that category.

### 4.6 Preprocessing (Track B owns the pipeline, run against the full merged raw set)

In `preprocessing/pipeline.py`, in this order:
1. Remove duplicate records (hash the feature row, drop exact dupes).
2. Handle missing values (impute or drop per-column based on missingness rate — document the rule per feature).
3. Normalize numerical features (StandardScaler or MinMaxScaler — pick one and note it in `docs/`).
4. One-hot encode categorical features.
5. Balance classes with **SMOTE** or **ADASYN** (try both, keep whichever gives better validation F1 without overfitting the minority class).
6. Feature engineering: derive any composite features you find useful (e.g., entropy buckets, beacon regularity score).
7. Feature selection: run **Mutual Information**, **Recursive Feature Elimination**, and **SHAP feature importance**; keep features that show up as important in at least two of the three methods.

### 4.7 Merge into the standardized benchmark dataset

Merge the Public Dataset output (§4.1) with the Custom Dataset output (§4.5 → §4.6) into one table with exactly these columns:

`sample_id | process_features... | command_features... | network_features... | memory_features... | binary_label | malware_family`

### 4.8 Labels (fixed convention — use exactly this everywhere)

Binary: `0 = Benign, 1 = Malware`

Multi-class (pick your final 4–5 families from what you actually collected in §2.5):
`0 = Benign, 1 = PowerShell Fileless, 2 = WMI Malware, 3 = Process Hollowing, 4 = Reflective DLL Injection, 5 = Registry Malware`

**Acceptance criteria for Phase 1:** one versioned (DVC-tracked) CSV/Parquet file in `data/processed/`, a data card in `docs/dataset_card.md` describing sources, class balance, and known limitations, and both people can load it and get identical shapes.

---

## 5. Phase 2 — Objective 2: Real-Time Hybrid Detection Framework

### 5.1 Train the four base models
Standard split: 70/15/15 train/val/test, stratified on `binary_label`. Log every run to MLflow.

| Model | Owner | Library | Notes |
|---|---|---|---|
| Process | Track A | XGBoost | Start with `max_depth=6, n_estimators=300, learning_rate=0.05`; tune via `optuna` or grid search on val F1 |
| Memory | Track A | CatBoost | Handles categorical memory-region features natively; start with `iterations=500, depth=6` |
| Command | Track B | DistilBERT (upgrade to RoBERTa if compute allows) | Fine-tune on tokenized command-line text; max seq length ~128; 3–5 epochs, learning rate 2e-5 |
| Network | Track B | LightGBM | Start with `num_leaves=31, n_estimators=300` |

Report per model: Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, and confusion matrix — save each as an MLflow artifact.

### 5.2 Live feature collectors
Each collector polls the live OS and outputs data conforming to the same schema as the offline extractors (§4.5), so the same trained model scores both offline dumps and live telemetry.

- `process_collector.py` (Track A): `psutil` for process list/tree/thread/handle counts; Sysmon Event ID 1 stream (Windows) or `/proc` + `auditd` (Linux) for injection-adjacent signals.
- `memory_trigger.py` (Track A): idle until called; on trigger, runs a **partial** memory dump (target the flagged process's working set, not the whole system RAM) and calls the Volatility memory extractor from §4.5.
- `command_collector.py` (Track B): tails PowerShell ScriptBlock/Transcript logs and Sysmon Event ID 1 command lines (Windows) or shell history/audit logs (Linux).
- `network_collector.py` (Track B): `pyshark`/`scapy` live capture on the monitored interface, computing the same connection/DNS/beacon features as §4.5.

### 5.3 Confidence fusion (Track A, `framework/fusion/fuse.py`)
Exact logic from the requirements:
```
avg_confidence = mean(process_conf, command_conf, network_conf, memory_conf)
verdict = "Malware" if avg_confidence >= 0.60 else "Benign"
```
Make `0.60` a config value (`config/thresholds.yaml`), not a hardcoded constant — you will want to tune it once you have real validation data.

### 5.4 Orchestration flow
```
Live Feature Collection (Process, Command, Network)
        │
        ▼
Three independent binary predictions + confidences
        │
        ▼
   Any suspicious? ──No──▶ Benign, done
        │Yes
        ▼
Partial Memory Dump ▶ Memory Feature Extraction ▶ Memory Model
        │
        ▼
Confidence Fusion (average of all 4)
        │
        ▼
   avg ≥ 0.60? ──No──▶ Benign
        │Yes
        ▼
     Malware  ──▶ (hand off to Objective 3)
```

### 5.5 FastAPI service (Track A, `framework/api/main.py`)
Expose `POST /v1/detect` per the contract in `AGENTS.md` §8. Keep model loading at startup (not per-request) for latency.

### 5.6 End-to-end test (Joint)
Run one full benign session and one full malicious session (a held-out sample, not used in training) through the live pipeline and confirm the verdict, per-model confidences, and latency are all sane before moving on. This is the checkpoint where Track A's and Track B's halves first have to work together — budget real time for debugging schema mismatches here.

**Acceptance criteria for Phase 2:** `/v1/detect` returns a correct verdict on both test sessions, all four models are loaded from versioned artifacts (not ad-hoc pickles), and the fusion threshold is configurable.

---

## 6. Phase 3 — Objective 3: Multi-Class Family Classification (Track B)

1. On a "Malware" verdict from Objective 2, take the four already-computed feature vectors (no new extraction) and concatenate into one fused vector.
2. Train a multi-class **XGBoost** classifier (`objective="multi:softprob"`) on the fused vectors using the multi-class labels from §4.8. Handle per-family class imbalance with class weights or targeted oversampling.
3. Extend the API response to include `family` (argmax class) and `family_confidence` (that class's probability), plus the full probability vector for transparency.
4. Validate with a held-out sample per family and confirm the predicted family and confidence look sane (e.g., a PowerShell sample should score highest on class 1).

**Acceptance criteria:** multi-class model reaches reasonable per-class F1 (document actual numbers — don't assume a target), and the API correctly returns a family label only when Objective 2 already said "Malware."

---

## 7. Phase 4 — Objective 4: Robustness, Generalization, Explainable AI (Track B)

### 7.1 Robustness evaluation
- Train on a subset of **known** variants per family (e.g., baseline PowerShell/WMI/Registry/Process-Hollowing samples).
- Test on **new, unseen variants** you generate separately (obfuscated PowerShell, new LOLBins, updated Cobalt Strike beacon configs, newer reflective-DLL techniques, memory-only ransomware variants).
- Report the same metric set (Accuracy/Precision/Recall/F1/ROC-AUC/FPR/FNR) on the unseen-variant test set and compare against the in-distribution test set from §5.1. A robust framework shows a small gap, not a collapse.

### 7.2 Generalization evaluation
- Per feature category, train on one indicator subset and test on a **disjoint** subset the model never saw:
  - Process: train on {thread count, handle count, parent PID} → test on {token info, session ID, privilege level}
  - Command: train on {PowerShell encoded commands, WMI commands} → test on {LOLBins commands, Bash scripts, CMD obfuscation}
  - Network: train on {TCP connections, DNS requests} → test on {HTTP headers, beacon timing, packet-size stats}
  - Memory: train on {memory entropy, RWX pages} → test on {API hooks, memory sections, reflective loading, shellcode signatures}
- Report the same metrics; a small gap indicates the model learned genuine behavioral patterns rather than memorizing specific fields.

### 7.3 Explainability — SHAP
- Tree models (Process/Memory/Network/Multiclass): `shap.TreeExplainer`.
- Command model (DistilBERT): `shap.Explainer` with the transformers pipeline, or a captum-based alternative if SHAP's transformer support is limited in your version.
- Produce both a **global** summary plot (which features matter most across the dataset) and a **local** force/waterfall plot for individual high-confidence predictions.

### 7.4 Explainability — LIME
- Tabular models: `lime.lime_tabular.LimeTabularExplainer` for a per-sample explanation.
- Command model: `lime.lime_text.LimeTextExplainer` on the raw command string.
- Save one annotated example per malware family showing the top contributing features/tokens.

### 7.5 Final metrics/report generator
Build one script (`evaluation/xai/build_report.py`) that regenerates every metric, confusion matrix, and SHAP/LIME figure used in your final report from the saved model artifacts — so results are reproducible on demand, not hand-copied from a notebook.

**Acceptance criteria for Phase 4:** a written robustness/generalization comparison table, at least one SHAP global plot and one LIME example per model, and everything reproducible by re-running `build_report.py`.

---

## 8. Integration & System Testing (Joint)

1. Full pipeline dry run: raw dump → extraction → live collector → fusion → multiclass → XAI report, on a fresh sample neither of you has looked at.
2. Load/latency check on the FastAPI service under a few concurrent requests.
3. Cross-review: Track A reviews Track B's PRs and vice versa (per the branch rules in `AGENTS.md`) — don't merge your own track's final PRs without the other person's eyes on it.
4. Freeze the dataset and all four base models before starting Phase 4's evaluation, so your robustness/generalization numbers are measuring a fixed system, not a moving target.

---

## 9. Suggested Timeline (adjust to your actual deadline)

| Weeks | Focus |
|---|---|
| 1 | Phase 0 (bootstrap) + start Phase 1 public dataset collection |
| 2–4 | Phase 1: sandbox setup, malware execution (both tracks, in parallel), memory acquisition, extraction pipelines |
| 5 | Phase 1: preprocessing, feature selection, dataset merge — freeze the benchmark dataset |
| 6–7 | Phase 2: train four base models; build live collectors and fusion engine in parallel |
| 8 | Phase 2: FastAPI integration + end-to-end test (Joint checkpoint) |
| 9 | Phase 3: multi-class classifier + API extension |
| 10–11 | Phase 4: robustness + generalization testing, SHAP/LIME integration |
| 12 | Integration testing, final report, demo recording, defense prep |

---

## 10. "Production-Grade / PhD-Level" Deliverables Checklist

- [ ] Versioned, documented dataset with a data card (`docs/dataset_card.md`)
- [ ] All models trained with logged experiments (MLflow), not ad-hoc scripts
- [ ] Reproducible pipeline: `docker compose up` brings up a working detection API from committed artifacts
- [ ] CI green on `main`: lint, tests, no stray binary/dump files
- [ ] Robustness + generalization tables in the final report, not just headline accuracy
- [ ] SHAP + LIME figures for every model, not just the strongest one
- [ ] A short recorded demo of `/v1/detect` catching a held-out malicious sample end-to-end
- [ ] Written report/paper draft in `docs/final_report.md` covering methodology, architecture diagram, results, limitations, and future work
- [ ] A one-page architecture diagram (data flow from §5.4, extended with Objective 3/4) for the defense/viva

---

## 11. Safety, Ethics & Legal Notes

- Treat every malware sample as hazardous data: isolated VM only, host-only networking, snapshot-and-revert discipline (§4.3). This protects your own machines and your institution's network.
- Public malware repositories (MalwareBazaar, VX-Underground, VirusShare, Hybrid Analysis, Any.Run) typically require registration and agreement to research/educational-use terms — read and follow each source's terms before downloading anything.
- Check whether your department/institution requires sign-off (advisor approval, an ethics or security review) before handling live malware samples for coursework — many do, and it's better to confirm this in week 1 than after you've already generated data.
- Never redistribute raw samples outside the team; keep them password-zipped and out of git per `AGENTS.md` §6.

---

## 12. Risk Register

| Risk | Mitigation |
|---|---|
| Custom dataset too small for robust training | Run 2–3 executions per malware family minimum; supplement with public datasets before training |
| Schema drift between Track A's and Track B's extractors | Freeze the pydantic schemas in §4.5/`AGENTS.md` §8 before either of you writes an extractor |
| VM escape / accidental host infection | Enforce host-only networking and snapshot discipline (§4.3) without exception |
| DistilBERT/RoBERTa fine-tuning needs more compute than available | Fall back to DistilBERT (smaller) or a classical TF-IDF + LightGBM baseline for the Command model if GPU time runs out |
| Fusion threshold (0.60) not actually optimal for your data | Keep it config-driven (§5.3) and tune it against your validation set once real scores exist |
| Two people's work diverging without integration | Weekly joint sync + the Phase 2 end-to-end checkpoint in §5.6/§8 |

---

## 13. Task Ownership Matrix (single source of truth — update the Status column as you go)

| ID | Task | Owner | Depends on | Status |
|---|---|---|---|---|
| A1 | Sandbox infra setup | Track A | — | Complete |
| A2 | Execute malware set 1 | Track A | A1 | Complete |
| A3 | Memory acquisition tooling | Track A | A1 | Complete |
| A4 | Process+Memory extraction pipeline | Track A | A2, A3 | Complete |
| A5 | Public data: CIC-MalMem-2022 | Track A | — | Complete |
| A6 | Train Process Model | Track A | A4, Merge | Complete |
| A7 | Train Memory Model | Track A | A4, Merge | Complete |
| A8 | Live collectors: process, memory-trigger | Track A | A6, A7 | Complete |
| A9 | Fusion engine | Track A | A8, B8 | Complete |
| A10 | FastAPI service | Track A | A9 | Complete |
| A11 | Docker/CI/scaffolding | Track A | Phase 0 | Complete |
| B1 | Execute malware set 2 | Track B | Phase 0 | Complete |
| B2 | Network + command capture tooling | Track B | Phase 0 | Complete |
| B3 | Command+Network extraction pipeline | Track B | B1, B2 | Complete |
| B4 | Public data: CAPEv2 Sandbox | Track B | — | Complete |
| B5 | Preprocessing pipeline | Track B | A4, B3, Merge | Complete |
| B6 | Train Command Model | Track B | B5 | Complete |
| B7 | Train Network Model | Track B | B5 | Complete |
| B8 | Live collectors: command, network | Track B | B6, B7 | Complete |
| B9 | Multi-class classifier + API extension | Track B | A10 | Complete |
| B10 | Robustness + generalization testing | Track B | B9 | Complete |
| B11 | SHAP/LIME + final report | Track B | B10 | Complete |
| J1 | Repo/env bootstrap | Joint | — | Complete |
| J2 | Dataset schema & labeling convention | Joint | J1 | Complete |
| J3 | Dataset merge / Unified dataset | Joint | A4, A5, B3, B4, B5 | Complete |
| J4 | End-to-end integration test | Joint | A10, B8 | Complete |
| J5 | Final report, demo, defense prep | Joint | B11, J4 | Complete |
