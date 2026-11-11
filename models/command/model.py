"""Command text and behavioral telemetry classification model (Objective 2).

Wraps detection model interface:
- predict_proba(X) -> 1D numpy array of probabilities in [0.0, 1.0]
- predict(X, threshold=0.5) -> 1D numpy array of binary predictions
- save(output_dir) / load(model_dir)

Supports:
1. GBDT (LightGBM) with TF-IDF + behavioral command telemetry (production default, lightweight, bundled in repository).
2. Transformer (DistilBERT) fine-tuned sequence classification when deep model weights are present.
"""

from __future__ import annotations

import base64
import json
import logging
import math
import re
import warnings
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# Suppress scikit-learn version mismatch warnings
try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass
warnings.filterwarnings("ignore", message="Trying to unpickle estimator.*")
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")

logger = logging.getLogger("models.command")

COMMAND_NUMERIC_FEATURE_COLS = [
    "command_length",
    "shannon_entropy",
    "is_base64_encoded",
    "has_download_cradle",
    "has_bypass_execution_policy",
    "has_hidden_window",
    "uses_lolbins",
    "registry_persistence_count",
]

LOLBINS_LIST = [
    "certutil",
    "mshta",
    "regsvr32",
    "rundll32",
    "bitsadmin",
    "wmic",
    "cscript",
    "wscript",
    "installutil",
    "regasm",
    "regsvcs",
    "msbuild",
    "hh.exe",
    "schtasks",
]

# Lazy-loaded modules to avoid slow CUDA initialization on host OS startup
_torch_mod = None
_transformers_mod = None


def _get_torch() -> Any:
    global _torch_mod
    if _torch_mod is None:
        import torch

        _torch_mod = torch
    return _torch_mod


def _get_transformers() -> Any:
    global _transformers_mod
    if _transformers_mod is None:
        import transformers

        _transformers_mod = transformers
    return _transformers_mod


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return round(-sum(p * math.log2(p) for p in prob), 2)


def _extract_command_features_row(cmd_text: str) -> list[float]:
    """Dynamically compute the 8 behavioral command telemetry features from raw text."""
    cmd_text = "" if (cmd_text is None or pd.isna(cmd_text)) else str(cmd_text)
    cmd_len = len(cmd_text)
    entropy = _shannon_entropy(cmd_text)
    cmd_lower = cmd_text.lower()

    b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    has_b64_switch = any(
        sw in cmd_lower for sw in ["-enc ", "-encodedcommand ", "-e ", "/e ", "frombase64"]
    )
    b64_match = b64_pattern.search(cmd_text)
    is_b64 = 1.0 if (has_b64_switch or (b64_match and len(b64_match.group(0)) >= 16)) else 0.0

    decoded_text = ""
    if is_b64 and b64_match:
        try:
            raw_b64 = b64_match.group(0)
            pad = len(raw_b64) % 4
            if pad:
                raw_b64 += "=" * (4 - pad)
            b_bytes = base64.b64decode(raw_b64)
            try:
                decoded_text = b_bytes.decode("utf-16le")
            except Exception:
                decoded_text = b_bytes.decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = ""

    combined_lower = (cmd_lower + " " + decoded_text.lower()).strip()

    has_cradle = (
        1.0
        if any(
            kw in combined_lower
            for kw in [
                "downloadstring",
                "downloadfile",
                "invoke-webrequest",
                "iwr ",
                "net.webclient",
                "curl ",
                "wget ",
                "bitsadmin /transfer",
                "certutil -urlcache",
            ]
        )
        else 0.0
    )

    has_bypass = (
        1.0
        if any(
            kw in combined_lower
            for kw in [
                "-executionpolicy bypass",
                "-ep bypass",
                "bypass",
                "-w hidden",
                "-windowstyle hidden",
                "unrestricted",
                "-nop",
                "-noprofile",
            ]
        )
        else 0.0
    )

    has_hidden = (
        1.0
        if any(
            kw in combined_lower
            for kw in [
                "-w hidden",
                "-windowstyle hidden",
                "-window hidden",
                "showwindow",
                "vbhide",
            ]
        )
        else 0.0
    )

    uses_lolbins = 1.0 if any(lb in combined_lower for lb in LOLBINS_LIST) else 0.0

    reg_persistence = (
        1.0
        if any(
            rk in combined_lower
            for rk in [
                "currentversion\\run",
                "currentversion\\runonce",
                "image file execution options",
                "reg add",
                "set-itemproperty",
            ]
        )
        else 0.0
    )

    return [
        float(cmd_len),
        float(entropy),
        is_b64,
        has_cradle,
        has_bypass,
        has_hidden,
        uses_lolbins,
        reg_persistence,
    ]


class CommandModel:
    """Command model supporting GBDT (TF-IDF + Telemetry) and Transformer (DistilBERT)."""

    def __init__(
        self,
        model: Any | None = None,
        tokenizer: Any | None = None,
        max_length: int = 128,
        device: Any | None = None,
        gbdt_model: Any | None = None,
        tfidf: Any | None = None,
        feature_names: list[str] | None = None,
    ) -> None:
        """Initialize CommandModel."""
        self.device = device or "cpu"
        self.model = model
        if self.model is not None and hasattr(self.model, "to"):
            try:
                self.model.to(self.device)
                self.model.eval()
            except Exception:
                pass

        self.tokenizer = tokenizer
        self.max_length = max_length
        self.gbdt_model = gbdt_model
        self.tfidf = tfidf
        self.feature_names = feature_names or ["raw_command_text"] + COMMAND_NUMERIC_FEATURE_COLS

    @property
    def model_type(self) -> str:
        """Return the active model architecture string."""
        if self.gbdt_model is not None and self.tfidf is not None:
            return "gbdt_tfidf"
        elif self.model is not None:
            return "distilbert"
        return "uninitialized"

    def _extract_texts_and_df(self, X: Any) -> tuple[list[str], pd.DataFrame | None]:
        """Extract list of raw string commands and optional dataframe input."""
        if isinstance(X, pd.DataFrame):
            if "raw_command_text" in X.columns:
                series = X["raw_command_text"]
            else:
                # Modality isolation check
                first_col = X.columns[0]
                if any(m in first_col for m in ("process", "memory", "network", "port", "page")):
                    raise KeyError(
                        "CommandModel requires 'raw_command_text'; cannot consume other modality features."
                    )
                series = X[first_col]
            texts = ["" if (pd.isna(v) or v is None) else str(v) for v in series]
            return texts, X
        elif isinstance(X, pd.Series):
            texts = ["" if (pd.isna(v) or v is None) else str(v) for v in X]
            return texts, None
        elif isinstance(X, (list, tuple, np.ndarray)):
            texts = [
                "" if (v is None or (isinstance(v, float) and pd.isna(v))) else str(v) for v in X
            ]
            return texts, None
        elif isinstance(X, str):
            return [X], None
        elif hasattr(X, "model_dump"):
            d = X.model_dump()
            return [str(d.get("raw_command_text", ""))], pd.DataFrame([d])
        elif isinstance(X, dict):
            return [str(X.get("raw_command_text", ""))], pd.DataFrame([X])
        else:
            return [str(X)], None

    def predict_proba(self, X: Any) -> np.ndarray:
        """Predict malware probability for given command line inputs."""
        texts, df_in = self._extract_texts_and_df(X)

        if len(texts) == 0:
            return np.empty((0,), dtype=float)

        # 1. Use GBDT + TF-IDF model if available (Production Default)
        if self.gbdt_model is not None and self.tfidf is not None:
            tfidf_mat = self.tfidf.transform(texts).toarray()

            # Check if df_in already has the 8 numeric telemetry columns
            if df_in is not None and all(c in df_in.columns for c in COMMAND_NUMERIC_FEATURE_COLS):
                num_mat = df_in[COMMAND_NUMERIC_FEATURE_COLS].fillna(0.0).astype(float).values
            else:
                # Dynamically extract the 8 numeric telemetry features from the text
                num_mat = np.array([_extract_command_features_row(t) for t in texts], dtype=float)

            # Check expected feature count of gbdt_model
            expected_n = getattr(self.gbdt_model, "n_features_in_", None)
            if expected_n == tfidf_mat.shape[1] + num_mat.shape[1]:
                X_comb = np.hstack([tfidf_mat, num_mat])
            elif expected_n == tfidf_mat.shape[1]:
                X_comb = tfidf_mat
            elif expected_n == num_mat.shape[1]:
                X_comb = num_mat
            else:
                X_comb = np.hstack([tfidf_mat, num_mat])

            # Predict probabilities
            probs_2d = self.gbdt_model.predict_proba(X_comb)
            if probs_2d.ndim == 2 and probs_2d.shape[1] >= 2:
                malware_probs = probs_2d[:, 1]
            elif probs_2d.ndim == 1:
                malware_probs = probs_2d
            else:
                malware_probs = probs_2d[:, -1]
            return np.asarray(malware_probs, dtype=float)

        # 2. Use Transformer model if available
        if self.model is not None:
            if self.tokenizer is None:
                raise RuntimeError(
                    "CommandModel initialized with transformer model but no tokenizer."
                )

            torch = _get_torch()
            self.model.eval()
            encoded = self.tokenizer(
                texts,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt",
            )
            if self.device is not None and hasattr(input_ids := encoded["input_ids"], "to"):
                input_ids = encoded["input_ids"].to(self.device)
                attention_mask = encoded["attention_mask"].to(self.device)
            else:
                input_ids = encoded["input_ids"]
                attention_mask = encoded["attention_mask"]

            with torch.no_grad():
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
                malware_probs = probs[:, 1].detach().cpu().numpy()

            return np.asarray(malware_probs, dtype=float)

        raise RuntimeError(
            "CommandModel must be initialized with either a fitted GBDT model or a transformer model."
        )

    def predict(self, X: Any, threshold: float = 0.5) -> np.ndarray:
        """Predict binary class (0: Benign, 1: Malware) at specified threshold."""
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)

    def save(self, output_dir: Path | str) -> None:
        """Save model weights, tokenizer / vectorizer, and metadata to directory."""
        p = Path(output_dir)
        p.mkdir(parents=True, exist_ok=True)

        if self.gbdt_model is not None:
            joblib.dump(self.gbdt_model, p / "model.joblib")
        if self.tfidf is not None:
            joblib.dump(self.tfidf, p / "tfidf.joblib")

        if self.model is not None and hasattr(self.model, "save_pretrained"):
            self.model.save_pretrained(str(p))
        if self.tokenizer is not None and hasattr(self.tokenizer, "save_pretrained"):
            self.tokenizer.save_pretrained(str(p))

        features_file = p / "features.json"
        features_file.write_text(
            json.dumps(
                {"feature_names": self.feature_names, "max_length": self.max_length}, indent=2
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, model_dir: Path | str, device: Any | None = None) -> CommandModel:
        """Load saved CommandModel from artifact directory with automatic architecture detection."""
        p = Path(model_dir)
        if not p.exists():
            raise FileNotFoundError(f"Model directory not found at {p}")

        # Check for GBDT artifacts first (model.joblib + tfidf.joblib)
        # This is the lightweight, deterministic, and committable model.
        joblib_file = p / "model.joblib"
        tfidf_file = p / "tfidf.joblib"
        if joblib_file.exists() and tfidf_file.exists():
            try:
                gbdt_model = joblib.load(joblib_file)
                tfidf = joblib.load(tfidf_file)
                logger.info(
                    "CommandModel loaded successfully via GBDT + TF-IDF from %s", joblib_file
                )
                return cls(gbdt_model=gbdt_model, tfidf=tfidf, device=device)
            except Exception as e:
                logger.warning("Could not load GBDT command model from %s: %s", joblib_file, e)

        # Check for Transformer artifacts (safetensors or pytorch_model.bin)
        safetensors_file = p / "model.safetensors"
        bin_file = p / "pytorch_model.bin"
        has_transformer_weights = (
            safetensors_file.exists() and safetensors_file.stat().st_size > 1_000_000
        ) or (bin_file.exists() and bin_file.stat().st_size > 1_000_000)

        if has_transformer_weights:
            try:
                tf_mod = _get_transformers()
                AutoTokenizer = tf_mod.AutoTokenizer
                AutoModelForSequenceClassification = tf_mod.AutoModelForSequenceClassification
                tokenizer = AutoTokenizer.from_pretrained(str(p), local_files_only=True)
                model = AutoModelForSequenceClassification.from_pretrained(
                    str(p), local_files_only=True
                )
                max_len = 128
                features_file = p / "features.json"
                if features_file.exists():
                    feat_data = json.loads(features_file.read_text(encoding="utf-8"))
                    max_len = feat_data.get("max_length", 128)
                logger.info("CommandModel loaded successfully via Transformer from %s", p)
                return cls(model=model, tokenizer=tokenizer, max_length=max_len, device=device)
            except Exception as e:
                logger.error("Failed loading transformer weights from %s: %s", p, e)
                raise

        # If only joblib_file exists without tfidf_file
        if joblib_file.exists():
            gbdt_model = joblib.load(joblib_file)
            return cls(gbdt_model=gbdt_model, tfidf=None, device=device)

        raise FileNotFoundError(
            f"No valid Command model weights found in {p}. Expected model.joblib + tfidf.joblib or model.safetensors"
        )
