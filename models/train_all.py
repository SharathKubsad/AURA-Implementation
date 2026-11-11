"""Train and serialize all 4 base models plus multi-class extension (Objectives 2 & 3)."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from models.command.train import train_command_model
from models.memory.train import train_memory_model
from models.multiclass.train import train_multiclass_model
from models.network.train import train_network_model
from models.process.train import train_process_model


def train_all() -> None:
    """Execute training for all detection and attribution models."""
    print("=== Training Process Model (XGBoost) ===")
    m_proc = train_process_model()
    p_test = m_proc.get("test_metrics", m_proc)

    print("\n=== Training Memory Model (CatBoost) ===")
    m_mem = train_memory_model()
    mem_test = m_mem.get("test_metrics", m_mem)

    print("\n=== Training Command Model (DistilBERT) ===")
    m_cmd = train_command_model()
    cmd_test = m_cmd.get("test_metrics", m_cmd)

    print("\n=== Training Network Model (LightGBM) ===")
    m_net = train_network_model()
    net_test = m_net.get("test_metrics", m_net)

    print("\n=== Training Multi-Class Family Model (Objective 3) ===")
    m_multi = train_multiclass_model()
    multi_f1 = m_multi.get("leave_one_out_macro_f1", m_multi.get("macro_f1", 0.0))

    print("\n" + "=" * 50)
    print("ALL MODELS SUCCESSFULLY TRAINED & SERIALIZED!")
    print(f"Process Model F1:   {p_test.get('f1', 0.0):.4f} (AUC: {p_test.get('roc_auc', 0.0):.4f})")
    print(f"Memory Model F1:    {mem_test.get('f1', 0.0):.4f} (AUC: {mem_test.get('roc_auc', 0.0):.4f})")
    print(f"Command Model F1:   {cmd_test.get('f1', 0.0):.4f} (AUC: {cmd_test.get('roc_auc', 0.0):.4f})")
    print(f"Network Model F1:   {net_test.get('f1', 0.0):.4f} (AUC: {net_test.get('roc_auc', 0.0):.4f})")
    print(f"Multi-Class Macro:  {multi_f1:.4f}")
    print("=" * 50)


if __name__ == "__main__":
    train_all()

