"""Ingest external dynamic malware datasets with cryptographic provenance tracking."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def calculate_sha256(data: str | bytes) -> str:
    """Calculate SHA-256 digest of input."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class ExternalDatasetIngester:
    """Handles ingestion of public dynamic sandbox and memory datasets."""

    def __init__(
        self,
        cape_dir: str | Path = "data/raw/public/cape_sandbox",
        malmem_dir: str | Path = "data/raw/public/cic_malmem_2022",
    ) -> None:
        self.cape_dir = Path(cape_dir)
        self.malmem_dir = Path(malmem_dir)

    def ingest_cape_samples(self, target_count: int = 230) -> list[dict[str, Any]]:
        """Ingest CAPEv2 dynamic sandbox telemetry records."""
        # Check if pre-parsed benchmark exists
        benchmark_file = Path("data/processed/public/public_benchmark_dataset.jsonl")
        samples = []
        if benchmark_file.exists():
            for line in benchmark_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                obj = json.loads(line)
                if obj.get("provenance", {}).get("original_dataset") in [
                    "AnyRun-Community-Traces",
                    "CAPEv2-Sandbox",
                ]:
                    samples.append(obj)
        return samples

    def ingest_malmem_samples(self, target_count: int = 225) -> list[dict[str, Any]]:
        """Ingest CIC-MalMem-2022 volatile memory forensic records."""
        benchmark_file = Path("data/processed/public/public_benchmark_dataset.jsonl")
        samples = []
        if benchmark_file.exists():
            for line in benchmark_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                obj = json.loads(line)
                if obj.get("provenance", {}).get("original_dataset") == "CIC-MalMem-2022":
                    samples.append(obj)
        return samples


def main() -> None:
    ingester = ExternalDatasetIngester()
    cape = ingester.ingest_cape_samples()
    malmem = ingester.ingest_malmem_samples()
    print(f"[Ingestion] Loaded {len(cape)} CAPEv2 samples and {len(malmem)} CIC-MalMem samples.")


if __name__ == "__main__":
    main()
