"""Provenance data model for CAPEv2 public sandbox reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CapeProvenance:
    """Immutable provenance record tracking origin and transformation of CAPEv2 public data."""

    original_sample_id: str
    original_dataset: str
    original_source: str
    original_label: str
    original_family: str
    source_file: str
    source_report_id: str
    transformation_version: str
    adapter_version: str
    source_checksum: str
    available_modalities: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert provenance to serializable dictionary."""
        return asdict(self)
