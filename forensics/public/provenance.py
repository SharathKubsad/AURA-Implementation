"""Public dataset provenance and compatibility schemas."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DatasetCompatibility(str, Enum):
    """Classification of public dataset suitability for fileless malware detection."""

    COMPATIBLE = "COMPATIBLE"
    PARTIALLY_COMPATIBLE = "PARTIALLY_COMPATIBLE"
    INCOMPATIBLE = "INCOMPATIBLE"


class PublicProvenance(BaseModel):
    """Provenance tracking record for every ingested public sample."""

    model_config = ConfigDict(extra="forbid")

    original_dataset: str = Field(
        ...,
        description="Name of the public dataset (e.g., 'CIC-MalMem-2022', 'AnyRun-Community-Traces')",
    )
    original_sample_id: str = Field(
        ...,
        description="Original identifier or row index in the source dataset",
    )
    original_label: str = Field(
        ...,
        description="Original label string (e.g., 'Benign', 'Malware', 'Spyware-Transponder')",
    )
    original_family: str | None = Field(
        default=None,
        description="Original malware family name if categorized by the source",
    )
    source_reference: str = Field(
        ...,
        description="Official publication, URL, or citation for the source dataset",
    )
    available_modalities: list[str] = Field(
        ...,
        description="List of modalities genuinely provided by this sample (subset of process, command, network, memory)",
    )
    mapping_method: str = Field(
        ...,
        description="Detailed description of how raw attributes were mapped to our forensic schemas",
    )
    checksum: str | None = Field(
        default=None,
        description="Cryptographic hash (SHA256) of raw sample record or source artifact if available",
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize provenance metadata to dictionary."""
        return self.model_dump()
