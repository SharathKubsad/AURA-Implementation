"""Pydantic schema for A5 custom dataset collection metadata."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class CollectionTrack(str, Enum):
    """Track ownership for custom sample collection."""

    BENIGN = "BENIGN"
    TRACK_A = "TRACK_A"
    TRACK_B = "TRACK_B"
    JOINT = "JOINT"


class CollectionOS(str, Enum):
    """Target guest operating system during execution."""

    WINDOWS_10 = "windows_10"
    WINDOWS_11 = "windows_11"
    UBUNTU_LINUX = "ubuntu_linux"
    GENERIC_WINDOWS = "generic_windows"
    OTHER = "other"


class CustomCollectionMetadata(BaseModel):
    """Canonical metadata schema for A5 custom collection runs."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(
        ...,
        pattern=r"^(EXEC|PUB)_[A-Za-z0-9_.-]+$",
        description="Canonical unique primary key across all modalities (e.g. EXEC_RUN-002)",
    )
    label: int = Field(..., ge=0, le=1, description="0 = Benign, 1 = Malware")
    family: str = Field(..., description="Canonical malware family or 'benign'")
    track: CollectionTrack = Field(..., description="Track ownership for collection")
    os: CollectionOS = Field(..., description="Target guest operating system")
    execution_timestamp: datetime = Field(..., description="ISO 8601 UTC timestamp of execution")
    source_type: str = Field(default="custom_sandbox", description="Origin of sample record")
    source_reference: str = Field(
        ..., description="Sample hash, framework payload ID, or baseline test identifier"
    )
    evidence_sha256: str = Field(
        ...,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="SHA-256 hash of the complete raw evidence package",
    )
    memory_dump: bool = Field(
        ..., description="Indicates whether volatile memory dump was acquired"
    )
    sysmon_available: bool = Field(
        ..., description="Indicates whether Sysmon telemetry was captured"
    )
    notes: str = Field(..., description="Operational notes and forensic observations")
