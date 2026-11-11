"""Shared sample identity and label schemas."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SourceType(str, Enum):
    """Source origin of the sample."""

    CUSTOM_SANDBOX = "custom_sandbox"
    PUBLIC_DATASET = "public_dataset"


class OperatingSystem(str, Enum):
    """Target OS."""

    WINDOWS_10 = "windows_10"
    WINDOWS_11 = "windows_11"
    UBUNTU_LINUX = "ubuntu_linux"
    GENERIC_WINDOWS = "generic_windows"
    OTHER = "other"


class EnvironmentType(str, Enum):
    """Hypervisor or execution platform."""

    VMWARE_WORKSTATION = "vmware_workstation"
    VIRTUALBOX = "virtualbox"
    HYPERV = "hyperv"
    BARE_METAL = "bare_metal"
    PUBLIC_BENCHMARK = "public_benchmark"


class BinaryLabel(int, Enum):
    """Objective 2 Binary detection labels."""

    BENIGN = 0
    MALWARE = 1


class InitialFamilyLabel(int, Enum):
    """Objective 3 Initial Multi-class mapping (subject to Phase 1 finalization)."""

    BENIGN = 0
    POWERSHELL_FILELESS = 1
    WMI_MALWARE = 2
    PROCESS_HOLLOWING = 3
    REFLECTIVE_DLL_INJECTION = 4
    REGISTRY_MALWARE = 5


class SampleMetadata(BaseModel):
    """Canonical execution and sample identity schema linking all 4 modalities."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(
        ...,
        pattern=r"^(EXEC|PUB)_[A-Za-z0-9_.-]+$",
        description="Canonical primary key linking all feature modalities.",
    )
    source_type: SourceType
    source_id: str = Field(..., description="Hash or upstream dataset identifier.")
    execution_id: str = Field(..., description="Sandbox run UUID or reference ID.")
    timestamp: datetime = Field(..., description="ISO timestamp of acquisition.")
    operating_system: OperatingSystem
    environment: EnvironmentType
    binary_label: BinaryLabel
    family_label: int = Field(
        ...,
        ge=0,
        description="Multi-class numeric label (0=Benign, 1..5 initial families, extensible).",
    )
    family_name: str = Field(..., description="Canonical malware family name or 'Benign'.")
    operator: str | None = Field(default=None, description="Operator or harness identifier.")
    notes: str | None = Field(default=None, description="Non-sensitive operational notes.")
