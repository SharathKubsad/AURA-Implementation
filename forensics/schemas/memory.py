"""Memory features contract (Track A)."""

from pydantic import BaseModel, ConfigDict, Field


class MemoryFeatures(BaseModel):
    """Features extracted from volatile memory forensics, VAD trees, and page entropy."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(..., description="Foreign key linking to SampleMetadata.sample_id")
    rwx_page_count: int = Field(..., ge=0)
    injected_code_regions: int = Field(..., ge=0)
    unmapped_executable_pages: int = Field(..., ge=0)
    vad_protection_anomaly_count: int = Field(..., ge=0)
    ldrmodules_inconsistencies: int = Field(..., ge=0)
    yara_shellcode_matches: int | None = Field(default=None, ge=0)
    mean_memory_entropy: float | None = Field(default=None, ge=0.0, le=8.0)
    max_memory_entropy: float | None = Field(default=None, ge=0.0, le=8.0)
