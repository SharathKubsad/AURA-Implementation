"""Process features contract (Track A)."""

from pydantic import BaseModel, ConfigDict, Field


class ProcessFeatures(BaseModel):
    """Features extracted from process list, parent-child tree, and handle forensics."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(..., description="Foreign key linking to SampleMetadata.sample_id")
    total_process_count: int = Field(..., ge=0)
    hidden_process_count: int = Field(..., ge=0)
    anomalous_ppid_count: int | None = Field(default=None, ge=0)
    avg_threads_per_process: float = Field(..., ge=0.0)
    max_threads_in_single_process: int | None = Field(default=None, ge=0)
    total_handle_count: int = Field(..., ge=0)
    suspicious_dll_count: int | None = Field(default=None, ge=0)
    malfind_process_count: int = Field(..., ge=0)
    elevated_privilege_count: int | None = Field(default=None, ge=0)
    unlinked_dll_count: int = Field(default=0, ge=0)
