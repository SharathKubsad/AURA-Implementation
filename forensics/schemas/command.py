"""Command features contract (Track B)."""

from pydantic import BaseModel, ConfigDict, Field


class CommandFeatures(BaseModel):
    """Features extracted from command line, PowerShell transcripts, and shell history.

    Note: `raw_command_text` is the raw NLP input representation for DistilBERT/RoBERTa
    tokenization, while the remaining fields are structured/derived metrics.
    """

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(..., description="Foreign key linking to SampleMetadata.sample_id")
    # Raw NLP Representation
    raw_command_text: str = Field(
        ...,
        description="Raw string of command/script block for NLP tokenization (not a tabular numeric feature)",
    )
    # Structured / Derived Metrics
    command_length: int = Field(..., ge=0)
    shannon_entropy: float = Field(..., ge=0.0, le=8.0)
    is_base64_encoded: int = Field(..., ge=0, le=1)
    has_download_cradle: int = Field(..., ge=0, le=1)
    has_bypass_execution_policy: int = Field(..., ge=0, le=1)
    has_hidden_window: int = Field(..., ge=0, le=1)
    uses_lolbins: int = Field(..., ge=0, le=1)
    registry_persistence_count: int = Field(default=0, ge=0)
