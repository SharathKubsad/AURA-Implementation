"""Network features contract (Track B)."""

from pydantic import BaseModel, ConfigDict, Field


class NetworkFeatures(BaseModel):
    """Features extracted from network sockets, DNS lookups, and pcap packet timing."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(..., description="Foreign key linking to SampleMetadata.sample_id")
    active_connection_count: int = Field(..., ge=0)
    listening_port_count: int = Field(..., ge=0)
    outbound_connection_count: int = Field(..., ge=0)
    dns_query_count: int | None = Field(default=None, ge=0)
    unique_remote_ips: int = Field(..., ge=0)
    avg_interpacket_interval_ms: float | None = Field(default=None, ge=0.0)
    beacon_regularity_score: float | None = Field(default=None, ge=0.0, le=1.0)
    total_bytes_sent: int | None = Field(default=None, ge=0)
    total_bytes_received: int | None = Field(default=None, ge=0)
    suspicious_port_usage: int = Field(..., ge=0, le=1)
