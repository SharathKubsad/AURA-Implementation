"""Network telemetry adapter for public benchmark datasets (Track B)."""

from __future__ import annotations

import logging
from typing import Any

from forensics.schemas.network import NetworkFeatures

logger = logging.getLogger("network_adapter")


class NetworkAdapter:
    """Adapts public network telemetry to canonical NetworkFeatures schema with strict NaN preservation."""

    @staticmethod
    def from_flow_or_sandbox(raw_record: dict[str, Any], sample_id: str) -> NetworkFeatures:
        """Map sandbox connections or network flow summaries to NetworkFeatures.

        Crucial constraint: Preserves PCAP-dependent timing and byte statistics as None
        when unsupported or unmeasured, rather than fabricating zeros or median values.

        Args:
            raw_record: Dictionary containing socket, connection, or DNS metrics.
            sample_id: Canonical target sample_id.

        Returns:
            Validated NetworkFeatures instance.
        """
        active_conn = int(raw_record.get("active_connection_count", 0))
        listening = int(raw_record.get("listening_port_count", 0))
        outbound = int(raw_record.get("outbound_connection_count", 0))
        unique_ips = int(raw_record.get("unique_remote_ips", 0))

        # Preserve genuine nulls for PCAP-dependent metrics if not directly measured
        dns_queries = raw_record.get("dns_query_count")
        interpacket = raw_record.get("avg_interpacket_interval_ms")
        beacon_score = raw_record.get("beacon_regularity_score")
        bytes_sent = raw_record.get("total_bytes_sent")
        bytes_recv = raw_record.get("total_bytes_received")

        suspicious_ports = int(raw_record.get("suspicious_port_usage", 0))

        return NetworkFeatures(
            sample_id=sample_id,
            active_connection_count=max(0, active_conn),
            listening_port_count=max(0, listening),
            outbound_connection_count=max(0, outbound),
            dns_query_count=int(dns_queries) if dns_queries is not None else None,
            unique_remote_ips=max(0, unique_ips),
            avg_interpacket_interval_ms=float(interpacket) if interpacket is not None else None,
            beacon_regularity_score=float(beacon_score) if beacon_score is not None else None,
            total_bytes_sent=int(bytes_sent) if bytes_sent is not None else None,
            total_bytes_received=int(bytes_recv) if bytes_recv is not None else None,
            suspicious_port_usage=1 if suspicious_ports else 0,
        )
