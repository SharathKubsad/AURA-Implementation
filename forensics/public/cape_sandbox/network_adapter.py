"""Network telemetry adapter for CAPEv2 sandbox execution reports."""

from __future__ import annotations

import logging
from typing import Any

from forensics.schemas.network import NetworkFeatures

logger = logging.getLogger("cape_network_adapter")

SUSPICIOUS_PORTS: frozenset[int] = frozenset([4444, 5555, 6666, 8080, 8443, 8888, 9001, 9999, 1337, 31337])


class CapeNetworkAdapter:
    """Adapts CAPEv2 network traffic summaries to canonical NetworkFeatures schema.

    Strictly preserves PCAP-dependent timing metrics as None (NaN) rather than
    fabricating synthetic values.
    """

    @staticmethod
    def from_cape_report(raw_report: dict[str, Any], sample_id: str) -> NetworkFeatures:
        """Extract NetworkFeatures from CAPEv2 JSON execution report.

        Args:
            raw_report: CAPEv2 report JSON.
            sample_id: Canonical sample ID.

        Returns:
            Validated NetworkFeatures instance.
        """
        network = raw_report.get("network", {})
        tcp_conns = network.get("tcp", [])
        udp_conns = network.get("udp", [])
        dns_queries = network.get("dns", [])
        hosts = network.get("hosts", [])

        # Connection counts
        active_conn = len(tcp_conns)
        outbound_conn = len(tcp_conns) + len(udp_conns)
        dns_count = len(dns_queries)
        unique_ips = len(set(hosts))

        # Suspicious port check
        suspicious_port = 0
        for conn in tcp_conns:
            dport = conn.get("dport")
            if dport and int(dport) in SUSPICIOUS_PORTS:
                suspicious_port = 1
                break

        # Byte counters
        bytes_sent = network.get("total_bytes_sent")
        bytes_recv = network.get("total_bytes_received")

        # Unmeasured timing features: preserve strictly as None
        interpacket_ms = None
        beacon_score = None
        listening_ports = 0  # not recorded in sandbox egress summaries

        return NetworkFeatures(
            sample_id=sample_id,
            active_connection_count=active_conn,
            listening_port_count=listening_ports,
            outbound_connection_count=outbound_conn,
            dns_query_count=dns_count,
            unique_remote_ips=unique_ips,
            avg_interpacket_interval_ms=interpacket_ms,
            beacon_regularity_score=beacon_score,
            total_bytes_sent=int(bytes_sent) if bytes_sent is not None else None,
            total_bytes_received=int(bytes_recv) if bytes_recv is not None else None,
            suspicious_port_usage=suspicious_port,
        )
