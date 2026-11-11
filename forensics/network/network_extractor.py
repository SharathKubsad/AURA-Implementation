"""Network feature extraction engine for network connection logs and telemetry (Track B)."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import logging
from pathlib import Path
from typing import Any

from forensics.schemas.network import NetworkFeatures

logger = logging.getLogger(__name__)

# Common C2, reverse-shell, and tunneling ports considered suspicious
SUSPICIOUS_PORTS: set[int] = {
    1337,
    31337,
    4443,
    4444,
    5555,
    6667,
    7777,
    8080,
    8443,
    8888,
    9001,
    9999,
    12345,
}

# TCP states considered active/connected
ACTIVE_STATES: set[str] = {
    "ESTABLISHED",
    "SYN_SENT",
    "SYNSENT",
    "SYN_RECEIVED",
    "SYNRECEIVED",
    "CLOSE_WAIT",
    "CLOSEWAIT",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
}

# TCP states considered listening
LISTEN_STATES: set[str] = {
    "LISTEN",
    "LISTENING",
}

# Values representing local/wildcard/unspecified addresses
UNSPECIFIED_ADDRESSES: set[str] = {
    "0.0.0.0",
    "::",
    "127.0.0.1",
    "::1",
    "localhost",
    "*",
    "0",
    "",
}


def _is_external_ip(ip_str: str) -> bool:
    """Check if an IP string is a valid non-loopback, non-unspecified IP."""
    clean_ip = ip_str.strip().strip("[]\"'")
    if not clean_ip or clean_ip in UNSPECIFIED_ADDRESSES:
        return False
    try:
        ip = ipaddress.ip_address(clean_ip)
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)
    except ValueError:
        return False


def _safe_parse_port(port_val: Any) -> int | None:
    """Parse port number safely, returning None if invalid."""
    if port_val is None:
        return None
    try:
        port_int = int(str(port_val).strip().strip("\"'"))
        if 0 <= port_int <= 65535:
            return port_int
    except (ValueError, TypeError):
        pass
    return None


def parse_network_connections_csv(csv_path: Path) -> list[dict[str, Any]]:
    """Parse network_connections.csv into a list of normalized connection dicts.

    Expected columns: LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    """
    if not csv_path.is_file():
        return []

    content = csv_path.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not content:
        return []

    records: list[dict[str, Any]] = []
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return []

    reader = csv.DictReader(lines)
    if not reader.fieldnames:
        return []

    # Normalize header mapping
    field_map: dict[str, str] = {}
    for col in reader.fieldnames:
        col_clean = col.strip().strip("\"'").lower()
        if "localaddress" in col_clean or col_clean == "local_address":
            field_map[col] = "local_address"
        elif "localport" in col_clean or col_clean == "local_port":
            field_map[col] = "local_port"
        elif "remoteaddress" in col_clean or col_clean == "remote_address":
            field_map[col] = "remote_address"
        elif "remoteport" in col_clean or col_clean == "remote_port":
            field_map[col] = "remote_port"
        elif "state" in col_clean:
            field_map[col] = "state"
        elif "owningprocess" in col_clean or "pid" in col_clean:
            field_map[col] = "owning_process"

    for row in reader:
        norm_row: dict[str, Any] = {}
        for orig_key, std_key in field_map.items():
            val = row.get(orig_key)
            if val is not None:
                norm_row[std_key] = val.strip().strip("\"'")
        records.append(norm_row)

    return records


class NetworkExtractor:
    """Track B Network Feature Extractor.

    Extracts genuine socket metrics from network_connections.csv and optional
    Sysmon/PCAP evidence. Preserves null semantics for metrics not supported
    by the available evidence.
    """

    def __init__(self, suspicious_ports: set[int] | None = None) -> None:
        self.suspicious_ports = suspicious_ports or SUSPICIOUS_PORTS

    def extract(self, evidence_dir: Path | str, sample_id: str = "EXEC_RUN-001") -> NetworkFeatures:
        """Extract NetworkFeatures from evidence directory.

        Args:
            evidence_dir: Path to directory containing network_connections.csv or source evidence.
            sample_id: Canonical sample identifier.

        Returns:
            NetworkFeatures: Validated Pydantic model with genuine metrics and nulls for unsupported fields.
        """
        dir_path = Path(evidence_dir)
        conn_csv: Path | None = None
        if not dir_path.is_dir():
            # If a direct CSV file was passed
            if dir_path.is_file() and dir_path.name.endswith(".csv"):
                conn_csv = dir_path
                dir_path = dir_path.parent
            else:
                raise FileNotFoundError(
                    f"Evidence path does not exist or is not a directory: {evidence_dir}"
                )
        else:
            # Locate network_connections.csv
            candidates = [
                dir_path / "network_connections.csv",
                dir_path / "network.csv",
                dir_path / "netstat.csv",
            ]
            for c in candidates:
                if c.is_file():
                    conn_csv = c
                    break

            if conn_csv is None:
                # Recursive search under evidence_dir
                for f in dir_path.rglob("network_connections.csv"):
                    if f.is_file():
                        conn_csv = f
                        break

        # Parse connection records
        records = parse_network_connections_csv(conn_csv) if conn_csv else []

        active_connections = 0
        listening_ports: set[int] = set()
        outbound_connections = 0
        remote_ips: set[str] = set()
        suspicious_port_flag = 0

        for r in records:
            state = (r.get("state") or "").upper().strip()
            l_port = _safe_parse_port(r.get("local_port"))
            r_port = _safe_parse_port(r.get("remote_port"))
            r_addr = (r.get("remote_address") or "").strip()

            # Check listening state
            if state in LISTEN_STATES and l_port is not None:
                listening_ports.add(l_port)
                if l_port in self.suspicious_ports:
                    suspicious_port_flag = 1

            # Check active connection state
            if state in ACTIVE_STATES:
                active_connections += 1

            # Check outbound/external remote destination
            if _is_external_ip(r_addr):
                remote_ips.add(r_addr.strip("[]"))
                # If connected or attempting connection
                if state in ACTIVE_STATES or (r_port is not None and r_port > 0):
                    outbound_connections += 1

            # Check suspicious port usage
            if (l_port is not None and l_port in self.suspicious_ports) or (
                r_port is not None and r_port in self.suspicious_ports
            ):
                suspicious_port_flag = 1

        # Check for optional evidence: Sysmon DNS queries (Event ID 22) or PCAP
        dns_query_count: int | None = None
        avg_interpacket_interval_ms: float | None = None
        beacon_regularity_score: float | None = None
        total_bytes_sent: int | None = None
        total_bytes_received: int | None = None

        # Look for Sysmon EVTX to genuinely extract DNS queries if present
        sysmon_files = list(dir_path.glob("sysmon.evtx")) + list(dir_path.glob("**/sysmon.evtx"))
        if sysmon_files:
            dns_count = self._extract_sysmon_dns_count(sysmon_files[0])
            if dns_count is not None:
                dns_query_count = dns_count

        return NetworkFeatures(
            sample_id=sample_id,
            active_connection_count=active_connections,
            listening_port_count=len(listening_ports),
            outbound_connection_count=outbound_connections,
            dns_query_count=dns_query_count,
            unique_remote_ips=len(remote_ips),
            avg_interpacket_interval_ms=avg_interpacket_interval_ms,
            beacon_regularity_score=beacon_regularity_score,
            total_bytes_sent=total_bytes_sent,
            total_bytes_received=total_bytes_received,
            suspicious_port_usage=suspicious_port_flag,
        )

    def _extract_sysmon_dns_count(self, sysmon_path: Path) -> int | None:
        """Extract count of Sysmon Event ID 22 (DNS query) events if available."""
        try:
            import xml.etree.ElementTree as ET

            import win32evtlog

            q = win32evtlog.EvtQuery(str(sysmon_path.resolve()), win32evtlog.EvtQueryFilePath)
            dns_count = 0
            has_dns_events = False
            while True:
                events = win32evtlog.EvtNext(q, 100)
                if not events:
                    break
                for e in events:
                    xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    eid = root.find("ns:System/ns:EventID", ns)
                    if eid is not None and eid.text == "22":
                        dns_count += 1
                        has_dns_events = True
            return dns_count if has_dns_events else None
        except Exception:
            return None


def extract_network_features(
    evidence_dir: Path | str, sample_id: str = "EXEC_RUN-001"
) -> NetworkFeatures:
    """Functional convenience entry point for Network feature extraction."""
    extractor = NetworkExtractor()
    return extractor.extract(evidence_dir=evidence_dir, sample_id=sample_id)


def main() -> None:
    """CLI interface for Network feature extraction."""
    parser = argparse.ArgumentParser(description="Extract Track B Network features from evidence")
    parser.add_argument(
        "--input-dir",
        "-i",
        type=Path,
        required=True,
        help="Directory containing network_connections.csv",
    )
    parser.add_argument(
        "--sample-id",
        "-s",
        type=str,
        default="EXEC_RUN-001",
        help="Sample identifier",
    )
    parser.add_argument(
        "--output-file",
        "-o",
        type=Path,
        default=None,
        help="Optional output JSON file path",
    )
    args = parser.parse_args()

    features = extract_network_features(args.input_dir, sample_id=args.sample_id)
    out_json = features.model_dump_json(indent=2)
    if args.output_file:
        args.output_file.parent.mkdir(parents=True, exist_ok=True)
        args.output_file.write_text(out_json, encoding="utf-8")
        print(f"[+] Wrote network features to {args.output_file}")
    else:
        print(out_json)


if __name__ == "__main__":
    main()
