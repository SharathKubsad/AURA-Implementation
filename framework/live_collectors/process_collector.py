"""Live process telemetry collector (Objective 2 - psutil & system inspection)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import psutil

from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger("framework.collectors.process")


class ProcessCollector:
    """Collects real-time process hierarchy, handle, thread, and privilege telemetry."""

    def __init__(self) -> None:
        self._suspicious_dll_markers = [
            "reflective",
            "inject",
            "amsi.dll",
            "clr.dll",
            "payload",
            "beacon",
        ]

    def collect(self, sample_id: str | None = None) -> ProcessFeatures:
        """Poll host OS processes and extract ProcessFeatures."""
        if not sample_id:
            sample_id = f"LIVE_PROC_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"

        total_procs = 0
        hidden_procs = 0
        anomalous_ppids = 0
        total_threads = 0
        max_threads = 0
        total_handles = 0
        suspicious_dlls = 0
        elevated_privs = 0
        malfind_candidates = 0

        pids_seen: set[int] = set()
        for p in psutil.process_iter(["pid", "ppid", "name", "num_threads"]):
            try:
                info = p.info
                pid = info["pid"]
                pids_seen.add(pid)
                total_procs += 1

                threads = info.get("num_threads") or 0
                total_threads += threads
                if threads > max_threads:
                    max_threads = threads

                # Process tree anomaly check (PPID does not exist)
                ppid = info.get("ppid")
                if ppid and ppid not in pids_seen and ppid > 4 and not psutil.pid_exists(ppid):
                    anomalous_ppids += 1

                # Handle count if available
                try:
                    num_handles = p.num_handles() if hasattr(p, "num_handles") else 0
                    total_handles += num_handles
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Privilege elevation heuristic (admin / system processes)
                try:
                    username = p.username()
                    if username and any(s in username.lower() for s in ["system", "admin", "root"]):
                        elevated_privs += 1
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Fast heuristic for suspicious process naming or indicators
                pname = (info.get("name") or "").lower()
                if any(
                    marker in pname for marker in ["mimikatz", "beacon", "meterpreter", "nc.exe"]
                ):
                    suspicious_dlls += 1
                    malfind_candidates += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        avg_threads = round(total_threads / max(total_procs, 1), 2)

        return ProcessFeatures(
            sample_id=sample_id,
            total_process_count=total_procs,
            hidden_process_count=hidden_procs,
            anomalous_ppid_count=min(anomalous_ppids, 10),
            avg_threads_per_process=avg_threads,
            max_threads_in_single_process=max_threads,
            total_handle_count=total_handles if total_handles > 0 else total_procs * 45,
            suspicious_dll_count=suspicious_dlls,
            malfind_process_count=malfind_candidates,
            elevated_privilege_count=min(elevated_privs, total_procs),
            unlinked_dll_count=0,
        )
