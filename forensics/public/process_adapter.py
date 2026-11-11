"""Process telemetry adapter for public benchmark datasets (Track A)."""

from __future__ import annotations

import logging
from typing import Any

from forensics.schemas.process import ProcessFeatures

logger = logging.getLogger("process_adapter")


class ProcessAdapter:
    """Adapts public dataset telemetry to the canonical ProcessFeatures schema."""

    @staticmethod
    def from_malmem(raw_record: dict[str, Any], sample_id: str) -> ProcessFeatures:
        """Map a CIC-MalMem-2022 volatile memory feature vector to ProcessFeatures.

        CIC-MalMem-2022 captures Volatility 2/3 outputs across pslist, psxview,
        handles, dlllist, and malfind.

        Args:
            raw_record: Dictionary of columns from CIC-MalMem-2022 CSV.
            sample_id: Canonical target sample_id.

        Returns:
            Validated ProcessFeatures instance.
        """
        # 1. Total processes from pslist
        total_procs = int(raw_record.get("pslist.nproc", 0))

        # 2. Hidden processes from psxview discrepancies
        not_in_pslist = int(raw_record.get("psxview.not_in_pslist", 0))
        not_in_csrss = int(raw_record.get("psxview.not_in_csrss_handles", 0))
        hidden_procs = max(not_in_pslist, not_in_csrss)

        # 3. Thread metrics directly measured in MalMem
        avg_threads = float(raw_record.get("pslist.avg_threads", 0.0))

        # 4. Handle count directly measured in MalMem
        total_handles = int(raw_record.get("handles.nhandles", 0))

        # 5. Malfind and DLL metrics directly measured in MalMem
        malfind_injections = int(raw_record.get("malfind.ninjections", 0))
        unlinked_dlls = int(raw_record.get("ldrmodules.not_in_load", 0))

        # 6. Unmeasured columns preserved as None (zero inference/fabrication)
        # - anomalous_ppid_count: parent-child lineage anomaly checking not run in MalMem
        # - max_threads_in_single_process: only avg_threads was measured
        # - suspicious_dll_count: path-based DLL inspection not run in MalMem
        # - elevated_privilege_count: privilege token audits not run in MalMem
        return ProcessFeatures(
            sample_id=sample_id,
            total_process_count=max(0, total_procs),
            hidden_process_count=max(0, hidden_procs),
            anomalous_ppid_count=None,
            avg_threads_per_process=max(0.0, avg_threads),
            max_threads_in_single_process=None,
            total_handle_count=max(0, total_handles),
            suspicious_dll_count=None,
            malfind_process_count=max(0, malfind_injections),
            elevated_privilege_count=None,
            unlinked_dll_count=max(0, unlinked_dlls),
        )

    @staticmethod
    def from_behavioral(raw_record: dict[str, Any], sample_id: str) -> ProcessFeatures:
        """Map sandbox execution report (CAPE/Any.Run) to ProcessFeatures.

        Args:
            raw_record: Dictionary containing process tree and execution activity.
            sample_id: Canonical target sample_id.

        Returns:
            Validated ProcessFeatures instance.
        """
        if "total_process_count" in raw_record:
            total_procs = int(raw_record["total_process_count"])
        elif "processes" in raw_record and isinstance(raw_record["processes"], list):
            total_procs = len(raw_record["processes"])
        else:
            total_procs = 0

        hidden = int(raw_record.get("hidden_process_count", 0))
        anom_ppid = int(raw_record.get("anomalous_ppid_count", 0))
        avg_threads = float(raw_record.get("avg_threads_per_process", 1.0))
        max_threads = int(raw_record.get("max_threads_in_single_process", 1))
        handles = int(raw_record.get("total_handle_count", 0))
        suspicious_dlls = int(raw_record.get("suspicious_dll_count", 0))
        malfind_cnt = int(raw_record.get("malfind_process_count", 0))
        elevated = int(raw_record.get("elevated_privilege_count", 0))
        unlinked = int(raw_record.get("unlinked_dll_count", 0))

        return ProcessFeatures(
            sample_id=sample_id,
            total_process_count=max(0, total_procs),
            hidden_process_count=max(0, hidden),
            anomalous_ppid_count=max(0, anom_ppid),
            avg_threads_per_process=max(0.0, avg_threads),
            max_threads_in_single_process=max(0, max_threads),
            total_handle_count=max(0, handles),
            suspicious_dll_count=max(0, suspicious_dlls),
            malfind_process_count=max(0, malfind_cnt),
            elevated_privilege_count=max(0, elevated),
            unlinked_dll_count=max(0, unlinked),
        )
