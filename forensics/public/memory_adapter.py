"""Memory forensics adapter for public benchmark datasets (Track A)."""

from __future__ import annotations

import logging
from typing import Any

from forensics.schemas.memory import MemoryFeatures

logger = logging.getLogger("memory_adapter")


class MemoryAdapter:
    """Adapts volatile memory forensic telemetry to the canonical MemoryFeatures schema."""

    @staticmethod
    def from_malmem(raw_record: dict[str, Any], sample_id: str) -> MemoryFeatures:
        """Map a CIC-MalMem-2022 memory forensic feature vector to MemoryFeatures.

        CIC-MalMem-2022 contains Volatility outputs from malfind, ldrmodules,
        and VAD structures. Memory entropy was not computed in MalMem-2022,
        so entropy fields are strictly preserved as None without synthetic imputation.

        NOTE ON vad_protection_anomaly_count:
        In MalMem, vad_protection_anomaly_count is a MALMEM_SPECIFIC_PROXY mapped from
        malfind.commitCharge > 0. It is NOT semantically equivalent to the custom domain's
        measurement of InitProtection != Protection (e.g. VirtualProtect state modification).

        Args:
            raw_record: Dictionary of columns from CIC-MalMem-2022 CSV.
            sample_id: Canonical target sample_id.

        Returns:
            Validated MemoryFeatures instance.
        """
        # 1. Protection anomalies (PAGE_EXECUTE_READWRITE pages) from malfind.protection
        rwx_pages = int(raw_record.get("malfind.protection", 0))

        # 2. Injected code regions and unmapped pages from malfind
        ninjections = int(raw_record.get("malfind.ninjections", 0))
        unique_inj = int(float(raw_record.get("malfind.uniqueInjections", 0)))

        # 3. LDR module discrepancies
        not_in_load = int(raw_record.get("ldrmodules.not_in_load", 0))
        not_in_init = int(raw_record.get("ldrmodules.not_in_init", 0))
        not_in_mem = int(raw_record.get("ldrmodules.not_in_mem", 0))
        ldr_inconsistencies = max(0, not_in_load + not_in_init + not_in_mem)

        # 4. VAD protection anomalies: MALMEM_SPECIFIC_PROXY based on commit charge in injected regions
        # Warning: NOT semantically equivalent to custom InitProtection != Protection!
        commit_charge = int(raw_record.get("malfind.commitCharge", 0))
        vad_anomalies = 1 if (ninjections > 0 and commit_charge > 0) else 0

        # 5. Unmeasured features preserved as None without synthetic imputation:
        # - yara_shellcode_matches: YARA rules not run in MalMem-2022
        # - mean_memory_entropy, max_memory_entropy: entropy not calculated in MalMem-2022
        return MemoryFeatures(
            sample_id=sample_id,
            rwx_page_count=max(0, rwx_pages),
            injected_code_regions=max(0, ninjections),
            unmapped_executable_pages=max(0, unique_inj),
            vad_protection_anomaly_count=max(0, vad_anomalies),
            ldrmodules_inconsistencies=max(0, ldr_inconsistencies),
            yara_shellcode_matches=None,
            mean_memory_entropy=None,
            max_memory_entropy=None,
        )

    @staticmethod
    def from_volatility_raw(raw_record: dict[str, Any], sample_id: str) -> MemoryFeatures:
        """Map raw Volatility 3 output metrics to MemoryFeatures.

        Args:
            raw_record: Dictionary of memory telemetry metrics.
            sample_id: Canonical target sample_id.

        Returns:
            Validated MemoryFeatures instance.
        """
        mean_ent = raw_record.get("mean_memory_entropy")
        max_ent = raw_record.get("max_memory_entropy")

        return MemoryFeatures(
            sample_id=sample_id,
            rwx_page_count=max(0, int(raw_record.get("rwx_page_count", 0))),
            injected_code_regions=max(0, int(raw_record.get("injected_code_regions", 0))),
            unmapped_executable_pages=max(0, int(raw_record.get("unmapped_executable_pages", 0))),
            vad_protection_anomaly_count=max(
                0, int(raw_record.get("vad_protection_anomaly_count", 0))
            ),
            ldrmodules_inconsistencies=max(0, int(raw_record.get("ldrmodules_inconsistencies", 0))),
            yara_shellcode_matches=max(0, int(raw_record.get("yara_shellcode_matches", 0))),
            mean_memory_entropy=float(mean_ent) if mean_ent is not None else None,
            max_memory_entropy=float(max_ent) if max_ent is not None else None,
        )
