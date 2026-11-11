"""Common parsing utilities and entropy calculation for Volatility 3 outputs."""

from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


def calculate_shannon_entropy(data: bytes | str | list[int]) -> float:
    """Calculate Shannon entropy for a sequence of bytes or characters (0.0 to 8.0).

    Args:
        data: Input bytes, string, or integer byte values.

    Returns:
        float: Shannon entropy in bits per symbol (0.0 to 8.0).
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        byte_data = data.encode("utf-8", errors="ignore")
    elif isinstance(data, list):
        byte_data = bytes(data)
    else:
        byte_data = data

    length = len(byte_data)
    if length == 0:
        return 0.0

    counts = Counter(byte_data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def find_plugin_file(directory: Path, plugin_name: str) -> Path | None:
    """Locate a plugin output file in a directory by name or standard variants.

    Args:
        directory: Path to the directory containing Volatility 3 outputs.
        plugin_name: Base plugin name (e.g. 'pslist', 'vadinfo').

    Returns:
        Path | None: File path if found, else None.
    """
    candidates = [
        f"{plugin_name}.json",
        f"windows.{plugin_name}.json",
        f"{plugin_name}.csv",
        f"windows.{plugin_name}.csv",
        f"{plugin_name}.txt",
        f"windows.{plugin_name}.txt",
        f"{plugin_name}.log",
    ]
    for c in candidates:
        target = directory / c
        if target.is_file():
            return target

    # Case-insensitive fallback
    for f in directory.iterdir():
        if f.is_file() and plugin_name.lower() in f.name.lower():
            return f

    return None


def parse_volatility_file(file_path: Path) -> list[dict[str, Any]]:
    """Parse a Volatility 3 output file in JSON, CSV, or tabular text format.

    Args:
        file_path: Path to the output file.

    Returns:
        list[dict[str, Any]]: List of row records as dictionaries with lowercased keys.
    """
    content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return []

    # 1. Try parsing as JSON
    if file_path.suffix.lower() == ".json" or content.startswith("{") or content.startswith("["):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                # Standard list of dicts
                if data and isinstance(data[0], dict):
                    return [{k.lower().strip(): v for k, v in row.items()} for row in data]
                # List of lists with header?
                return []
            if isinstance(data, dict):
                # Volatility tree format: {"columns": [...], "rows": [...]}
                if "columns" in data and "rows" in data:
                    cols = [str(c).lower().strip() for c in data["columns"]]
                    records: list[dict[str, Any]] = []
                    for row in data["rows"]:
                        if isinstance(row, list) and len(row) <= len(cols):
                            records.append(
                                {cols[i]: row[i] if i < len(row) else None for i in range(len(row))}
                            )
                        elif isinstance(row, dict):
                            records.append({k.lower().strip(): v for k, v in row.items()})
                    return records
                # Single record or dictionary map
                return [{k.lower().strip(): v for k, v in data.items()}]
        except json.JSONDecodeError:
            pass

    # 2. Try parsing as CSV
    if file_path.suffix.lower() == ".csv" or "," in content.splitlines()[0]:
        try:
            lines = [
                line for line in content.splitlines() if line.strip() and not line.startswith("#")
            ]
            if lines and "," in lines[0]:
                reader = csv.DictReader(lines)
                if reader.fieldnames:
                    records = []
                    for r in reader:
                        records.append(
                            {k.lower().strip(): v for k, v in r.items() if k is not None}
                        )
                    if records:
                        return records
        except Exception:
            pass

    # 3. Fallback: Parse as Whitespace-delimited Tabular Text
    return parse_tabular_text(content)


def parse_tabular_text(text: str) -> list[dict[str, Any]]:
    """Parse Volatility 3 standard CLI whitespace-delimited table output.

    Args:
        text: Raw text string from command stdout.

    Returns:
        list[dict[str, Any]]: Parsed row records.
    """
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []

    # Find the header line (ignore Volatility banner or metadata)
    header_idx = -1
    for idx, line in enumerate(lines):
        if (
            line.startswith("Volatility")
            or line.startswith("***")
            or line.startswith("Progress:")
            or line.lower().startswith("no records")
        ):
            continue
        # Check if line looks like column headers (PID, PPID, ImageFileName, etc.)
        if re.search(
            r"\b(PID|PPID|Offset|ImageFileName|Process|Protection|Base|Privilege|Rule|InLoad|Start VPN|Handles|Threads)\b",
            line,
            re.I,
        ):
            header_idx = idx
            break

    if header_idx == -1:
        # If no recognized header found, do not assume arbitrary text is tabular data
        return []

    header_line = lines[header_idx]
    # Check if next line is a separator (e.g. ----- -----)
    data_start_idx = header_idx + 1
    if data_start_idx < len(lines) and re.match(r"^[-=\s]+$", lines[data_start_idx]):
        data_start_idx += 1

    headers = [h.lower().strip() for h in re.split(r"\s{2,}|\t+", header_line) if h.strip()]
    if not headers:
        # Fallback to single space split
        headers = [h.lower().strip() for h in header_line.split() if h.strip()]

    records: list[dict[str, Any]] = []
    for line in lines[data_start_idx:]:
        if line.startswith("Volatility") or line.startswith("***") or line.startswith("Progress:"):
            continue
        # Split by 2+ spaces or tabs
        parts = [p.strip() for p in re.split(r"\s{2,}|\t+", line) if p.strip()]
        if len(parts) == len(headers):
            records.append(dict(zip(headers, parts, strict=False)))
        elif len(parts) > len(headers):
            # Combine overflowing trailing tokens into last column
            merged = parts[: len(headers) - 1] + [" ".join(parts[len(headers) - 1 :])]
            records.append(dict(zip(headers, merged, strict=False)))
        elif parts:
            # Fewer tokens: pad with empty strings
            padded = parts + [""] * (len(headers) - len(parts))
            records.append(dict(zip(headers, padded, strict=False)))

    return records


def parse_malfind_output(file_path: Path) -> list[dict[str, Any]]:
    """Parse Volatility 3 malfind output, extracting genuine findings.

    A single malfind finding in Volatility 3 text output spans multiple lines:
    a header row (PID, Process, Start VPN, End VPN, Tag, Protection, ...)
    followed by multiple lines of hexdump (0x... byte data) and disassembly
    instructions.

    This parser:
    - Identifies genuine finding rows (first token is decimal integer PID, and
      line contains executable protection like PAGE_EXECUTE_READWRITE).
    - Ignores hexdump and disassembly lines so findings are not inflated.
    - Deduplicates per (pid, start_vpn) boundary.
    - Preserves distinct VAD regions in the same process as separate findings.
    - Works seamlessly on both JSON and raw CLI text format.

    Args:
        file_path: Path to the malfind output file.

    Returns:
        list[dict[str, Any]]: List of genuine malfind findings.
    """
    content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return []

    # JSON format handling
    if file_path.suffix.lower() == ".json" or content.startswith("[") or content.startswith("{"):
        try:
            data = json.loads(content)
            raw_records: list[dict[str, Any]] = []
            if isinstance(data, list):
                raw_records = data
            elif isinstance(data, dict) and "rows" in data and "columns" in data:
                cols = [str(c).lower().strip() for c in data["columns"]]
                for row in data["rows"]:
                    if isinstance(row, list):
                        raw_records.append(
                            dict(
                                zip(
                                    cols,
                                    row[: len(cols)] + [None] * (len(cols) - len(row)),
                                    strict=False,
                                )
                            )
                        )
                    elif isinstance(row, dict):
                        raw_records.append(row)
            elif isinstance(data, dict):
                raw_records = [data]

            findings: list[dict[str, Any]] = []
            seen_keys: set[tuple[int, str]] = set()
            for r in raw_records:
                pid_raw = str(r.get("pid") or r.get("PID") or "").strip()
                prot = str(r.get("protection") or r.get("Protection") or "").upper()
                if not (re.match(r"^[0-9]+$", pid_raw) and "EXECUTE" in prot):
                    continue
                pid = int(pid_raw)
                start_vpn = str(
                    r.get("start vpn")
                    or r.get("startvpn")
                    or r.get("start_vpn")
                    or r.get("offset")
                    or ""
                ).lower()
                key = (pid, start_vpn) if start_vpn else (pid, str(len(findings)))
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        {
                            "pid": pid,
                            "process": str(r.get("process") or r.get("Process") or "").strip(),
                            "start_vpn": start_vpn,
                            "protection": prot,
                            "tag": str(r.get("tag") or r.get("Tag") or "").strip() or "Vad",
                        }
                    )
            return findings
        except json.JSONDecodeError:
            pass

    # Text / CLI line-by-line format handling
    findings = []
    seen_keys = set()
    for line in content.splitlines():
        line_clean = line.strip()
        if (
            not line_clean
            or line_clean.startswith("Volatility")
            or line_clean.startswith("Progress:")
            or line_clean.startswith("***")
        ):
            continue

        parts = re.split(r"\s{2,}|\t+", line_clean)
        if not parts or len(parts) < 3:
            parts = line_clean.split()
        if not parts or len(parts) < 3:
            continue

        # Requirement: First field must be decimal integer PID
        # awk '$1 ~ /^[0-9]+$/ && $0 ~ /PAGE_EXECUTE/ {n++} END {print n}'
        first_token = parts[0].strip()
        if not re.match(r"^[0-9]+$", first_token):
            continue

        # Requirement: Line must contain executable protection
        line_upper = line_clean.upper()
        if "EXECUTE" not in line_upper:
            continue

        pid = int(first_token)
        # Find start_vpn as the first 0x token after PID
        start_vpn = ""
        for p in parts[1:]:
            if p.lower().startswith("0x"):
                start_vpn = p.lower()
                break
        if not start_vpn and len(parts) > 2:
            start_vpn = parts[2].lower()

        prot_token = ""
        for p in parts:
            if "EXECUTE" in p.upper():
                prot_token = p.upper()
                break

        tag_token = "Vad"
        for p in parts:
            if p.startswith("Vad"):
                tag_token = p
                break

        process = parts[1] if len(parts) > 1 else ""
        key = (pid, start_vpn) if start_vpn else (pid, f"finding_{len(findings)}")
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(
                {
                    "pid": pid,
                    "process": process,
                    "start_vpn": start_vpn,
                    "protection": prot_token or "PAGE_EXECUTE_READWRITE",
                    "tag": tag_token,
                }
            )

    return findings


def parse_ldrmodules_output(file_path: Path) -> list[dict[str, Any]]:
    """Parse Volatility 3 ldrmodules output into validated module records.

    Ensures module records are identified cleanly according to (PID, Base) semantics:
    - Validates that PID is a numeric integer > 0 (filters header/banner lines).
    - Validates that Base is a valid memory address (starts with 0x).
    - Correctly parses InLoad and InMem boolean values.
    - Ignores wrapped path lines or malformed trailing text.
    - Deduplicates per (PID, Base) module boundary.

    Args:
        file_path: Path to ldrmodules output file.

    Returns:
        list[dict[str, Any]]: Validated module records.
    """
    content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return []

    # JSON format handling
    if file_path.suffix.lower() == ".json" or content.startswith("[") or content.startswith("{"):
        try:
            data = json.loads(content)
            raw_records: list[dict[str, Any]] = []
            if isinstance(data, list):
                raw_records = data
            elif isinstance(data, dict) and "rows" in data and "columns" in data:
                cols = [str(c).lower().strip() for c in data["columns"]]
                for row in data["rows"]:
                    if isinstance(row, list):
                        raw_records.append(
                            dict(
                                zip(
                                    cols,
                                    row[: len(cols)] + [None] * (len(cols) - len(row)),
                                    strict=False,
                                )
                            )
                        )
                    elif isinstance(row, dict):
                        raw_records.append(row)
            elif isinstance(data, dict):
                raw_records = [data]

            modules: list[dict[str, Any]] = []
            seen_keys: set[tuple[int, str]] = set()
            for r in raw_records:
                pid_raw = str(r.get("pid") or r.get("PID") or "").strip()
                if not re.match(r"^[0-9]+$", pid_raw):
                    continue
                pid = int(pid_raw)
                base_raw = str(r.get("base") or r.get("Base") or "").strip().lower()
                if base_raw and not (base_raw.startswith("0x") or base_raw.isdigit()):
                    continue
                name_raw = str(r.get("name") or r.get("mappedpath") or "").strip()
                key = (pid, base_raw) if base_raw else (pid, name_raw or f"mod_{len(modules)}")
                if key not in seen_keys:
                    seen_keys.add(key)
                    in_load = str(r.get("inload", "")).lower().strip() in ("true", "1", "yes")
                    in_init = str(r.get("ininit", "")).lower().strip() in ("true", "1", "yes")
                    in_mem = str(r.get("inmem", "")).lower().strip() in ("true", "1", "yes")
                    modules.append(
                        {
                            "pid": pid,
                            "process": str(r.get("process") or r.get("Process") or ""),
                            "base": base_raw,
                            "name": name_raw,
                            "inload": in_load,
                            "ininit": in_init,
                            "inmem": in_mem,
                        }
                    )
            return modules
        except json.JSONDecodeError:
            pass

    # Text / CLI format handling
    modules = []
    seen_keys = set()
    for line in content.splitlines():
        line_clean = line.strip()
        if (
            not line_clean
            or line_clean.startswith("Volatility")
            or line_clean.startswith("Progress:")
            or line_clean.startswith("***")
        ):
            continue

        parts = re.split(r"\s{2,}|\t+", line_clean)
        if not parts or len(parts) < 6:
            parts = line_clean.split()
        if len(parts) < 6:
            continue

        # Field 1: PID must be decimal integer
        first_token = parts[0].strip()
        if not re.match(r"^[0-9]+$", first_token):
            continue

        # Find base address token (starts with 0x)
        base_idx = -1
        for i, token in enumerate(parts[1:], start=1):
            if token.lower().startswith("0x"):
                base_idx = i
                break
        if base_idx == -1 or len(parts) < base_idx + 4:
            continue

        base_token = parts[base_idx].strip().lower()
        pid = int(first_token)
        key = (pid, base_token)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        process_name = " ".join(parts[1:base_idx]).strip()
        in_load = parts[base_idx + 1].strip().lower() in ("true", "1", "yes")
        in_init = parts[base_idx + 2].strip().lower() in ("true", "1", "yes")
        in_mem = parts[base_idx + 3].strip().lower() in ("true", "1", "yes")
        mapped_path = " ".join(parts[base_idx + 4 :]).strip() if len(parts) > base_idx + 4 else ""

        modules.append(
            {
                "pid": pid,
                "process": process_name,
                "base": base_token,
                "name": mapped_path,
                "inload": in_load,
                "ininit": in_init,
                "inmem": in_mem,
            }
        )

    return modules
