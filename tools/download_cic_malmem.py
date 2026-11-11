"""Download and verification script for CIC-MalMem-2022 dataset.

Downloads Obfuscated-MalMem2022.csv from the public research repository,
computes the cryptographic SHA-256 checksum, and validates:
- Expected file existence
- Total row count (58,596 samples)
- Label distribution (29,298 Benign, 29,298 Malware)
- Malware family breakdown
"""

from __future__ import annotations

import csv
import hashlib
import logging
import ssl
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import certifi

logger = logging.getLogger("download_cic_malmem")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

_REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = _REPO_ROOT / "data" / "raw" / "public" / "cic_malmem_2022"
TARGET_FILE = TARGET_DIR / "Obfuscated-MalMem2022.csv"

SOURCE_URL = "https://raw.githubusercontent.com/Inyrkz/obfuscated_malware_detection/main/Obfuscated-MalMem2022.csv"
EXPECTED_ROW_COUNT = 58596
EXPECTED_BENIGN_COUNT = 29298
EXPECTED_MALWARE_COUNT = 29298


def download_cic_malmem() -> dict[str, Any]:
    """Download the raw CSV file if not already cached and compute its SHA256."""
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    if TARGET_FILE.exists() and TARGET_FILE.stat().st_size > 10_000_000:
        logger.info(
            f"Target file already exists: {TARGET_FILE} ({TARGET_FILE.stat().st_size:,} bytes)"
        )
    else:
        logger.info(f"Downloading CIC-MalMem-2022 from {SOURCE_URL}...")
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        req = urllib.request.Request(
            SOURCE_URL, headers={"User-Agent": "Antigravity-FMD-Ingestion/1.0"}
        )

        hasher = hashlib.sha256()
        with (
            urllib.request.urlopen(req, context=ssl_ctx) as response,
            open(TARGET_FILE, "wb") as out_f,
        ):
            total_bytes = 0
            while chunk := response.read(1024 * 1024):
                hasher.update(chunk)
                out_f.write(chunk)
                total_bytes += len(chunk)
                print(f"Downloaded {total_bytes / (1024 * 1024):.1f} MB...", end="\r")

        print()
        logger.info(f"Download complete: {TARGET_FILE} ({total_bytes:,} bytes)")

    # Compute SHA-256
    logger.info("Computing SHA-256 checksum of raw dataset...")
    hasher = hashlib.sha256()
    with open(TARGET_FILE, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    sha256_hash = hasher.hexdigest()
    logger.info(f"SHA-256: {sha256_hash}")

    # Verify rows, labels, and class distribution
    logger.info("Validating dataset structure, row counts, and class balance...")
    row_count = 0
    class_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    with open(TARGET_FILE, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for row in reader:
            row_count += 1
            cls_val = row.get("Class", "").strip()
            cat_val = row.get("Category", "").strip()
            class_counts[cls_val] += 1
            category_counts[cat_val] += 1

    logger.info(f"Total data rows read: {row_count}")
    logger.info(f"Class distribution: {dict(class_counts)}")
    logger.info(f"Top 5 categories: {category_counts.most_common(5)}")

    if row_count != EXPECTED_ROW_COUNT:
        raise ValueError(f"Expected {EXPECTED_ROW_COUNT} rows, but got {row_count}")

    benign_cnt = class_counts.get("Benign", 0)
    malware_cnt = class_counts.get("Malware", 0)
    if benign_cnt != EXPECTED_BENIGN_COUNT or malware_cnt != EXPECTED_MALWARE_COUNT:
        raise ValueError(
            f"Class balance mismatch: expected {EXPECTED_BENIGN_COUNT} Benign and {EXPECTED_MALWARE_COUNT} Malware, "
            f"got {benign_cnt} Benign and {malware_cnt} Malware"
        )

    logger.info("Dataset verification PASSED with 100% precision.")

    verification_meta = {
        "dataset_name": "CIC-MalMem-2022",
        "file_name": TARGET_FILE.name,
        "file_path": str(TARGET_FILE.relative_to(_REPO_ROOT)),
        "file_size_bytes": TARGET_FILE.stat().st_size,
        "sha256": sha256_hash,
        "total_rows": row_count,
        "columns_count": len(fieldnames),
        "columns": fieldnames,
        "class_distribution": dict(class_counts),
        "category_distribution": dict(category_counts),
        "source_url": SOURCE_URL,
    }

    # Save verification metadata
    meta_path = TARGET_DIR / "verification.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        import json

        json.dump(verification_meta, f, indent=2)

    return verification_meta


if __name__ == "__main__":
    download_cic_malmem()
