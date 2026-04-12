"""
Acquisition quality metadata bridge (ddrescue-like awareness).

Lightweight companion module that stores metadata about forensic
acquisition quality — bad sectors, retries, partial reads — and
adjusts report caveats and confidence ceilings accordingly.

This module does NOT implement full imaging.  It integrates
user-supplied acquisition logs/maps so the pipeline can factor
degraded media into its governed conclusions.
"""

from __future__ import annotations

import logging
import os
import re
from typing import List, Optional

from .models import (
    AcquisitionMetadata,
    AcquisitionQuality,
    ConfidenceLevel,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Acquisition metadata factory
# ---------------------------------------------------------------------------

def build_acquisition_metadata(
    source_image_path: str = "",
    acquisition_tool: str = "",
    quality: str = "unknown",
    bad_sector_count: int = 0,
    retry_count: int = 0,
    partial_read_map_path: str = "",
    acquisition_notes: str = "",
) -> AcquisitionMetadata:
    """Create an AcquisitionMetadata from user-supplied values."""
    q = {
        "normal": AcquisitionQuality.NORMAL,
        "degraded": AcquisitionQuality.DEGRADED,
    }.get(quality.lower(), AcquisitionQuality.UNKNOWN)

    return AcquisitionMetadata(
        source_image_path=source_image_path,
        acquisition_tool=acquisition_tool,
        acquisition_quality=q,
        bad_sector_count=bad_sector_count,
        retry_count=retry_count,
        partial_read_map_path=partial_read_map_path,
        acquisition_notes=acquisition_notes,
    )


# ---------------------------------------------------------------------------
# ddrescue map file parser
# ---------------------------------------------------------------------------

def parse_ddrescue_map(map_path: str) -> AcquisitionMetadata:
    """
    Parse a GNU ddrescue map/log file and extract acquisition metadata.

    The map format has lines like:
        0x00000000  0x00100000  +   (finished)
        0x00100000  0x00001000  -   (bad sector)
        0x00101000  0x00200000  /   (non-tried)
    """
    meta = AcquisitionMetadata(
        partial_read_map_path=map_path,
        acquisition_tool="ddrescue (parsed from map)",
    )

    if not os.path.isfile(map_path):
        logger.warning("ddrescue map file not found: %s", map_path)
        meta.acquisition_quality = AcquisitionQuality.UNKNOWN
        return meta

    bad = 0
    total = 0
    good = 0
    try:
        with open(map_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                try:
                    size = int(parts[1], 0)
                except ValueError:
                    continue
                status_char = parts[2]
                total += size
                if status_char == "+":
                    good += size
                elif status_char == "-":
                    bad += size
    except OSError as exc:
        logger.warning("Cannot read ddrescue map %s: %s", map_path, exc)
        meta.acquisition_quality = AcquisitionQuality.UNKNOWN
        return meta

    meta.total_sectors = total
    meta.successful_sectors = good
    meta.bad_sector_count = bad

    if bad == 0 and total > 0:
        meta.acquisition_quality = AcquisitionQuality.NORMAL
    elif bad > 0:
        meta.acquisition_quality = AcquisitionQuality.DEGRADED
    else:
        meta.acquisition_quality = AcquisitionQuality.UNKNOWN

    return meta


# ---------------------------------------------------------------------------
# Confidence ceiling adjustments
# ---------------------------------------------------------------------------

def confidence_ceiling_for_acquisition(
    meta: Optional[AcquisitionMetadata],
) -> ConfidenceLevel:
    """
    Return the maximum confidence level that should be assigned to any
    artifact given the acquisition quality.

    - NORMAL acquisition → no ceiling (HIGH allowed)
    - DEGRADED acquisition → ceiling at MODERATE
    - UNKNOWN → ceiling at MODERATE (conservative)
    """
    if meta is None:
        return ConfidenceLevel.HIGH  # no metadata → no restriction
    if meta.acquisition_quality == AcquisitionQuality.NORMAL:
        return ConfidenceLevel.HIGH
    # Degraded or unknown → cap at moderate
    return ConfidenceLevel.MODERATE


def acquisition_caveats(meta: Optional[AcquisitionMetadata]) -> List[str]:
    """Generate caveat strings arising from acquisition quality."""
    if meta is None:
        return []
    caveats: List[str] = []
    if meta.acquisition_quality == AcquisitionQuality.DEGRADED:
        caveats.append(
            f"Acquisition quality is DEGRADED "
            f"({meta.bad_sector_count} bad sectors reported). "
            "Confidence ceilings are reduced; negative findings "
            "are weakened."
        )
    if meta.acquisition_quality == AcquisitionQuality.UNKNOWN:
        caveats.append(
            "Acquisition quality is UNKNOWN. Absence of artifacts "
            "cannot be relied upon for negative inference."
        )
    if meta.retry_count > 0:
        caveats.append(
            f"Acquisition required {meta.retry_count} retry passes. "
            "Some sectors may contain unreliable data."
        )
    return caveats
