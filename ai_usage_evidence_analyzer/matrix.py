"""
Comparative artifact matrix generator.

Builds a structured matrix comparing AI tool artifacts across platforms,
browsers, artifact families, and evidence quality dimensions.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List

from .models import (
    AccessMode,
    AIPlatform,
    ArtifactFamily,
    ArtifactRecord,
    ComparativeMatrixRow,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceCoverage,
)

logger = logging.getLogger(__name__)


# Persistence ratings for artifact families
PERSISTENCE_RATINGS: Dict[ArtifactFamily, str] = {
    ArtifactFamily.BROWSER_HISTORY: "Medium - survives session close, cleared on history delete",
    ArtifactFamily.BROWSER_DOWNLOADS: "High - persists until manually deleted",
    ArtifactFamily.BROWSER_COOKIES: "Low-Medium - subject to expiry and deletion",
    ArtifactFamily.BROWSER_LOCAL_STORAGE: "Medium - persists until site data cleared",
    ArtifactFamily.BROWSER_SESSION: "Low - lost on browser close unless restored",
    ArtifactFamily.BROWSER_CACHE: "Low-Medium - subject to eviction and size limits",
    ArtifactFamily.NATIVE_APP: "High - persists until app uninstall",
    ArtifactFamily.OS_EXECUTION: "High - Prefetch/AmCache persist across reboots",
    ArtifactFamily.OS_RECENT_FILES: "Medium - limited to recent window size",
    ArtifactFamily.OS_REGISTRY: "High - persists until key deletion",
    ArtifactFamily.OS_EVENT_LOG: "Medium-High - subject to log rotation",
    ArtifactFamily.OS_PLIST: "Medium-High - persists until pref reset",
    ArtifactFamily.OS_UNIFIED_LOG: "Low-Medium - subject to TTL-based pruning",
    ArtifactFamily.FILE_SYSTEM: "Variable - depends on file and FS state",
    ArtifactFamily.USER_CONTENT: "High - persists until user deletion",
    ArtifactFamily.CLIPBOARD: "Very Low - transient",
    ArtifactFamily.SCREENSHOT: "High - persists until user deletion",
    ArtifactFamily.NOTIFICATION: "Low - transient after dismissal",
    ArtifactFamily.UNKNOWN: "Unknown",
}


def build_comparative_matrix(
    artifacts: List[ArtifactRecord],
    evidence_coverage: EvidenceCoverage,
) -> List[ComparativeMatrixRow]:
    """
    Build the comparative artifact matrix from scored artifacts.
    """
    rows: List[ComparativeMatrixRow] = []

    for art in artifacts:
        # Determine evidentiary value
        if art.classification == EvidenceClassification.DIRECT and art.confidence == ConfidenceLevel.HIGH:
            ev_value = "Strong"
        elif art.classification == EvidenceClassification.DIRECT:
            ev_value = "Moderate"
        elif art.confidence in (ConfidenceLevel.MODERATE, ConfidenceLevel.HIGH):
            ev_value = "Supportive"
        else:
            ev_value = "Weak"

        # Timestamp quality
        if art.timestamp and art.timezone_normalized:
            ts_quality = "Good - UTC normalized"
        elif art.timestamp:
            ts_quality = "Fair - timestamp present, normalization uncertain"
        else:
            ts_quality = "Absent"

        # Persistence
        persistence = PERSISTENCE_RATINGS.get(art.artifact_family, "Unknown")

        # Relevance to crime-scene workflow
        relevance = _assess_crime_scene_relevance(art)

        # Coverage caveat
        caveat = ""
        if not evidence_coverage.full_disk_available:
            caveat = "Evidence source is not a full disk image. Some artifacts may be absent."
        if not evidence_coverage.carving_enabled:
            if caveat:
                caveat += " "
            caveat += "File carving was disabled."

        # Model display
        model_display = art.suspected_model.value if art.suspected_model and art.suspected_model.value != "Unknown" else ""
        tool_display = art.suspected_platform.value
        if model_display:
            tool_display = f"{tool_display} / {model_display}"

        row = ComparativeMatrixRow(
            platform=art.suspected_platform,
            user_profile=art.user_profile,
            ai_tool_or_model=tool_display,
            browser_vs_app=art.suspected_access_mode,
            artifact_family=art.artifact_family,
            artifact_type=art.artifact_type,
            artifact_location=art.artifact_path,
            evidentiary_value=ev_value,
            timestamp_quality=ts_quality,
            persistence_after_deletion=persistence,
            relevance_to_crime_scene=relevance,
            classification=art.classification,
            confidence=art.confidence,
            evidence_coverage_caveat=caveat,
            comments=art.notes[:200] if art.notes else "",
        )
        rows.append(row)

    return rows


def _assess_crime_scene_relevance(art: ArtifactRecord) -> str:
    """Assess how relevant an artifact is to crime-scene investigation workflow."""
    indicator = (art.extracted_indicator or "").lower()
    art_type = (art.artifact_type or "").lower()
    subtype = (art.artifact_subtype or "").lower()

    # Image analysis indicators
    if any(kw in indicator for kw in ["image", "upload", "photo", "camera", "crime scene"]):
        return "High - possible image analysis activity"

    # Prompt/response indicators
    if "prompt" in subtype or "response" in subtype:
        return "High - possible interactive AI use"

    # Export/download indicators
    if art.artifact_family == ArtifactFamily.BROWSER_DOWNLOADS:
        return "Moderate-High - content download from AI platform"

    if art.artifact_family == ArtifactFamily.USER_CONTENT:
        return "Moderate - AI-related content in user files"

    # Browser history
    if art.artifact_family == ArtifactFamily.BROWSER_HISTORY:
        return "Moderate - platform visit (does not prove substantive use)"

    # Cookies
    if art.artifact_family == ArtifactFamily.BROWSER_COOKIES:
        return "Low - session/login indicator only"

    # Native app
    if art.artifact_family == ArtifactFamily.NATIVE_APP:
        return "Moderate - app presence (does not prove active investigative use)"

    # Execution traces
    if art.artifact_family == ArtifactFamily.OS_EXECUTION:
        return "Moderate - program execution indicator"

    return "Low - indirect or weak indicator"


def matrix_to_dicts(rows: List[ComparativeMatrixRow]) -> List[Dict]:
    """Convert matrix rows to list of dicts for export."""
    return [
        {
            "platform": r.platform.value,
            "user_profile": r.user_profile,
            "ai_tool_or_model": r.ai_tool_or_model,
            "browser_vs_app": r.browser_vs_app.value,
            "artifact_family": r.artifact_family.value,
            "artifact_type": r.artifact_type,
            "artifact_location": r.artifact_location,
            "evidentiary_value": r.evidentiary_value,
            "timestamp_quality": r.timestamp_quality,
            "persistence_after_deletion": r.persistence_after_deletion,
            "relevance_to_crime_scene": r.relevance_to_crime_scene,
            "classification": r.classification.value,
            "confidence": r.confidence.value,
            "evidence_coverage_caveat": r.evidence_coverage_caveat,
            "comments": r.comments,
        }
        for r in rows
    ]
