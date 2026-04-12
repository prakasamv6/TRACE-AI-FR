"""
Correlation engine and timeline reconstruction.

Takes normalized artifact records and correlates them into:
- A chronological timeline of AI-related activity
- Cross-artifact corroboration links
- Session boundary estimates
- Evidence-source-class assignment (TRACE-AI-FR Rule 8)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple


def _naive(dt: datetime) -> datetime:
    """Strip timezone info for safe comparisons of mixed naive/aware datetimes."""
    return dt.replace(tzinfo=None) if dt.tzinfo else dt

from .models import (
    AccessMode,
    AIPlatform,
    AcquisitionSource,
    ArtifactFamily,
    ArtifactRecord,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceSourceClass,
    PlatformSurface,
    TimelineEvent,
)

logger = logging.getLogger(__name__)

# Maximum time gap between artifacts to consider them part of the same session
SESSION_GAP_THRESHOLD = timedelta(hours=2)


class CorrelationEngine:
    """
    Correlate artifacts and build a timeline of AI-related activity.
    """

    def __init__(self, artifacts: List[ArtifactRecord]):
        self.artifacts = artifacts
        self.timeline: List[TimelineEvent] = []
        self.corroboration_map: Dict[str, List[str]] = defaultdict(list)

    def run(self) -> List[TimelineEvent]:
        """Execute correlation pipeline."""
        logger.info(f"Correlating {len(self.artifacts)} artifacts")

        # Step 1: Build temporal groups per platform
        platform_groups = self._group_by_platform()

        # Step 2: Find corroborating artifacts
        self._find_corroborations()

        # Step 3: Build timeline events
        self._build_timeline()

        # Step 4: Estimate sessions
        self._estimate_sessions()

        logger.info(f"Timeline built with {len(self.timeline)} events")
        return self.timeline

    def _group_by_platform(self) -> Dict[AIPlatform, List[ArtifactRecord]]:
        """Group artifacts by suspected AI platform."""
        groups: Dict[AIPlatform, List[ArtifactRecord]] = defaultdict(list)
        for art in self.artifacts:
            groups[art.suspected_platform].append(art)
        return groups

    def _find_corroborations(self):
        """
        Find corroborating artifacts:
        - Same platform + similar timestamp -> corroborate each other
        - Same URL across different artifact types -> corroborate
        - Browser history + cookie + download for same platform -> strong corroboration
        """
        # Group artifacts by platform and approximate time window
        platform_time_groups: Dict[Tuple[AIPlatform, str], List[ArtifactRecord]] = defaultdict(list)

        for art in self.artifacts:
            if art.timestamp:
                time_key = art.timestamp.strftime("%Y-%m-%d-%H")
                platform_time_groups[(art.suspected_platform, time_key)].append(art)

        # Within each group, mark corroborations
        for key, group in platform_time_groups.items():
            if len(group) < 2:
                continue

            # Each artifact in a temporal group corroborates the others
            ids = [a.record_id for a in group]
            for art in group:
                corroborating = [rid for rid in ids if rid != art.record_id]
                art.corroborating_artifacts.extend(corroborating[:5])  # Keep top 5
                self.corroboration_map[art.record_id].extend(corroborating)

        # Cross-artifact-type corroboration (e.g., history + cookie + download)
        platform_artifacts: Dict[AIPlatform, Dict[str, List[ArtifactRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for art in self.artifacts:
            platform_artifacts[art.suspected_platform][art.artifact_family.value].append(art)

        for platform, family_map in platform_artifacts.items():
            families = list(family_map.keys())
            if len(families) >= 2:
                # Multiple artifact families for same platform = stronger evidence
                all_ids = []
                for fam_arts in family_map.values():
                    all_ids.extend(a.record_id for a in fam_arts)

                for fam_arts in family_map.values():
                    for art in fam_arts:
                        corroborating = [rid for rid in all_ids if rid != art.record_id]
                        for rid in corroborating[:3]:
                            if rid not in art.corroborating_artifacts:
                                art.corroborating_artifacts.append(rid)

    def _build_timeline(self):
        """Build chronological timeline events from artifacts."""
        timestamped = [a for a in self.artifacts if a.timestamp is not None]
        timestamped.sort(key=lambda a: _naive(a.timestamp))

        for art in timestamped:
            event = TimelineEvent(
                timestamp=art.timestamp,
                event_type=art.artifact_type,
                description=self._describe_event(art),
                platform=art.suspected_platform,
                access_mode=art.suspected_access_mode,
                artifact_record_id=art.record_id,
                confidence=art.confidence,
                classification=art.classification,
            )
            self.timeline.append(event)

    def _estimate_sessions(self):
        """
        Estimate AI usage sessions based on temporal clustering.
        Groups timeline events within SESSION_GAP_THRESHOLD.
        """
        if not self.timeline:
            return

        sessions: List[List[TimelineEvent]] = []
        current_session: List[TimelineEvent] = [self.timeline[0]]

        for event in self.timeline[1:]:
            if (_naive(event.timestamp) - _naive(current_session[-1].timestamp)) <= SESSION_GAP_THRESHOLD:
                current_session.append(event)
            else:
                sessions.append(current_session)
                current_session = [event]

        sessions.append(current_session)

        # Tag session boundaries
        for i, session in enumerate(sessions):
            if session:
                session[0].event_type = f"[Session {i+1} Start] {session[0].event_type}"
                if len(session) > 1:
                    session[-1].event_type = f"[Session {i+1} End] {session[-1].event_type}"

    def _describe_event(self, art: ArtifactRecord) -> str:
        """Create a human-readable description for a timeline event."""
        parts = [
            f"[{art.suspected_platform.value}]",
            f"({art.artifact_family.value})",
            art.extracted_indicator[:100] if art.extracted_indicator else art.artifact_type,
        ]
        if art.suspected_access_mode != AccessMode.UNKNOWN:
            parts.insert(1, f"[{art.suspected_access_mode.value}]")
        return " ".join(parts)

    def get_platform_summary(self) -> Dict[AIPlatform, Dict]:
        """Get a summary of findings per platform."""
        summary = {}
        for platform in AIPlatform:
            if platform == AIPlatform.UNKNOWN:
                continue
            arts = [a for a in self.artifacts if a.suspected_platform == platform]
            if not arts:
                continue

            timestamped = [a for a in arts if a.timestamp]
            earliest = min(a.timestamp for a in timestamped) if timestamped else None
            latest = max(a.timestamp for a in timestamped) if timestamped else None

            direct_count = sum(1 for a in arts if a.classification == EvidenceClassification.DIRECT)
            inferred_count = sum(1 for a in arts if a.classification == EvidenceClassification.INFERRED)

            families = set(a.artifact_family.value for a in arts)

            summary[platform] = {
                "total_artifacts": len(arts),
                "direct_artifacts": direct_count,
                "inferred_artifacts": inferred_count,
                "earliest_activity": earliest,
                "latest_activity": latest,
                "artifact_families": sorted(families),
                "access_modes": sorted(set(a.suspected_access_mode.value for a in arts)),
            }

        return summary


# ---------------------------------------------------------------------------
# Evidence-source-class assignment (TRACE-AI-FR Rule 8)
# ---------------------------------------------------------------------------

# Mapping from artifact family -> evidence source class
_FAMILY_TO_SOURCE_CLASS: Dict[ArtifactFamily, EvidenceSourceClass] = {
    ArtifactFamily.BROWSER_HISTORY: EvidenceSourceClass.BROWSER_DERIVED,
    ArtifactFamily.BROWSER_COOKIES: EvidenceSourceClass.BROWSER_DERIVED,
    ArtifactFamily.BROWSER_CACHE: EvidenceSourceClass.BROWSER_DERIVED,
    ArtifactFamily.BROWSER_LOCAL_STORAGE: EvidenceSourceClass.BROWSER_DERIVED,
    ArtifactFamily.BROWSER_SESSION: EvidenceSourceClass.BROWSER_DERIVED,
    ArtifactFamily.BROWSER_DOWNLOADS: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.USER_CONTENT: EvidenceSourceClass.CONTENT_REMNANT_DERIVED,
    ArtifactFamily.NATIVE_APP: EvidenceSourceClass.NATIVE_APP_DERIVED,
    ArtifactFamily.CLIPBOARD: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.NOTIFICATION: EvidenceSourceClass.NATIVE_APP_DERIVED,
    ArtifactFamily.OS_REGISTRY: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.OS_EXECUTION: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.OS_RECENT_FILES: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.OS_EVENT_LOG: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.OS_PLIST: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.OS_UNIFIED_LOG: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.FILE_SYSTEM: EvidenceSourceClass.OS_DERIVED,
    ArtifactFamily.SCREENSHOT: EvidenceSourceClass.CONTENT_REMNANT_DERIVED,
}


def assign_evidence_source_classes(artifacts: List[ArtifactRecord]) -> None:
    """
    Assign evidence_source_class to each artifact based on its family.

    Rule 8: Browser artefacts, file-system traces, app telemetry, OS-level
    configuration, and volatile memory captures must be classified into
    distinct evidence source classes and never merged into a single
    credibility pool.
    """
    for art in artifacts:
        art.evidence_source_class = _FAMILY_TO_SOURCE_CLASS.get(
            art.artifact_family, EvidenceSourceClass.UNKNOWN
        )
        # v4.0: assign acquisition source if not already set
        if art.acquisition_source == AcquisitionSource.UNKNOWN:
            art.acquisition_source = _infer_acquisition_source(art)
        # v4.0: assign platform surface if not already set
        if art.platform_surface == PlatformSurface.UNKNOWN:
            art.platform_surface = _infer_platform_surface(art)


# ---------------------------------------------------------------------------
# v4.0 acquisition-source inference
# ---------------------------------------------------------------------------

_FAMILY_TO_ACQ_SOURCE: Dict[ArtifactFamily, AcquisitionSource] = {
    ArtifactFamily.BROWSER_HISTORY: AcquisitionSource.BROWSER_ARTIFACT,
    ArtifactFamily.BROWSER_COOKIES: AcquisitionSource.BROWSER_ARTIFACT,
    ArtifactFamily.BROWSER_CACHE: AcquisitionSource.BROWSER_ARTIFACT,
    ArtifactFamily.BROWSER_LOCAL_STORAGE: AcquisitionSource.BROWSER_ARTIFACT,
    ArtifactFamily.BROWSER_SESSION: AcquisitionSource.BROWSER_ARTIFACT,
    ArtifactFamily.BROWSER_DOWNLOADS: AcquisitionSource.BROWSER_ARTIFACT,
    ArtifactFamily.USER_CONTENT: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.NATIVE_APP: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.CLIPBOARD: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.NOTIFICATION: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.OS_REGISTRY: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.OS_EXECUTION: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.OS_RECENT_FILES: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.OS_EVENT_LOG: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.OS_PLIST: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.OS_UNIFIED_LOG: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.FILE_SYSTEM: AcquisitionSource.MOUNTED_DIRECTORY,
    ArtifactFamily.SCREENSHOT: AcquisitionSource.SCREENSHOT_CAPTURE,
}


def _infer_acquisition_source(art: ArtifactRecord) -> AcquisitionSource:
    """Infer acquisition source from artifact family and metadata."""
    # Check notes for recovery indicators
    notes_lower = (art.notes or "").lower()
    if "[carved]" in notes_lower:
        return AcquisitionSource.E01_IMAGE
    if "[raw]" in notes_lower:
        return AcquisitionSource.E01_IMAGE

    return _FAMILY_TO_ACQ_SOURCE.get(art.artifact_family, AcquisitionSource.UNKNOWN)


# ---------------------------------------------------------------------------
# v4.0 platform-surface inference
# ---------------------------------------------------------------------------

def _infer_platform_surface(art: ArtifactRecord) -> PlatformSurface:
    """Infer platform surface from artifact metadata."""
    fam = art.artifact_family
    mode = art.suspected_access_mode

    if fam in (
        ArtifactFamily.BROWSER_HISTORY, ArtifactFamily.BROWSER_COOKIES,
        ArtifactFamily.BROWSER_CACHE, ArtifactFamily.BROWSER_LOCAL_STORAGE,
        ArtifactFamily.BROWSER_SESSION,
    ):
        return PlatformSurface.BROWSER_WEB

    if fam == ArtifactFamily.BROWSER_DOWNLOADS:
        return PlatformSurface.BROWSER_WEB

    if fam == ArtifactFamily.NATIVE_APP:
        from .models import AccessMode
        if mode == AccessMode.NATIVE_APP:
            return PlatformSurface.NATIVE_DESKTOP_APP
        return PlatformSurface.NATIVE_DESKTOP_APP

    if fam == ArtifactFamily.SCREENSHOT:
        return PlatformSurface.UNKNOWN

    # OS artifacts don't map to a specific surface
    return PlatformSurface.UNKNOWN
