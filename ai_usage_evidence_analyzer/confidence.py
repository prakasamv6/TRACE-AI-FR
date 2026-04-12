"""
Confidence scoring engine.

Applies layered confidence scoring to artifact records based on:
- Artifact reliability
- Timestamp quality
- Source redundancy
- Cross-artifact corroboration
- Artifact persistence class
- Attribution layer specificity
- Evidence source completeness
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Optional, Set

from .models import (
    AccessMode,
    AIPlatform,
    AIModel,
    AIUsageFootprint,
    ArtifactFamily,
    ArtifactRecord,
    AttributionLayer,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceCoverage,
    EvidenceConfidenceClass,
    PersistenceState,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Artifact reliability weights
# ---------------------------------------------------------------------------

FAMILY_RELIABILITY: Dict[ArtifactFamily, float] = {
    ArtifactFamily.BROWSER_HISTORY: 0.7,
    ArtifactFamily.BROWSER_DOWNLOADS: 0.8,
    ArtifactFamily.BROWSER_COOKIES: 0.3,
    ArtifactFamily.BROWSER_LOCAL_STORAGE: 0.4,
    ArtifactFamily.BROWSER_SESSION: 0.5,
    ArtifactFamily.BROWSER_CACHE: 0.3,
    ArtifactFamily.NATIVE_APP: 0.7,
    ArtifactFamily.OS_EXECUTION: 0.6,
    ArtifactFamily.OS_RECENT_FILES: 0.5,
    ArtifactFamily.OS_REGISTRY: 0.5,
    ArtifactFamily.OS_EVENT_LOG: 0.6,
    ArtifactFamily.OS_PLIST: 0.5,
    ArtifactFamily.OS_UNIFIED_LOG: 0.6,
    ArtifactFamily.FILE_SYSTEM: 0.5,
    ArtifactFamily.USER_CONTENT: 0.6,
    ArtifactFamily.CLIPBOARD: 0.4,
    ArtifactFamily.SCREENSHOT: 0.4,
    ArtifactFamily.NOTIFICATION: 0.3,
    ArtifactFamily.UNKNOWN: 0.1,
}

CLASSIFICATION_WEIGHT = {
    EvidenceClassification.DIRECT: 1.0,
    EvidenceClassification.INFERRED: 0.5,
}

ATTRIBUTION_WEIGHT = {
    AttributionLayer.MODEL: 1.0,
    AttributionLayer.CONTENT: 0.8,
    AttributionLayer.PLATFORM: 0.6,
}


class ConfidenceScoringEngine:
    """
    Score and classify confidence levels for artifact records.
    """

    def __init__(
        self,
        artifacts: List[ArtifactRecord],
        evidence_coverage: Optional[EvidenceCoverage] = None,
    ):
        self.artifacts = artifacts
        self.evidence_coverage = evidence_coverage

    def score_all(self) -> List[ArtifactRecord]:
        """Score all artifacts and return updated records."""
        # First pass: base scores
        for art in self.artifacts:
            self._score_single(art)

        # Second pass: corroboration boost
        self._apply_corroboration_boost()

        # Third pass: evidence coverage adjustment
        if self.evidence_coverage:
            self._apply_coverage_adjustment()

        return self.artifacts

    def _score_single(self, art: ArtifactRecord):
        """Compute base confidence score for a single artifact."""
        score = 0.0

        # Factor 1: Artifact family reliability
        score += FAMILY_RELIABILITY.get(art.artifact_family, 0.1)

        # Factor 2: Classification (direct vs inferred)
        score *= CLASSIFICATION_WEIGHT.get(art.classification, 0.5)

        # Factor 3: Attribution layer
        score *= ATTRIBUTION_WEIGHT.get(art.attribution_layer, 0.6)

        # Factor 4: Timestamp quality
        if art.timestamp and art.timezone_normalized:
            score += 0.1
        elif art.timestamp:
            score += 0.05

        # Factor 5: Deductions for weak indicators
        if "weak indicator" in (art.notes or "").lower():
            score *= 0.7
        if "alone is not sufficient" in (art.notes or "").lower():
            score *= 0.7

        # Factor 6: Recovery-aware penalties
        notes_lower = (art.notes or "").lower()
        if "[carved]" in notes_lower:
            score *= 0.6  # carved_fragment_penalty
        elif "[raw]" in notes_lower:
            score *= 0.5  # raw hits penalised more
        if art.persistence_state == PersistenceState.FRAGMENT_ONLY:
            score *= 0.7  # missing_metadata_penalty

        # Map to confidence level
        art.confidence = self._score_to_level(score)

    def _apply_corroboration_boost(self):
        """Boost confidence for artifacts with corroborating evidence."""
        id_to_art = {a.record_id: a for a in self.artifacts}

        for art in self.artifacts:
            if not art.corroborating_artifacts:
                continue

            # Count distinct artifact families in corroborating set
            corr_families: Set[str] = set()
            for rid in art.corroborating_artifacts:
                corr_art = id_to_art.get(rid)
                if corr_art:
                    corr_families.add(corr_art.artifact_family.value)

            # Boost based on diversity of corroboration
            if len(corr_families) >= 3:
                # Multiple diverse sources corroborating
                if art.confidence == ConfidenceLevel.MODERATE:
                    art.confidence = ConfidenceLevel.HIGH
                elif art.confidence == ConfidenceLevel.LOW:
                    art.confidence = ConfidenceLevel.MODERATE
            elif len(corr_families) >= 1:
                if art.confidence == ConfidenceLevel.LOW:
                    art.confidence = ConfidenceLevel.MODERATE

        # Recovery claim ceiling: carved/raw-only artifacts cap at MODERATE
        for art in self.artifacts:
            notes_lower = (art.notes or "").lower()
            is_recovery = "[carved]" in notes_lower or "[raw]" in notes_lower
            if is_recovery and art.confidence == ConfidenceLevel.HIGH:
                art.confidence = ConfidenceLevel.MODERATE
                art.notes = (art.notes or "") + " [Confidence capped: recovery-sourced artifact]"

    def _apply_coverage_adjustment(self):
        """
        Adjust confidence based on evidence coverage limitations.
        Partial evidence means we should be more cautious about HIGH ratings.
        """
        if not self.evidence_coverage:
            return

        from .models import ImageType
        if self.evidence_coverage.image_type in (ImageType.TRIAGE, ImageType.PARTIAL):
            for art in self.artifacts:
                # Downgrade HIGH to MODERATE for triage/partial sources
                if art.confidence == ConfidenceLevel.HIGH:
                    art.confidence = ConfidenceLevel.MODERATE
                    if not art.notes:
                        art.notes = ""
                    art.notes += " [Confidence adjusted: partial evidence source]"

    def _score_to_level(self, score: float) -> ConfidenceLevel:
        """Map numeric score to confidence level."""
        if score >= 0.7:
            return ConfidenceLevel.HIGH
        elif score >= 0.4:
            return ConfidenceLevel.MODERATE
        elif score >= 0.15:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNSUPPORTED

    def build_footprints(self) -> List[AIUsageFootprint]:
        """Build AI Usage Footprints per platform."""
        footprints = []

        platform_groups: Dict[AIPlatform, List[ArtifactRecord]] = defaultdict(list)
        for art in self.artifacts:
            if art.suspected_platform != AIPlatform.UNKNOWN:
                platform_groups[art.suspected_platform].append(art)

        for platform, arts in platform_groups.items():
            timestamped = [a for a in arts if a.timestamp]
            direct = [a for a in arts if a.classification == EvidenceClassification.DIRECT]
            inferred = [a for a in arts if a.classification == EvidenceClassification.INFERRED]

            # Determine most common model
            model_counts: Dict[AIModel, int] = defaultdict(int)
            for a in arts:
                if a.suspected_model != AIModel.UNKNOWN:
                    model_counts[a.suspected_model] += 1
            best_model = max(model_counts, key=model_counts.get) if model_counts else AIModel.UNKNOWN

            # Determine access mode
            mode_counts: Dict[AccessMode, int] = defaultdict(int)
            for a in arts:
                mode_counts[a.suspected_access_mode] += 1
            best_mode = max(
                (m for m in mode_counts if m != AccessMode.UNKNOWN),
                key=lambda m: mode_counts[m],
                default=AccessMode.UNKNOWN,
            )

            # Count image upload indicators
            image_indicators = sum(
                1 for a in arts
                if "image" in (a.extracted_indicator or "").lower()
                or "upload" in (a.extracted_indicator or "").lower()
                or "screenshot" in (a.artifact_type or "").lower()
            )

            # Count content export indicators
            export_indicators = sum(
                1 for a in arts
                if a.artifact_family in (ArtifactFamily.BROWSER_DOWNLOADS, ArtifactFamily.USER_CONTENT)
            )

            # Count prompt/response remnants
            prompt_remnants = sum(
                1 for a in arts
                if "prompt" in (a.artifact_subtype or "").lower()
            )
            response_remnants = sum(
                1 for a in arts
                if "response" in (a.artifact_subtype or "").lower()
            )

            # Estimate sessions from temporal gaps
            if len(timestamped) >= 2:
                sorted_times = sorted(
                    (a.timestamp.replace(tzinfo=None) if a.timestamp.tzinfo else a.timestamp)
                    for a in timestamped
                )
                sessions = 1
                for i in range(1, len(sorted_times)):
                    if (sorted_times[i] - sorted_times[i-1]).total_seconds() > 7200:
                        sessions += 1
            else:
                sessions = 1 if timestamped else 0

            # Overall confidence
            confidence_levels = [a.confidence for a in arts]
            if ConfidenceLevel.HIGH in confidence_levels:
                overall = ConfidenceLevel.HIGH
            elif ConfidenceLevel.MODERATE in confidence_levels:
                overall = ConfidenceLevel.MODERATE
            elif ConfidenceLevel.LOW in confidence_levels:
                overall = ConfidenceLevel.LOW
            else:
                overall = ConfidenceLevel.UNSUPPORTED

            # Caveats
            caveats = []
            if not direct:
                caveats.append("No directly observed evidence; all findings are inferred.")
            if best_model == AIModel.UNKNOWN:
                caveats.append("Model-level attribution not possible; platform-level only.")
            if self.evidence_coverage and not self.evidence_coverage.full_disk_available:
                caveats.append("Evidence source may not contain all relevant artifacts.")

            footprint = AIUsageFootprint(
                platform=platform,
                model=best_model,
                access_mode=best_mode,
                total_artifacts=len(arts),
                direct_artifacts=len(direct),
                inferred_artifacts=len(inferred),
                earliest_activity=min(timestamped, key=lambda a: a.timestamp.replace(tzinfo=None) if a.timestamp.tzinfo else a.timestamp).timestamp if timestamped else None,
                latest_activity=max(timestamped, key=lambda a: a.timestamp.replace(tzinfo=None) if a.timestamp.tzinfo else a.timestamp).timestamp if timestamped else None,
                estimated_session_count=sessions,
                image_upload_indicators=image_indicators,
                content_export_indicators=export_indicators,
                prompt_remnants_found=prompt_remnants,
                response_remnants_found=response_remnants,
                overall_confidence=overall,
                caveats=caveats,
            )
            footprints.append(footprint)

        return footprints
