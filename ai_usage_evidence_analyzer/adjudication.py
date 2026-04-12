"""
TRACE-AI-FR Adjudication Layer (Layer 5).

Separates artifact-level confidence from event-level confidence and
reconstructs Forensically Reconstructed AI-Use Events (FRAUEs) from
corroborated artifact clusters.

Event-level confidence requires:
  - minimum corroboration across artifact families
  - source diversity
  - time coherence
  - coverage sufficiency
  - confound resistance
  - persistence-state qualification
  - version-valid parser status
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    AccessMode,
    AIPlatform,
    AIModel,
    AcquisitionSource,
    ArtifactFamily,
    ArtifactRecord,
    ClaimLevel,
    ConfidenceLevel,
    EvidenceConfidenceClass,
    EventConfidenceLevel,
    EvidenceClassification,
    EvidenceSourceClass,
    FRAUE,
    ImageReviewEvidenceState,
    PersistenceState,
    PlatformSurface,
    ValidationLevel,
)
from .claim_ladder import (
    compute_claim_caveats,
    evaluate_fraue_readiness,
    evaluate_platform_presence,
    promote_claim_levels,
)

logger = logging.getLogger(__name__)

# Maximum gap between artifacts within a candidate session
SESSION_WINDOW = timedelta(hours=2)

# Minimum source-class diversity for full event confidence
MIN_SOURCE_DIVERSITY = 2


class AdjudicationEngine:
    """
    Reconstruct FRAUEs from corroborated artifact groups and assign
    event-level confidence distinct from artifact-level confidence.
    """

    def __init__(
        self,
        artifacts: List[ArtifactRecord],
        coverage_sufficient: bool = True,
    ):
        self.artifacts = artifacts
        self.coverage_sufficient = coverage_sufficient
        self.fraues: List[FRAUE] = []

    def adjudicate(self) -> List[FRAUE]:
        """Run the full adjudication pipeline."""
        # Group artifacts by (platform, user_profile)
        groups = self._group_artifacts()

        for (platform, profile), arts in groups.items():
            # Sessionize into candidate time windows
            sessions = self._sessionize(arts)

            for session_arts in sessions:
                fraue = self._build_fraue(platform, profile, session_arts)
                self.fraues.append(fraue)

        # Promote claim levels on artifacts based on FRAUEs
        promote_claim_levels(self.artifacts, self.fraues)

        logger.info(f"Adjudication produced {len(self.fraues)} FRAUE(s)")
        return self.fraues

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    def _group_artifacts(
        self,
    ) -> Dict[Tuple[AIPlatform, str], List[ArtifactRecord]]:
        groups: Dict[Tuple[AIPlatform, str], List[ArtifactRecord]] = defaultdict(list)
        for a in self.artifacts:
            if a.suspected_platform != AIPlatform.UNKNOWN:
                groups[(a.suspected_platform, a.user_profile)].append(a)
        return groups

    # ------------------------------------------------------------------
    # Sessionization (Layer 4 / correlation)
    # ------------------------------------------------------------------

    def _sessionize(
        self, artifacts: List[ArtifactRecord]
    ) -> List[List[ArtifactRecord]]:
        """Split artifacts into candidate sessions based on time proximity."""
        timestamped = sorted(
            [a for a in artifacts if a.timestamp],
            key=lambda a: a.timestamp,
        )
        no_ts = [a for a in artifacts if not a.timestamp]

        if not timestamped:
            # All artifacts lack timestamps — single group
            return [artifacts] if artifacts else []

        sessions: List[List[ArtifactRecord]] = []
        current: List[ArtifactRecord] = [timestamped[0]]

        for art in timestamped[1:]:
            if (art.timestamp - current[-1].timestamp) <= SESSION_WINDOW:
                current.append(art)
            else:
                sessions.append(current)
                current = [art]
        sessions.append(current)

        # Distribute non-timestamped artifacts to the nearest session
        # or create a catch-all session
        if no_ts:
            if sessions:
                sessions[0].extend(no_ts)
            else:
                sessions.append(no_ts)

        return sessions

    # ------------------------------------------------------------------
    # FRAUE construction
    # ------------------------------------------------------------------

    def _build_fraue(
        self,
        platform: AIPlatform,
        profile: str,
        arts: List[ArtifactRecord],
    ) -> FRAUE:
        fraue = FRAUE(
            platform=platform,
            user_profile=profile,
        )

        fraue.artifact_ids = [a.record_id for a in arts]

        # Families and source classes
        families: Set[str] = set()
        source_classes: Set[str] = set()
        for a in arts:
            families.add(a.artifact_family.value)
            source_classes.add(a.evidence_source_class.value)

        fraue.artifact_family_count = len(families)
        fraue.source_diversity = len(source_classes - {"Unknown"}) or len(source_classes)

        # Counts
        fraue.direct_artifact_count = sum(
            1 for a in arts if a.classification == EvidenceClassification.DIRECT
        )
        fraue.inferred_artifact_count = len(arts) - fraue.direct_artifact_count

        # Time window
        timestamped = [a for a in arts if a.timestamp]
        if timestamped:
            sorted_ts = sorted(timestamped, key=lambda a: a.timestamp)
            fraue.window_start = sorted_ts[0].timestamp
            fraue.window_end = sorted_ts[-1].timestamp
            fraue.time_provenance = (
                f"Derived from {len(timestamped)} timestamped artifact(s); "
                f"earliest and latest artifact timestamps define the window."
            )
            fraue.time_coherence = True
        else:
            fraue.time_provenance = "No timestamped artifacts available."
            fraue.time_coherence = False

        # Model
        model_counts: Dict[AIModel, int] = defaultdict(int)
        for a in arts:
            if a.suspected_model != AIModel.UNKNOWN:
                model_counts[a.suspected_model] += 1
        if model_counts:
            fraue.model = max(model_counts, key=model_counts.get)

        # Access mode
        mode_counts: Dict[AccessMode, int] = defaultdict(int)
        for a in arts:
            mode_counts[a.suspected_access_mode] += 1
        best_mode = max(
            (m for m in mode_counts if m != AccessMode.UNKNOWN),
            key=lambda m: mode_counts[m],
            default=AccessMode.UNKNOWN,
        )
        fraue.access_mode = best_mode

        # Activity class
        fraue.likely_activity_class = self._infer_activity_class(arts)

        # v4.0: acquisition sources and platform surfaces
        acq_sources = set()
        plat_surfaces = set()
        direct_ids = []
        corr_ids = []
        voice_related = False
        shared_link_related = False
        generated_asset_related = False

        for a in arts:
            if a.acquisition_source != AcquisitionSource.UNKNOWN:
                acq_sources.add(a.acquisition_source.value)
            if a.platform_surface != PlatformSurface.UNKNOWN:
                plat_surfaces.add(a.platform_surface.value)
            if a.classification == EvidenceClassification.DIRECT:
                direct_ids.append(a.record_id)
            else:
                corr_ids.append(a.record_id)
            if a.related_voice_event_id:
                voice_related = True
            if a.related_shared_link_id:
                shared_link_related = True
            if a.related_generated_asset_id:
                generated_asset_related = True

        fraue.acquisition_sources = sorted(acq_sources)
        fraue.platform_surfaces = sorted(plat_surfaces)
        fraue.direct_evidence_artifact_ids = direct_ids
        fraue.corroborating_artifact_ids = corr_ids
        fraue.voice_related = voice_related
        fraue.shared_link_related = shared_link_related
        fraue.generated_asset_related = generated_asset_related

        # v4.0: evidence confidence class (usage vs authorship)
        fraue.confidence_class = self._assign_confidence_class(fraue, arts)

        # Image-review evidence grading (Rule 5)
        fraue.image_review_state = self._grade_image_evidence(arts)

        # Persistence state
        fraue.persistence_state = self._assess_persistence(arts)

        # Coverage
        fraue.coverage_sufficient = self.coverage_sufficient

        # Corroboration check (Rule 9)
        fraue.corroboration_met = evaluate_fraue_readiness(arts)

        # Event-level confidence
        fraue.event_confidence = self._compute_event_confidence(fraue, arts)

        # Assign claim level
        if fraue.corroboration_met and fraue.event_confidence in (
            EventConfidenceLevel.HIGH,
            EventConfidenceLevel.MODERATE,
        ):
            if fraue.coverage_sufficient:
                fraue.claim_level = ClaimLevel.GOVERNED_CONCLUSION
            else:
                fraue.claim_level = ClaimLevel.FRAUE_RECONSTRUCTION
        elif evaluate_platform_presence(arts):
            fraue.claim_level = ClaimLevel.PLATFORM_PRESENCE
        else:
            fraue.claim_level = ClaimLevel.ARTIFACT_OBSERVATION

        # Mandatory caveats
        fraue.inference_boundaries = self._build_inference_boundaries(fraue)
        fraue.caveats = self._build_caveats(fraue, arts)
        # Claim-ladder corroboration caveats
        fraue.caveats.extend(compute_claim_caveats(arts, fraue))
        fraue.alternative_explanations = self._build_alternatives(fraue)

        return fraue

    # ------------------------------------------------------------------
    # Activity class inference
    # ------------------------------------------------------------------

    def _infer_activity_class(self, arts: List[ArtifactRecord]) -> str:
        indicators = {
            "chat session": 0,
            "file download": 0,
            "image upload/review": 0,
            "content export": 0,
            "app installation": 0,
            "search/query": 0,
        }
        for a in arts:
            fam = a.artifact_family
            indicator = (a.extracted_indicator or "").lower()

            if fam in (ArtifactFamily.BROWSER_HISTORY, ArtifactFamily.BROWSER_COOKIES):
                indicators["chat session"] += 1
            if fam == ArtifactFamily.BROWSER_DOWNLOADS:
                indicators["file download"] += 1
            if fam == ArtifactFamily.USER_CONTENT:
                indicators["content export"] += 1
            if fam == ArtifactFamily.NATIVE_APP:
                indicators["app installation"] += 1
            if any(kw in indicator for kw in ("image", "upload", "photo", "camera")):
                indicators["image upload/review"] += 1
            if any(kw in indicator for kw in ("search", "query", "wordwheel")):
                indicators["search/query"] += 1

        best = max(indicators, key=indicators.get)
        return best if indicators[best] > 0 else "general AI platform interaction"

    # ------------------------------------------------------------------
    # Image-review evidence grading (Rule 5)
    # ------------------------------------------------------------------

    def _grade_image_evidence(
        self, arts: List[ArtifactRecord]
    ) -> ImageReviewEvidenceState:
        image_arts = [
            a for a in arts
            if any(kw in (a.extracted_indicator or "").lower()
                   for kw in ("image", "upload", "photo", "camera",
                              "crime scene", "screenshot", "picture"))
        ]
        if not image_arts:
            return ImageReviewEvidenceState.NONE_IDENTIFIED

        direct_image = [
            a for a in image_arts
            if a.classification == EvidenceClassification.DIRECT
        ]
        if direct_image:
            return ImageReviewEvidenceState.DIRECTLY_SUPPORTED
        if len(image_arts) >= 2:
            return ImageReviewEvidenceState.CONSISTENT_WITH
        return ImageReviewEvidenceState.SUGGESTIVE_OF

    # ------------------------------------------------------------------
    # Persistence assessment (Rule 7)
    # ------------------------------------------------------------------

    def _assess_persistence(self, arts: List[ArtifactRecord]) -> PersistenceState:
        states = [a.persistence_state for a in arts]
        if PersistenceState.INTACT in states:
            return PersistenceState.INTACT
        if PersistenceState.PARTIALLY_RETAINED in states:
            return PersistenceState.PARTIALLY_RETAINED
        if PersistenceState.WEAKLY_RETAINED in states:
            return PersistenceState.WEAKLY_RETAINED
        return PersistenceState.NOT_OBSERVED

    # ------------------------------------------------------------------
    # Event-level confidence (distinct from artifact confidence, Rule 9)
    # ------------------------------------------------------------------

    def _compute_event_confidence(
        self, fraue: FRAUE, arts: List[ArtifactRecord]
    ) -> EventConfidenceLevel:
        score = 0.0

        # 1. Corroboration across families (weight: 0.25)
        if fraue.artifact_family_count >= 3:
            score += 0.25
        elif fraue.artifact_family_count >= 2:
            score += 0.15
        elif fraue.artifact_family_count >= 1:
            score += 0.05

        # 2. Source diversity (weight: 0.15)
        if fraue.source_diversity >= 3:
            score += 0.15
        elif fraue.source_diversity >= 2:
            score += 0.10
        elif fraue.source_diversity >= 1:
            score += 0.03

        # 3. Time coherence (weight: 0.15)
        if fraue.time_coherence:
            score += 0.15

        # 4. Coverage sufficiency (weight: 0.10)
        if fraue.coverage_sufficient:
            score += 0.10

        # 5. Direct evidence presence (weight: 0.20)
        if fraue.direct_artifact_count >= 2:
            score += 0.20
        elif fraue.direct_artifact_count >= 1:
            score += 0.12

        # 6. Confound resistance (weight: 0.10)
        # Artifacts with corroboration from multiple families are less
        # likely to be false positives
        if fraue.corroboration_met and fraue.artifact_family_count >= 2:
            score += 0.10

        # 7. Persistence state (weight: 0.05)
        if fraue.persistence_state == PersistenceState.INTACT:
            score += 0.05
        elif fraue.persistence_state == PersistenceState.PARTIALLY_RETAINED:
            score += 0.03

        # Map to event confidence level
        if score >= 0.70:
            return EventConfidenceLevel.HIGH
        elif score >= 0.40:
            return EventConfidenceLevel.MODERATE
        elif score >= 0.20:
            return EventConfidenceLevel.LOW
        else:
            return EventConfidenceLevel.INSUFFICIENT

    # ------------------------------------------------------------------
    # Mandatory qualifications
    # ------------------------------------------------------------------

    def _build_inference_boundaries(self, fraue: FRAUE) -> List[str]:
        """Rule 1: interaction is reportable; cognition is not."""
        boundaries = [
            "This reconstruction describes observable AI-system interaction; "
            "it does not infer belief, trust, acceptance, reliance, or "
            "investigative intent.",
        ]
        if not fraue.time_coherence:
            boundaries.append(
                "Time-window boundaries could not be established from the "
                "available timestamps."
            )
        if fraue.model == AIModel.UNKNOWN:
            boundaries.append(
                "Model-level attribution was not possible; finding is limited "
                "to platform-level attribution (Rule 3)."
            )
        return boundaries

    def _build_caveats(
        self, fraue: FRAUE, arts: List[ArtifactRecord]
    ) -> List[str]:
        caveats = []

        # Rule 2: uneven recovery
        if not fraue.coverage_sufficient:
            caveats.append(
                "Evidence coverage is partial; negative findings must be "
                "interpreted as scope-limited (Rule 2)."
            )

        # Rule 4: time findings are bounded
        if fraue.window_start and fraue.window_end:
            caveats.append(
                "Reported time window is approximate and derived from artifact "
                "timestamps, not from direct session-start/session-end records."
            )

        # Rule 6: unsupported is not absent
        if fraue.event_confidence == EventConfidenceLevel.INSUFFICIENT:
            caveats.append(
                "Insufficient support within examined scope does not mean "
                "the platform was not used (Rule 6)."
            )

        # Rule 7: cleanup is persistence, not motive
        if fraue.persistence_state in (
            PersistenceState.WEAKLY_RETAINED,
            PersistenceState.NOT_OBSERVED,
        ):
            caveats.append(
                "Weak or absent persistence is reported as a preservation "
                "effect, not as evidence of concealment (Rule 7)."
            )

        # Rule 10: narrative is explanatory
        caveats.append(
            "Any narrative text in this report is explanatory only; "
            "evidentiary facts are the artifacts, exhibits, and scoring "
            "decisions (Rule 10)."
        )

        return caveats

    def _build_alternatives(self, fraue: FRAUE) -> List[str]:
        alts = []
        if fraue.artifact_family_count == 1:
            alts.append(
                "Single artifact-family evidence could result from automated "
                "browser sync, shared device, or background process."
            )
        if fraue.direct_artifact_count == 0:
            alts.append(
                "All evidence is inferred; platform interaction could be "
                "explained by third-party redirects or advertising beacons."
            )
        return alts

    # ------------------------------------------------------------------
    # v4.0: Evidence confidence class
    # ------------------------------------------------------------------

    def _assign_confidence_class(
        self, fraue: FRAUE, arts: List[ArtifactRecord]
    ) -> EvidenceConfidenceClass:
        """
        Assign evidence confidence class (Caveat 4):
        - OBSERVED_AI_USE: strong direct evidence of platform interaction
        - CORROBORATED_AI_USE: corroborated inferred evidence
        - SUSPECTED_AI_USE: limited or single-source evidence
        - INSUFFICIENT_SUPPORT: cannot support a claim
        """
        if fraue.event_confidence == EventConfidenceLevel.HIGH and fraue.direct_artifact_count >= 2:
            return EvidenceConfidenceClass.OBSERVED_AI_USE
        if fraue.event_confidence in (EventConfidenceLevel.HIGH, EventConfidenceLevel.MODERATE):
            if fraue.corroboration_met:
                return EvidenceConfidenceClass.CORROBORATED_AI_USE
        if fraue.direct_artifact_count >= 1 or len(arts) >= 2:
            return EvidenceConfidenceClass.SUSPECTED_AI_USE
        return EvidenceConfidenceClass.INSUFFICIENT_SUPPORT
