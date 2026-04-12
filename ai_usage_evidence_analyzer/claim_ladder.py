"""
TRACE-AI-FR Claim Ladder.

Enforces the four-level claim ladder that prevents the framework from
jumping from a single artifact to an overconfident behavioral conclusion.

Levels:
  1. Artifact Observation    — A discrete artifact exists with provenance.
  2. Platform Presence       — Corroborated artifacts support platform access.
  3. FRAUE Reconstruction    — Bounded session with access mode and activity class.
  4. Governed Conclusion     — Reportable after thresholds, coverage, validation, caveats.
"""

from __future__ import annotations

import logging
from typing import List, Set

from .models import (
    ArtifactRecord,
    ClaimLevel,
    ConfidenceLevel,
    EvidenceClassification,
    EventConfidenceLevel,
    FRAUE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimum requirements per claim level
# ---------------------------------------------------------------------------

# Level 2 (Platform Presence): at least this many artifacts from >= 2 families
MIN_ARTIFACTS_PLATFORM_PRESENCE = 2
MIN_FAMILIES_PLATFORM_PRESENCE = 1  # Relaxed: 1 family OK if 2+ artifacts

# Level 3 (FRAUE Reconstruction): at least 2 corroborating families OR
# 1 direct + 1 supporting with coherent timing (Rule 9)
MIN_FAMILIES_FRAUE = 2

# Level 4 (Governed Conclusion): event confidence >= MODERATE + coverage check
MIN_EVENT_CONFIDENCE_GOVERNED = EventConfidenceLevel.MODERATE


def assign_artifact_claim_level(artifact: ArtifactRecord) -> ClaimLevel:
    """
    Assign a claim level to a single artifact.
    Every artifact starts at Level 1 (Artifact Observation).
    Higher levels are assigned by the adjudication engine at event scope.
    """
    artifact.claim_level = ClaimLevel.ARTIFACT_OBSERVATION
    return ClaimLevel.ARTIFACT_OBSERVATION


def evaluate_platform_presence(
    artifacts: List[ArtifactRecord],
) -> bool:
    """
    Determine whether corroborated artifacts support the presence of
    a platform (Level 2).

    Returns True if the minimum thresholds are met.
    Considers both artifact-family diversity and evidence-class diversity
    (from notes field, e.g. "Evidence class: B-Configuration").
    """
    if len(artifacts) < MIN_ARTIFACTS_PLATFORM_PRESENCE:
        return False

    families: Set[str] = set()
    for a in artifacts:
        families.add(a.artifact_family.value)

    if len(families) >= MIN_FAMILIES_PLATFORM_PRESENCE:
        return True

    # Single family is acceptable only if there are multiple distinct direct artifacts
    direct = [a for a in artifacts if a.classification == EvidenceClassification.DIRECT]
    if len(direct) >= 2:
        return True

    # Also accept if evidence classes are diverse (A + B, or A + C, etc.)
    ev_classes = _extract_evidence_classes(artifacts)
    return len(ev_classes) >= 2


def evaluate_fraue_readiness(
    artifacts: List[ArtifactRecord],
) -> bool:
    """
    Determine whether a set of artifacts can support a Level 3 FRAUE.

    Rule 9: requires either
      - at least 2 corroborating artifact families, OR
      - 1 direct artifact + 1 supporting artifact with coherent timing.
    """
    if not artifacts:
        return False

    families: Set[str] = {a.artifact_family.value for a in artifacts}

    # Path A: multiple families
    if len(families) >= MIN_FAMILIES_FRAUE:
        return True

    # Path B: 1 direct + 1 supporting with timing
    direct = [a for a in artifacts if a.classification == EvidenceClassification.DIRECT]
    timestamped = [a for a in artifacts if a.timestamp is not None]

    if direct and len(timestamped) >= 2:
        return True

    return False


def evaluate_governed_conclusion(fraue: FRAUE) -> bool:
    """
    Determine whether a FRAUE qualifies for Level 4 (Governed Conclusion).

    Requirements:
      - event_confidence >= MODERATE
      - corroboration_met == True
      - coverage_sufficient == True
    """
    confidence_ok = fraue.event_confidence in (
        EventConfidenceLevel.HIGH,
        EventConfidenceLevel.MODERATE,
    )
    return confidence_ok and fraue.corroboration_met and fraue.coverage_sufficient


def promote_claim_levels(
    artifacts: List[ArtifactRecord],
    fraues: List[FRAUE],
):
    """
    Walk through FRAUEs and promote constituent artifact claim levels
    according to the claim ladder.
    """
    art_map = {a.record_id: a for a in artifacts}

    for fraue in fraues:
        # Determine this FRAUE's claim level
        if evaluate_governed_conclusion(fraue):
            fraue.claim_level = ClaimLevel.GOVERNED_CONCLUSION
        elif fraue.corroboration_met:
            fraue.claim_level = ClaimLevel.FRAUE_RECONSTRUCTION
        else:
            fraue.claim_level = ClaimLevel.PLATFORM_PRESENCE

        # Promote contributing artifacts
        for aid in fraue.artifact_ids:
            art = art_map.get(aid)
            if art and _level_rank(fraue.claim_level) > _level_rank(art.claim_level):
                art.claim_level = fraue.claim_level


def _level_rank(level: ClaimLevel) -> int:
    """Numeric rank for comparison."""
    ranks = {
        ClaimLevel.ARTIFACT_OBSERVATION: 1,
        ClaimLevel.PLATFORM_PRESENCE: 2,
        ClaimLevel.FRAUE_RECONSTRUCTION: 3,
        ClaimLevel.GOVERNED_CONCLUSION: 4,
    }
    return ranks.get(level, 0)


# ---------------------------------------------------------------------------
# Evidence-class helpers
# ---------------------------------------------------------------------------

_EVIDENCE_CLASS_PREFIX = "Evidence class: "


def _extract_evidence_classes(artifacts: List[ArtifactRecord]) -> Set[str]:
    """
    Extract evidence classes (A–F) from artifact notes.

    The AI Tool Scanner tags each artifact with an evidence class like
    ``Evidence class: B-Configuration``.  Returns set of class prefixes.
    """
    classes: Set[str] = set()
    for a in artifacts:
        notes = a.notes or ""
        idx = notes.find(_EVIDENCE_CLASS_PREFIX)
        if idx >= 0:
            rest = notes[idx + len(_EVIDENCE_CLASS_PREFIX):]
            # Extract up to the next period or end of string
            token = rest.split(".")[0].strip()
            if token:
                classes.add(token.split("-")[0])  # Just the letter
    return classes


def compute_claim_caveats(
    artifacts: List[ArtifactRecord],
    fraue: FRAUE,
) -> List[str]:
    """
    Compute claim-ladder-specific caveats that must be attached to a FRAUE
    based on the evidence diversity and corroboration state.

    Returns a list of caveat strings to be appended to fraue.caveats.
    """
    caveats: List[str] = []

    families = {a.artifact_family.value for a in artifacts}
    ev_classes = _extract_evidence_classes(artifacts)

    # Single-family corroboration warning
    if len(families) <= 1 and len(artifacts) >= 2:
        caveats.append(
            "All corroborating artifacts belong to a single artifact family; "
            "claim level is limited by corroboration diversity (Rule 9)."
        )

    # Single evidence class warning
    if len(ev_classes) <= 1 and len(artifacts) >= 2:
        caveats.append(
            "All evidence originates from a single evidence class "
            f"({''.join(ev_classes) or 'A'}); higher claim levels require "
            "independent evidence classes."
        )

    # Presence-only artifacts (no D-Usage or above)
    usage_classes = ev_classes & {"D", "E", "F"}
    if not usage_classes and artifacts:
        caveats.append(
            "Evidence is limited to presence/installation/configuration; "
            "no usage, output, or attribution evidence was identified."
        )

    # Coverage sufficiency
    if not fraue.coverage_sufficient:
        caveats.append(
            "Evidence coverage is partial; claim level capped at "
            "Level 3 (FRAUE Reconstruction) per Rule 2."
        )

    return caveats
