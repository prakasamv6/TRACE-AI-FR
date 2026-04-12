"""
TRACE-AI-FR Persistence State Tracker.

Assigns persistence state (Rule 7) to every artifact based on the source
characteristics. Cleanup, logout, cache clearing, or uninstall are reported
as preservation effects, not as concealment or motive.

States:
  - Intact              — Artifact recovered from active, unmodified source.
  - Partially Retained  — Artifact recovered but source shows signs of aging/rotation.
  - Weakly Retained     — Artifact recovered from fallback source (binary scan, cache).
  - Not Observed        — Artifact type expected but not found within scope.
"""

from __future__ import annotations

import logging
from typing import List

from .models import (
    ArtifactFamily,
    ArtifactRecord,
    EvidenceClassification,
    PersistenceState,
)

logger = logging.getLogger(__name__)

# Families considered strong-persistence when present and direct
STRONG_PERSISTENCE_FAMILIES = {
    ArtifactFamily.BROWSER_HISTORY,
    ArtifactFamily.BROWSER_DOWNLOADS,
    ArtifactFamily.NATIVE_APP,
    ArtifactFamily.USER_CONTENT,
    ArtifactFamily.OS_REGISTRY,
}

# Families that are typically short-lived or rotated
WEAK_PERSISTENCE_FAMILIES = {
    ArtifactFamily.BROWSER_COOKIES,
    ArtifactFamily.BROWSER_CACHE,
    ArtifactFamily.BROWSER_SESSION,
    ArtifactFamily.BROWSER_LOCAL_STORAGE,
    ArtifactFamily.CLIPBOARD,
    ArtifactFamily.NOTIFICATION,
}


def assign_persistence_state(artifact: ArtifactRecord) -> PersistenceState:
    """
    Assign a persistence state to a single artifact based on its
    artifact family, classification, and source characteristics.
    """

    # Carved / recovery artifacts — fragment-only persistence
    subtype_lower = (artifact.artifact_subtype or "").lower()
    notes_lower = (artifact.notes or "").lower()
    if subtype_lower.startswith("carved_") or "[carved]" in notes_lower:
        artifact.persistence_state = PersistenceState.FRAGMENT_ONLY
        return PersistenceState.FRAGMENT_ONLY

    # Raw-hit artifacts — weakly retained (no structural context)
    if subtype_lower.startswith("raw_") or "[raw]" in notes_lower:
        artifact.persistence_state = PersistenceState.WEAKLY_RETAINED
        return PersistenceState.WEAKLY_RETAINED

    # Binary scan fallback artifacts are weakly retained
    if "binary scan" in subtype_lower:
        artifact.persistence_state = PersistenceState.WEAKLY_RETAINED
        return PersistenceState.WEAKLY_RETAINED

    # Direct evidence from strong-persistence families
    if (artifact.artifact_family in STRONG_PERSISTENCE_FAMILIES
            and artifact.classification == EvidenceClassification.DIRECT):
        artifact.persistence_state = PersistenceState.INTACT
        return PersistenceState.INTACT

    # Inferred evidence from strong families (e.g., inferred from filename pattern)
    if artifact.artifact_family in STRONG_PERSISTENCE_FAMILIES:
        artifact.persistence_state = PersistenceState.PARTIALLY_RETAINED
        return PersistenceState.PARTIALLY_RETAINED

    # Weak-persistence families (cookies, cache, session, etc.)
    if artifact.artifact_family in WEAK_PERSISTENCE_FAMILIES:
        if artifact.classification == EvidenceClassification.DIRECT:
            artifact.persistence_state = PersistenceState.PARTIALLY_RETAINED
        else:
            artifact.persistence_state = PersistenceState.WEAKLY_RETAINED
        return artifact.persistence_state

    # OS execution traces, event logs, plists
    if artifact.artifact_family in (
        ArtifactFamily.OS_EXECUTION,
        ArtifactFamily.OS_EVENT_LOG,
        ArtifactFamily.OS_PLIST,
        ArtifactFamily.OS_UNIFIED_LOG,
        ArtifactFamily.OS_RECENT_FILES,
    ):
        artifact.persistence_state = PersistenceState.PARTIALLY_RETAINED
        return PersistenceState.PARTIALLY_RETAINED

    # Screenshots and file-system artifacts
    if artifact.artifact_family in (
        ArtifactFamily.SCREENSHOT,
        ArtifactFamily.FILE_SYSTEM,
    ):
        artifact.persistence_state = PersistenceState.INTACT
        return PersistenceState.INTACT

    # Default
    artifact.persistence_state = PersistenceState.NOT_OBSERVED
    return PersistenceState.NOT_OBSERVED


def assign_persistence_states(artifacts: List[ArtifactRecord]) -> None:
    """Assign persistence states to all artifacts."""
    for art in artifacts:
        assign_persistence_state(art)
    logger.info(f"Persistence states assigned to {len(artifacts)} artifact(s)")
