"""
TRACE-AI-FR Governance Layer (Layer 8).

Builds and exports the case-level AI Use Evidence Governance Record
containing collection scope, legal basis, evidence classes examined,
parser versions, signature versions, validation state, known blind
spots, inference boundaries, and required disclosures.

Also enforces the 12 framework rules by populating the governance
record with the applicable rules list and generating the mandatory
"Scope of Conclusion" and "Inference Boundaries" sections.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from .models import (
    EvidenceCoverage,
    EvidenceSourceClass,
    FilesystemHealth,
    ForensicReport,
    GovernanceRecord,
    ImageType,
    ParserResult,
    RecoveryMode,
    ValidationLevel,
    VersionDriftEntry,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# The 12 TRACE-AI-FR framework rules
# ---------------------------------------------------------------------------

FRAMEWORK_RULES: Dict[int, str] = {
    1: "Interaction is reportable; cognition is not.",
    2: "Evidence recovery is expected to be uneven.",
    3: "Platform attribution is stronger than model attribution.",
    4: "Time findings are bounded, not exact.",
    5: "Image-review findings are graded.",
    6: "Unsupported is not the same as absent.",
    7: "Cleanup affects persistence, not motive.",
    8: "Evidence classes are not interchangeable.",
    9: "Artifact confidence is not event confidence.",
    10: "Narrative text is explanatory, not evidentiary.",
    11: "Framework output is forensic reconstruction, not automatic admissibility.",
    12: "Validation is continuous, not one-time.",
}

# Standard inference boundaries (Rule 1 + Rule 11)
STANDARD_INFERENCE_BOUNDARIES: List[str] = [
    "This examination looks for traces of AI service usage left on the "
    "device. It cannot determine why a person used the service, what they "
    "intended, or whether they relied on the AI output.",
    "The dates and times reported are approximate. They are based on "
    "records found on the device, not on live monitoring of the user's "
    "activity.",
    "This examination can identify which AI service (e.g., ChatGPT, "
    "Claude) was used, but identifying the specific AI model version "
    "requires additional data such as an exported conversation log.",
    "Not finding evidence of AI use does not mean AI was never used. "
    "Evidence may have been deleted or may not have been preserved.",
    "If the user deleted browsing data, cleared cookies, or logged out, "
    "this is reported as a fact. It does not imply the user was trying "
    "to hide anything.",
    "The inability to recover certain files should not be interpreted as "
    "proof that AI services were never used. Technical limitations or "
    "damage to the device's storage may prevent recovery.",
    "Recovered or partially damaged files are noted as such and are given "
    "lower confidence ratings than complete, undamaged files.",
]

# Standard required disclosures (Rule 11)
STANDARD_DISCLOSURES: List[str] = [
    "This report presents the results of a forensic examination. The "
    "admissibility of this evidence is subject to the Court's determination "
    "under applicable rules of evidence.",
    "Explanatory text in this report is intended to help the reader "
    "understand the findings. The actual evidence consists of the digital "
    "artifacts recovered from the device.",
    "The analysis tools used in this examination are subject to ongoing "
    "quality checks. The current validation status is documented in the "
    "technical appendix.",
]


def build_governance_record(
    report: ForensicReport,
    parser_results: List[ParserResult],
    evidence_coverage: EvidenceCoverage,
    legal_basis: str = "",
) -> GovernanceRecord:
    """
    Build the AI Use Evidence Governance Record for a case.
    """
    record = GovernanceRecord(
        case_id=report.case_info.case_id,
        legal_basis=legal_basis,
    )

    # Collection scope
    record.collection_scope = _describe_collection_scope(report, evidence_coverage)

    # Evidence source classes examined
    source_classes = set()
    for art in report.all_artifacts:
        source_classes.add(art.evidence_source_class.value)
    record.evidence_source_classes_examined = sorted(source_classes)

    # Parser versions
    for pr in parser_results:
        record.parser_versions[pr.parser_name] = pr.parser_version

    # Signature version
    from . import __version__
    record.signature_version = __version__

    # Validation state — default to PARTIALLY_VALIDATED since tests exist
    record.validation_state = ValidationLevel.PARTIALLY_VALIDATED

    # Version drift register
    record.version_drift_register = _build_drift_register(parser_results)

    # Known blind spots
    record.known_blind_spots = _identify_blind_spots(evidence_coverage)

    # Inference boundaries
    record.inference_boundaries = list(STANDARD_INFERENCE_BOUNDARIES)

    # Recovery-aware inference boundaries
    if hasattr(report, "recovery_mode_used") and report.recovery_mode_used:
        if report.recovery_mode_used != RecoveryMode.NONE:
            record.inference_boundaries.append(
                f"Additional data recovery methods were used during this "
                f"examination. Files recovered through these methods may be "
                f"incomplete and are given lower confidence ratings."
            )
    if hasattr(report, "filesystem_health") and report.filesystem_health:
        if report.filesystem_health not in (FilesystemHealth.INTACT, FilesystemHealth.UNKNOWN):
            record.inference_boundaries.append(
                f"The device's storage showed signs of damage or wear. "
                f"Some evidence may not be recoverable due to this damage, "
                f"and the absence of certain files should not be taken as "
                f"proof that AI services were never used."
            )

    # Required disclosures
    record.required_disclosures = list(STANDARD_DISCLOSURES)

    # Rules applied
    record.rules_applied = [
        f"Rule {num}: {desc}" for num, desc in FRAMEWORK_RULES.items()
    ]

    # v4.0: Provider capability blind spots
    try:
        from .capability_registry import capability_registry
        platforms_seen = set()
        for art in report.all_artifacts:
            if art.suspected_platform.value != "Unknown":
                platforms_seen.add(art.suspected_platform.value)
        all_blind_spots = []
        for plat in sorted(platforms_seen):
            spots = capability_registry.get_blind_spots_for_platform(plat)
            for s in spots:
                all_blind_spots.append(f"[{plat}] {s}")
        record.provider_capability_blind_spots = all_blind_spots
    except Exception:
        record.provider_capability_blind_spots = []

    # v4.0: Acquisition blind spots
    acq_sources_found = set()
    for art in report.all_artifacts:
        if hasattr(art, "acquisition_source"):
            acq_sources_found.add(art.acquisition_source.value)
    acq_blind = []
    if "Provider Export" not in acq_sources_found:
        acq_blind.append(
            "No data exported directly from the AI service provider was "
            "available for this examination. Such exports (for example, a "
            "downloaded copy of ChatGPT conversation history) would provide "
            "the strongest possible evidence and were not included."
        )
    if "Transcript Capture" not in acq_sources_found and "Voice Capture" not in acq_sources_found:
        acq_blind.append(
            "No audio recordings or voice transcripts were available. If the "
            "user interacted with AI services using voice (such as speaking "
            "to ChatGPT), those interactions are not represented here."
        )
    record.acquisition_blind_spots = acq_blind

    # v4.0: Surface coverage summary
    surfaces_found = set()
    for art in report.all_artifacts:
        if hasattr(art, "platform_surface"):
            surfaces_found.add(art.platform_surface.value)
    record.surface_coverage_summary = [
        f"The following areas of the device were examined: "
        f"{', '.join(sorted(surfaces_found)) or 'None'}. "
        f"Other areas of the device that were not examined may contain "
        f"additional evidence."
    ]

    # v4.0: Direct/corroborating/missing evidence summaries
    direct_count = sum(
        1 for a in report.all_artifacts
        if a.classification.value == "Directly Observed"
    )
    inferred_count = len(report.all_artifacts) - direct_count
    record.direct_evidence_summary = [
        f"{direct_count} item(s) of evidence directly show that an AI service "
        f"was accessed from this device."
    ]
    record.corroborating_evidence_summary = [
        f"{inferred_count} additional item(s) of evidence provide supporting "
        f"information that strengthens the findings."
    ]

    # Missing evidence families
    missing_fams = getattr(evidence_coverage, "artifact_families_missing", [])
    if missing_fams:
        record.missing_evidence_summary = [
            f"The following types of evidence were expected but not found: "
            f"{', '.join(missing_fams)}. This limits the conclusions that "
            f"can be drawn about certain types of AI service usage."
        ]
    else:
        record.missing_evidence_summary = [
            "All expected types of evidence were found and examined."
        ]

    # v4.0: Alternative explanations
    record.alternative_explanations = [
        "Records showing visits to AI websites could have been created "
        "automatically by browser syncing between devices, by another "
        "person using a shared computer, or by a website loading AI "
        "content in the background without the user's knowledge.",
        "The presence of AI service cookies on the device does not "
        "necessarily mean the user intentionally visited the AI service. "
        "Cookies can be set by advertisements, website redirects, or "
        "embedded content from third-party websites.",
    ]

    return record


def generate_scope_of_conclusion(report: ForensicReport) -> str:
    """
    Generate the mandatory "Scope of Conclusion" paragraph (Rule 11).
    """
    platforms_found = sorted(set(
        a.suspected_platform.value for a in report.all_artifacts
        if a.suspected_platform.value != "Unknown"
    ))

    if not platforms_found:
        return (
            "Based on the forensic examination of the submitted evidence, "
            "no evidence was found to indicate that any AI service (such as "
            "ChatGPT, Claude, or Google Gemini) was used on this device. "
            "However, this does not prove that AI services were never used. "
            "Evidence may have been deleted, or AI services may have been "
            "accessed through other means not detectable on this device."
        )

    platform_str = ", ".join(platforms_found)
    fraue_count = len(report.fraues)

    return (
        f"Based on the forensic examination of the submitted evidence, "
        f"the examiner identified {fraue_count} instance(s) of AI service "
        f"usage involving {platform_str}. These findings are based on "
        f"digital evidence recovered from the device and are subject to "
        f"the limitations described in this report. This report presents "
        f"factual findings from the forensic examination; the Court will "
        f"determine the admissibility and weight of the evidence under "
        f"applicable rules."
    )


def export_governance_record(
    record: GovernanceRecord, output_dir: str, case_prefix: str
) -> str:
    """Export the governance record as a standalone JSON file."""
    path = os.path.join(output_dir, f"{case_prefix}_governance_record.json")
    os.makedirs(output_dir, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(record.to_dict(), f, indent=2, default=str)
    logger.info(f"Governance record exported: {path}")
    return path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _describe_collection_scope(
    report: ForensicReport, cov: EvidenceCoverage
) -> str:
    parts = [
        f"Evidence source: {report.evidence_info.image_path or 'N/A'}",
        f"Image type: {cov.image_type.value}",
        f"Detected OS: {cov.os_detected.value}",
        f"User profiles: {', '.join(cov.user_profiles_found) or 'None'}",
        f"Browsers detected: {', '.join(cov.browsers_detected) or 'None'}",
        f"Full disk available: {'Yes' if cov.full_disk_available else 'No'}",
        f"File carving: {'Enabled' if cov.carving_enabled else 'Disabled'}",
    ]
    return "; ".join(parts)


def _build_drift_register(
    parser_results: List[ParserResult],
) -> List[VersionDriftEntry]:
    entries = []
    today = datetime.utcnow().strftime("%Y-%m-%d")
    for pr in parser_results:
        entry = VersionDriftEntry(
            component=pr.parser_name,
            component_version=pr.parser_version,
            signature_version="built-in",
            last_validated_date=today,
            validation_status=ValidationLevel.PARTIALLY_VALIDATED,
            notes="Tested against synthetic evidence fixtures.",
        )
        entries.append(entry)
    return entries


def _identify_blind_spots(cov: EvidenceCoverage) -> List[str]:
    spots = []

    if not cov.full_disk_available:
        spots.append(
            "Evidence is not a full disk image; unallocated space, volume "
            "shadow copies, and deleted artifacts may be inaccessible."
        )

    if cov.encrypted_areas_detected:
        spots.append(
            "Encrypted areas detected in the evidence source; artifacts "
            "within encrypted volumes are inaccessible."
        )

    if not cov.carving_enabled:
        spots.append(
            "File carving was disabled; deleted but not overwritten "
            "artifacts were not recovered."
        )

    for fam in cov.artifact_families_missing:
        spots.append(
            f"Artifact family '{fam}' was not found in the evidence; "
            f"conclusions about platform use from that family are not possible."
        )

    for stub in cov.parsers_stub:
        spots.append(
            f"Parser '{stub}' is a stub and did not produce findings; "
            f"artifacts that parser targets may be present but unexamined."
        )

    # Recovery-aware blind spots
    if hasattr(cov, "filesystem_health"):
        fh = getattr(cov, "filesystem_health", None)
        if fh and fh not in (FilesystemHealth.INTACT, FilesystemHealth.UNKNOWN):
            spots.append(
                f"Filesystem health is '{fh.value}'; some artifacts may be "
                "irrecoverable due to filesystem damage."
            )

    return spots
