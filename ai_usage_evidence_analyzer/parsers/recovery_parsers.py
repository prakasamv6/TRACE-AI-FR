"""
Recovery artifact parsers.

Converts carved artifacts, raw hits, and recovered files into
ArtifactRecord-compatible objects so they flow through the
existing correlation → confidence → adjudication pipeline.

Design invariants:
  • Carved fragments NEVER score equal to intact native artifacts
  • Raw hits alone stay at LOW unless corroborated
  • Every record preserves full provenance (offset, rule, mode)
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from ..models import (
    AIPlatform,
    AIModel,
    AccessMode,
    ArtifactFamily,
    ArtifactRecord,
    AttributionLayer,
    CarvedArtifact,
    CarvingValidation,
    ConfidenceLevel,
    EvidenceClassification,
    OSPlatform,
    ParserResult,
    ParserStatus,
    RawHit,
    RawHitType,
    RecoveryMode,
)
from ..parser_registry import BaseParser, register_parser

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Carved Artifact Parser
# ---------------------------------------------------------------------------

@register_parser
class CarvedArtifactParser(BaseParser):
    """
    Convert CarvedArtifact records (from the carving engine)
    into ArtifactRecord objects.
    """

    PARSER_NAME = "CarvedArtifactParser"
    PARSER_VERSION = "3.0.0"
    SUPPORTED_OS = [
        OSPlatform.WINDOWS, OSPlatform.MACOS, OSPlatform.IPHONE,
    ]
    ARTIFACT_FAMILY = "Recovery"
    IS_STUB = False

    def __init__(self, evidence_root: str, user_profile: str = "",
                 case_id: str = "", evidence_item_id: str = "",
                 source_image: str = "",
                 carved_artifacts: Optional[List[CarvedArtifact]] = None):
        super().__init__(evidence_root, user_profile, case_id,
                         evidence_item_id, source_image)
        self._carved = carved_artifacts or []

    def parse(self) -> ParserResult:
        if not self._carved:
            return self._make_result(
                status=ParserStatus.SUCCESS,
                notes="No carved artifacts to process",
            )

        artifacts: List[ArtifactRecord] = []
        for ca in self._carved:
            art = self._carved_to_artifact(ca)
            if art:
                artifacts.append(art)

        return self._make_result(
            status=ParserStatus.SUCCESS,
            artifacts=artifacts,
            notes=f"Converted {len(artifacts)} carved artifact(s) to ArtifactRecords",
        )

    def _carved_to_artifact(self, ca: CarvedArtifact) -> Optional[ArtifactRecord]:
        # Determine artifact type and family from carving rule name
        artifact_type = f"Carved File ({ca.signature_rule_used})"
        family = ArtifactFamily.FILE_SYSTEM
        classification = EvidenceClassification.INFERRED
        layer = AttributionLayer.CONTENT

        # Detect AI-related content (ChatGPT export, etc.)
        platform = AIPlatform.UNKNOWN
        if ca.signature_rule_used in ("ChatGPT_Export",):
            platform = AIPlatform.CHATGPT
            family = ArtifactFamily.USER_CONTENT
            layer = AttributionLayer.PLATFORM

        # Confidence: carved content is always capped
        confidence = ca.confidence_hint
        if confidence == ConfidenceLevel.HIGH:
            confidence = ConfidenceLevel.MODERATE  # carved NEVER gets HIGH

        provenance = (
            f"[CARVED] offset={ca.offset:#x}, size={ca.recovered_size}, "
            f"rule={ca.signature_rule_used}, "
            f"validation={ca.validation.value}, "
            f"mode={ca.recovery_mode.value}"
        )

        return ArtifactRecord(
            artifact_type=artifact_type,
            artifact_subtype=f"carved_{ca.signature_rule_used}",
            artifact_family=family,
            artifact_path=ca.temp_path,
            extracted_indicator=ca.carved_filename,
            classification=classification,
            attribution_layer=layer,
            suspected_platform=platform,
            suspected_model=AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.UNKNOWN,
            confidence=confidence,
            notes=provenance,
            evidence_item_id=ca.source_evidence_id,
            source_image=ca.source_image_path,
        )


# ---------------------------------------------------------------------------
# Raw Hit Parser
# ---------------------------------------------------------------------------

@register_parser
class RawHitParser(BaseParser):
    """
    Convert RawHit records into ArtifactRecord objects.

    Raw hits alone stay at LOW confidence.  Downstream corroboration
    may upgrade them, but the parser itself never inflates.
    """

    PARSER_NAME = "RawHitParser"
    PARSER_VERSION = "3.0.0"
    SUPPORTED_OS = [
        OSPlatform.WINDOWS, OSPlatform.MACOS, OSPlatform.IPHONE,
    ]
    ARTIFACT_FAMILY = "Recovery"
    IS_STUB = False

    def __init__(self, evidence_root: str, user_profile: str = "",
                 case_id: str = "", evidence_item_id: str = "",
                 source_image: str = "",
                 raw_hits: Optional[List[RawHit]] = None):
        super().__init__(evidence_root, user_profile, case_id,
                         evidence_item_id, source_image)
        self._hits = raw_hits or []

    def parse(self) -> ParserResult:
        if not self._hits:
            return self._make_result(
                status=ParserStatus.SUCCESS,
                notes="No raw hits to process",
            )

        artifacts: List[ArtifactRecord] = []
        for hit in self._hits:
            art = self._hit_to_artifact(hit)
            if art:
                artifacts.append(art)

        return self._make_result(
            status=ParserStatus.SUCCESS,
            artifacts=artifacts,
            notes=f"Converted {len(artifacts)} raw hit(s) to ArtifactRecords",
        )

    def _hit_to_artifact(self, hit: RawHit) -> ArtifactRecord:
        artifact_type = f"Raw Hit ({hit.hit_type.value})"
        family = ArtifactFamily.FILE_SYSTEM
        classification = EvidenceClassification.INFERRED
        layer = AttributionLayer.PLATFORM

        if hit.hit_type == RawHitType.DOMAIN_HIT:
            layer = AttributionLayer.PLATFORM
        elif hit.hit_type == RawHitType.MODEL_NAME_HIT:
            layer = AttributionLayer.MODEL
        elif hit.hit_type in (RawHitType.EXPORT_MARKER, RawHitType.HIGH_VALUE_STRUCTURED):
            layer = AttributionLayer.CONTENT
            family = ArtifactFamily.USER_CONTENT

        provenance = (
            f"[RAW] offset={hit.offset:#x}, len={hit.length}, "
            f"type={hit.hit_type.value}, "
            f"pattern={hit.matched_pattern}"
        )

        return ArtifactRecord(
            artifact_type=artifact_type,
            artifact_subtype=f"raw_{hit.hit_type.value}",
            artifact_family=family,
            artifact_path=f"raw_stream@{hit.offset:#x}",
            extracted_indicator=hit.matched_pattern,
            classification=classification,
            attribution_layer=layer,
            suspected_platform=hit.suspected_platform,
            suspected_model=AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.UNKNOWN,
            confidence=ConfidenceLevel.LOW,  # raw hits ALWAYS start at LOW
            notes=provenance,
            evidence_item_id=hit.evidence_id,
        )


# ---------------------------------------------------------------------------
# Recovered File Classifier
# ---------------------------------------------------------------------------

@register_parser
class RecoveredFileClassifier(BaseParser):
    """
    Classify recovered (undeleted) files by checking their contents
    for AI-platform indicators.  Works on files that were recovered
    from filesystem metadata (not carved).
    """

    PARSER_NAME = "RecoveredFileClassifier"
    PARSER_VERSION = "3.0.0"
    SUPPORTED_OS = [
        OSPlatform.WINDOWS, OSPlatform.MACOS, OSPlatform.IPHONE,
    ]
    ARTIFACT_FAMILY = "Recovery"
    IS_STUB = True  # Full implementation requires filesystem-level recovery

    def parse(self) -> ParserResult:
        return self._stub_result()
