"""
Recovery Engine — orchestrates deleted-file recovery, unallocated-space
scanning, signature carving, and damaged-filesystem fallback.

Returns structured RecoveryAuditRecord and artifact collections that
feed into the correlation and adjudication layers.

Design invariants:
  • Carved fragments NEVER score equal to intact native artifacts.
  • Raw hits alone stay at LOW confidence unless corroborated.
  • Non-recovery NEVER becomes proof of non-use.
  • Every artifact includes full provenance (offset, rule, mode).
"""

from __future__ import annotations

import io
import logging
import os
from datetime import datetime, timezone
from typing import BinaryIO, Dict, List, Optional, Tuple

from .acquisition_bridge import (
    acquisition_caveats,
    build_acquisition_metadata,
    confidence_ceiling_for_acquisition,
    parse_ddrescue_map,
)
from .carving import DEFAULT_SIGNATURES, SignatureRuleEngine, load_signature_pack
from .models import (
    AcquisitionMetadata,
    AcquisitionQuality,
    CarvedArtifact,
    ConfidenceLevel,
    EvidenceAccessCapabilities,
    EvidenceAccessTier,
    FilesystemHealth,
    PartitionFinding,
    RawHit,
    RecoveryAuditRecord,
    RecoveryMode,
    RecoveryStatus,
)
from .partition_analysis import (
    FilesystemHealthAssessor,
    PartitionScanner,
)
from .raw_inspector import RawInspector

logger = logging.getLogger(__name__)


class RecoveryEngine:
    """
    Top-level recovery orchestrator.

    Usage::

        engine = RecoveryEngine(
            evidence_id="E001",
            output_dir="./output/recovery",
            recovery_mode=RecoveryMode.SIGNATURE_CARVING,
        )
        audit = engine.run(stream)
    """

    def __init__(
        self,
        evidence_id: str = "",
        output_dir: str = "",
        recovery_mode: RecoveryMode = RecoveryMode.NONE,
        signature_pack_path: str = "",
        acquisition_quality: AcquisitionQuality = AcquisitionQuality.UNKNOWN,
        acquisition_log_path: str = "",
        extra_keywords: Optional[List[str]] = None,
        scan_unallocated: bool = False,
        raw_search: bool = False,
        partition_scan: bool = False,
    ):
        self.evidence_id = evidence_id
        self.output_dir = output_dir
        self.recovery_mode = recovery_mode
        self.signature_pack_path = signature_pack_path
        self.acquisition_quality = acquisition_quality
        self.acquisition_log_path = acquisition_log_path
        self.extra_keywords = extra_keywords or []
        self.scan_unallocated = scan_unallocated
        self.raw_search = raw_search
        self.partition_scan = partition_scan

        # Outputs — populated by run()
        self.carved_artifacts: List[CarvedArtifact] = []
        self.raw_hits: List[RawHit] = []
        self.partition_findings: List[PartitionFinding] = []
        self.acquisition_metadata: Optional[AcquisitionMetadata] = None
        self.filesystem_health: FilesystemHealth = FilesystemHealth.UNKNOWN
        self.evidence_access_tier: EvidenceAccessTier = EvidenceAccessTier.DIRECTORY_ONLY
        self.capabilities: Optional[EvidenceAccessCapabilities] = None

    # ------------------------------------------------------------------
    def run(self, stream: BinaryIO) -> RecoveryAuditRecord:
        """
        Execute the recovery pipeline and return an audit record.

        Steps executed depend on *recovery_mode* and flags:
        1. Acquisition metadata (if log provided)
        2. Partition scan (if enabled / needed)
        3. Signature carving (if mode includes it)
        4. Raw scan (if flag set)
        """
        started = datetime.now(tz=timezone.utc)
        modes_applied: List[str] = []
        caveats: List[str] = []

        # Step 0: Acquisition metadata
        if self.acquisition_log_path:
            self.acquisition_metadata = parse_ddrescue_map(
                self.acquisition_log_path,
            )
        else:
            self.acquisition_metadata = build_acquisition_metadata(
                quality=self.acquisition_quality.value,
            )
        if self.acquisition_metadata:
            caveats.extend(acquisition_caveats(self.acquisition_metadata))

        # Step 1: Partition scan
        if self.partition_scan or self.recovery_mode in (
            RecoveryMode.PARTITION_RECONSTRUCTION,
            RecoveryMode.SIGNATURE_CARVING,
            RecoveryMode.RAW_SCAN,
        ):
            self._run_partition_scan(stream)
            modes_applied.append("partition_scan")

        # Step 2: Signature carving
        if self.recovery_mode in (
            RecoveryMode.SIGNATURE_CARVING,
            RecoveryMode.DELETED_FILE,
        ) or self.scan_unallocated:
            self._run_carving(stream)
            modes_applied.append("signature_carving")

        # Step 3: Raw scan
        if self.raw_search or self.recovery_mode == RecoveryMode.RAW_SCAN:
            self._run_raw_scan(stream)
            modes_applied.append("raw_scan")

        ended = datetime.now(tz=timezone.utc)

        # Build audit record
        audit = RecoveryAuditRecord(
            evidence_id=self.evidence_id,
            recovery_mode=self.recovery_mode,
            started_at=started,
            ended_at=ended,
            modes_applied=modes_applied,
            total_carved=len(self.carved_artifacts),
            total_raw_hits=len(self.raw_hits),
            partitions_found=len(self.partition_findings),
            filesystem_health=self.filesystem_health,
            evidence_access_tier=self.evidence_access_tier,
            caveats=caveats,
            provenance_note=(
                f"Recovery executed with mode={self.recovery_mode.value}, "
                f"acquisition_quality={self.acquisition_quality.value}"
            ),
        )
        logger.info(
            "Recovery complete for %s: carved=%d, raw_hits=%d, partitions=%d",
            self.evidence_id,
            len(self.carved_artifacts),
            len(self.raw_hits),
            len(self.partition_findings),
        )
        return audit

    # ------------------------------------------------------------------
    # Internal pipeline stages
    # ------------------------------------------------------------------

    def _run_partition_scan(self, stream: BinaryIO):
        scanner = PartitionScanner()
        self.partition_findings = scanner.scan(stream, self.evidence_id)

        assessor = FilesystemHealthAssessor()
        self.filesystem_health, self.evidence_access_tier = assessor.assess(
            self.partition_findings
        )
        self.capabilities = assessor.build_capabilities(
            self.partition_findings, self.filesystem_health, self.evidence_access_tier,
        )

    def _run_carving(self, stream: BinaryIO):
        carve_dir = os.path.join(self.output_dir, "carved") if self.output_dir else ""
        signatures = list(DEFAULT_SIGNATURES)
        if self.signature_pack_path:
            custom = load_signature_pack(self.signature_pack_path)
            signatures.extend(custom)

        engine = SignatureRuleEngine(signatures=signatures)
        self.carved_artifacts = engine.carve(
            stream, evidence_id=self.evidence_id, output_dir=carve_dir,
        )

        # Apply acquisition-quality confidence ceiling
        if self.acquisition_metadata:
            ceiling = confidence_ceiling_for_acquisition(self.acquisition_metadata)
            for art in self.carved_artifacts:
                art.confidence_hint = _cap_confidence(art.confidence_hint, ceiling)

    def _run_raw_scan(self, stream: BinaryIO):
        inspector = RawInspector(extra_keywords=self.extra_keywords)
        self.raw_hits = inspector.scan(stream, evidence_id=self.evidence_id)

        # Apply acquisition-quality confidence ceiling
        if self.acquisition_metadata:
            ceiling = confidence_ceiling_for_acquisition(self.acquisition_metadata)
            for hit in self.raw_hits:
                hit.confidence_hint = _cap_confidence(hit.confidence_hint, ceiling)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CONFIDENCE_ORDER = [
    ConfidenceLevel.UNSUPPORTED,
    ConfidenceLevel.LOW,
    ConfidenceLevel.MODERATE,
    ConfidenceLevel.HIGH,
]


def _cap_confidence(
    current: ConfidenceLevel, ceiling: ConfidenceLevel
) -> ConfidenceLevel:
    """Ensure *current* does not exceed *ceiling*."""
    cur_idx = _CONFIDENCE_ORDER.index(current) if current in _CONFIDENCE_ORDER else 0
    ceil_idx = _CONFIDENCE_ORDER.index(ceiling) if ceiling in _CONFIDENCE_ORDER else len(_CONFIDENCE_ORDER) - 1
    return _CONFIDENCE_ORDER[min(cur_idx, ceil_idx)]
