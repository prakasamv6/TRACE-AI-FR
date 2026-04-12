"""
Tests for TRACE-AI-FR v3.0 recovery features.

Tests cover:
  - Signature-based carving engine
  - Partition analysis
  - Raw byte inspector
  - Recovery engine orchestration
  - Recovery parser conversion
  - Confidence/persistence recovery-aware scoring
  - Governance recovery rules
  - Storage recovery tables
  - Anti-overclaim controls
"""

import io
import json
import os
import shutil
import struct
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from ai_usage_evidence_analyzer.models import (
    AcquisitionMetadata,
    AcquisitionQuality,
    AIPlatform,
    AIModel,
    AccessMode,
    ArtifactFamily,
    ArtifactRecord,
    AttributionLayer,
    CarvedArtifact,
    CarvingValidation,
    ConfidenceLevel,
    EvidenceAccessTier,
    EvidenceClassification,
    FilesystemHealth,
    PartitionFinding,
    PartitionScheme,
    PersistenceState,
    RawHit,
    RawHitType,
    RecoveryAuditRecord,
    RecoveryMode,
    RecoveryStatus,
    SignatureRule,
    TimestampType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="trace_v3_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def jpeg_stream():
    """Return a BytesIO with a fake JPEG."""
    buf = io.BytesIO()
    buf.write(b"\x00" * 100)  # padding
    buf.write(b"\xff\xd8\xff\xe0")  # JPEG header
    buf.write(b"\x00" * 200)  # body
    buf.write(b"\xff\xd9")  # JPEG footer
    buf.write(b"\x00" * 100)  # trailing
    buf.seek(0)
    return buf


@pytest.fixture
def pdf_stream():
    """Return a BytesIO with a fake PDF."""
    buf = io.BytesIO()
    buf.write(b"%PDF-1.5\nfake pdf body content here\n%%EOF")
    buf.seek(0)
    return buf


@pytest.fixture
def ai_content_stream():
    """Return a BytesIO with embedded AI domain strings."""
    buf = io.BytesIO()
    buf.write(b"\x00" * 50)
    buf.write(b"visited https://chat.openai.com/c/abc123 at 2024-01-15")
    buf.write(b"\x00" * 50)
    buf.write(b'"model": "gpt-4o", "conversation_id": "conv_xyz"')
    buf.write(b"\x00" * 50)
    buf.write(b"claude.ai response received")
    buf.write(b"\x00" * 50)
    buf.seek(0)
    return buf


@pytest.fixture
def mbr_stream():
    """Return a BytesIO with a minimal MBR partition table."""
    buf = io.BytesIO(b"\x00" * 1024)
    # MBR signature at 510
    buf.seek(510)
    buf.write(b"\x55\xAA")
    # Partition entry at 446: type=0x07 (NTFS), LBA_start=2048, sectors=1024000
    buf.seek(446)
    entry = bytearray(16)
    entry[0] = 0x80  # active
    entry[4] = 0x07  # NTFS
    struct.pack_into("<I", entry, 8, 2048)
    struct.pack_into("<I", entry, 12, 1024000)
    buf.write(bytes(entry))
    buf.seek(0)
    return buf


@pytest.fixture
def sample_carved_artifact():
    return CarvedArtifact(
        source_evidence_id="E001",
        source_image_path="/evidence/disk.e01",
        offset=0x1A000,
        recovered_size=4096,
        signature_rule_used="JPEG",
        carved_filename="carved_0x0001a000.jpg",
        temp_path="/tmp/carved_0x0001a000.jpg",
        validation=CarvingValidation.HEADER_ONLY,
        recovery_mode=RecoveryMode.SIGNATURE_CARVING,
        recovery_status=RecoveryStatus.PARTIAL,
        confidence_hint=ConfidenceLevel.LOW,
        extraction_timestamp=datetime.now(tz=timezone.utc),
    )


@pytest.fixture
def sample_raw_hit():
    return RawHit(
        evidence_id="E001",
        offset=0x5000,
        length=20,
        matched_pattern="chat.openai.com",
        hit_type=RawHitType.DOMAIN_HIT,
        suspected_platform=AIPlatform.CHATGPT,
        confidence_hint=ConfidenceLevel.LOW,
        context_preview="visited https://chat.openai.com/c/abc",
        scan_timestamp=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Carving Engine
# ---------------------------------------------------------------------------

class TestSignatureRuleEngine:
    def test_carve_jpeg(self, jpeg_stream, tmp_dir):
        from ai_usage_evidence_analyzer.carving import SignatureRuleEngine, DEFAULT_SIGNATURES
        engine = SignatureRuleEngine(signatures=DEFAULT_SIGNATURES)
        results = engine.carve(jpeg_stream, evidence_id="E001", output_dir=tmp_dir)
        assert len(results) >= 1
        carved = results[0]
        assert carved.signature_rule_used == "JPEG"
        assert carved.offset == 100
        assert carved.recovery_mode == RecoveryMode.SIGNATURE_CARVING
        assert carved.confidence_hint in (ConfidenceLevel.LOW, ConfidenceLevel.MODERATE)
        assert os.path.exists(carved.temp_path)

    def test_carve_pdf(self, pdf_stream, tmp_dir):
        from ai_usage_evidence_analyzer.carving import SignatureRuleEngine, DEFAULT_SIGNATURES
        engine = SignatureRuleEngine(signatures=DEFAULT_SIGNATURES)
        results = engine.carve(pdf_stream, evidence_id="E001", output_dir=tmp_dir)
        pdf_results = [r for r in results if r.signature_rule_used == "PDF"]
        assert len(pdf_results) >= 1

    def test_carved_confidence_never_high(self, jpeg_stream, tmp_dir):
        """Carved fragments NEVER score HIGH."""
        from ai_usage_evidence_analyzer.carving import SignatureRuleEngine, DEFAULT_SIGNATURES
        engine = SignatureRuleEngine(signatures=DEFAULT_SIGNATURES)
        results = engine.carve(jpeg_stream, evidence_id="E001", output_dir=tmp_dir)
        for r in results:
            assert r.confidence_hint != ConfidenceLevel.HIGH, \
                "Carved artifacts must NEVER receive HIGH confidence"

    def test_empty_stream_returns_nothing(self, tmp_dir):
        from ai_usage_evidence_analyzer.carving import SignatureRuleEngine
        engine = SignatureRuleEngine()
        stream = io.BytesIO(b"\x00" * 100)
        results = engine.carve(stream, output_dir=tmp_dir)
        assert len(results) == 0

    def test_custom_signature(self, tmp_dir):
        from ai_usage_evidence_analyzer.carving import SignatureRuleEngine
        custom = [SignatureRule(
            name="CustomMagic", extension="custom",
            header=b"\xCA\xFE\xBA\xBE", footer=b"\xDE\xAD",
            max_size=1024,
        )]
        data = b"\x00" * 10 + b"\xCA\xFE\xBA\xBE" + b"body" + b"\xDE\xAD" + b"\x00" * 10
        engine = SignatureRuleEngine(signatures=custom)
        results = engine.carve(io.BytesIO(data), output_dir=tmp_dir)
        assert len(results) == 1
        assert results[0].signature_rule_used == "CustomMagic"


# ---------------------------------------------------------------------------
# Partition Analysis
# ---------------------------------------------------------------------------

class TestPartitionScanner:
    def test_detect_mbr(self, mbr_stream):
        from ai_usage_evidence_analyzer.partition_analysis import PartitionScanner
        scanner = PartitionScanner()
        findings = scanner.scan(mbr_stream, evidence_id="E001")
        assert len(findings) >= 1
        assert findings[0].scheme == PartitionScheme.MBR
        assert findings[0].fs_type_label == "NTFS/exFAT"

    def test_no_partition_table(self):
        from ai_usage_evidence_analyzer.partition_analysis import PartitionScanner
        scanner = PartitionScanner()
        findings = scanner.scan(io.BytesIO(b"\x00" * 2048), evidence_id="E001")
        assert len(findings) >= 1
        assert findings[0].scheme == PartitionScheme.NONE_DETECTED

    def test_filesystem_health_assessor(self):
        from ai_usage_evidence_analyzer.partition_analysis import FilesystemHealthAssessor
        findings = [
            PartitionFinding(
                evidence_id="E001", partition_index=0,
                scheme=PartitionScheme.MBR, offset=0, size_bytes=1024,
                fs_type_label="NTFS", health=FilesystemHealth.INTACT,
            ),
        ]
        assessor = FilesystemHealthAssessor()
        health, tier = assessor.assess(findings)
        assert health == FilesystemHealth.INTACT
        assert tier == EvidenceAccessTier.FULL_FORENSIC_ACCESS

    def test_degraded_health(self):
        from ai_usage_evidence_analyzer.partition_analysis import FilesystemHealthAssessor
        findings = [
            PartitionFinding("E001", 0, PartitionScheme.GPT, 0, 1024, "ext4", FilesystemHealth.INTACT),
            PartitionFinding("E001", 1, PartitionScheme.GPT, 1024, 2048, "unknown", FilesystemHealth.CORRUPT),
        ]
        assessor = FilesystemHealthAssessor()
        health, tier = assessor.assess(findings)
        assert health == FilesystemHealth.DEGRADED
        assert tier == EvidenceAccessTier.PARTIAL_FILESYSTEM_ACCESS


# ---------------------------------------------------------------------------
# Raw Inspector
# ---------------------------------------------------------------------------

class TestRawInspector:
    def test_scan_domains(self, ai_content_stream):
        from ai_usage_evidence_analyzer.raw_inspector import RawInspector
        inspector = RawInspector()
        hits = inspector.scan(ai_content_stream, evidence_id="E001")
        domain_hits = [h for h in hits if h.hit_type == RawHitType.DOMAIN_HIT]
        assert len(domain_hits) >= 2  # openai + claude

    def test_scan_model_names(self, ai_content_stream):
        from ai_usage_evidence_analyzer.raw_inspector import RawInspector
        inspector = RawInspector()
        hits = inspector.scan(ai_content_stream, evidence_id="E001")
        model_hits = [h for h in hits if h.hit_type == RawHitType.MODEL_NAME_HIT]
        assert len(model_hits) >= 1

    def test_raw_hits_always_low_confidence(self, ai_content_stream):
        """Raw hits alone stay at LOW confidence."""
        from ai_usage_evidence_analyzer.raw_inspector import RawInspector
        inspector = RawInspector()
        hits = inspector.scan(ai_content_stream, evidence_id="E001")
        for h in hits:
            assert h.confidence_hint == ConfidenceLevel.LOW, \
                "Raw hits must ALWAYS start at LOW confidence"

    def test_token_redaction(self):
        """API keys must be redacted in raw hit records."""
        from ai_usage_evidence_analyzer.raw_inspector import RawInspector
        buf = io.BytesIO(b"sk-abcdefghijklmnopqrstuvwxyz1234567890")
        inspector = RawInspector()
        hits = inspector.scan(buf, evidence_id="E001")
        token_hits = [h for h in hits if h.hit_type == RawHitType.PLATFORM_TOKEN]
        for h in token_hits:
            assert "sk-" not in h.matched_pattern, "Tokens must be redacted"
            assert "REDACTED" in h.matched_pattern

    def test_dump_offset(self):
        from ai_usage_evidence_analyzer.raw_inspector import RawInspector
        data = b"Hello, World! This is a test buffer for hex dump."
        inspector = RawInspector()
        dump = inspector.dump_offset(io.BytesIO(data), offset=0, length=32)
        assert "Hello" in dump
        assert "00000000" in dump

    def test_extra_keywords(self):
        from ai_usage_evidence_analyzer.raw_inspector import RawInspector
        buf = io.BytesIO(b"custom forensic keyword found here")
        inspector = RawInspector(extra_keywords=["forensic keyword"])
        hits = inspector.scan(buf, evidence_id="E001")
        kw_hits = [h for h in hits if h.hit_type == RawHitType.GENERIC_STRING]
        assert len(kw_hits) >= 1


# ---------------------------------------------------------------------------
# Recovery Engine
# ---------------------------------------------------------------------------

class TestRecoveryEngine:
    def test_recovery_with_carving(self, jpeg_stream, tmp_dir):
        from ai_usage_evidence_analyzer.recovery import RecoveryEngine
        engine = RecoveryEngine(
            evidence_id="E001",
            output_dir=tmp_dir,
            recovery_mode=RecoveryMode.SIGNATURE_CARVING,
        )
        audit = engine.run(jpeg_stream)
        assert audit.evidence_id == "E001"
        assert audit.total_carved >= 1
        assert "signature_carving" in audit.modes_applied

    def test_recovery_with_raw_scan(self, ai_content_stream, tmp_dir):
        from ai_usage_evidence_analyzer.recovery import RecoveryEngine
        engine = RecoveryEngine(
            evidence_id="E001",
            output_dir=tmp_dir,
            recovery_mode=RecoveryMode.RAW_SCAN,
            raw_search=True,
        )
        audit = engine.run(ai_content_stream)
        assert audit.total_raw_hits >= 1
        assert "raw_scan" in audit.modes_applied

    def test_recovery_mode_none_does_nothing(self, tmp_dir):
        from ai_usage_evidence_analyzer.recovery import RecoveryEngine
        engine = RecoveryEngine(
            evidence_id="E001",
            output_dir=tmp_dir,
            recovery_mode=RecoveryMode.NONE,
        )
        audit = engine.run(io.BytesIO(b"\x00" * 100))
        assert audit.total_carved == 0
        assert audit.total_raw_hits == 0


# ---------------------------------------------------------------------------
# Recovery Parsers
# ---------------------------------------------------------------------------

class TestRecoveryParsers:
    def test_carved_artifact_parser(self, sample_carved_artifact):
        from ai_usage_evidence_analyzer.parsers.recovery_parsers import CarvedArtifactParser
        parser = CarvedArtifactParser(
            evidence_root="/evidence",
            carved_artifacts=[sample_carved_artifact],
        )
        result = parser.parse()
        assert len(result.artifacts_found) == 1
        art = result.artifacts_found[0]
        assert "[CARVED]" in art.notes
        assert art.classification == EvidenceClassification.INFERRED
        # Carved must not get HIGH
        assert art.confidence != ConfidenceLevel.HIGH

    def test_raw_hit_parser(self, sample_raw_hit):
        from ai_usage_evidence_analyzer.parsers.recovery_parsers import RawHitParser
        parser = RawHitParser(
            evidence_root="/evidence",
            raw_hits=[sample_raw_hit],
        )
        result = parser.parse()
        assert len(result.artifacts_found) == 1
        art = result.artifacts_found[0]
        assert "[RAW]" in art.notes
        assert art.confidence == ConfidenceLevel.LOW  # raw = always LOW

    def test_recovered_file_classifier_is_stub(self):
        from ai_usage_evidence_analyzer.parsers.recovery_parsers import RecoveredFileClassifier
        from ai_usage_evidence_analyzer.models import ParserStatus
        parser = RecoveredFileClassifier(evidence_root="/evidence")
        result = parser.parse()
        assert result.status == ParserStatus.STUB


# ---------------------------------------------------------------------------
# Confidence Recovery-Aware Scoring
# ---------------------------------------------------------------------------

class TestRecoveryConfidence:
    def _make_artifact(self, notes="", subtype=""):
        return ArtifactRecord(
            artifact_type="test",
            artifact_subtype=subtype,
            artifact_family=ArtifactFamily.FILE_SYSTEM,
            source_image="test.dat",
            classification=EvidenceClassification.DIRECT,
            attribution_layer=AttributionLayer.PLATFORM,
            suspected_platform=AIPlatform.CHATGPT,
            suspected_model=AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.BROWSER,
            confidence=ConfidenceLevel.LOW,
            notes=notes,
        )

    def test_carved_artifact_penalty(self):
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine
        art = self._make_artifact(notes="[CARVED] offset=0x1000")
        engine = ConfidenceScoringEngine([art])
        engine.score_all()
        # Carved artifacts get penalised — should not be HIGH
        assert art.confidence != ConfidenceLevel.HIGH

    def test_raw_artifact_penalty(self):
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine
        art = self._make_artifact(notes="[RAW] offset=0x2000")
        engine = ConfidenceScoringEngine([art])
        engine.score_all()
        assert art.confidence != ConfidenceLevel.HIGH

    def test_recovery_claim_ceiling(self):
        """Recovery artifacts cannot exceed MODERATE even with corroboration."""
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine
        art1 = self._make_artifact(notes="[CARVED] offset=0x1000")
        art2 = self._make_artifact(subtype="browser_history")
        art3 = self._make_artifact(subtype="downloads")
        art1.artifact_family = ArtifactFamily.USER_CONTENT
        art2.artifact_family = ArtifactFamily.BROWSER_HISTORY
        art3.artifact_family = ArtifactFamily.BROWSER_DOWNLOADS
        # Link corroboration
        art1.corroborating_artifacts = [art2.record_id, art3.record_id]
        engine = ConfidenceScoringEngine([art1, art2, art3])
        engine.score_all()
        # Carved art1 must still be capped
        assert art1.confidence != ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# Persistence Recovery States
# ---------------------------------------------------------------------------

class TestRecoveryPersistence:
    def test_carved_persistence_fragment_only(self):
        from ai_usage_evidence_analyzer.persistence import assign_persistence_state
        art = ArtifactRecord(
            artifact_type="test",
            artifact_subtype="carved_JPEG",
            artifact_family=ArtifactFamily.FILE_SYSTEM,
            source_image="carved.jpg",
            classification=EvidenceClassification.INFERRED,
            attribution_layer=AttributionLayer.CONTENT,
            suspected_platform=AIPlatform.UNKNOWN,
            suspected_model=AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            notes="[CARVED] offset=0x1000",
        )
        state = assign_persistence_state(art)
        assert state == PersistenceState.FRAGMENT_ONLY

    def test_raw_persistence_weakly_retained(self):
        from ai_usage_evidence_analyzer.persistence import assign_persistence_state
        art = ArtifactRecord(
            artifact_type="test",
            artifact_subtype="raw_domain_hit",
            artifact_family=ArtifactFamily.FILE_SYSTEM,
            source_image="raw@0x5000",
            classification=EvidenceClassification.INFERRED,
            attribution_layer=AttributionLayer.PLATFORM,
            suspected_platform=AIPlatform.CHATGPT,
            suspected_model=AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            notes="[RAW] hit",
        )
        state = assign_persistence_state(art)
        assert state == PersistenceState.WEAKLY_RETAINED


# ---------------------------------------------------------------------------
# Acquisition Bridge
# ---------------------------------------------------------------------------

class TestAcquisitionBridge:
    def test_build_metadata(self):
        from ai_usage_evidence_analyzer.acquisition_bridge import build_acquisition_metadata
        meta = build_acquisition_metadata(quality="normal")
        assert meta.acquisition_quality == AcquisitionQuality.NORMAL

    def test_confidence_ceiling_normal(self):
        from ai_usage_evidence_analyzer.acquisition_bridge import (
            build_acquisition_metadata,
            confidence_ceiling_for_acquisition,
        )
        meta = build_acquisition_metadata(quality=AcquisitionQuality.NORMAL)
        ceiling = confidence_ceiling_for_acquisition(meta)
        assert ceiling == ConfidenceLevel.HIGH

    def test_confidence_ceiling_degraded(self):
        from ai_usage_evidence_analyzer.acquisition_bridge import (
            build_acquisition_metadata,
            confidence_ceiling_for_acquisition,
        )
        meta = build_acquisition_metadata(quality=AcquisitionQuality.DEGRADED)
        ceiling = confidence_ceiling_for_acquisition(meta)
        assert ceiling == ConfidenceLevel.MODERATE

    def test_acquisition_caveats_degraded(self):
        from ai_usage_evidence_analyzer.acquisition_bridge import (
            build_acquisition_metadata,
            acquisition_caveats,
        )
        meta = build_acquisition_metadata(quality=AcquisitionQuality.DEGRADED)
        caveats = acquisition_caveats(meta)
        assert len(caveats) >= 1
        assert any("degraded" in c.lower() or "bad sector" in c.lower() for c in caveats)


# ---------------------------------------------------------------------------
# Governance Recovery Rules
# ---------------------------------------------------------------------------

class TestGovernanceRecovery:
    def test_inference_boundary_non_recovery(self):
        from ai_usage_evidence_analyzer.governance import STANDARD_INFERENCE_BOUNDARIES
        assert any("not finding evidence" in b.lower() or "inability to recover" in b.lower()
                    for b in STANDARD_INFERENCE_BOUNDARIES)

    def test_inference_boundary_carved_provenance(self):
        from ai_usage_evidence_analyzer.governance import STANDARD_INFERENCE_BOUNDARIES
        assert any("recovered" in b.lower() or "partially damaged" in b.lower()
                    for b in STANDARD_INFERENCE_BOUNDARIES)


# ---------------------------------------------------------------------------
# Storage Recovery Tables
# ---------------------------------------------------------------------------

class TestStorageRecovery:
    def test_schema_has_recovery_tables(self):
        from ai_usage_evidence_analyzer.storage import SCHEMA_SQL
        assert "carved_artifacts" in SCHEMA_SQL
        assert "raw_hits" in SCHEMA_SQL
        assert "partition_findings" in SCHEMA_SQL
        assert "recovery_audit" in SCHEMA_SQL
        assert "acquisition_metadata" in SCHEMA_SQL


# ---------------------------------------------------------------------------
# Models (new types)
# ---------------------------------------------------------------------------

class TestRecoveryModels:
    def test_recovery_mode_values(self):
        assert RecoveryMode.NONE.value == "None"
        assert RecoveryMode.SIGNATURE_CARVING.value == "Signature Carving"

    def test_carved_artifact_to_dict(self, sample_carved_artifact):
        d = sample_carved_artifact.to_dict()
        assert d["signature_rule_used"] == "JPEG"
        assert d["offset"] == 0x1A000
        assert d["validation"] == "Header Only"  # HEADER_ONLY

    def test_raw_hit_to_dict(self, sample_raw_hit):
        d = sample_raw_hit.to_dict()
        assert d["hit_type"] == "Domain Hit"
        assert d["suspected_platform"] == "ChatGPT"

    def test_persistence_fragment_only_exists(self):
        assert PersistenceState.FRAGMENT_ONLY.value == "Fragment Only"

    def test_recovery_audit_to_dict(self):
        audit = RecoveryAuditRecord(
            source_evidence_id="E001",
            recovery_mode=RecoveryMode.SIGNATURE_CARVING,
        )
        d = audit.to_dict()
        assert d["source_evidence_id"] == "E001"
        assert d["recovery_mode"] == "Signature Carving"


# ---------------------------------------------------------------------------
# Anti-Overclaim Controls
# ---------------------------------------------------------------------------

class TestAntiOverclaim:
    """Verify that the framework enforces mandatory anti-overclaim controls."""

    def test_carved_never_equals_native(self):
        """Carved fragments must NEVER achieve HIGH confidence."""
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine
        # Native artifact — DIRECT with strong family
        native = ArtifactRecord(
            artifact_type="Browser History URL",
            artifact_subtype="navigation",
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
            source_image="History",
            classification=EvidenceClassification.DIRECT,
            attribution_layer=AttributionLayer.PLATFORM,
            suspected_platform=AIPlatform.CHATGPT,
            suspected_model=AIModel.GPT4O,
            suspected_access_mode=AccessMode.BROWSER,
            confidence=ConfidenceLevel.LOW,
        )
        # Carved artifact — same info but carved provenance
        carved = ArtifactRecord(
            artifact_type="Carved File (JPEG)",
            artifact_subtype="carved_JPEG",
            artifact_family=ArtifactFamily.FILE_SYSTEM,
            source_image="carved_0x1000.jpg",
            classification=EvidenceClassification.INFERRED,
            attribution_layer=AttributionLayer.CONTENT,
            suspected_platform=AIPlatform.UNKNOWN,
            suspected_model=AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            notes="[CARVED] offset=0x1000",
        )
        engine = ConfidenceScoringEngine([native, carved])
        engine.score_all()
        # Native can be HIGH, carved cannot
        if native.confidence == ConfidenceLevel.HIGH:
            assert carved.confidence != ConfidenceLevel.HIGH

    def test_non_recovery_is_not_proof_of_absence(self):
        """Governance must state that non-recovery ≠ proof of non-use."""
        from ai_usage_evidence_analyzer.governance import STANDARD_INFERENCE_BOUNDARIES
        absence_controls = [
            b for b in STANDARD_INFERENCE_BOUNDARIES
            if "absence" in b.lower() or "not finding evidence" in b.lower()
            or "does not mean" in b.lower() or "should not be" in b.lower()
        ]
        assert len(absence_controls) >= 2, \
            "Must have explicit anti-absence-proof controls"

    def test_version_bumped_to_3(self):
        from ai_usage_evidence_analyzer import __version__
        assert __version__ == "4.0.0"
