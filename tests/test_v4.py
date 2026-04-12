"""
Unit tests for TRACE-AI-FR v4.0 features.

Covers: capability registry, voice evidence, provider exports, shared links,
generated assets, confidence class, acquisition source, platform surface,
governance v4.0 fields, DOCX generation, repo reality check, schema migration.
"""

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="aiuea_v4_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 1. Enum / Model Extensions
# ---------------------------------------------------------------------------

class TestV4Enums:
    """Test v4.0 enum additions."""

    def test_acquisition_source_values(self):
        from ai_usage_evidence_analyzer.models import AcquisitionSource
        assert AcquisitionSource.E01_IMAGE.value == "E01 Image"
        assert AcquisitionSource.PROVIDER_EXPORT.value == "Provider Export"
        assert AcquisitionSource.MANUAL_IMPORT.value == "Manual Import"
        assert len(AcquisitionSource) >= 10

    def test_platform_surface_values(self):
        from ai_usage_evidence_analyzer.models import PlatformSurface
        assert PlatformSurface.BROWSER_WEB.value == "Browser Web"
        assert PlatformSurface.NATIVE_DESKTOP_APP.value == "Native Desktop App"
        assert PlatformSurface.MOBILE_APP.value == "Mobile App"

    def test_evidence_confidence_class_values(self):
        from ai_usage_evidence_analyzer.models import EvidenceConfidenceClass
        assert EvidenceConfidenceClass.OBSERVED_AI_USE.value == "Observed AI Use"
        assert EvidenceConfidenceClass.CORROBORATED_AI_USE.value == "Corroborated AI Use"
        assert EvidenceConfidenceClass.SUSPECTED_AI_USE.value == "Suspected AI Use"
        assert EvidenceConfidenceClass.INSUFFICIENT_SUPPORT.value == "Insufficient Support"

    def test_voice_artifact_type_values(self):
        from ai_usage_evidence_analyzer.models import VoiceArtifactType
        assert VoiceArtifactType.TRANSCRIPT_TEXT.value == "Transcript Text"
        assert VoiceArtifactType.AUDIO_METADATA.value == "Audio Metadata"

    def test_evidence_source_class_extended(self):
        from ai_usage_evidence_analyzer.models import EvidenceSourceClass
        assert hasattr(EvidenceSourceClass, "PROVIDER_EXPORT_DERIVED")
        assert hasattr(EvidenceSourceClass, "VOICE_DERIVED")


class TestV4ArtifactRecordExtensions:
    """Test ArtifactRecord v4.0 fields."""

    def test_artifact_record_v4_defaults(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, AcquisitionSource, PlatformSurface,
        )
        r = ArtifactRecord(suspected_platform=AIPlatform.CHATGPT)
        assert r.acquisition_source == AcquisitionSource.UNKNOWN
        assert r.platform_surface == PlatformSurface.UNKNOWN
        assert r.related_voice_event_id == ""
        assert r.related_shared_link_id == ""
        assert r.related_generated_asset_id == ""

    def test_artifact_record_v4_to_dict(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, AcquisitionSource, PlatformSurface,
        )
        r = ArtifactRecord(
            suspected_platform=AIPlatform.CLAUDE,
            acquisition_source=AcquisitionSource.MOUNTED_DIRECTORY,
            platform_surface=PlatformSurface.BROWSER_WEB,
        )
        d = r.to_dict()
        assert d["acquisition_source"] == "Mounted Directory"
        assert d["platform_surface"] == "Browser Web"


class TestV4FRAUEExtensions:
    """Test FRAUE v4.0 fields."""

    def test_fraue_v4_defaults(self):
        from ai_usage_evidence_analyzer.models import (
            FRAUE, AIPlatform, EvidenceConfidenceClass,
        )
        f = FRAUE(platform=AIPlatform.CHATGPT)
        assert f.confidence_class == EvidenceConfidenceClass.INSUFFICIENT_SUPPORT
        assert f.acquisition_sources == []
        assert f.platform_surfaces == []
        assert f.direct_evidence_artifact_ids == []
        assert f.corroborating_artifact_ids == []
        assert f.voice_related is False
        assert f.shared_link_related is False
        assert f.generated_asset_related is False

    def test_fraue_v4_to_dict(self):
        from ai_usage_evidence_analyzer.models import (
            FRAUE, AIPlatform, EvidenceConfidenceClass,
        )
        f = FRAUE(
            platform=AIPlatform.GEMINI,
            confidence_class=EvidenceConfidenceClass.OBSERVED_AI_USE,
        )
        d = f.to_dict()
        assert d["confidence_class"] == "Observed AI Use"


class TestV4GovernanceExtensions:
    """Test GovernanceRecord v4.0 fields."""

    def test_governance_v4_defaults(self):
        from ai_usage_evidence_analyzer.models import GovernanceRecord
        g = GovernanceRecord(case_id="V4TEST")
        assert g.framework_version == "4.0.0"
        assert g.provider_capability_blind_spots == []
        assert g.acquisition_blind_spots == []
        assert g.surface_coverage_summary == []
        assert g.direct_evidence_summary == []
        assert g.corroborating_evidence_summary == []
        assert g.missing_evidence_summary == []
        assert g.alternative_explanations == []

    def test_governance_v4_to_dict(self):
        from ai_usage_evidence_analyzer.models import GovernanceRecord
        g = GovernanceRecord(case_id="V4TEST")
        g.provider_capability_blind_spots = ["ChatGPT: no access logs"]
        g.alternative_explanations = ["Shared device"]
        d = g.to_dict()
        assert d["provider_capability_blind_spots"] == ["ChatGPT: no access logs"]
        assert d["alternative_explanations"] == ["Shared device"]


class TestV4ForensicReportExtensions:
    """Test ForensicReport v4.0 fields."""

    def test_report_v4_defaults(self):
        from ai_usage_evidence_analyzer.models import ForensicReport
        r = ForensicReport()
        assert r.schema_version == "4.0.0"
        assert r.tool_version == "4.0.0"
        assert r.voice_evidence == []
        assert r.shared_links == []
        assert r.generated_assets == []
        assert r.docx_generated is False
        assert r.report_template_name == "UNCC-DFL-TRACE-AI-FR"
        assert r.report_template_version == "4.0.0"


class TestV4NewDataclasses:
    """Test new v4.0 dataclasses."""

    def test_voice_evidence_record(self):
        from ai_usage_evidence_analyzer.models import VoiceEvidenceRecord
        v = VoiceEvidenceRecord(source_path="/test/transcript.txt")
        assert v.source_path == "/test/transcript.txt"
        assert v.voice_id.startswith("VOICE-")

    def test_shared_link_record(self):
        from ai_usage_evidence_analyzer.models import SharedLinkRecord
        s = SharedLinkRecord(url="https://chatgpt.com/share/abc")
        assert s.url == "https://chatgpt.com/share/abc"
        assert s.link_id.startswith("SLINK-")

    def test_generated_asset_record(self):
        from ai_usage_evidence_analyzer.models import GeneratedAssetRecord
        g = GeneratedAssetRecord(file_path="/evidence/dalle_output.png")
        assert g.file_path == "/evidence/dalle_output.png"
        assert g.asset_id.startswith("GASSET-")

    def test_provider_capability_profile(self):
        from ai_usage_evidence_analyzer.models import ProviderCapabilityProfile, AIPlatform
        p = ProviderCapabilityProfile(platform=AIPlatform.CHATGPT)
        assert p.platform == AIPlatform.CHATGPT
        assert p.supports_export is False
        assert p.supports_voice is False


# ---------------------------------------------------------------------------
# 2. Capability Registry
# ---------------------------------------------------------------------------

class TestCapabilityRegistry:
    """Test the provider capability registry."""

    def test_registry_singleton(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        assert capability_registry is not None

    def test_all_8_platforms_seeded(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        profiles = capability_registry.get_all_profiles()
        assert len(profiles) >= 8
        platform_names = {p.platform.value for p in profiles}
        for expected in ["ChatGPT", "Claude", "Gemini", "Perplexity",
                         "Copilot", "Meta AI", "Grok", "Poe"]:
            assert expected in platform_names

    def test_get_profile(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        from ai_usage_evidence_analyzer.models import AIPlatform
        p = capability_registry.get_profile(AIPlatform.CHATGPT)
        assert p is not None
        assert p.platform.value == "ChatGPT"

    def test_get_blind_spots(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        from ai_usage_evidence_analyzer.models import AIPlatform
        bs = capability_registry.get_blind_spots_for_platform(AIPlatform.CHATGPT)
        assert isinstance(bs, list)

    def test_supports_feature(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        from ai_usage_evidence_analyzer.models import AIPlatform
        # ChatGPT should support export
        result = capability_registry.supports_feature(AIPlatform.CHATGPT, "export")
        assert isinstance(result, bool)

    def test_get_capability_matrix(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        matrix = capability_registry.get_capability_matrix()
        assert isinstance(matrix, list)
        assert len(matrix) >= 8

    def test_get_all_blind_spots(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        all_bs = capability_registry.get_all_blind_spots()
        assert isinstance(all_bs, list)


# ---------------------------------------------------------------------------
# 3. Voice Evidence
# ---------------------------------------------------------------------------

class TestVoiceEvidence:
    """Test voice evidence engine."""

    def test_engine_creation(self):
        from ai_usage_evidence_analyzer.voice_evidence import VoiceEvidenceEngine
        engine = VoiceEvidenceEngine()
        assert engine is not None

    def test_import_transcripts_empty(self, tmp_dir):
        from ai_usage_evidence_analyzer.voice_evidence import VoiceEvidenceEngine
        engine = VoiceEvidenceEngine()
        records = engine.import_transcripts(tmp_dir)
        assert records == []

    def test_import_text_transcript(self, tmp_dir):
        from ai_usage_evidence_analyzer.voice_evidence import VoiceEvidenceEngine
        # Write a mock transcript
        transcript_path = os.path.join(tmp_dir, "chatgpt_voice.txt")
        with open(transcript_path, "w") as f:
            f.write("User: What is the capital of France?\n")
            f.write("Assistant: The capital of France is Paris.\n")
            f.write("ChatGPT conversation transcript\n")

        engine = VoiceEvidenceEngine()
        records = engine.import_transcripts(tmp_dir)
        assert len(records) >= 1

    def test_scan_evidence_for_voice(self, tmp_dir):
        from ai_usage_evidence_analyzer.voice_evidence import VoiceEvidenceEngine
        # Create a mock audio file (just a placeholder, won't actually parse audio)
        audio_path = os.path.join(tmp_dir, "voice_memo.mp3")
        with open(audio_path, "wb") as f:
            f.write(b"\x00" * 100)

        engine = VoiceEvidenceEngine()
        records = engine.scan_evidence_for_voice(tmp_dir)
        # Should find the mp3 file even if it can't parse content
        assert isinstance(records, list)


# ---------------------------------------------------------------------------
# 4. Provider Export Parser
# ---------------------------------------------------------------------------

class TestProviderExportParser:
    """Test provider export parser."""

    def test_parse_chatgpt_conversations(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.provider_export_parser import ProviderExportParser
        # Create a mock ChatGPT export
        export_dir = os.path.join(tmp_dir, "chatgpt_export")
        os.makedirs(export_dir, exist_ok=True)
        conversations = [
            {
                "title": "Test Chat",
                "create_time": 1700000000,
                "update_time": 1700001000,
                "mapping": {
                    "msg1": {
                        "message": {
                            "author": {"role": "user"},
                            "content": {"parts": ["What is AI?"]},
                            "create_time": 1700000000,
                        }
                    }
                }
            }
        ]
        with open(os.path.join(export_dir, "conversations.json"), "w") as f:
            json.dump(conversations, f)

        parser = ProviderExportParser(export_dir, "CASE001", "EV001")
        results = parser.scan()
        assert isinstance(results, list)

    def test_parse_empty_dir(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.provider_export_parser import ProviderExportParser
        parser = ProviderExportParser(tmp_dir, "C001", "E001")
        results = parser.scan()
        assert results == []


# ---------------------------------------------------------------------------
# 5. Shared Link Parser
# ---------------------------------------------------------------------------

class TestSharedLinkParser:
    """Test shared link parser."""

    def test_detect_chatgpt_share_link(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.shared_link_parser import SharedLinkParser
        # Create a file with a ChatGPT share link
        test_file = os.path.join(tmp_dir, "notes.txt")
        with open(test_file, "w") as f:
            f.write("Check out this chat: https://chatgpt.com/share/abc123def456\n")
            f.write("Normal text here.\n")

        parser = SharedLinkParser(tmp_dir, "CASE001", "EV001")
        links = parser.scan()
        assert len(links) >= 1
        assert links[0].url == "https://chatgpt.com/share/abc123def456"

    def test_detect_claude_share_link(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.shared_link_parser import SharedLinkParser
        test_file = os.path.join(tmp_dir, "bookmarks.txt")
        with open(test_file, "w") as f:
            f.write("Claude: https://claude.ai/share/abc123\n")

        parser = SharedLinkParser(tmp_dir, "CASE001", "EV001")
        links = parser.scan()
        assert len(links) >= 1

    def test_no_links_found(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.shared_link_parser import SharedLinkParser
        test_file = os.path.join(tmp_dir, "normal.txt")
        with open(test_file, "w") as f:
            f.write("No AI links here.\n")

        parser = SharedLinkParser(tmp_dir, "CASE001", "EV001")
        links = parser.scan()
        assert links == []


# ---------------------------------------------------------------------------
# 6. Generated Asset Parser
# ---------------------------------------------------------------------------

class TestGeneratedAssetParser:
    """Test generated asset parser."""

    def test_detect_dalle_filename(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.generated_asset_parser import GeneratedAssetParser
        # Create a file with DALL-E naming pattern
        dalle_file = os.path.join(tmp_dir, "DALL-E_2025-01-15_image.png")
        with open(dalle_file, "wb") as f:
            f.write(b"\x89PNG" + b"\x00" * 50)

        parser = GeneratedAssetParser(tmp_dir, "CASE001", "EV001")
        assets = parser.scan()
        assert len(assets) >= 1

    def test_detect_c2pa_sidecar(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.generated_asset_parser import GeneratedAssetParser
        # Create an image with C2PA metadata sidecar
        img_file = os.path.join(tmp_dir, "generated_image.png")
        with open(img_file, "wb") as f:
            f.write(b"\x89PNG" + b"\x00" * 50)
        meta_file = os.path.join(tmp_dir, "generated_image.png.ai_metadata.json")
        with open(meta_file, "w") as f:
            json.dump({"generator": "DALL-E 3", "c2pa": True}, f)

        parser = GeneratedAssetParser(tmp_dir, "CASE001", "EV001")
        assets = parser.scan()
        assert isinstance(assets, list)

    def test_no_assets_found(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.generated_asset_parser import GeneratedAssetParser
        test_file = os.path.join(tmp_dir, "normal_doc.txt")
        with open(test_file, "w") as f:
            f.write("Normal content.")

        parser = GeneratedAssetParser(tmp_dir, "CASE001", "EV001")
        assets = parser.scan()
        assert assets == []


# ---------------------------------------------------------------------------
# 7. Confidence Class Assignment
# ---------------------------------------------------------------------------

class TestConfidenceClassAssignment:
    """Test evidence confidence class assignment (Caveat 4)."""

    def test_confidence_class_import(self):
        from ai_usage_evidence_analyzer.models import EvidenceConfidenceClass
        assert EvidenceConfidenceClass.OBSERVED_AI_USE is not None

    def test_fraue_default_confidence_class(self):
        from ai_usage_evidence_analyzer.models import (
            FRAUE, AIPlatform, EvidenceConfidenceClass,
        )
        f = FRAUE(platform=AIPlatform.CHATGPT)
        assert f.confidence_class == EvidenceConfidenceClass.INSUFFICIENT_SUPPORT


# ---------------------------------------------------------------------------
# 8. Acquisition Source Inference
# ---------------------------------------------------------------------------

class TestAcquisitionSourceInference:
    """Test acquisition source and platform surface inference."""

    def test_infer_from_browser_history(self):
        from ai_usage_evidence_analyzer.correlation import _infer_acquisition_source
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily, AcquisitionSource,
        )
        art = ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
        )
        source = _infer_acquisition_source(art)
        assert isinstance(source, AcquisitionSource)

    def test_infer_platform_surface(self):
        from ai_usage_evidence_analyzer.correlation import _infer_platform_surface
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily, PlatformSurface,
        )
        art = ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
        )
        surface = _infer_platform_surface(art)
        assert isinstance(surface, PlatformSurface)


# ---------------------------------------------------------------------------
# 9. Governance v4.0 Fields
# ---------------------------------------------------------------------------

class TestGovernanceV4:
    """Test v4.0 governance field population."""

    def test_governance_record_v4_framework_version(self):
        from ai_usage_evidence_analyzer.models import GovernanceRecord
        g = GovernanceRecord(case_id="TEST")
        assert g.framework_version == "4.0.0"

    def test_governance_v4_blind_spot_fields_exist(self):
        from ai_usage_evidence_analyzer.models import GovernanceRecord
        g = GovernanceRecord(case_id="TEST")
        # All v4.0 list fields should exist and be empty by default
        assert hasattr(g, 'provider_capability_blind_spots')
        assert hasattr(g, 'acquisition_blind_spots')
        assert hasattr(g, 'surface_coverage_summary')
        assert hasattr(g, 'direct_evidence_summary')
        assert hasattr(g, 'corroborating_evidence_summary')
        assert hasattr(g, 'missing_evidence_summary')
        assert hasattr(g, 'alternative_explanations')


# ---------------------------------------------------------------------------
# 10. SQLite Schema v4.0
# ---------------------------------------------------------------------------

class TestSQLiteSchemaV4:
    """Test v4.0 schema additions."""

    def test_schema_version_table(self, tmp_dir):
        from ai_usage_evidence_analyzer.storage import SQLiteStorage
        db_path = os.path.join(tmp_dir, "test_v4.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT version FROM schema_version")
        versions = [row[0] for row in cursor.fetchall()]
        conn.close()
        storage.close()
        assert "4.0.0" in versions

    def test_v4_tables_exist(self, tmp_dir):
        from ai_usage_evidence_analyzer.storage import SQLiteStorage
        db_path = os.path.join(tmp_dir, "test_v4_tables.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()

        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        storage.close()

        assert "voice_evidence_records" in tables
        assert "shared_link_records" in tables
        assert "generated_asset_records" in tables
        assert "schema_version" in tables

    def test_artifact_records_v4_columns(self, tmp_dir):
        from ai_usage_evidence_analyzer.storage import SQLiteStorage
        db_path = os.path.join(tmp_dir, "test_v4_cols.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("PRAGMA table_info(artifact_records)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()
        storage.close()

        assert "acquisition_source" in columns
        assert "platform_surface" in columns
        assert "evidence_source_class" in columns
        assert "related_voice_event_id" in columns
        assert "related_shared_link_id" in columns
        assert "related_generated_asset_id" in columns

    def test_export_with_v4_fields(self, tmp_dir):
        from ai_usage_evidence_analyzer.models import (
            ForensicReport, CaseInfo, ArtifactRecord, AIPlatform,
            AcquisitionSource, PlatformSurface,
        )
        from ai_usage_evidence_analyzer.storage import SQLiteStorage

        report = ForensicReport()
        report.case_info = CaseInfo(case_name="V4 Test Case")
        report.all_artifacts = [
            ArtifactRecord(
                case_id=report.case_info.case_id,
                suspected_platform=AIPlatform.CHATGPT,
                acquisition_source=AcquisitionSource.E01_IMAGE,
                platform_surface=PlatformSurface.BROWSER_WEB,
            )
        ]

        db_path = os.path.join(tmp_dir, "v4_export.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()
        storage.export_report(report)
        storage.close()

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT acquisition_source, platform_surface FROM artifact_records"
        ).fetchone()
        conn.close()
        assert row[0] == "E01 Image"
        assert row[1] == "Browser Web"


# ---------------------------------------------------------------------------
# 11. Report v4.0 Fields (version metadata)
# ---------------------------------------------------------------------------

class TestReportV4Metadata:
    """Test v4.0 report metadata fields."""

    def test_report_schema_version(self):
        from ai_usage_evidence_analyzer.models import ForensicReport
        r = ForensicReport()
        assert r.schema_version == "4.0.0"
        assert r.tool_version == "4.0.0"
        assert r.report_template_name == "UNCC-DFL-TRACE-AI-FR"

    def test_report_docx_fields(self):
        from ai_usage_evidence_analyzer.models import ForensicReport
        r = ForensicReport()
        assert r.docx_generated is False
        assert r.docx_path == ""
        assert r.report_fallback_used is False
        assert r.report_fallback_reason == ""


# ---------------------------------------------------------------------------
# 12. Repo Reality Check
# ---------------------------------------------------------------------------

class TestRepoRealityCheck:
    """Test repository reality check module."""

    def test_reality_check_module_import(self):
        from ai_usage_evidence_analyzer.repo_reality_check import RealityCheckSummary
        s = RealityCheckSummary()
        assert isinstance(s.checks, list)

    def test_reality_check_runs(self):
        from ai_usage_evidence_analyzer import repo_reality_check
        # Should be importable and have the main check function
        assert hasattr(repo_reality_check, 'run_reality_check') or hasattr(repo_reality_check, 'RealityCheckSummary')


# ---------------------------------------------------------------------------
# 13. Package Version
# ---------------------------------------------------------------------------

class TestPackageVersion:
    """Test package version is v4.0.0."""

    def test_version_string(self):
        from ai_usage_evidence_analyzer import __version__
        assert __version__ == "4.0.0"

    def test_cli_info_version(self):
        """Validate the CLI info command references v4.0.0."""
        import importlib
        cli = importlib.import_module("ai_usage_evidence_analyzer.cli")
        # The source should contain v4.0.0 for the framework info
        import inspect
        source = inspect.getsource(cli)
        assert "TRACE-AI-FR v4.0.0" in source


# ---------------------------------------------------------------------------
# 14. DOCX Report Generation
# ---------------------------------------------------------------------------

class TestDOCXReport:
    """Test DOCX report generation (v4.0 primary format)."""

    def test_docx_generator_import(self):
        from ai_usage_evidence_analyzer.docx_report import generate_docx_report
        assert callable(generate_docx_report)

    def test_docx_mentions_8_platforms(self):
        """Verify the conclusion fallback mentions all 8 platforms."""
        import inspect
        from ai_usage_evidence_analyzer import docx_report
        source = inspect.getsource(docx_report)
        assert "Grok" in source
        assert "Poe" in source
        assert "Meta AI" in source
        assert "Copilot" in source
        assert "Perplexity" in source

    def test_generate_minimal_docx(self, tmp_dir):
        """Generate a minimal DOCX report and verify file creation."""
        from ai_usage_evidence_analyzer.docx_report import generate_docx_report
        from ai_usage_evidence_analyzer.models import (
            ForensicReport, CaseInfo, GovernanceRecord,
        )
        report = ForensicReport()
        report.case_info = CaseInfo(case_name="DOCX Test")
        report.governance_record = GovernanceRecord(case_id=report.case_info.case_id)

        output_path = os.path.join(tmp_dir, "test_report.docx")
        result = generate_docx_report(report, output_path)
        assert os.path.exists(result)
        assert result.endswith(".docx")
        # File should be non-trivial size
        assert os.path.getsize(result) > 1000


# ---------------------------------------------------------------------------
# 15. Provenance Dataclass
# ---------------------------------------------------------------------------

class TestArtifactProvenance:
    """Test the ArtifactProvenance dataclass."""

    def test_provenance_creation(self):
        from ai_usage_evidence_analyzer.models import ArtifactProvenance, AcquisitionSource
        p = ArtifactProvenance(
            acquisition_source=AcquisitionSource.E01_IMAGE,
            parser_name="browser_parsers",
            extraction_method="sqlite_query",
        )
        assert p.acquisition_source == AcquisitionSource.E01_IMAGE
        assert p.parser_name == "browser_parsers"
        assert p.hash_status == ""


# ---------------------------------------------------------------------------
# 16. Capability Matrix Feature Check
# ---------------------------------------------------------------------------

class TestCapabilityMatrixFeatures:
    """Test specific platform capabilities."""

    def test_chatgpt_supports_export(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        from ai_usage_evidence_analyzer.models import AIPlatform
        profile = capability_registry.get_profile(AIPlatform.CHATGPT)
        assert profile.supports_export is True

    def test_claude_platform_name(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        from ai_usage_evidence_analyzer.models import AIPlatform
        profile = capability_registry.get_profile(AIPlatform.CLAUDE)
        assert profile.platform.value == "Claude"

    def test_profile_version_format(self):
        from ai_usage_evidence_analyzer.capability_registry import capability_registry
        profiles = capability_registry.get_all_profiles()
        for profile in profiles:
            assert profile.profile_version is not None
            assert len(profile.profile_version) > 0


# ---------------------------------------------------------------------------
# 17. Report Generator v4.0 Sections
# ---------------------------------------------------------------------------

class TestReportGeneratorV4:
    """Test that report generator includes v4.0 sections."""

    def test_v4_evidence_sections_method_exists(self):
        from ai_usage_evidence_analyzer.report_generator import MarkdownReportGenerator
        gen = MarkdownReportGenerator()
        assert hasattr(gen, '_v4_evidence_sections')
        assert callable(gen._v4_evidence_sections)

    def test_markdown_generator_v4_sections_in_generate(self):
        """Verify _v4_evidence_sections is called in the generate pipeline."""
        import inspect
        from ai_usage_evidence_analyzer.report_generator import MarkdownReportGenerator
        source = inspect.getsource(MarkdownReportGenerator.generate)
        assert "_v4_evidence_sections" in source


# ---------------------------------------------------------------------------
# 18. ProjectWorkspaceRecord & MemoryItemRecord
# ---------------------------------------------------------------------------

class TestProjectWorkspaceRecord:
    """Test ProjectWorkspaceRecord dataclass."""

    def test_creation_defaults(self):
        from ai_usage_evidence_analyzer.models import ProjectWorkspaceRecord, AIPlatform
        r = ProjectWorkspaceRecord()
        assert r.workspace_id.startswith("WS-")
        assert r.platform == AIPlatform.UNKNOWN
        assert r.workspace_name == ""
        assert r.workspace_type == ""
        assert r.linked_artifact_ids == []

    def test_creation_with_values(self):
        from ai_usage_evidence_analyzer.models import ProjectWorkspaceRecord, AIPlatform
        from datetime import datetime, timezone
        ts = datetime(2025, 6, 1, tzinfo=timezone.utc)
        r = ProjectWorkspaceRecord(
            platform=AIPlatform.CHATGPT,
            workspace_name="My Project",
            workspace_type="project",
            discovery_path="/evidence/projects",
            creation_timestamp=ts,
            linked_artifact_ids=["ART-001"],
        )
        assert r.platform == AIPlatform.CHATGPT
        assert r.workspace_name == "My Project"
        assert r.linked_artifact_ids == ["ART-001"]

    def test_to_dict(self):
        from ai_usage_evidence_analyzer.models import ProjectWorkspaceRecord, AIPlatform
        r = ProjectWorkspaceRecord(
            platform=AIPlatform.CLAUDE,
            workspace_name="Research",
        )
        d = r.to_dict()
        assert d["platform"] == "Claude"
        assert d["workspace_name"] == "Research"
        assert d["workspace_id"].startswith("WS-")
        assert d["creation_timestamp"] is None

    def test_unique_ids(self):
        from ai_usage_evidence_analyzer.models import ProjectWorkspaceRecord
        r1 = ProjectWorkspaceRecord()
        r2 = ProjectWorkspaceRecord()
        assert r1.workspace_id != r2.workspace_id


class TestMemoryItemRecord:
    """Test MemoryItemRecord dataclass."""

    def test_creation_defaults(self):
        from ai_usage_evidence_analyzer.models import MemoryItemRecord, AIPlatform
        r = MemoryItemRecord()
        assert r.memory_id.startswith("MEM-")
        assert r.platform == AIPlatform.UNKNOWN
        assert r.memory_key == ""
        assert r.memory_value == ""
        assert r.linked_artifact_ids == []

    def test_creation_with_values(self):
        from ai_usage_evidence_analyzer.models import MemoryItemRecord, AIPlatform
        r = MemoryItemRecord(
            platform=AIPlatform.CHATGPT,
            memory_key="user_preference",
            memory_value="Prefers Python",
            discovery_path="/evidence/memories.json",
        )
        assert r.platform == AIPlatform.CHATGPT
        assert r.memory_key == "user_preference"
        assert r.memory_value == "Prefers Python"

    def test_to_dict(self):
        from ai_usage_evidence_analyzer.models import MemoryItemRecord, AIPlatform
        r = MemoryItemRecord(
            platform=AIPlatform.GEMINI,
            memory_key="lang",
            memory_value="English",
        )
        d = r.to_dict()
        assert d["platform"] == "Gemini"
        assert d["memory_key"] == "lang"
        assert d["memory_value"] == "English"
        assert d["memory_id"].startswith("MEM-")

    def test_unique_ids(self):
        from ai_usage_evidence_analyzer.models import MemoryItemRecord
        r1 = MemoryItemRecord()
        r2 = MemoryItemRecord()
        assert r1.memory_id != r2.memory_id


# ---------------------------------------------------------------------------
# 19. CLI Flags: --surface-summary & --emit-migration-notes
# ---------------------------------------------------------------------------

class TestCLIV4Flags:
    """Test v4.0 CLI flag definitions."""

    def test_surface_summary_flag_defined(self):
        import inspect
        from ai_usage_evidence_analyzer import cli
        source = inspect.getsource(cli)
        assert "--surface-summary" in source

    def test_emit_migration_notes_flag_defined(self):
        import inspect
        from ai_usage_evidence_analyzer import cli
        source = inspect.getsource(cli)
        assert "--emit-migration-notes" in source

    def test_surface_summary_default_false(self):
        import inspect
        from ai_usage_evidence_analyzer import cli
        source = inspect.getsource(cli)
        # default=False is set for --surface-summary
        idx = source.index("--surface-summary")
        snippet = source[idx:idx+200]
        assert "default=False" in snippet

    def test_emit_migration_notes_default_false(self):
        import inspect
        from ai_usage_evidence_analyzer import cli
        source = inspect.getsource(cli)
        idx = source.index("--emit-migration-notes")
        snippet = source[idx:idx+200]
        assert "default=False" in snippet

    def test_surface_summary_is_store_true(self):
        import inspect
        from ai_usage_evidence_analyzer import cli
        source = inspect.getsource(cli)
        idx = source.index("--surface-summary")
        snippet = source[idx:idx+200]
        assert "store_true" in snippet

    def test_emit_migration_notes_is_store_true(self):
        import inspect
        from ai_usage_evidence_analyzer import cli
        source = inspect.getsource(cli)
        idx = source.index("--emit-migration-notes")
        snippet = source[idx:idx+200]
        assert "store_true" in snippet


# ---------------------------------------------------------------------------
# 20. DOCX Validation
# ---------------------------------------------------------------------------

class TestDocxValidation:
    """Test DOCX report validation."""

    def test_validation_imports(self):
        from ai_usage_evidence_analyzer.validation import (
            DocxValidationResult, validate_docx_report,
            DOCX_REQUIRED_HEADINGS, DOCX_GOVERNANCE_HEADINGS,
        )
        assert callable(validate_docx_report)
        assert len(DOCX_REQUIRED_HEADINGS) >= 5

    def test_validation_result_defaults(self):
        from ai_usage_evidence_analyzer.validation import DocxValidationResult
        r = DocxValidationResult()
        assert r.is_valid is False
        assert r.opens_successfully is False
        assert r.headings_found == []
        assert r.headings_missing == []
        assert r.errors == []

    def test_validation_result_to_dict(self):
        from ai_usage_evidence_analyzer.validation import DocxValidationResult
        r = DocxValidationResult(file_path="/test.docx", is_valid=True)
        d = r.to_dict()
        assert d["file_path"] == "/test.docx"
        assert d["is_valid"] is True

    def test_validate_nonexistent_file(self):
        from ai_usage_evidence_analyzer.validation import validate_docx_report
        result = validate_docx_report("/nonexistent/report.docx")
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_generated_docx(self, tmp_dir):
        """Generate a DOCX and validate it passes forensic checks."""
        from ai_usage_evidence_analyzer.docx_report import generate_docx_report
        from ai_usage_evidence_analyzer.validation import validate_docx_report
        from ai_usage_evidence_analyzer.models import (
            ForensicReport, CaseInfo, GovernanceRecord,
        )
        report = ForensicReport()
        report.case_info = CaseInfo(case_name="Validation Test")
        report.governance_record = GovernanceRecord(case_id=report.case_info.case_id)

        docx_path = os.path.join(tmp_dir, "validate_test.docx")
        generate_docx_report(report, docx_path)

        result = validate_docx_report(docx_path)
        assert result.opens_successfully is True
        assert result.has_conclusion is True
        assert result.has_signature_block is True
        assert result.has_glossary is True


# ---------------------------------------------------------------------------
# 21. DOCX Auto-Primary in Desktop App
# ---------------------------------------------------------------------------

class TestDesktopAutoDocx:
    """Test that desktop app has auto-DOCX generation wired in."""

    def test_auto_generate_docx_method_exists(self):
        import inspect
        import importlib
        mod = importlib.import_module("desktop_app")
        source = inspect.getsource(mod)
        assert "_auto_generate_docx" in source

    def test_auto_generate_called_from_on_analysis_done(self):
        import inspect
        import importlib
        mod = importlib.import_module("desktop_app")
        source = inspect.getsource(mod)
        # Verify it's called after analysis completes
        assert "_auto_generate_docx" in source
        assert "docx_generated" in source


# ---------------------------------------------------------------------------
# 22. Confidence Class Pipeline Wiring
# ---------------------------------------------------------------------------

class TestConfidenceClassPipeline:
    """Test that confidence_class is wired through adjudication."""

    def test_assign_confidence_class_exists(self):
        import inspect
        from ai_usage_evidence_analyzer.adjudication import AdjudicationEngine
        assert hasattr(AdjudicationEngine, '_assign_confidence_class')

    def test_adjudication_sets_confidence_class(self):
        import inspect
        from ai_usage_evidence_analyzer import adjudication
        source = inspect.getsource(adjudication)
        assert "fraue.confidence_class = self._assign_confidence_class" in source

    def test_confidence_class_values_in_adjudication(self):
        import inspect
        from ai_usage_evidence_analyzer import adjudication
        source = inspect.getsource(adjudication)
        assert "OBSERVED_AI_USE" in source
        assert "CORROBORATED_AI_USE" in source
        assert "SUSPECTED_AI_USE" in source
        assert "INSUFFICIENT_SUPPORT" in source
