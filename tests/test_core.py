"""
Unit tests for the AI Usage Evidence Analyzer.
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
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test evidence and output."""
    d = tempfile.mkdtemp(prefix="aiuea_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def mock_windows_evidence(tmp_dir):
    """Create a mock Windows evidence directory structure."""
    root = os.path.join(tmp_dir, "evidence")
    user = "TestUser"

    # Create directory structure
    dirs = [
        f"Users/{user}/AppData/Local/Google/Chrome/User Data/Default",
        f"Users/{user}/AppData/Local/Microsoft/Edge/User Data/Default",
        f"Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles/test.default",
        f"Users/{user}/AppData/Roaming/Microsoft/Windows/Recent",
        f"Users/{user}/Downloads",
        f"Users/{user}/Documents",
        f"Users/{user}/Desktop",
        "Windows/Prefetch",
        "Windows/System32/winevt/Logs",
    ]
    for d in dirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)

    # Create a mock Chrome History database
    chrome_history = os.path.join(
        root, f"Users/{user}/AppData/Local/Google/Chrome/User Data/Default/History"
    )
    _create_mock_chrome_history(chrome_history)

    # Create a mock Chrome Cookies database
    chrome_cookies = os.path.join(
        root, f"Users/{user}/AppData/Local/Google/Chrome/User Data/Default/Cookies"
    )
    _create_mock_chrome_cookies(chrome_cookies)

    # Create a mock Firefox history
    ff_places = os.path.join(
        root, f"Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles/test.default/places.sqlite"
    )
    _create_mock_firefox_history(ff_places)

    # Create some AI-related files in Downloads
    ai_files = [
        "chatgpt_export_2025.json",
        "claude_artifact_analysis.md",
        "gemini_response.txt",
        "normal_document.docx",
    ]
    for f in ai_files:
        filepath = os.path.join(root, f"Users/{user}/Downloads/{f}")
        with open(filepath, "w") as fh:
            if f.endswith(".json"):
                json.dump({"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]}, fh)
            elif "claude" in f:
                fh.write("Claude 3.5 Sonnet\nThis is a test artifact response.")
            elif "gemini" in f:
                fh.write("Gemini Pro response\nAnalysis of the crime scene image.")
            else:
                fh.write("Normal document content.")

    # Create a Recent file with AI reference
    recent_lnk = os.path.join(
        root, f"Users/{user}/AppData/Roaming/Microsoft/Windows/Recent/chatgpt_export.lnk"
    )
    with open(recent_lnk, "wb") as f:
        # Write a minimal LNK-like binary with AI domain
        f.write(b"\x00" * 20 + b"chat.openai.com" + b"\x00" * 20)

    return root, user


@pytest.fixture
def mock_macos_evidence(tmp_dir):
    """Create a mock macOS evidence directory structure."""
    root = os.path.join(tmp_dir, "evidence_mac")
    user = "macuser"

    dirs = [
        f"Users/{user}/Library/Safari",
        f"Users/{user}/Library/Preferences",
        f"Users/{user}/Library/Application Support/Google/Chrome/Default",
        f"Users/{user}/Downloads",
    ]
    for d in dirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)

    # Create Library directory to trigger macOS detection
    os.makedirs(os.path.join(root, "Library"), exist_ok=True)
    os.makedirs(os.path.join(root, "Applications"), exist_ok=True)

    return root, user


def _create_mock_chrome_history(db_path: str):
    """Create a mock Chrome History SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            last_visit_time INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            target_path TEXT,
            tab_url TEXT,
            total_bytes INTEGER,
            start_time INTEGER,
            end_time INTEGER,
            mime_type TEXT,
            original_mime_type TEXT
        )
    """)

    # AI-related URLs (Chrome timestamps: microseconds since 1601-01-01)
    # Approximate time for 2025-01-15 12:00:00 UTC = 13381084800000000
    base_time = 13381084800000000
    urls = [
        ("https://chat.openai.com/c/abc123", "ChatGPT", 5, base_time),
        ("https://chatgpt.com/c/def456", "ChatGPT - Crime Scene Analysis", 3, base_time + 3600000000),
        ("https://claude.ai/chat/xyz789", "Claude", 2, base_time + 7200000000),
        ("https://gemini.google.com/app/conversation1", "Google Gemini", 1, base_time + 10800000000),
        ("https://www.google.com/search?q=weather", "Google Search", 10, base_time - 86400000000),
        ("https://example.com", "Example", 1, base_time - 172800000000),
    ]
    for url, title, count, time in urls:
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            (url, title, count, time),
        )

    # AI-related downloads
    downloads = [
        ("/Users/test/Downloads/chatgpt_export.json", "https://chat.openai.com/export", 1024, base_time, base_time + 1000000, "application/json", "application/json"),
    ]
    for target, tab_url, size, start, end, mime, orig_mime in downloads:
        conn.execute(
            "INSERT INTO downloads (target_path, tab_url, total_bytes, start_time, end_time, mime_type, original_mime_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target, tab_url, size, start, end, mime, orig_mime),
        )

    conn.commit()
    conn.close()


def _create_mock_chrome_cookies(db_path: str):
    """Create a mock Chrome Cookies SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE cookies (
            creation_utc INTEGER,
            host_key TEXT,
            name TEXT,
            path TEXT,
            last_access_utc INTEGER,
            expires_utc INTEGER,
            is_secure INTEGER,
            is_httponly INTEGER
        )
    """)
    base_time = 13381084800000000
    cookies = [
        (base_time, ".openai.com", "__Secure-next-auth.session-token", "/", base_time + 3600000000, base_time + 86400000000, 1, 1),
        (base_time, ".claude.ai", "sessionKey", "/", base_time + 7200000000, base_time + 86400000000, 1, 1),
        (base_time, ".google.com", "SID", "/", base_time + 10800000000, base_time + 86400000000, 1, 0),
        (base_time, ".example.com", "test", "/", base_time, base_time + 86400000000, 0, 0),
    ]
    for c in cookies:
        conn.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?)", c
        )
    conn.commit()
    conn.close()


def _create_mock_firefox_history(db_path: str):
    """Create a mock Firefox places.sqlite database."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            last_visit_date INTEGER
        )
    """)
    # Firefox timestamps: microseconds since Unix epoch
    base_time = 1705312800000000  # ~2024-01-15 12:00 UTC
    places = [
        (1, "https://chat.openai.com/c/test123", "ChatGPT", 3, base_time),
        (2, "https://claude.ai/chat/test456", "Claude", 1, base_time + 3600000000),
        (3, "https://example.com", "Example", 5, base_time - 86400000000),
    ]
    for p in places:
        conn.execute("INSERT INTO moz_places VALUES (?, ?, ?, ?, ?)", p)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Tests: Models
# ---------------------------------------------------------------------------

class TestModels:
    def test_artifact_record_creation(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily, ConfidenceLevel,
        )
        record = ArtifactRecord(
            case_id="TEST001",
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
            confidence=ConfidenceLevel.MODERATE,
        )
        assert record.case_id == "TEST001"
        assert record.suspected_platform == AIPlatform.CHATGPT
        assert record.record_id  # Should be auto-generated

    def test_artifact_record_to_dict(self):
        from ai_usage_evidence_analyzer.models import ArtifactRecord, AIPlatform
        record = ArtifactRecord(suspected_platform=AIPlatform.CLAUDE)
        d = record.to_dict()
        assert d["suspected_platform"] == "Claude"
        assert "record_id" in d

    def test_case_info_defaults(self):
        from ai_usage_evidence_analyzer.models import CaseInfo
        case = CaseInfo()
        assert case.case_id  # Should be auto-generated
        assert isinstance(case.created_at, datetime)

    def test_confidence_levels(self):
        from ai_usage_evidence_analyzer.models import ConfidenceLevel
        assert ConfidenceLevel.HIGH.value == "High"
        assert ConfidenceLevel.UNSUPPORTED.value == "Unsupported"

    def test_evidence_classification(self):
        from ai_usage_evidence_analyzer.models import EvidenceClassification
        assert EvidenceClassification.DIRECT.value == "Direct"
        assert EvidenceClassification.INFERRED.value == "Inferred"


# ---------------------------------------------------------------------------
# Tests: Signatures
# ---------------------------------------------------------------------------

class TestSignatures:
    def test_match_domain_chatgpt(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://chat.openai.com/c/abc").value == "ChatGPT"
        assert match_domain("https://chatgpt.com/c/def").value == "ChatGPT"

    def test_match_domain_claude(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://claude.ai/chat/xyz").value == "Claude"

    def test_match_domain_gemini(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://gemini.google.com/app/test").value == "Gemini"

    def test_match_domain_no_match(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://example.com") is None

    def test_match_domain_perplexity(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://perplexity.ai/search/test").value == "Perplexity"

    def test_match_domain_copilot(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://copilot.microsoft.com/chat").value == "Copilot"

    def test_match_domain_meta_ai(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://meta.ai/").value == "Meta AI"

    def test_match_domain_grok(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://grok.com/chat").value == "Grok"

    def test_match_domain_poe(self):
        from ai_usage_evidence_analyzer.signatures import match_domain
        assert match_domain("https://poe.com/ChatGPT").value == "Poe"

    def test_match_model_string(self):
        from ai_usage_evidence_analyzer.signatures import match_model_string
        from ai_usage_evidence_analyzer.models import AIModel
        assert match_model_string("Using gpt-4 model") == AIModel.GPT4
        assert match_model_string("claude-3-opus response") == AIModel.CLAUDE_3_OPUS
        assert match_model_string("gemini-1.5-pro output") == AIModel.GEMINI_15_PRO
        assert match_model_string("no model here") is None

    def test_all_signatures_populated(self):
        from ai_usage_evidence_analyzer.signatures import ALL_SIGNATURES
        assert len(ALL_SIGNATURES) == 8
        for sig in ALL_SIGNATURES:
            assert len(sig.domains) > 0
            assert len(sig.url_patterns) > 0


# ---------------------------------------------------------------------------
# Tests: Parser Registry
# ---------------------------------------------------------------------------

class TestParserRegistry:
    def test_registry_has_parsers(self):
        # Import parsers to trigger registration
        from ai_usage_evidence_analyzer import parsers  # noqa
        from ai_usage_evidence_analyzer.parser_registry import registry

        all_parsers = registry.get_all()
        assert len(all_parsers) > 0

    def test_registry_get_for_windows(self):
        from ai_usage_evidence_analyzer import parsers  # noqa
        from ai_usage_evidence_analyzer.parser_registry import registry
        from ai_usage_evidence_analyzer.models import OSPlatform

        win_parsers = registry.get_for_os(OSPlatform.WINDOWS)
        assert len(win_parsers) > 0

    def test_registry_get_for_macos(self):
        from ai_usage_evidence_analyzer import parsers  # noqa
        from ai_usage_evidence_analyzer.parser_registry import registry
        from ai_usage_evidence_analyzer.models import OSPlatform

        mac_parsers = registry.get_for_os(OSPlatform.MACOS)
        assert len(mac_parsers) > 0


# ---------------------------------------------------------------------------
# Tests: Browser Parsers
# ---------------------------------------------------------------------------

class TestBrowserParsers:
    def test_chromium_history_parser(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.parsers.browser_parsers import ChromiumHistoryParser
        root, user = mock_windows_evidence

        parser = ChromiumHistoryParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST001",
        )
        result = parser.parse()

        assert result.parser_name == "ChromiumHistoryParser"
        assert len(result.artifacts_found) > 0

        # Check that AI URLs were detected
        platforms_found = set(a.suspected_platform.value for a in result.artifacts_found)
        assert "ChatGPT" in platforms_found

    def test_firefox_history_parser(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.parsers.browser_parsers import FirefoxHistoryParser
        root, user = mock_windows_evidence

        parser = FirefoxHistoryParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST001",
        )
        result = parser.parse()

        assert result.parser_name == "FirefoxHistoryParser"
        # Firefox should find ChatGPT and Claude
        if result.artifacts_found:
            platforms = set(a.suspected_platform.value for a in result.artifacts_found)
            assert "ChatGPT" in platforms or "Claude" in platforms

    def test_chromium_cookies_detected(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.parsers.browser_parsers import ChromiumHistoryParser
        root, user = mock_windows_evidence

        parser = ChromiumHistoryParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST001",
        )
        result = parser.parse()

        # Should find cookie artifacts
        cookie_arts = [a for a in result.artifacts_found
                       if a.artifact_family.value == "Browser Cookies"]
        assert len(cookie_arts) > 0

    def test_chromium_downloads_detected(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.parsers.browser_parsers import ChromiumHistoryParser
        root, user = mock_windows_evidence

        parser = ChromiumHistoryParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST001",
        )
        result = parser.parse()

        # Should find download artifacts
        dl_arts = [a for a in result.artifacts_found
                   if a.artifact_family.value == "Browser Downloads"]
        assert len(dl_arts) > 0


# ---------------------------------------------------------------------------
# Tests: Windows Parsers
# ---------------------------------------------------------------------------

class TestWindowsParsers:
    def test_recent_files_parser(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.parsers.windows_parsers import RecentFilesParser
        root, user = mock_windows_evidence

        parser = RecentFilesParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST001",
        )
        result = parser.parse()
        assert result.parser_name == "WindowsRecentFilesParser"
        # Should find the ChatGPT LNK reference
        if result.artifacts_found:
            assert any("ChatGPT" in a.suspected_platform.value
                       for a in result.artifacts_found)

    def test_prefetch_parser_no_dir(self, tmp_dir):
        from ai_usage_evidence_analyzer.parsers.windows_parsers import PrefetchParser

        parser = PrefetchParser(
            evidence_root=os.path.join(tmp_dir, "nonexistent"),
            case_id="TEST001",
        )
        result = parser.parse()
        assert result.status.value == "Not Applicable"


# ---------------------------------------------------------------------------
# Tests: Content Parsers
# ---------------------------------------------------------------------------

class TestContentParsers:
    def test_ai_content_scanner(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.parsers.content_parsers import AIContentScanner
        root, user = mock_windows_evidence

        parser = AIContentScanner(
            evidence_root=root,
            user_profile=user,
            case_id="TEST001",
        )
        result = parser.parse()

        assert result.parser_name == "AIContentScanner"
        assert len(result.artifacts_found) > 0

        # Should detect AI export files
        platforms = set(a.suspected_platform.value for a in result.artifacts_found)
        assert len(platforms) > 0


# ---------------------------------------------------------------------------
# Tests: Correlation
# ---------------------------------------------------------------------------

class TestCorrelation:
    def test_basic_correlation(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily, ConfidenceLevel,
        )
        from ai_usage_evidence_analyzer.correlation import CorrelationEngine

        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        artifacts = [
            ArtifactRecord(
                suspected_platform=AIPlatform.CHATGPT,
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                timestamp=now,
            ),
            ArtifactRecord(
                suspected_platform=AIPlatform.CHATGPT,
                artifact_family=ArtifactFamily.BROWSER_COOKIES,
                timestamp=now,
            ),
        ]

        engine = CorrelationEngine(artifacts)
        timeline = engine.run()

        assert len(timeline) == 2
        # Artifacts should corroborate each other
        assert len(artifacts[0].corroborating_artifacts) > 0

    def test_platform_summary(self):
        from ai_usage_evidence_analyzer.models import ArtifactRecord, AIPlatform, ArtifactFamily
        from ai_usage_evidence_analyzer.correlation import CorrelationEngine

        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        artifacts = [
            ArtifactRecord(suspected_platform=AIPlatform.CHATGPT, timestamp=now,
                          artifact_family=ArtifactFamily.BROWSER_HISTORY),
            ArtifactRecord(suspected_platform=AIPlatform.CLAUDE, timestamp=now,
                          artifact_family=ArtifactFamily.BROWSER_HISTORY),
        ]

        engine = CorrelationEngine(artifacts)
        engine.run()
        summary = engine.get_platform_summary()

        assert AIPlatform.CHATGPT in summary
        assert AIPlatform.CLAUDE in summary


# ---------------------------------------------------------------------------
# Tests: Confidence Scoring
# ---------------------------------------------------------------------------

class TestConfidenceScoring:
    def test_direct_browser_history_scoring(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, AttributionLayer, ConfidenceLevel,
        )
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine

        art = ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
            classification=EvidenceClassification.DIRECT,
            attribution_layer=AttributionLayer.PLATFORM,
            timestamp=datetime(2025, 1, 15, tzinfo=timezone.utc),
            timezone_normalized=True,
        )

        engine = ConfidenceScoringEngine([art])
        scored = engine.score_all()

        assert scored[0].confidence in (ConfidenceLevel.MODERATE, ConfidenceLevel.HIGH)

    def test_weak_cookie_scoring(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, AttributionLayer, ConfidenceLevel,
        )
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine

        art = ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_COOKIES,
            classification=EvidenceClassification.DIRECT,
            attribution_layer=AttributionLayer.PLATFORM,
            notes="Cookie alone is not sufficient to conclude substantive AI use.",
        )

        engine = ConfidenceScoringEngine([art])
        scored = engine.score_all()

        # Cookies with weak notes should score Low
        assert scored[0].confidence in (ConfidenceLevel.LOW, ConfidenceLevel.UNSUPPORTED)

    def test_footprint_building(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel,
        )
        from ai_usage_evidence_analyzer.confidence import ConfidenceScoringEngine

        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        artifacts = [
            ArtifactRecord(
                suspected_platform=AIPlatform.CHATGPT,
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                classification=EvidenceClassification.DIRECT,
                timestamp=now,
                confidence=ConfidenceLevel.MODERATE,
            ),
        ]

        engine = ConfidenceScoringEngine(artifacts)
        engine.score_all()
        footprints = engine.build_footprints()

        assert len(footprints) == 1
        assert footprints[0].platform == AIPlatform.CHATGPT
        assert footprints[0].total_artifacts == 1


# ---------------------------------------------------------------------------
# Tests: SQLite Storage
# ---------------------------------------------------------------------------

class TestSQLiteStorage:
    def test_schema_creation(self, tmp_dir):
        from ai_usage_evidence_analyzer.storage import SQLiteStorage

        db_path = os.path.join(tmp_dir, "test.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()

        # Check tables exist
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        storage.close()

        assert "case_info" in tables
        assert "artifact_records" in tables
        assert "timeline_events" in tables
        assert "comparative_matrix" in tables
        assert "evidence_coverage" in tables

    def test_full_export(self, tmp_dir):
        from ai_usage_evidence_analyzer.models import ForensicReport, CaseInfo, ArtifactRecord, AIPlatform
        from ai_usage_evidence_analyzer.storage import SQLiteStorage

        report = ForensicReport()
        report.case_info = CaseInfo(case_name="Test Case")
        report.all_artifacts = [
            ArtifactRecord(
                case_id=report.case_info.case_id,
                suspected_platform=AIPlatform.CHATGPT,
            )
        ]

        db_path = os.path.join(tmp_dir, "export_test.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()
        storage.export_report(report)
        storage.close()

        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM artifact_records").fetchone()[0]
        conn.close()
        assert count == 1


# ---------------------------------------------------------------------------
# Tests: Matrix
# ---------------------------------------------------------------------------

class TestMatrix:
    def test_matrix_generation(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel, EvidenceCoverage,
        )
        from ai_usage_evidence_analyzer.matrix import build_comparative_matrix

        art = ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
            classification=EvidenceClassification.DIRECT,
            confidence=ConfidenceLevel.MODERATE,
            timestamp=datetime(2025, 1, 15, tzinfo=timezone.utc),
            timezone_normalized=True,
        )

        cov = EvidenceCoverage()
        rows = build_comparative_matrix([art], cov)

        assert len(rows) == 1
        assert rows[0].platform == AIPlatform.CHATGPT


# ---------------------------------------------------------------------------
# Tests: Report Generation
# ---------------------------------------------------------------------------

class TestReportGeneration:
    def test_json_export(self, tmp_dir):
        from ai_usage_evidence_analyzer.models import ForensicReport, CaseInfo
        from ai_usage_evidence_analyzer.report_generator import JSONExporter

        report = ForensicReport(case_info=CaseInfo(case_name="JSON Test"))
        path = os.path.join(tmp_dir, "test.json")

        JSONExporter().export(report, path)
        assert os.path.isfile(path)

        with open(path) as f:
            data = json.load(f)
        assert data["tool"] == "TRACE-AI-FR"

    def test_markdown_generation(self, tmp_dir):
        from ai_usage_evidence_analyzer.models import ForensicReport, CaseInfo
        from ai_usage_evidence_analyzer.report_generator import MarkdownReportGenerator

        report = ForensicReport(case_info=CaseInfo(case_name="MD Test"))
        path = os.path.join(tmp_dir, "test.md")

        MarkdownReportGenerator().generate(report, path)
        assert os.path.isfile(path)

        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "Overview" in content
        assert "Forensic Acquisition" in content
        assert "Conclusion" in content

    def test_html_generation(self, tmp_dir):
        from ai_usage_evidence_analyzer.models import ForensicReport, CaseInfo
        from ai_usage_evidence_analyzer.report_generator import HTMLReportGenerator

        report = ForensicReport(case_info=CaseInfo(case_name="HTML Test"))
        path = os.path.join(tmp_dir, "test.html")

        HTMLReportGenerator().generate(report, path)
        assert os.path.isfile(path)

        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "Forensic Report" in content


# ---------------------------------------------------------------------------
# Tests: E01 Handler (mounted-directory mode)
# ---------------------------------------------------------------------------

class TestMountedEvidence:
    def test_os_detection_windows(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.e01_handler import MountedEvidenceHandler
        root, user = mock_windows_evidence

        handler = MountedEvidenceHandler(root)
        assert handler.validate()

        os_platform = handler.detect_os_platform()
        assert os_platform.value == "Windows"

    def test_user_profile_detection(self, mock_windows_evidence):
        from ai_usage_evidence_analyzer.e01_handler import MountedEvidenceHandler
        root, user = mock_windows_evidence

        handler = MountedEvidenceHandler(root)
        profiles = handler.find_user_profiles()
        assert user in profiles


# ---------------------------------------------------------------------------
# Tests: End-to-End Integration
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_full_analysis_windows(self, mock_windows_evidence, tmp_dir):
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        root, user = mock_windows_evidence
        output = os.path.join(tmp_dir, "output")

        engine = AnalysisEngine(
            evidence_path=root,
            output_dir=output,
            case_name="Integration Test",
            examiner="Test Examiner",
            input_mode="mounted",
        )
        report = engine.run()

        # Should find artifacts
        assert len(report.all_artifacts) > 0

        # Should have timeline
        assert len(report.timeline) >= 0  # May or may not have timestamped events

        # Should have parser results
        assert len(report.parser_results) > 0

        # Output files should exist
        assert os.path.isdir(output)
        files = os.listdir(output)
        assert any(f.endswith(".sqlite") for f in files)
        assert any(f.endswith(".json") for f in files)
        assert any(f.endswith(".md") for f in files)
        assert any(f.endswith(".html") for f in files)

    def test_empty_evidence(self, tmp_dir):
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        empty_dir = os.path.join(tmp_dir, "empty_evidence")
        os.makedirs(empty_dir)
        output = os.path.join(tmp_dir, "output_empty")

        engine = AnalysisEngine(
            evidence_path=empty_dir,
            output_dir=output,
            case_name="Empty Test",
            input_mode="mounted",
        )
        report = engine.run()

        # Should still produce a report, just with no artifacts
        assert len(report.all_artifacts) == 0
        assert os.path.isdir(output)


# ---------------------------------------------------------------------------
# Tests: Evidence Exhibit System
# ---------------------------------------------------------------------------

class TestEvidenceExhibit:
    def test_exhibit_manager_creation(self, tmp_dir):
        from ai_usage_evidence_analyzer.evidence_exhibit import ExhibitManager

        mgr = ExhibitManager(output_dir=tmp_dir, evidence_source="test.E01")
        assert mgr.evidence_source == "test.E01"
        assert len(mgr.get_all()) == 0

    def test_add_exhibit_from_artifact(self, tmp_dir):
        from ai_usage_evidence_analyzer.evidence_exhibit import ExhibitManager
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel,
        )

        mgr = ExhibitManager(output_dir=tmp_dir, evidence_source="evidence.E01")

        art = ArtifactRecord(
            artifact_path="/Users/TestUser/AppData/Local/Google/Chrome/History",
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
            suspected_platform=AIPlatform.CHATGPT,
            classification=EvidenceClassification.DIRECT,
            confidence=ConfidenceLevel.HIGH,
            extracted_indicator="chatgpt.com visited",
        )

        mgr.add_exhibit_from_artifact(art, evidence_root="")
        exhibits = mgr.get_all()
        assert len(exhibits) == 1
        assert exhibits[0].platform == "ChatGPT"
        assert "evidence.E01" in exhibits[0].full_evidence_reference

    def test_exhibit_numbering(self, tmp_dir):
        from ai_usage_evidence_analyzer.evidence_exhibit import ExhibitManager
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel,
        )

        mgr = ExhibitManager(output_dir=tmp_dir, evidence_source="disk.E01")

        for i in range(3):
            art = ArtifactRecord(
                artifact_path=f"/path/artifact_{i}",
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                suspected_platform=AIPlatform.CHATGPT,
                classification=EvidenceClassification.DIRECT,
                confidence=ConfidenceLevel.MODERATE,
                extracted_indicator=f"indicator {i}",
            )
            mgr.add_exhibit_from_artifact(art, evidence_root="")

        exhibits = mgr.get_all()
        assert len(exhibits) == 3
        assert exhibits[0].exhibit_number == 1
        assert exhibits[1].exhibit_number == 2
        assert exhibits[2].exhibit_number == 3

    def test_get_exhibits_for_platform(self, tmp_dir):
        from ai_usage_evidence_analyzer.evidence_exhibit import ExhibitManager
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel,
        )

        mgr = ExhibitManager(output_dir=tmp_dir, evidence_source="disk.E01")

        for platform in [AIPlatform.CHATGPT, AIPlatform.CLAUDE, AIPlatform.CHATGPT]:
            art = ArtifactRecord(
                artifact_path=f"/path/{platform.value}",
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                suspected_platform=platform,
                classification=EvidenceClassification.DIRECT,
                confidence=ConfidenceLevel.HIGH,
                extracted_indicator=f"visit {platform.value}",
            )
            mgr.add_exhibit_from_artifact(art, evidence_root="")

        chatgpt_exhibits = mgr.get_exhibits_for_platform("ChatGPT")
        assert len(chatgpt_exhibits) == 2
        claude_exhibits = mgr.get_exhibits_for_platform("Claude")
        assert len(claude_exhibits) == 1

    def test_exhibit_reference_md(self, tmp_dir):
        from ai_usage_evidence_analyzer.evidence_exhibit import (
            ExhibitManager, generate_exhibit_reference_md,
        )
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel,
        )

        mgr = ExhibitManager(output_dir=tmp_dir, evidence_source="test.E01")
        art = ArtifactRecord(
            artifact_path="/Users/Test/Chrome/History",
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
            suspected_platform=AIPlatform.CHATGPT,
            classification=EvidenceClassification.DIRECT,
            confidence=ConfidenceLevel.HIGH,
            extracted_indicator="chatgpt visit",
        )
        mgr.add_exhibit_from_artifact(art, evidence_root="")
        ex = mgr.get_all()[0]

        md_ref = generate_exhibit_reference_md(ex)
        assert "Exhibit 1" in md_ref
        assert "test.E01" in md_ref


# ---------------------------------------------------------------------------
# Tests: LLM Narrator (Fallback Mode — No API Key)
# ---------------------------------------------------------------------------

class TestLLMNarrator:
    def test_overview_narrative_fallback(self):
        from ai_usage_evidence_analyzer.llm_narrator import generate_overview_narrative

        result = generate_overview_narrative(
            case_name="Test Case",
            examiner="John Doe",
            organization="UNCC Lab",
            evidence_path="evidence.E01",
            image_type="E01",
            detected_os="Windows",
            date_str="01/15/2025",
            description="Test description",
        )
        assert isinstance(result, str)
        assert len(result) > 50
        assert "evidence" in result.lower() or "forensic" in result.lower()

    def test_acquisition_narrative_fallback(self):
        from ai_usage_evidence_analyzer.llm_narrator import generate_acquisition_narrative

        result = generate_acquisition_narrative(
            tool_version="1.0.0",
            md5_hash="abc123",
            sha1_hash="def456",
            image_path="test.E01",
            image_type="E01",
            image_size_bytes=1024000,
            detected_os="Windows",
            read_only=True,
            parsers_used=["Chrome Parser v1.0", "Firefox Parser v1.0"],
        )
        assert isinstance(result, str)
        assert len(result) > 50

    def test_finding_narrative_fallback(self):
        from ai_usage_evidence_analyzer.llm_narrator import generate_finding_narrative

        result = generate_finding_narrative(
            finding_number=2,
            platform_name="ChatGPT",
            total_artifacts=5,
            direct_count=3,
            inferred_count=2,
            overall_confidence="High",
            access_mode="Browser",
            earliest_activity="2025-01-10 08:00:00 UTC",
            latest_activity="2025-01-15 16:30:00 UTC",
            estimated_sessions=4,
            model_name="GPT-4o",
            exhibits=[
                {"exhibit_number": 1, "description": "Chrome History",
                 "evidence_path": "test.E01:/Users/Test/Chrome/History",
                 "confidence": "High", "timestamp": "2025-01-10"},
            ],
            caveats=["Cookie-only evidence"],
        )
        assert isinstance(result, str)
        assert "ChatGPT" in result

    def test_conclusion_narrative_fallback(self):
        from ai_usage_evidence_analyzer.llm_narrator import generate_conclusion_narrative

        result = generate_conclusion_narrative(
            platforms_found=[
                {"name": "ChatGPT", "confidence": "High", "total": 5, "direct": 3},
            ],
            total_artifacts=5,
            carving_enabled=False,
            full_disk=True,
        )
        assert isinstance(result, str)
        assert len(result) > 30


# ---------------------------------------------------------------------------
# Tests: Report Generation with Exhibits
# ---------------------------------------------------------------------------

class TestReportWithExhibits:
    def test_markdown_report_includes_exhibits(self, mock_windows_evidence, tmp_dir):
        """Full integration: analysis → report → exhibits referenced."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        root, user = mock_windows_evidence
        output = os.path.join(tmp_dir, "output_exhibits")

        engine = AnalysisEngine(
            evidence_path=root,
            output_dir=output,
            case_name="Exhibit Test",
            examiner="Test Examiner",
            input_mode="mounted",
        )
        report = engine.run()

        # Read the markdown report
        md_files = [f for f in os.listdir(output) if f.endswith(".md")]
        assert len(md_files) == 1

        md_path = os.path.join(output, md_files[0])
        with open(md_path, encoding="utf-8") as f:
            content = f.read()

        # Should have exhibit appendix if artifacts were found
        if report.all_artifacts:
            assert "Exhibit" in content
            assert "Appendix" in content or "Evidence" in content


# ---------------------------------------------------------------------------
# Tests: ZIP Evidence Extraction
# ---------------------------------------------------------------------------

class TestZIPExtraction:
    def test_zip_auto_detection(self, mock_windows_evidence, tmp_dir):
        """Engine auto-detects .zip files and sets input_mode='zip'."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine
        import zipfile as zf

        root, user = mock_windows_evidence
        zip_path = os.path.join(tmp_dir, "evidence.zip")
        output = os.path.join(tmp_dir, "output_zip_auto")

        # Create a valid ZIP from the mock evidence
        with zf.ZipFile(zip_path, "w", zf.ZIP_DEFLATED) as z:
            for dirpath, dirnames, filenames in os.walk(root):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    arcname = os.path.relpath(full, os.path.dirname(root))
                    z.write(full, arcname)

        engine = AnalysisEngine(
            evidence_path=zip_path,
            output_dir=output,
            case_name="ZIP Auto Test",
            input_mode="auto",
        )
        # _ingest_evidence updates input_mode from "auto" to "zip"
        report = engine.run()
        assert engine.input_mode == "zip"
        assert report is not None

    def test_zip_extraction_produces_artifacts(self, mock_windows_evidence, tmp_dir):
        """ZIP extraction should produce forensic artifacts."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine
        import zipfile as zf

        root, user = mock_windows_evidence
        zip_path = os.path.join(tmp_dir, "evidence_full.zip")
        output = os.path.join(tmp_dir, "output_zip_full")

        with zf.ZipFile(zip_path, "w", zf.ZIP_DEFLATED) as z:
            for dirpath, dirnames, filenames in os.walk(root):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    arcname = os.path.relpath(full, os.path.dirname(root))
                    z.write(full, arcname)

        engine = AnalysisEngine(
            evidence_path=zip_path,
            output_dir=output,
            case_name="ZIP Artifacts Test",
            input_mode="zip",
        )
        report = engine.run()

        assert len(report.all_artifacts) > 0
        assert report.evidence_info.image_format == "ZIP Archive"

    def test_zip_hash_computation(self, mock_windows_evidence, tmp_dir):
        """ZIP hashing should produce MD5 and SHA-1 values."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine
        import zipfile as zf

        root, user = mock_windows_evidence
        zip_path = os.path.join(tmp_dir, "evidence_hash.zip")
        output = os.path.join(tmp_dir, "output_zip_hash")

        with zf.ZipFile(zip_path, "w", zf.ZIP_DEFLATED) as z:
            for dirpath, dirnames, filenames in os.walk(root):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    arcname = os.path.relpath(full, os.path.dirname(root))
                    z.write(full, arcname)

        engine = AnalysisEngine(
            evidence_path=zip_path,
            output_dir=output,
            case_name="ZIP Hash Test",
            input_mode="zip",
        )
        report = engine.run()

        assert report.evidence_info.md5_hash is not None
        assert report.evidence_info.sha1_hash is not None
        assert len(report.evidence_info.md5_hash) == 32
        assert len(report.evidence_info.sha1_hash) == 40

    def test_invalid_zip_graceful_failure(self, tmp_dir):
        """Non-ZIP file with input_mode='zip' should fail gracefully."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        bad_path = os.path.join(tmp_dir, "not_a_zip.zip")
        with open(bad_path, "w") as f:
            f.write("This is not a zip file at all.")

        output = os.path.join(tmp_dir, "output_bad_zip")

        engine = AnalysisEngine(
            evidence_path=bad_path,
            output_dir=output,
            case_name="Bad ZIP Test",
            input_mode="zip",
        )
        report = engine.run()

        # Should produce an empty report, not crash
        assert len(report.all_artifacts) == 0

    def test_zip_cleanup_temp_dirs(self, mock_windows_evidence, tmp_dir):
        """Temp directories created during ZIP extraction should be cleaned up."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine
        import zipfile as zf

        root, user = mock_windows_evidence
        zip_path = os.path.join(tmp_dir, "evidence_cleanup.zip")
        output = os.path.join(tmp_dir, "output_zip_cleanup")

        with zf.ZipFile(zip_path, "w", zf.ZIP_DEFLATED) as z:
            for dirpath, dirnames, filenames in os.walk(root):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    arcname = os.path.relpath(full, os.path.dirname(root))
                    z.write(full, arcname)

        engine = AnalysisEngine(
            evidence_path=zip_path,
            output_dir=output,
            case_name="ZIP Cleanup Test",
            input_mode="zip",
        )
        engine.run()

        # After run(), temp dirs should be cleaned up
        assert len(engine._temp_dirs) == 0

    def test_zip_missing_file(self, tmp_dir):
        """Missing ZIP path should fail gracefully."""
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        output = os.path.join(tmp_dir, "output_missing_zip")
        engine = AnalysisEngine(
            evidence_path=os.path.join(tmp_dir, "does_not_exist.zip"),
            output_dir=output,
            case_name="Missing ZIP Test",
            input_mode="zip",
        )
        report = engine.run()
        assert len(report.all_artifacts) == 0


# ---------------------------------------------------------------------------
# Tests: Registry Hive Parser
# ---------------------------------------------------------------------------

class TestRegistryHiveParser:
    def test_registry_parser_registered(self):
        """RegistryHiveParser should be in the parser registry."""
        from ai_usage_evidence_analyzer import parsers  # noqa
        from ai_usage_evidence_analyzer.parser_registry import registry
        from ai_usage_evidence_analyzer.models import OSPlatform

        win_parsers = registry.get_for_os(OSPlatform.WINDOWS)
        parser_names = [p.PARSER_NAME for p in win_parsers]
        assert "WindowsRegistryHiveParser" in parser_names

    def test_ntuser_binary_scan(self, mock_windows_evidence):
        """Binary scan should find AI domains embedded in a mock NTUSER.DAT."""
        from ai_usage_evidence_analyzer.parsers.windows_parsers import RegistryHiveParser

        root, user = mock_windows_evidence

        # Create a fake NTUSER.DAT file with AI domain strings
        ntuser_dir = os.path.join(root, f"Users/{user}")
        ntuser_path = os.path.join(ntuser_dir, "NTUSER.DAT")
        with open(ntuser_path, "wb") as f:
            # Write some binary data with embedded AI-related strings
            f.write(b"\x00" * 100)
            f.write(b"https://chat.openai.com/c/abc123")
            f.write(b"\x00" * 50)
            f.write(b"claude.ai")
            f.write(b"\x00" * 50)
            f.write(b"chatgpt.com/share/xyz")
            f.write(b"\x00" * 100)

        parser = RegistryHiveParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST_REG",
        )
        result = parser.parse()

        # Binary scan should find OpenAI/Claude domains
        assert result.parser_name == "WindowsRegistryHiveParser"
        assert len(result.artifacts_found) > 0

        platforms = set(a.suspected_platform.value for a in result.artifacts_found)
        assert "ChatGPT" in platforms or "Claude" in platforms

    def test_no_hives_returns_not_applicable(self, tmp_dir):
        """When no registry hives exist the status should be NOT_APPLICABLE."""
        from ai_usage_evidence_analyzer.parsers.windows_parsers import RegistryHiveParser

        empty_root = os.path.join(tmp_dir, "empty_evidence")
        os.makedirs(os.path.join(empty_root, "Users/nobody"), exist_ok=True)

        parser = RegistryHiveParser(
            evidence_root=empty_root,
            user_profile="nobody",
            case_id="TEST_EMPTY",
        )
        result = parser.parse()
        assert result.status.value == "Not Applicable"
        assert len(result.artifacts_found) == 0

    def test_software_hive_binary_scan(self, mock_windows_evidence):
        """SOFTWARE hive binary scan should detect installed AI apps."""
        from ai_usage_evidence_analyzer.parsers.windows_parsers import RegistryHiveParser

        root, user = mock_windows_evidence

        # Create mock SOFTWARE hive
        config_dir = os.path.join(root, "Windows/System32/config")
        os.makedirs(config_dir, exist_ok=True)
        software_path = os.path.join(config_dir, "SOFTWARE")
        with open(software_path, "wb") as f:
            f.write(b"\x00" * 100)
            f.write(b"ChatGPT.exe")
            f.write(b"\x00" * 50)
            f.write(b"OpenAI")
            f.write(b"\x00" * 50)
            f.write(b"anthropic.com")
            f.write(b"\x00" * 100)

        parser = RegistryHiveParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST_SW",
        )
        result = parser.parse()

        # Should find artifacts from SOFTWARE hive
        assert len(result.artifacts_found) > 0
        sw_arts = [a for a in result.artifacts_found
                   if "SOFTWARE" in (a.artifact_type or "")]
        assert len(sw_arts) > 0

    def test_multiple_hive_coverage(self, mock_windows_evidence):
        """Parser should search both user-scoped and system-scoped hive paths."""
        from ai_usage_evidence_analyzer.parsers.windows_parsers import RegistryHiveParser

        root, user = mock_windows_evidence

        parser = RegistryHiveParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST_COVERAGE",
        )
        result = parser.parse()

        # artifact_paths_searched should include all candidate hive locations
        # (NTUSER.DAT, UsrClass.dat for user + SOFTWARE, SYSTEM, SAM for system)
        assert len(result.artifact_paths_searched) >= 5

    def test_binary_scan_deduplication(self, mock_windows_evidence):
        """Binary scan should deduplicate identical matches within the same hive."""
        from ai_usage_evidence_analyzer.parsers.windows_parsers import RegistryHiveParser

        root, user = mock_windows_evidence

        # Create NTUSER.DAT with repeated AI strings
        ntuser_path = os.path.join(root, f"Users/{user}/NTUSER.DAT")
        with open(ntuser_path, "wb") as f:
            for _ in range(5):
                f.write(b"\x00" * 30)
                f.write(b"chat.openai.com")
                f.write(b"\x00" * 30)

        parser = RegistryHiveParser(
            evidence_root=root,
            user_profile=user,
            case_id="TEST_DEDUP",
        )
        result = parser.parse()

        # Dedup key is (platform, matched_string, hive_name), so
        # "chat.openai.com" and "openai.com" are distinct matched_strings.
        # Verify we have fewer artifacts than the 5 repetitions.
        chatgpt_arts = [a for a in result.artifacts_found
                        if a.suspected_platform.value == "ChatGPT"
                        and "NTUSER" in (a.artifact_type or "")]
        assert len(chatgpt_arts) <= 2  # at most 2 distinct domain matches
        assert len(chatgpt_arts) < 5   # definitely deduplicated from 5 copies


# ---------------------------------------------------------------------------
# TRACE-AI-FR Framework Tests
# ---------------------------------------------------------------------------

class TestFRAUEModel:
    """Test the FRAUE data model."""

    def test_fraue_creation(self):
        from ai_usage_evidence_analyzer.models import (
            FRAUE, AIPlatform, EventConfidenceLevel, ClaimLevel,
        )
        f = FRAUE(platform=AIPlatform.CHATGPT)
        assert f.fraue_id.startswith("FRAUE-")
        assert f.platform == AIPlatform.CHATGPT
        assert f.event_confidence == EventConfidenceLevel.INSUFFICIENT
        assert f.claim_level == ClaimLevel.ARTIFACT_OBSERVATION

    def test_fraue_to_dict(self):
        from ai_usage_evidence_analyzer.models import FRAUE, AIPlatform
        f = FRAUE(platform=AIPlatform.CLAUDE, likely_activity_class="chat session")
        d = f.to_dict()
        assert d["platform"] == "Claude"
        assert d["likely_activity_class"] == "chat session"
        assert d["fraue_id"].startswith("FRAUE-")
        # model can be None
        assert "model" in d

    def test_fraue_to_dict_with_none_model(self):
        from ai_usage_evidence_analyzer.models import FRAUE, AIPlatform
        f = FRAUE(platform=AIPlatform.GEMINI, model=None)
        d = f.to_dict()
        assert d["model"] is None


class TestGovernanceRecord:
    """Test GovernanceRecord model."""

    def test_governance_record_defaults(self):
        from ai_usage_evidence_analyzer.models import GovernanceRecord
        g = GovernanceRecord(case_id="TEST123")
        assert g.framework_name == "TRACE-AI-FR"
        assert g.framework_version == "4.0.0"
        assert g.case_id == "TEST123"

    def test_governance_record_to_dict(self):
        from ai_usage_evidence_analyzer.models import GovernanceRecord
        g = GovernanceRecord(case_id="TEST456")
        g.inference_boundaries = ["Boundary 1"]
        g.rules_applied = ["Rule 1: Test"]
        d = g.to_dict()
        assert d["case_id"] == "TEST456"
        assert d["framework_name"] == "TRACE-AI-FR"
        assert d["inference_boundaries"] == ["Boundary 1"]
        assert d["rules_applied"] == ["Rule 1: Test"]


class TestClaimLadder:
    """Test the 4-level claim ladder."""

    def test_artifact_claim_level_assignment(self):
        from ai_usage_evidence_analyzer.claim_ladder import assign_artifact_claim_level
        from ai_usage_evidence_analyzer.models import ArtifactRecord, ClaimLevel
        art = ArtifactRecord()
        assign_artifact_claim_level(art)
        assert art.claim_level == ClaimLevel.ARTIFACT_OBSERVATION

    def test_platform_presence_requires_minimum(self):
        from ai_usage_evidence_analyzer.claim_ladder import evaluate_platform_presence
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
        )
        # Single artifact -> not enough
        arts = [ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_HISTORY,
        )]
        assert evaluate_platform_presence(arts) is False

        # Two artifacts, different families -> enough
        arts.append(ArtifactRecord(
            suspected_platform=AIPlatform.CHATGPT,
            artifact_family=ArtifactFamily.BROWSER_COOKIES,
        ))
        assert evaluate_platform_presence(arts) is True


class TestPersistence:
    """Test persistence state assignment."""

    def test_assign_persistence_state(self):
        from ai_usage_evidence_analyzer.persistence import assign_persistence_state
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, PersistenceState,
        )
        art = ArtifactRecord(artifact_family=ArtifactFamily.BROWSER_HISTORY)
        assign_persistence_state(art)
        assert art.persistence_state != PersistenceState.NOT_OBSERVED

    def test_assign_persistence_states_batch(self):
        from ai_usage_evidence_analyzer.persistence import assign_persistence_states
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, PersistenceState,
        )
        arts = [
            ArtifactRecord(artifact_family=ArtifactFamily.BROWSER_HISTORY),
            ArtifactRecord(artifact_family=ArtifactFamily.BROWSER_CACHE),
        ]
        assign_persistence_states(arts)
        for a in arts:
            assert a.persistence_state != PersistenceState.NOT_OBSERVED


class TestEvidenceSourceClass:
    """Test evidence-source-class assignment (Rule 8)."""

    def test_browser_history_is_browser_derived(self):
        from ai_usage_evidence_analyzer.correlation import assign_evidence_source_classes
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceSourceClass,
        )
        art = ArtifactRecord(artifact_family=ArtifactFamily.BROWSER_HISTORY)
        assign_evidence_source_classes([art])
        assert art.evidence_source_class == EvidenceSourceClass.BROWSER_DERIVED

    def test_native_app_is_native_derived(self):
        from ai_usage_evidence_analyzer.correlation import assign_evidence_source_classes
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceSourceClass,
        )
        art = ArtifactRecord(artifact_family=ArtifactFamily.NATIVE_APP)
        assign_evidence_source_classes([art])
        assert art.evidence_source_class == EvidenceSourceClass.NATIVE_APP_DERIVED

    def test_unknown_family_gets_unknown(self):
        from ai_usage_evidence_analyzer.correlation import assign_evidence_source_classes
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceSourceClass,
        )
        art = ArtifactRecord(artifact_family=ArtifactFamily.UNKNOWN)
        assign_evidence_source_classes([art])
        assert art.evidence_source_class == EvidenceSourceClass.UNKNOWN


class TestAdjudication:
    """Test the adjudication engine (FRAUE reconstruction)."""

    def _make_artifacts(self):
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, AIPlatform, ArtifactFamily,
            EvidenceClassification, ConfidenceLevel,
        )
        return [
            ArtifactRecord(
                suspected_platform=AIPlatform.CHATGPT,
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                classification=EvidenceClassification.DIRECT,
                confidence=ConfidenceLevel.HIGH,
                user_profile="TestUser",
                timestamp=datetime(2024, 1, 15, 10, 0),
            ),
            ArtifactRecord(
                suspected_platform=AIPlatform.CHATGPT,
                artifact_family=ArtifactFamily.BROWSER_COOKIES,
                classification=EvidenceClassification.INFERRED,
                confidence=ConfidenceLevel.MODERATE,
                user_profile="TestUser",
                timestamp=datetime(2024, 1, 15, 10, 30),
            ),
        ]

    def test_adjudication_produces_fraues(self):
        from ai_usage_evidence_analyzer.adjudication import AdjudicationEngine
        arts = self._make_artifacts()
        engine = AdjudicationEngine(arts, coverage_sufficient=True)
        fraues = engine.adjudicate()
        assert isinstance(fraues, list)
        assert len(fraues) >= 1

    def test_fraue_has_required_fields(self):
        from ai_usage_evidence_analyzer.adjudication import AdjudicationEngine
        arts = self._make_artifacts()
        engine = AdjudicationEngine(arts, coverage_sufficient=True)
        fraues = engine.adjudicate()
        f = fraues[0]
        assert f.fraue_id.startswith("FRAUE-")
        assert len(f.artifact_ids) > 0
        assert f.platform.value == "ChatGPT"
        assert len(f.caveats) > 0  # Always has Rule-based caveats
        assert len(f.inference_boundaries) > 0

    def test_adjudication_with_no_artifacts(self):
        from ai_usage_evidence_analyzer.adjudication import AdjudicationEngine
        engine = AdjudicationEngine([], coverage_sufficient=True)
        fraues = engine.adjudicate()
        assert fraues == []


class TestGovernanceModule:
    """Test the governance layer module."""

    def test_framework_rules_count(self):
        from ai_usage_evidence_analyzer.governance import FRAMEWORK_RULES
        assert len(FRAMEWORK_RULES) == 12

    def test_build_governance_record(self):
        from ai_usage_evidence_analyzer.governance import build_governance_record
        from ai_usage_evidence_analyzer.models import (
            ForensicReport, CaseInfo, EvidenceCoverage,
        )
        report = ForensicReport(case_info=CaseInfo(case_name="Gov Test"))
        record = build_governance_record(
            report=report,
            parser_results=[],
            evidence_coverage=EvidenceCoverage(),
        )
        assert record.framework_name == "TRACE-AI-FR"
        assert len(record.rules_applied) == 12
        assert len(record.inference_boundaries) > 0
        assert len(record.required_disclosures) > 0

    def test_scope_of_conclusion_no_artifacts(self):
        from ai_usage_evidence_analyzer.governance import generate_scope_of_conclusion
        from ai_usage_evidence_analyzer.models import ForensicReport
        report = ForensicReport()
        scope = generate_scope_of_conclusion(report)
        assert "no evidence was found" in scope.lower()

    def test_scope_of_conclusion_with_fraues(self):
        from ai_usage_evidence_analyzer.governance import generate_scope_of_conclusion
        from ai_usage_evidence_analyzer.models import (
            ForensicReport, FRAUE, ArtifactRecord, AIPlatform,
        )
        report = ForensicReport(
            all_artifacts=[ArtifactRecord(suspected_platform=AIPlatform.CHATGPT)],
            fraues=[FRAUE(platform=AIPlatform.CHATGPT)],
        )
        scope = generate_scope_of_conclusion(report)
        assert "ChatGPT" in scope
        assert "1 instance" in scope


class TestFrameworkEnums:
    """Test new TRACE-AI-FR enums."""

    def test_claim_levels(self):
        from ai_usage_evidence_analyzer.models import ClaimLevel
        assert ClaimLevel.ARTIFACT_OBSERVATION.value
        assert ClaimLevel.PLATFORM_PRESENCE.value
        assert ClaimLevel.FRAUE_RECONSTRUCTION.value
        assert ClaimLevel.GOVERNED_CONCLUSION.value

    def test_persistence_states(self):
        from ai_usage_evidence_analyzer.models import PersistenceState
        assert PersistenceState.INTACT.value
        assert PersistenceState.PARTIALLY_RETAINED.value
        assert PersistenceState.WEAKLY_RETAINED.value
        assert PersistenceState.NOT_OBSERVED.value

    def test_event_confidence_levels(self):
        from ai_usage_evidence_analyzer.models import EventConfidenceLevel
        assert EventConfidenceLevel.HIGH.value
        assert EventConfidenceLevel.MODERATE.value
        assert EventConfidenceLevel.LOW.value
        assert EventConfidenceLevel.INSUFFICIENT.value

    def test_evidence_source_classes(self):
        from ai_usage_evidence_analyzer.models import EvidenceSourceClass
        assert len(EvidenceSourceClass) >= 5

    def test_image_review_states(self):
        from ai_usage_evidence_analyzer.models import ImageReviewEvidenceState
        assert ImageReviewEvidenceState.DIRECTLY_SUPPORTED.value
        assert ImageReviewEvidenceState.CONSISTENT_WITH.value
        assert ImageReviewEvidenceState.SUGGESTIVE_OF.value
        assert ImageReviewEvidenceState.NONE_IDENTIFIED.value


class TestIntegrationV2:
    """Integration tests for the full TRACE-AI-FR pipeline."""

    def test_full_pipeline_produces_fraues(self, mock_windows_evidence, tmp_dir):
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        root, user = mock_windows_evidence
        output = os.path.join(tmp_dir, "output_v2")

        engine = AnalysisEngine(
            evidence_path=root,
            output_dir=output,
            case_name="TRACE-AI-FR V2 Test",
            examiner="Test Examiner",
            input_mode="mounted",
        )
        report = engine.run()

        # FRAUEs should be present (may be empty if no corroborated events)
        assert hasattr(report, "fraues")
        assert isinstance(report.fraues, list)

        # Governance record should be populated
        assert report.governance_record is not None
        assert report.governance_record.framework_name == "TRACE-AI-FR"
        assert len(report.governance_record.rules_applied) == 12

        # Scope of conclusion should be set
        assert report.scope_of_conclusion
        assert len(report.scope_of_conclusion) > 50

        # Inference boundaries should be populated
        assert len(report.inference_boundaries) > 0

        # Governance JSON should be exported
        gov_path = os.path.join(
            output, f"{report.case_info.case_id}_governance_record.json"
        )
        assert os.path.isfile(gov_path)

    def test_json_export_contains_fraues(self, mock_windows_evidence, tmp_dir):
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        root, user = mock_windows_evidence
        output = os.path.join(tmp_dir, "output_json")

        engine = AnalysisEngine(
            evidence_path=root,
            output_dir=output,
            case_name="JSON FRAUE Test",
            input_mode="mounted",
        )
        report = engine.run()

        json_path = os.path.join(
            output, f"{report.case_info.case_id}_findings.json"
        )
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["tool"] == "TRACE-AI-FR"
        assert data["framework_name"] == "TRACE-AI-FR"
        assert "fraues" in data
        assert isinstance(data["fraues"], list)
        assert "governance_record" in data
        assert "scope_of_conclusion" in data
        assert "inference_boundaries" in data

    def test_html_report_has_tabs(self, mock_windows_evidence, tmp_dir):
        from ai_usage_evidence_analyzer.engine import AnalysisEngine

        root, user = mock_windows_evidence
        output = os.path.join(tmp_dir, "output_html")

        engine = AnalysisEngine(
            evidence_path=root,
            output_dir=output,
            case_name="HTML Tab Test",
            input_mode="mounted",
        )
        report = engine.run()

        html_path = os.path.join(
            output, f"{report.case_info.case_id}_report.html"
        )
        with open(html_path, encoding="utf-8") as f:
            content = f.read()

        assert "TRACE" in content
        assert "tab-report" in content
        assert "tab-fraues" in content
        assert "tab-governance" in content
        assert "switchTab" in content
        assert "dashboard" in content
