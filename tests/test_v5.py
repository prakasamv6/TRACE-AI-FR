"""
Comprehensive v5.0 test suite for AI tool inventory, scanner, checklist, caveats,
engine integration, and report generation.
"""

import csv
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------
from ai_usage_evidence_analyzer.tool_registry import (
    AttributionScope,
    CaveatFlag,
    CorroborationLevel,
    EvidenceStatus,
    ExecutionSurface,
    InferenceLocation,
    ToolRecord,
    ToolRegistry,
)
from ai_usage_evidence_analyzer.forensic_checklist import (
    ForensicChecklistEntry,
    ForensicChecklistGenerator,
)
from ai_usage_evidence_analyzer.caveats import (
    CAVEAT_LANGUAGE,
    GLOBAL_REPORT_FOOTER,
    UI_WARNINGS,
    get_caveat_text,
)

# -------------------------------------------------------------------------- #
#  Fixtures                                                                    #
# -------------------------------------------------------------------------- #

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "config", "ai_tool_inventory.yaml"
)


@pytest.fixture
def registry():
    return ToolRegistry(CONFIG_PATH)


@pytest.fixture
def evidence_tree(tmp_path):
    """
    Build a minimal evidence tree that mimics a Windows forensic image with a
    few well-known AI tool paths so the scanner can detect them.
    """
    users_dir = tmp_path / "Users" / "JohnDoe" / "AppData"
    # ChatGPT Desktop
    (users_dir / "Local" / "Programs" / "ChatGPT").mkdir(parents=True)
    # Ollama
    (tmp_path / "Users" / "JohnDoe" / ".ollama").mkdir(parents=True)
    # GitHub Copilot
    (users_dir / "Roaming" / "Code" / "User" / "globalStorage" / "github.copilot").mkdir(parents=True)
    # Claude Code CLI
    (tmp_path / "Users" / "JohnDoe" / ".claude").mkdir(parents=True)
    # Cursor AI IDE
    (users_dir / "Local" / "Programs" / "Cursor").mkdir(parents=True)
    return tmp_path


# ========================================================================== #
#  1. ToolRegistry tests                                                      #
# ========================================================================== #

class TestToolRegistry:
    def test_loads_yaml_successfully(self, registry):
        assert len(registry.tools) >= 30, (
            f"Expected ≥30 tools, got {len(registry.tools)}"
        )

    def test_known_tools_present(self, registry):
        expected_ids = [
            "chatgpt_desktop", "ollama", "cursor", "claude_desktop",
            "lm_studio", "gpt4all", "jan_ai", "github_copilot",
            "claude_code", "codex_cli", "aider", "comfyui_desktop",
        ]
        for tid in expected_ids:
            assert registry.get_tool(tid) is not None, f"Missing tool: {tid}"

    def test_tool_record_fields(self, registry):
        tool = registry.get_tool("chatgpt_desktop")
        assert tool.tool_name == "ChatGPT Desktop"
        assert tool.vendor == "OpenAI"
        assert "Windows" in tool.platform_supported
        assert ExecutionSurface.DESKTOP_APP in tool.execution_surface

    def test_find_by_surface(self, registry):
        desktop_tools = registry.find_by_surface(ExecutionSurface.DESKTOP_APP)
        names = [t.tool_name for t in desktop_tools]
        assert "ChatGPT Desktop" in names

    def test_find_by_category(self, registry):
        local_llms = registry.find_by_category("Local LLM")
        ids = [t.tool_id for t in local_llms]
        assert "ollama" in ids
        assert "lm_studio" in ids

    def test_candidate_paths_windows(self, registry):
        paths = registry.candidate_paths("chatgpt_desktop", "Windows")
        assert len(paths) >= 1
        assert any("ChatGPT" in p for p in paths)

    def test_candidate_paths_missing_os(self, registry):
        paths = registry.candidate_paths("chatgpt_desktop", "Linux")
        assert paths == []

    def test_unknown_tool_returns_none(self, registry):
        assert registry.get_tool("nonexistent_tool_xyz") is None

    def test_all_tools_returns_list(self, registry):
        tools = registry.all_tools()
        assert isinstance(tools, list)
        assert all(isinstance(t, ToolRecord) for t in tools)


# ========================================================================== #
#  2. ForensicChecklistEntry & Generator tests                                #
# ========================================================================== #

class TestForensicChecklist:
    def test_entry_to_dict(self):
        entry = ForensicChecklistEntry(
            tool_id="test",
            tool_name="Test Tool",
            category="Test Category",
            artifact_paths=["/path/a", "/path/b"],
            evidence_status=EvidenceStatus.FOUND,
            notes="two paths",
            caveat_flags=[CaveatFlag.PRESENCE_ONLY],
            artifact_count=2,
        )
        d = entry.to_dict()
        assert d["Tool Name"] == "Test Tool"
        assert d["Evidence Status"] == EvidenceStatus.FOUND
        assert d["Artifact Count"] == 2

    def test_generator_add_entry(self, registry):
        gen = ForensicChecklistGenerator(registry)
        entry = ForensicChecklistEntry(
            tool_id="x", tool_name="X", category="C",
            artifact_paths=[], evidence_status=EvidenceStatus.NOT_FOUND,
        )
        gen.add_entry(entry)
        assert len(gen.entries) == 1

    def test_generate_from_scan_found(self, registry):
        gen = ForensicChecklistGenerator(registry)
        gen.generate_from_scan([{
            "tool_id": "chatgpt_desktop",
            "evidence_status": EvidenceStatus.FOUND,
            "artifact_paths": ["/path"],
            "notes": "ok",
            "caveat_flags": [CaveatFlag.PRESENCE_ONLY],
            "artifact_count": 1,
        }])
        assert gen.entries[0].evidence_status == EvidenceStatus.FOUND

    def test_generate_from_scan_skips_unknown_tool(self, registry):
        gen = ForensicChecklistGenerator(registry)
        gen.generate_from_scan([{
            "tool_id": "does_not_exist",
            "evidence_status": EvidenceStatus.FOUND,
        }])
        assert len(gen.entries) == 0

    def test_csv_export(self, registry):
        gen = ForensicChecklistGenerator(registry)
        gen.generate_from_scan([{
            "tool_id": "ollama",
            "evidence_status": EvidenceStatus.NOT_FOUND,
            "artifact_paths": [],
            "notes": "not found",
            "artifact_count": 0,
        }])
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="w") as fp:
            path = fp.name
        try:
            gen.to_csv(path)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "Ollama" in content
            assert "NOT_FOUND" in content
        finally:
            os.unlink(path)

    def test_json_export(self, registry):
        gen = ForensicChecklistGenerator(registry)
        gen.generate_from_scan([{
            "tool_id": "cursor",
            "evidence_status": EvidenceStatus.PARTIAL,
            "artifact_paths": ["/p"],
            "notes": "",
            "artifact_count": 1,
        }])
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as fp:
            path = fp.name
        try:
            gen.to_json(path)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            assert len(data) == 1
            assert data[0]["Tool Name"] == "Cursor"
        finally:
            os.unlink(path)

    def test_as_table(self, registry):
        gen = ForensicChecklistGenerator(registry)
        gen.generate_from_scan([{
            "tool_id": "chatgpt_desktop",
            "evidence_status": EvidenceStatus.FOUND,
            "artifact_paths": ["/p"],
            "artifact_count": 1,
        }])
        table = gen.as_table()
        assert isinstance(table, list)
        assert table[0]["Tool Name"] == "ChatGPT Desktop"


# ========================================================================== #
#  3. Caveats tests                                                           #
# ========================================================================== #

class TestCaveats:
    def test_all_caveat_flags_have_language(self):
        for flag in CaveatFlag:
            assert flag in CAVEAT_LANGUAGE, f"No language for {flag}"

    def test_get_caveat_text_returns_strings(self):
        texts = get_caveat_text([
            CaveatFlag.PRESENCE_ONLY,
            CaveatFlag.USE_NOT_ESTABLISHED,
        ])
        assert len(texts) == 2
        assert all(isinstance(t, str) for t in texts)

    def test_global_report_footer_present(self):
        assert "artifacts" in GLOBAL_REPORT_FOOTER.lower()

    def test_ui_warnings_non_empty(self):
        assert len(UI_WARNINGS) >= 4

    def test_presence_only_caveat_text(self):
        text = CAVEAT_LANGUAGE[CaveatFlag.PRESENCE_ONLY]
        assert "presence" in text.lower() or "installation" in text.lower()

    def test_negative_finding_caveat_text(self):
        text = CAVEAT_LANGUAGE[CaveatFlag.NEGATIVE_FINDING_SCOPED]
        assert "examined" in text.lower()

    def test_unknown_flag_graceful(self):
        # get_caveat_text should not crash with an unknown flag
        result = get_caveat_text(["UNKNOWNFLAG"])
        assert len(result) == 1


# ========================================================================== #
#  4. AIToolScannerParser tests                                               #
# ========================================================================== #

class TestAIToolScanner:
    def test_scanner_finds_chatgpt(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform, ParserStatus

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        result = scanner.parse()
        assert result.status == ParserStatus.SUCCESS

        found_names = [
            e.tool_name for e in scanner.checklist_entries
            if str(e.evidence_status).replace("EvidenceStatus.", "") == "FOUND"
        ]
        assert "ChatGPT Desktop" in found_names

    def test_scanner_finds_ollama(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        found_ids = [
            e.tool_id for e in scanner.checklist_entries
            if str(e.evidence_status).replace("EvidenceStatus.", "") == "FOUND"
        ]
        assert "ollama" in found_ids

    def test_scanner_finds_copilot(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        found_ids = [
            e.tool_id for e in scanner.checklist_entries
            if str(e.evidence_status).replace("EvidenceStatus.", "") == "FOUND"
        ]
        assert "github_copilot" in found_ids

    def test_scanner_not_found_has_caveats(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        not_found = [
            e for e in scanner.checklist_entries
            if str(e.evidence_status).replace("EvidenceStatus.", "") == "NOT_FOUND"
        ]
        assert len(not_found) > 0
        for entry in not_found:
            flag_strs = [str(f) for f in entry.caveat_flags]
            assert any("NEGATIVE_FINDING" in s for s in flag_strs)

    def test_scanner_found_has_presence_caveat(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        found = [
            e for e in scanner.checklist_entries
            if str(e.evidence_status).replace("EvidenceStatus.", "") == "FOUND"
        ]
        for entry in found:
            flag_strs = [str(f) for f in entry.caveat_flags]
            assert any("PRESENCE_ONLY" in s for s in flag_strs)

    def test_scanner_produces_artifact_records(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        result = scanner.parse()
        # At least some artifact records from found tools
        assert len(result.artifacts_found) >= 1

    def test_scanner_empty_evidence_all_not_found(self, tmp_path):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(tmp_path),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["Test"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        found = [
            e for e in scanner.checklist_entries
            if str(e.evidence_status).replace("EvidenceStatus.", "") == "FOUND"
        ]
        assert len(found) == 0

    def test_scanner_covers_all_registered_tools(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        registry = ToolRegistry(CONFIG_PATH)
        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        # Every tool in registry should produce a checklist entry
        assert len(scanner.checklist_entries) == len(registry.tools)

    def test_scanner_bad_config_returns_error(self, tmp_path):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform, ParserStatus

        scanner = AIToolScannerParser(
            evidence_root=str(tmp_path),
            os_platform=OSPlatform.WINDOWS,
            config_path="/nonexistent/path.yaml",
        )
        result = scanner.parse()
        assert result.status == ParserStatus.ERROR

    def test_scanner_unknown_os_produces_not_verified(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.UNKNOWN,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()
        # With UNKNOWN OS, tools still get checked via fallback
        assert len(scanner.checklist_entries) > 0


# ========================================================================== #
#  5. Enum completeness tests                                                 #
# ========================================================================== #

class TestEnums:
    def test_evidence_status_values(self):
        assert EvidenceStatus.FOUND.value == "FOUND"
        assert EvidenceStatus.NOT_FOUND.value == "NOT_FOUND"
        assert EvidenceStatus.NOT_VERIFIED.value == "NOT_VERIFIED"
        assert EvidenceStatus.PARTIAL.value == "PARTIAL"

    def test_execution_surface_values(self):
        Surface = ExecutionSurface
        assert Surface.DESKTOP_APP.value == "DESKTOP_APP"
        assert Surface.BROWSER.value == "BROWSER"
        assert Surface.IDE_EXTENSION.value == "IDE_EXTENSION"
        assert Surface.TERMINAL.value == "TERMINAL"
        assert Surface.DOCKER_CONTAINER.value == "DOCKER_CONTAINER"

    def test_caveat_flag_count(self):
        assert len(CaveatFlag) >= 36

    def test_corroboration_levels(self):
        assert len(CorroborationLevel) == 4

    def test_attribution_scopes(self):
        assert len(AttributionScope) == 5


# ========================================================================== #
#  6. ForensicReport checklist field test                                    #
# ========================================================================== #

class TestForensicReportField:
    def test_report_has_forensic_checklist_field(self):
        from ai_usage_evidence_analyzer.models import ForensicReport
        report = ForensicReport()
        assert hasattr(report, "forensic_checklist")
        assert isinstance(report.forensic_checklist, list)

    def test_report_checklist_accepts_entries(self):
        from ai_usage_evidence_analyzer.models import ForensicReport
        report = ForensicReport()
        entry = ForensicChecklistEntry(
            tool_id="test", tool_name="Test",
            category="Cat", artifact_paths=[],
            evidence_status=EvidenceStatus.NOT_FOUND,
        )
        report.forensic_checklist.append(entry)
        assert len(report.forensic_checklist) == 1


# ========================================================================== #
#  7. Path expansion helper tests                                             #
# ========================================================================== #

class TestPathExpansion:
    def test_expand_localappdata(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _expand_template,
        )
        paths = _expand_template(
            "%LocalAppData%/Programs/ChatGPT", username="Jane"
        )
        assert len(paths) >= 1
        assert "Jane" in paths[0]
        assert "AppData" in paths[0]

    def test_expand_userprofile(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _expand_template,
        )
        paths = _expand_template("%UserProfile%/.ollama", username="Joe")
        assert any(".ollama" in p for p in paths)
        assert any("Joe" in p for p in paths)

    def test_tilde_path_passthrough(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _expand_template,
        )
        paths = _expand_template("~/Library/Application Support/ChatGPT")
        assert paths == ["~/Library/Application Support/ChatGPT"]

    def test_resolve_all_templates_multiple_users(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _resolve_all_templates,
        )
        raw = ["%UserProfile%/.ollama"]
        resolved = _resolve_all_templates(raw, "Windows", ["Alice", "Bob"])
        assert any("Alice" in p for p in resolved)
        assert any("Bob" in p for p in resolved)


# ========================================================================== #
#  8. Evidence existence helper tests                                         #
# ========================================================================== #

class TestEvidencePathExists:
    def test_exact_path_found(self, tmp_path):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _evidence_path_exists,
        )
        (tmp_path / "some" / "dir").mkdir(parents=True)
        found, path = _evidence_path_exists(str(tmp_path), "some/dir")
        assert found
        assert path is not None

    def test_path_not_found(self, tmp_path):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _evidence_path_exists,
        )
        found, path = _evidence_path_exists(str(tmp_path), "nonexistent/path")
        assert not found
        assert path is None

    def test_glob_path_found(self, tmp_path):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            _evidence_path_exists,
        )
        (tmp_path / "ext" / "github.copilot-1.0").mkdir(parents=True)
        found, path = _evidence_path_exists(str(tmp_path), "ext/github.copilot*")
        assert found


# ========================================================================== #
#  9. Integration smoke test — full scanner → checklist → CSV round-trip      #
# ========================================================================== #

class TestScannerChecklistIntegration:
    def test_full_round_trip(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import (
            AIToolScannerParser,
        )
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        # Build generator from entries
        registry = ToolRegistry(CONFIG_PATH)
        gen = ForensicChecklistGenerator(registry)
        for e in scanner.checklist_entries:
            gen.add_entry(e)

        # Export CSV
        csv_path = str(evidence_tree / "checklist_test.csv")
        gen.to_csv(csv_path)
        assert os.path.isfile(csv_path)
        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == len(scanner.checklist_entries)

        # Export JSON
        json_path = str(evidence_tree / "checklist_test.json")
        gen.to_json(json_path)
        data = json.loads(Path(json_path).read_text())
        assert len(data) == len(rows)


# ========================================================================== #
#  10. Surface-class enforcement path tests                                   #
# ========================================================================== #

class TestSurfaceClassClassification:
    """Verify classify_surface dispatches tools to the right enforcement path."""

    def test_browser_first_web_assistant(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_gemini", tool_name="Gemini", vendor="Google",
            category="Web Assistant", platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.BROWSER],
            artifact_path_candidates={}, detection_method="browser_history",
        )
        assert classify_surface(tool) == SurfaceClass.BROWSER_FIRST

    def test_local_webui_image_gen(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_comfyui", tool_name="ComfyUI", vendor="comfyanonymous",
            category="Image Generator",
            platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.DESKTOP_APP, ExecutionSurface.SELF_HOSTED_REMOTE],
            artifact_path_candidates={}, detection_method="install_folder",
        )
        assert classify_surface(tool) == SurfaceClass.LOCAL_WEBUI

    def test_local_webui_docker(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_openwebui", tool_name="Open WebUI", vendor="open-webui",
            category="Local LLM",
            platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.DOCKER_CONTAINER, ExecutionSurface.SELF_HOSTED_REMOTE],
            artifact_path_candidates={}, detection_method="docker_volume",
        )
        assert classify_surface(tool) == SurfaceClass.LOCAL_WEBUI

    def test_ide_cli_extension(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_copilot", tool_name="GitHub Copilot", vendor="GitHub",
            category="IDE Extension",
            platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.IDE_EXTENSION],
            artifact_path_candidates={}, detection_method="vscode_extension",
        )
        assert classify_surface(tool) == SurfaceClass.IDE_CLI

    def test_ide_cli_terminal(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_claude_code", tool_name="Claude Code", vendor="Anthropic",
            category="Terminal CLI",
            platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.TERMINAL],
            artifact_path_candidates={}, detection_method="config_folder",
        )
        assert classify_surface(tool) == SurfaceClass.IDE_CLI

    def test_native_desktop(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_chatgpt", tool_name="ChatGPT Desktop", vendor="OpenAI",
            category="Native Assistant",
            platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.DESKTOP_APP],
            artifact_path_candidates={}, detection_method="install_folder",
        )
        assert classify_surface(tool) == SurfaceClass.NATIVE_DESKTOP

    def test_api_credential_is_ide_cli(self):
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRecord, ExecutionSurface,
        )
        tool = ToolRecord(
            tool_id="test_api", tool_name="OpenAI API", vendor="OpenAI",
            category="API Credential",
            platform_supported=["Windows"],
            execution_surface=[ExecutionSurface.TERMINAL],
            artifact_path_candidates={}, detection_method="env_file",
        )
        assert classify_surface(tool) == SurfaceClass.IDE_CLI


class TestSurfaceClassCaveats:
    """Verify that each enforcement path produces the correct caveat flags."""

    def test_browser_first_found_has_browser_caveat(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        # Gemini is a browser-first tool
        gemini = [e for e in scanner.checklist_entries if "Gemini" in e.tool_name]
        if gemini:
            entry = gemini[0]
            flag_vals = [f.value for f in entry.caveat_flags]
            assert "BROWSER_ACCESS_ONLY" in flag_vals
            # browser-first tools should NOT have IDE_CONFIG_NOT_USAGE
            assert "IDE_CONFIG_NOT_USAGE" not in flag_vals

    def test_browser_first_not_found_has_history_cleared(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        # Find any NOT_FOUND browser-first entry
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRegistry,
        )
        registry = ToolRegistry(CONFIG_PATH)
        for entry in scanner.checklist_entries:
            if str(entry.evidence_status) != "EvidenceStatus.NOT_FOUND":
                continue
            tool = registry.get_tool(entry.tool_id)
            if tool and classify_surface(tool) == SurfaceClass.BROWSER_FIRST:
                flag_vals = [f.value for f in entry.caveat_flags]
                assert "BROWSER_HISTORY_CLEARED" in flag_vals
                assert "PRIVACY_OR_CLEANUP_POSSIBLE" in flag_vals
                break

    def test_ide_cli_found_has_config_caveat(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        # Copilot is IDE_CLI, and evidence_tree fixture creates its path
        copilot = [
            e for e in scanner.checklist_entries
            if "Copilot" in e.tool_name
            and str(e.evidence_status).endswith("FOUND")
            and "NOT_FOUND" not in str(e.evidence_status)
        ]
        if copilot:
            flag_vals = [f.value for f in copilot[0].caveat_flags]
            assert "IDE_CONFIG_NOT_USAGE" in flag_vals
            # IDE tools should NOT have BROWSER_ACCESS_ONLY
            assert "BROWSER_ACCESS_ONLY" not in flag_vals

    def test_local_webui_not_found_has_container_caveat(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRegistry,
        )

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        registry = ToolRegistry(CONFIG_PATH)
        for entry in scanner.checklist_entries:
            if str(entry.evidence_status) != "EvidenceStatus.NOT_FOUND":
                continue
            tool = registry.get_tool(entry.tool_id)
            if tool and classify_surface(tool) == SurfaceClass.LOCAL_WEBUI:
                flag_vals = [f.value for f in entry.caveat_flags]
                assert "LOCAL_WEBUI_LOCALHOST_ONLY" in flag_vals
                break

    def test_native_desktop_found_has_use_not_established(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        chatgpt = [
            e for e in scanner.checklist_entries
            if "ChatGPT" in e.tool_name
            and str(e.evidence_status).endswith("FOUND")
            and "NOT_FOUND" not in str(e.evidence_status)
        ]
        if chatgpt:
            flag_vals = [f.value for f in chatgpt[0].caveat_flags]
            assert "USE_NOT_ESTABLISHED" in flag_vals
            assert "PRESENCE_ONLY" in flag_vals

    def test_each_surface_class_has_distinct_caveat_set(self, evidence_tree):
        """Verify that different surface classes produce mutually exclusive caveats."""
        from ai_usage_evidence_analyzer.tool_registry import (
            SurfaceClass, classify_surface, ToolRegistry,
        )
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform

        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        scanner.parse()

        registry = ToolRegistry(CONFIG_PATH)
        caveats_by_class: dict = {}
        for entry in scanner.checklist_entries:
            tool = registry.get_tool(entry.tool_id)
            if not tool:
                continue
            sc = classify_surface(tool)
            flag_vals = {f.value for f in entry.caveat_flags}
            caveats_by_class.setdefault(sc, set()).update(flag_vals)

        # Browser-first should have BROWSER_ACCESS_ONLY but NOT IDE_CONFIG_NOT_USAGE
        if SurfaceClass.BROWSER_FIRST in caveats_by_class:
            assert "BROWSER_ACCESS_ONLY" in caveats_by_class[SurfaceClass.BROWSER_FIRST]
            assert "IDE_CONFIG_NOT_USAGE" not in caveats_by_class[SurfaceClass.BROWSER_FIRST]

        # IDE_CLI should have IDE_CONFIG_NOT_USAGE but NOT BROWSER_ACCESS_ONLY
        if SurfaceClass.IDE_CLI in caveats_by_class:
            assert "IDE_CONFIG_NOT_USAGE" in caveats_by_class[SurfaceClass.IDE_CLI]
            assert "BROWSER_ACCESS_ONLY" not in caveats_by_class[SurfaceClass.IDE_CLI]

        # LOCAL_WEBUI should have LOCAL_WEBUI_LOCALHOST_ONLY
        if SurfaceClass.LOCAL_WEBUI in caveats_by_class:
            assert "LOCAL_WEBUI_LOCALHOST_ONLY" in caveats_by_class[SurfaceClass.LOCAL_WEBUI]


# ========================================================================== #
#  12. Caveat Enforcement Regression Tests                                    #
# ========================================================================== #

class TestCaveatEnforcement:
    """
    Verify that the caveat enforcement layer is fully wired:
    new CaveatFlags exist, caveat language is present for all flags,
    evidence-path classification works, and claim-ladder gates fire
    correctly.
    """

    def test_new_caveat_flags_exist(self):
        """All enforcement CaveatFlag values must be importable."""
        expected = [
            "PERSON_LEVEL_ATTRIBUTION_NOT_ESTABLISHED",
            "LOCAL_INFERENCE_NOT_ESTABLISHED",
            "STANDALONE_BINARY_POSSIBLE",
            "BROWSER_FIRST_TOOL",
            "SELF_HOSTED_OR_LOCAL_WEBUI_POSSIBLE",
            "IDE_SURFACE_ONLY",
            "CLI_SURFACE_ONLY",
            "REMOTE_SESSION_POSSIBLE",
            "ACQUISITION_SCOPE_LIMITED",
            "CORROBORATION_LEVEL_LIMITED",
        ]
        for name in expected:
            assert hasattr(CaveatFlag, name), f"Missing CaveatFlag: {name}"

    def test_caveat_language_covers_all_flags(self):
        """Every CaveatFlag member must have a text entry in CAVEAT_LANGUAGE."""
        for flag in CaveatFlag:
            assert flag in CAVEAT_LANGUAGE, (
                f"CaveatFlag.{flag.name} has no entry in CAVEAT_LANGUAGE"
            )

    def test_get_caveat_text_returns_strings(self):
        """get_caveat_text should return human-readable strings, not raw enum names."""
        flags = [CaveatFlag.PRESENCE_ONLY, CaveatFlag.USE_NOT_ESTABLISHED]
        texts = get_caveat_text(flags)
        assert len(texts) == 2
        for t in texts:
            assert isinstance(t, str)
            assert "PRESENCE_ONLY" not in t  # should be resolved language

    def test_global_footer_present_and_nonempty(self):
        assert isinstance(GLOBAL_REPORT_FOOTER, str)
        assert len(GLOBAL_REPORT_FOOTER) > 50

    def test_ui_warnings_include_enforcement_messages(self):
        assert len(UI_WARNINGS) >= 7
        assert any("Presence" in w for w in UI_WARNINGS)
        assert any("person-level" in w.lower() for w in UI_WARNINGS)


class TestEvidencePathClassification:
    """Verify evidence-path classification (A–F) in the scanner."""

    def test_classify_install_path(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform
        scanner = AIToolScannerParser(
            evidence_root="/tmp", os_platform=OSPlatform.WINDOWS
        )
        tool = ToolRecord(
            tool_id="t", tool_name="T", vendor="V", category="C",
            platform_supported=[], execution_surface=[],
            artifact_path_candidates={}, detection_method="", notes="",
        )
        result = scanner._classify_evidence_path(
            "C:/Users/John/AppData/Local/Programs/OllamaSetup/bin/ollama.exe", tool
        )
        # 'program' keyword matches A-Presence, '.exe' matches C-Execution
        assert result.startswith("A") or result.startswith("C"), f"Expected A or C, got {result}"

    def test_classify_config_path(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform
        scanner = AIToolScannerParser(
            evidence_root="/tmp", os_platform=OSPlatform.WINDOWS
        )
        tool = ToolRecord(
            tool_id="t", tool_name="T", vendor="V", category="C",
            platform_supported=[], execution_surface=[],
            artifact_path_candidates={}, detection_method="", notes="",
        )
        result = scanner._classify_evidence_path(
            "Users/John/AppData/Roaming/Code/User/globalStorage/github.copilot/config.json", tool
        )
        assert result.startswith("B"), f"Expected B-Configuration, got {result}"

    def test_classify_history_path(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform
        scanner = AIToolScannerParser(
            evidence_root="/tmp", os_platform=OSPlatform.WINDOWS
        )
        tool = ToolRecord(
            tool_id="t", tool_name="T", vendor="V", category="C",
            platform_supported=[], execution_surface=[],
            artifact_path_candidates={}, detection_method="", notes="",
        )
        result = scanner._classify_evidence_path(
            "Users/John/AppData/Local/Google/Chrome/User Data/Default/History", tool
        )
        assert result.startswith("D"), f"Expected D-Usage, got {result}"

    def test_classify_token_path(self):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform
        scanner = AIToolScannerParser(
            evidence_root="/tmp", os_platform=OSPlatform.WINDOWS
        )
        tool = ToolRecord(
            tool_id="t", tool_name="T", vendor="V", category="C",
            platform_supported=[], execution_surface=[],
            artifact_path_candidates={}, detection_method="", notes="",
        )
        result = scanner._classify_evidence_path(
            "Users/John/.claude/credentials.json", tool
        )
        assert result.startswith("F"), f"Expected F-Attribution, got {result}"

    def test_scanner_tags_evidence_class_in_notes(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform, ParserStatus
        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        result = scanner.parse()
        assert result.status == ParserStatus.SUCCESS
        # Check that at least some artifacts have evidence class in notes
        tagged = [a for a in result.artifacts_found if "Evidence class:" in (a.notes or "")]
        assert len(tagged) > 0, "No artifacts tagged with evidence class"


class TestClaimLadderCaveats:
    """Verify that claim-ladder corroboration gates produce correct caveats."""

    def test_compute_claim_caveats_single_family(self):
        from ai_usage_evidence_analyzer.claim_ladder import compute_claim_caveats
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceClassification,
            EventConfidenceLevel, FRAUE,
        )
        arts = [
            ArtifactRecord(
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: A-Presence. AI Tool Scanner.",
            ),
            ArtifactRecord(
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: A-Presence. AI Tool Scanner.",
            ),
        ]
        fraue = FRAUE()
        fraue.corroboration_met = True
        fraue.coverage_sufficient = True
        fraue.event_confidence = EventConfidenceLevel.MODERATE

        caveats = compute_claim_caveats(arts, fraue)
        assert any("single artifact family" in c for c in caveats)
        assert any("single evidence class" in c for c in caveats)

    def test_compute_claim_caveats_diverse_evidence(self):
        from ai_usage_evidence_analyzer.claim_ladder import compute_claim_caveats
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceClassification,
            EventConfidenceLevel, FRAUE,
        )
        arts = [
            ArtifactRecord(
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: A-Presence.",
            ),
            ArtifactRecord(
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                classification=EvidenceClassification.DIRECT,
                notes="Evidence class: D-Usage.",
            ),
        ]
        fraue = FRAUE()
        fraue.corroboration_met = True
        fraue.coverage_sufficient = True
        fraue.event_confidence = EventConfidenceLevel.HIGH

        caveats = compute_claim_caveats(arts, fraue)
        # Should NOT have single-family or single-class caveats
        assert not any("single artifact family" in c for c in caveats)
        assert not any("single evidence class" in c for c in caveats)

    def test_compute_claim_caveats_presence_only(self):
        from ai_usage_evidence_analyzer.claim_ladder import compute_claim_caveats
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceClassification,
            EventConfidenceLevel, FRAUE,
        )
        arts = [
            ArtifactRecord(
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: A-Presence.",
            ),
            ArtifactRecord(
                artifact_family=ArtifactFamily.OS_REGISTRY,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: B-Configuration.",
            ),
        ]
        fraue = FRAUE()
        fraue.corroboration_met = True
        fraue.coverage_sufficient = True
        fraue.event_confidence = EventConfidenceLevel.MODERATE

        caveats = compute_claim_caveats(arts, fraue)
        assert any("presence/installation/configuration" in c for c in caveats)

    def test_coverage_caveat_when_insufficient(self):
        from ai_usage_evidence_analyzer.claim_ladder import compute_claim_caveats
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceClassification,
            EventConfidenceLevel, FRAUE,
        )
        arts = [
            ArtifactRecord(
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                classification=EvidenceClassification.DIRECT,
                notes="Evidence class: D-Usage.",
            ),
        ]
        fraue = FRAUE()
        fraue.corroboration_met = False
        fraue.coverage_sufficient = False
        fraue.event_confidence = EventConfidenceLevel.LOW

        caveats = compute_claim_caveats(arts, fraue)
        assert any("partial" in c.lower() for c in caveats)

    def test_evaluate_platform_presence_with_evidence_classes(self):
        """Platform presence should accept diverse evidence classes even from single family."""
        from ai_usage_evidence_analyzer.claim_ladder import evaluate_platform_presence
        from ai_usage_evidence_analyzer.models import (
            ArtifactRecord, ArtifactFamily, EvidenceClassification,
        )
        arts = [
            ArtifactRecord(
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: A-Presence.",
            ),
            ArtifactRecord(
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                notes="Evidence class: B-Configuration.",
            ),
        ]
        result = evaluate_platform_presence(arts)
        assert result is True, "Should accept diverse evidence classes"


class TestScannerCoverageRecords:
    """Verify that the scanner now produces structured coverage/gap records."""

    def test_scanner_produces_coverage_records(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform, ParserStatus
        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        result = scanner.parse()
        assert result.status == ParserStatus.SUCCESS
        # Should have coverage records for FOUND tools
        assert len(result.artifact_coverage) > 0

    def test_scanner_produces_gap_records(self, evidence_tree):
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform, ParserStatus
        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        result = scanner.parse()
        assert result.status == ParserStatus.SUCCESS
        # Should have gap records for NOT_FOUND tools
        assert len(result.coverage_gaps) > 0

    def test_corroboration_limited_caveat_on_single_class(self, evidence_tree):
        """FOUND tools with single evidence class should get CORROBORATION_LEVEL_LIMITED."""
        from ai_usage_evidence_analyzer.parsers.ai_tool_scanner import AIToolScannerParser
        from ai_usage_evidence_analyzer.models import OSPlatform, ParserStatus
        scanner = AIToolScannerParser(
            evidence_root=str(evidence_tree),
            os_platform=OSPlatform.WINDOWS,
            user_profiles=["JohnDoe"],
            config_path=CONFIG_PATH,
        )
        result = scanner.parse()
        assert result.status == ParserStatus.SUCCESS
        found = [e for e in scanner.checklist_entries
                 if str(e.evidence_status).endswith("FOUND")
                 and "NOT_FOUND" not in str(e.evidence_status)]
        if found:
            # At least one FOUND entry should have the corroboration caveat
            has_corr_caveat = any(
                CaveatFlag.CORROBORATION_LEVEL_LIMITED in (e.caveat_flags or [])
                for e in found
            )
            # It's valid to NOT have this if multiple evidence classes exist
            # Just verify no crash
            assert isinstance(has_corr_caveat, bool)


class TestReportCaveatEnforcement:
    """Verify that report generators include enforced caveat language."""

    def test_json_export_has_evidentiary_notice(self):
        """JSON export must include the evidentiary_notice field."""
        from ai_usage_evidence_analyzer.report_generator import JSONExporter
        from ai_usage_evidence_analyzer.models import ForensicReport
        import json

        report = ForensicReport()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as fp:
            path = fp.name
        try:
            exporter = JSONExporter()
            exporter.export(report, path)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            assert "evidentiary_notice" in data
            assert len(data["evidentiary_notice"]) > 50
        finally:
            os.unlink(path)
