# tests/test_checklist.py
"""
Test cases for forensic checklist logic, evidence status, caveat propagation, export formatting, and negative finding scoping.
"""
import os
import tempfile
import pytest
from ai_usage_evidence_analyzer.tool_registry import ToolRegistry, EvidenceStatus, CaveatFlag, CorroborationLevel, AttributionScope
from ai_usage_evidence_analyzer.forensic_checklist import ForensicChecklistGenerator

@pytest.fixture
def tool_registry():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "ai_tool_inventory.yaml")
    return ToolRegistry(config_path)

def test_checklist_entry_found(tool_registry):
    gen = ForensicChecklistGenerator(tool_registry)
    scan_results = [{
        "tool_id": "chatgpt_desktop",
        "evidence_status": EvidenceStatus.FOUND,
        "artifact_paths": ["C:/Users/Examiner/AppData/Local/Programs/ChatGPT"],
        "notes": "Install folder present.",
        "caveat_flags": [CaveatFlag.PRESENCE_ONLY, CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED],
        "acquisition_source": "FORENSIC_IMAGE",
        "corroboration_level": CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY,
        "attribution_scope": AttributionScope.DEVICE_LEVEL_ONLY,
        "artifact_count": 1
    }]
    gen.generate_from_scan(scan_results)
    entry = gen.entries[0]
    assert entry.evidence_status == EvidenceStatus.FOUND
    assert CaveatFlag.PRESENCE_ONLY in entry.caveat_flags
    assert entry.acquisition_source == "FORENSIC_IMAGE"
    assert entry.corroboration_level == CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY
    assert entry.attribution_scope == AttributionScope.DEVICE_LEVEL_ONLY

def test_checklist_entry_not_found(tool_registry):
    gen = ForensicChecklistGenerator(tool_registry)
    scan_results = [{
        "tool_id": "ollama",
        "evidence_status": EvidenceStatus.NOT_FOUND,
        "artifact_paths": [],
        "notes": "No artifacts in examined locations.",
        "caveat_flags": [CaveatFlag.NEGATIVE_FINDING_SCOPED],
        "acquisition_source": "LIVE_HOST",
        "corroboration_level": CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY,
        "attribution_scope": AttributionScope.DEVICE_LEVEL_ONLY,
        "artifact_count": 0
    }]
    gen.generate_from_scan(scan_results)
    entry = gen.entries[0]
    assert entry.evidence_status == EvidenceStatus.NOT_FOUND
    assert CaveatFlag.NEGATIVE_FINDING_SCOPED in entry.caveat_flags
    assert entry.acquisition_source == "LIVE_HOST"

def test_checklist_csv_export(tool_registry):
    gen = ForensicChecklistGenerator(tool_registry)
    scan_results = [{
        "tool_id": "cursor",
        "evidence_status": EvidenceStatus.PARTIAL,
        "artifact_paths": ["/home/user/.vscode/extensions/cursor*"],
        "notes": "Extension folder found, config missing.",
        "caveat_flags": [CaveatFlag.PARTIAL, CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED],
        "acquisition_source": "FORENSIC_IMAGE",
        "corroboration_level": CorroborationLevel.LEVEL_2_CONFIGURATION_OR_WORKSPACE_INDICATORS,
        "attribution_scope": AttributionScope.USER_PROFILE_LINKED,
        "artifact_count": 1
    }]
    gen.generate_from_scan(scan_results)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        gen.to_csv(tmp.name)
        tmp.close()
        with open(tmp.name, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Cursor" in content
        assert "PARTIAL" in content
    os.unlink(tmp.name)
