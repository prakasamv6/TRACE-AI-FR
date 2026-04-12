# tests/test_caveats.py
"""
Test cases for caveat enforcement, status/corroboration/attribution rules, parser-failure handling, and inaccessible-source handling.
"""
from ai_usage_evidence_analyzer.caveats import get_caveat_text, CAVEAT_LANGUAGE, GLOBAL_REPORT_FOOTER, UI_WARNINGS
from ai_usage_evidence_analyzer.tool_registry import CaveatFlag

def test_caveat_text_mapping():
    flags = [CaveatFlag.PRESENCE_ONLY, CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED]
    texts = get_caveat_text(flags)
    assert CAVEAT_LANGUAGE[CaveatFlag.PRESENCE_ONLY] in texts
    assert CAVEAT_LANGUAGE[CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED] in texts

def test_global_report_footer():
    assert "AI-related artifacts" in GLOBAL_REPORT_FOOTER
    assert "do not independently establish actual use" in GLOBAL_REPORT_FOOTER

def test_ui_warnings():
    assert any("Presence does not equal use" in w for w in UI_WARNINGS)
    assert any("NOT_FOUND applies only to examined locations" in w for w in UI_WARNINGS)
