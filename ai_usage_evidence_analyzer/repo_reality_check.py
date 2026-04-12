"""
Repository Reality Check Module (v4.0).

Before patching any module, TRACE-AI-FR v4.0 verifies the current repo
state against the documented architecture. This module provides:
- Version consistency checks across all modules
- Schema version validation
- Module existence verification
- Critical field presence validation on core dataclasses
- Governance record version drift detection

Rule: Every v4.0 patch must verify before modifying.
"""

from __future__ import annotations

import importlib
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RealityCheckResult:
    """Result of a single check."""
    check_name: str = ""
    passed: bool = True
    expected: str = ""
    actual: str = ""
    severity: str = "INFO"  # INFO, WARNING, ERROR
    notes: str = ""


@dataclass
class RealityCheckSummary:
    """Aggregate results of all repo reality checks."""
    checks: List[RealityCheckResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    overall_ok: bool = True

    def to_dict(self) -> Dict:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "overall_ok": self.overall_ok,
            "checks": [
                {
                    "check_name": c.check_name,
                    "passed": c.passed,
                    "expected": c.expected,
                    "actual": c.actual,
                    "severity": c.severity,
                    "notes": c.notes,
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Expected module list for v4.0
# ---------------------------------------------------------------------------
_EXPECTED_MODULES = [
    "models",
    "engine",
    "signatures",
    "correlation",
    "confidence",
    "claim_ladder",
    "adjudication",
    "governance",
    "validation",
    "storage",
    "persistence",
    "matrix",
    "report_generator",
    "docx_report",
    "fr_assessment",
    "cli",
    "capability_registry",
    "voice_evidence",
    "e01_handler",
    "evidence_exhibit",
    "llm_narrator",
    "docx_parser",
    "parser_registry",
]


def run_reality_check(
    package_root: Optional[str] = None,
    strict: bool = False,
) -> RealityCheckSummary:
    """
    Run all repository reality checks.

    Args:
        package_root: path to ai_usage_evidence_analyzer/ directory.
                     Auto-detected if None.
        strict: if True, warnings become errors.

    Returns:
        RealityCheckSummary
    """
    if package_root is None:
        package_root = os.path.dirname(os.path.abspath(__file__))

    summary = RealityCheckSummary()

    # Check 1: Package version
    _check_package_version(summary)

    # Check 2: Module existence
    _check_module_existence(summary, package_root)

    # Check 3: Core model fields
    _check_core_model_fields(summary)

    # Check 4: GovernanceRecord framework_version
    _check_governance_version(summary)

    # Check 5: ForensicReport tool_version
    _check_report_version(summary)

    # Tally
    summary.total = len(summary.checks)
    summary.passed = sum(1 for c in summary.checks if c.passed)
    summary.failed = sum(1 for c in summary.checks if not c.passed and c.severity == "ERROR")
    summary.warnings = sum(1 for c in summary.checks if not c.passed and c.severity == "WARNING")
    summary.overall_ok = summary.failed == 0

    if strict:
        summary.overall_ok = summary.failed == 0 and summary.warnings == 0

    logger.info(
        "Reality check: %d/%d passed, %d warnings, %d errors",
        summary.passed, summary.total, summary.warnings, summary.failed,
    )
    return summary


def _check_package_version(summary: RealityCheckSummary):
    """Verify __init__.py version is 4.0.0."""
    try:
        from . import __version__
        result = RealityCheckResult(
            check_name="package_version",
            expected="4.0.0",
            actual=__version__,
            passed=__version__ == "4.0.0",
            severity="ERROR" if __version__ != "4.0.0" else "INFO",
        )
    except Exception as e:
        result = RealityCheckResult(
            check_name="package_version",
            expected="4.0.0",
            actual=f"import error: {e}",
            passed=False,
            severity="ERROR",
        )
    summary.checks.append(result)


def _check_module_existence(
    summary: RealityCheckSummary, package_root: str
):
    """Verify expected modules exist."""
    for mod in _EXPECTED_MODULES:
        mod_path = os.path.join(package_root, f"{mod}.py")
        exists = os.path.isfile(mod_path)
        result = RealityCheckResult(
            check_name=f"module_exists:{mod}",
            expected="exists",
            actual="exists" if exists else "missing",
            passed=exists,
            severity="WARNING" if not exists else "INFO",
            notes="" if exists else f"File not found: {mod_path}",
        )
        summary.checks.append(result)


def _check_core_model_fields(summary: RealityCheckSummary):
    """Verify critical v4.0 fields exist on core dataclasses."""
    try:
        from .models import ArtifactRecord, FRAUE, GovernanceRecord, ForensicReport

        # ArtifactRecord v4.0 fields
        for field_name in [
            "acquisition_source", "platform_surface", "provenance",
            "related_voice_event_id",
        ]:
            has = hasattr(ArtifactRecord, field_name) or field_name in ArtifactRecord.__dataclass_fields__
            result = RealityCheckResult(
                check_name=f"field:ArtifactRecord.{field_name}",
                expected="present",
                actual="present" if has else "missing",
                passed=has,
                severity="ERROR" if not has else "INFO",
            )
            summary.checks.append(result)

        # FRAUE v4.0 fields
        for field_name in [
            "confidence_class", "acquisition_sources", "platform_surfaces",
            "missing_expected_artifact_families",
        ]:
            has = hasattr(FRAUE, field_name) or field_name in FRAUE.__dataclass_fields__
            result = RealityCheckResult(
                check_name=f"field:FRAUE.{field_name}",
                expected="present",
                actual="present" if has else "missing",
                passed=has,
                severity="ERROR" if not has else "INFO",
            )
            summary.checks.append(result)

        # GovernanceRecord v4.0 fields
        for field_name in [
            "provider_capability_blind_spots",
            "acquisition_blind_spots",
            "direct_evidence_summary",
        ]:
            has = hasattr(GovernanceRecord, field_name) or field_name in GovernanceRecord.__dataclass_fields__
            result = RealityCheckResult(
                check_name=f"field:GovernanceRecord.{field_name}",
                expected="present",
                actual="present" if has else "missing",
                passed=has,
                severity="ERROR" if not has else "INFO",
            )
            summary.checks.append(result)

        # ForensicReport v4.0 fields
        for field_name in [
            "schema_version", "voice_evidence", "shared_links",
            "generated_assets", "docx_generated",
        ]:
            has = hasattr(ForensicReport, field_name) or field_name in ForensicReport.__dataclass_fields__
            result = RealityCheckResult(
                check_name=f"field:ForensicReport.{field_name}",
                expected="present",
                actual="present" if has else "missing",
                passed=has,
                severity="ERROR" if not has else "INFO",
            )
            summary.checks.append(result)

    except Exception as e:
        summary.checks.append(RealityCheckResult(
            check_name="core_model_fields",
            expected="importable",
            actual=f"error: {e}",
            passed=False,
            severity="ERROR",
        ))


def _check_governance_version(summary: RealityCheckSummary):
    """Verify GovernanceRecord defaults to framework_version 4.0.0."""
    try:
        from .models import GovernanceRecord
        gr = GovernanceRecord()
        result = RealityCheckResult(
            check_name="governance_framework_version",
            expected="4.0.0",
            actual=gr.framework_version,
            passed=gr.framework_version == "4.0.0",
            severity="WARNING" if gr.framework_version != "4.0.0" else "INFO",
        )
    except Exception as e:
        result = RealityCheckResult(
            check_name="governance_framework_version",
            expected="4.0.0",
            actual=f"error: {e}",
            passed=False,
            severity="ERROR",
        )
    summary.checks.append(result)


def _check_report_version(summary: RealityCheckSummary):
    """Verify ForensicReport defaults to tool_version 4.0.0."""
    try:
        from .models import ForensicReport, CaseInfo, EvidenceImageInfo, EvidenceCoverage
        r = ForensicReport(
            case_info=CaseInfo(),
            evidence_info=EvidenceImageInfo(),
            evidence_coverage=EvidenceCoverage(),
        )
        result = RealityCheckResult(
            check_name="report_tool_version",
            expected="4.0.0",
            actual=r.tool_version,
            passed=r.tool_version == "4.0.0",
            severity="WARNING" if r.tool_version != "4.0.0" else "INFO",
        )
    except Exception as e:
        result = RealityCheckResult(
            check_name="report_tool_version",
            expected="4.0.0",
            actual=f"error: {e}",
            passed=False,
            severity="ERROR",
        )
    summary.checks.append(result)
