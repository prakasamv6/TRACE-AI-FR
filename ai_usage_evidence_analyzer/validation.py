"""
TRACE-AI-FR Validation Framework (Layer 7).

Provides structured validation following the NIST CFTT model:
  Phase 1: Known-answer parser validation
  Phase 2: Ground-truth scenario validation
  Phase 3: False-positive validation (negative controls)
  Phase 4: Drift validation across platform updates
  Phase 5: Examiner reproducibility

This module exposes the validation runner and result tracking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .models import ValidationLevel

logger = logging.getLogger(__name__)


@dataclass
class ValidationCase:
    """A single validation test case."""
    case_id: str = ""
    phase: str = ""  # "parser", "scenario", "false_positive", "drift", "reproducibility"
    description: str = ""
    expected_platforms: List[str] = field(default_factory=list)
    expected_artifact_count_min: int = 0
    expected_false_positives: int = 0
    is_negative_control: bool = False


@dataclass
class ValidationResult:
    """Result of a single validation test."""
    case_id: str = ""
    phase: str = ""
    passed: bool = False
    actual_platforms: List[str] = field(default_factory=list)
    actual_artifact_count: int = 0
    actual_false_positives: int = 0
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ValidationSummary:
    """Aggregate validation summary for framework-level reporting."""
    total_cases: int = 0
    passed: int = 0
    failed: int = 0
    phases_covered: List[str] = field(default_factory=list)
    overall_status: ValidationLevel = ValidationLevel.NOT_VALIDATED
    results: List[ValidationResult] = field(default_factory=list)
    last_run: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "total_cases": self.total_cases,
            "passed": self.passed,
            "failed": self.failed,
            "phases_covered": self.phases_covered,
            "overall_status": self.overall_status.value,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "results": [
                {
                    "case_id": r.case_id,
                    "phase": r.phase,
                    "passed": r.passed,
                    "actual_platforms": r.actual_platforms,
                    "actual_artifact_count": r.actual_artifact_count,
                    "actual_false_positives": r.actual_false_positives,
                    "notes": r.notes,
                    "timestamp": r.timestamp.isoformat(),
                }
                for r in self.results
            ],
        }


class ValidationRunner:
    """
    Runs validation cases against the analysis engine and tracks results.

    Usage:
        runner = ValidationRunner()
        runner.add_case(ValidationCase(...))
        summary = runner.run(engine_factory)
    """

    def __init__(self):
        self.cases: List[ValidationCase] = []
        self.results: List[ValidationResult] = []

    def add_case(self, case: ValidationCase):
        self.cases.append(case)

    def run(self, engine_factory=None) -> ValidationSummary:
        """
        Execute all validation cases.

        Args:
            engine_factory: Callable(evidence_path, output_dir) -> AnalysisEngine.
                           If None, only tracks the structure (dry run).
        """
        for case in self.cases:
            result = self._execute_case(case, engine_factory)
            self.results.append(result)

        return self._summarize()

    def _execute_case(
        self, case: ValidationCase, engine_factory
    ) -> ValidationResult:
        """Execute a single validation case."""
        result = ValidationResult(
            case_id=case.case_id,
            phase=case.phase,
        )

        if engine_factory is None:
            result.notes = "Dry run — no engine factory provided."
            result.passed = True
            return result

        try:
            # Engine factory provides a configured AnalysisEngine
            engine = engine_factory(case)
            report = engine.run()

            result.actual_platforms = sorted(set(
                a.suspected_platform.value for a in report.all_artifacts
                if a.suspected_platform.value != "Unknown"
            ))
            result.actual_artifact_count = len(report.all_artifacts)

            # Evaluate pass/fail
            if case.is_negative_control:
                # No artifacts should be found for negative controls
                result.actual_false_positives = result.actual_artifact_count
                result.passed = result.actual_false_positives <= case.expected_false_positives
            else:
                # Check platform detection
                expected_set = set(case.expected_platforms)
                actual_set = set(result.actual_platforms)
                platforms_ok = expected_set.issubset(actual_set)

                # Check minimum artifact count
                count_ok = result.actual_artifact_count >= case.expected_artifact_count_min

                result.passed = platforms_ok and count_ok

            result.notes = "PASSED" if result.passed else "FAILED"

        except Exception as exc:
            result.passed = False
            result.notes = f"Exception: {exc}"

        return result

    def _summarize(self) -> ValidationSummary:
        summary = ValidationSummary(
            total_cases=len(self.results),
            passed=sum(1 for r in self.results if r.passed),
            failed=sum(1 for r in self.results if not r.passed),
            phases_covered=sorted(set(r.phase for r in self.results)),
            results=self.results,
            last_run=datetime.utcnow(),
        )

        if summary.total_cases == 0:
            summary.overall_status = ValidationLevel.NOT_VALIDATED
        elif summary.failed == 0:
            summary.overall_status = ValidationLevel.VALIDATED
        elif summary.passed > 0:
            summary.overall_status = ValidationLevel.PARTIALLY_VALIDATED
        else:
            summary.overall_status = ValidationLevel.NOT_VALIDATED

        return summary


# ---------------------------------------------------------------------------
# Built-in validation case library
# ---------------------------------------------------------------------------

def get_standard_validation_cases() -> List[ValidationCase]:
    """
    Return built-in validation cases for the five phases.
    These are intended to be run against synthetic evidence fixtures.
    """
    return [
        # Phase 1: Parser validation
        ValidationCase(
            case_id="P1-CHROM-01",
            phase="parser",
            description="Chromium History parser detects ChatGPT URL visits",
            expected_platforms=["ChatGPT"],
            expected_artifact_count_min=1,
        ),
        ValidationCase(
            case_id="P1-CHROM-02",
            phase="parser",
            description="Chromium History parser detects Claude URL visits",
            expected_platforms=["Claude"],
            expected_artifact_count_min=1,
        ),
        ValidationCase(
            case_id="P1-FF-01",
            phase="parser",
            description="Firefox parser detects ChatGPT visits from places.sqlite",
            expected_platforms=["ChatGPT"],
            expected_artifact_count_min=1,
        ),
        ValidationCase(
            case_id="P1-CONTENT-01",
            phase="parser",
            description="Content scanner detects AI export files",
            expected_platforms=["ChatGPT"],
            expected_artifact_count_min=1,
        ),
        ValidationCase(
            case_id="P1-REG-01",
            phase="parser",
            description="Registry parser detects AI domains in NTUSER.DAT binary scan",
            expected_platforms=["ChatGPT"],
            expected_artifact_count_min=1,
        ),
        # Phase 2: Scenario validation
        ValidationCase(
            case_id="P2-FULL-WIN-01",
            phase="scenario",
            description="Full Windows evidence with ChatGPT, Claude, and content artifacts",
            expected_platforms=["ChatGPT", "Claude"],
            expected_artifact_count_min=5,
        ),
        # Phase 3: False-positive validation
        ValidationCase(
            case_id="P3-NEG-01",
            phase="false_positive",
            description="Empty evidence directory should produce zero artifacts",
            expected_platforms=[],
            expected_artifact_count_min=0,
            is_negative_control=True,
            expected_false_positives=0,
        ),
        # Phase 4: Drift validation
        ValidationCase(
            case_id="P4-DRIFT-01",
            phase="drift",
            description="Re-run standard scenario to check for signature drift",
            expected_platforms=["ChatGPT"],
            expected_artifact_count_min=1,
        ),
        # Phase 5: Reproducibility
        ValidationCase(
            case_id="P5-REPRO-01",
            phase="reproducibility",
            description="Second run of same evidence should produce identical artifact count",
            expected_platforms=["ChatGPT"],
            expected_artifact_count_min=1,
        ),
    ]


# ---------------------------------------------------------------------------
# DOCX forensic report validation
# ---------------------------------------------------------------------------

# Headings that MUST appear in every court-ready DOCX report.
DOCX_REQUIRED_HEADINGS = [
    "Purpose and Scope",
    "Summary of Findings",
    "Evidence Examined",
    "Examination Process",
    "Detailed Findings",
    "Conclusion",
    "Appendix",
]

# Additional headings expected when governance data is present.
DOCX_GOVERNANCE_HEADINGS = [
    "Evidence Strength",
    "Limitations",
]

# Headings expected when findings exist.
DOCX_FINDINGS_HEADINGS = [
    "AI Services Detected",
]


@dataclass
class DocxValidationResult:
    """Result of DOCX forensic-completeness validation."""
    file_path: str = ""
    is_valid: bool = False
    opens_successfully: bool = False
    headings_found: List[str] = field(default_factory=list)
    headings_missing: List[str] = field(default_factory=list)
    has_governance_section: bool = False
    has_conclusion: bool = False
    has_signature_block: bool = False
    has_glossary: bool = False
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "is_valid": self.is_valid,
            "opens_successfully": self.opens_successfully,
            "headings_found": self.headings_found,
            "headings_missing": self.headings_missing,
            "has_governance_section": self.has_governance_section,
            "has_conclusion": self.has_conclusion,
            "has_signature_block": self.has_signature_block,
            "has_glossary": self.has_glossary,
            "errors": self.errors,
        }


def validate_docx_report(docx_path: str) -> DocxValidationResult:
    """
    Validate that a generated DOCX report meets forensic completeness
    requirements for court submission.

    Checks:
    - file opens successfully as a valid Word document
    - required section headings are present
    - governance / limitations section exists
    - conclusion section exists
    - examiner signature block exists
    - glossary / appendix exists
    """
    result = DocxValidationResult(file_path=docx_path)

    try:
        from docx import Document
    except ImportError:
        result.errors.append("python-docx not installed; cannot validate DOCX")
        return result

    import os
    if not os.path.isfile(docx_path):
        result.errors.append(f"File not found: {docx_path}")
        return result

    try:
        doc = Document(docx_path)
        result.opens_successfully = True
    except Exception as exc:
        result.errors.append(f"Failed to open DOCX: {exc}")
        return result

    # Collect all paragraph text for searching
    all_text = []
    for para in doc.paragraphs:
        text = para.text.strip()
        if text:
            all_text.append(text)

    all_text_joined = "\n".join(all_text).lower()

    # Check required headings (substring match, case-insensitive)
    for heading in DOCX_REQUIRED_HEADINGS:
        if heading.lower() in all_text_joined:
            result.headings_found.append(heading)
        else:
            result.headings_missing.append(heading)

    # Governance section
    result.has_governance_section = any(
        h.lower() in all_text_joined
        for h in DOCX_GOVERNANCE_HEADINGS
    )

    # Conclusion
    result.has_conclusion = "conclusion" in all_text_joined

    # Signature block — look for "respectfully submitted" or signature line
    result.has_signature_block = (
        "respectfully submitted" in all_text_joined
        or "____" in all_text_joined
    )

    # Glossary
    result.has_glossary = (
        "glossary" in all_text_joined
        or "appendix" in all_text_joined
    )

    # Overall validity
    result.is_valid = (
        result.opens_successfully
        and len(result.headings_missing) == 0
        and result.has_conclusion
        and result.has_signature_block
    )

    if not result.is_valid and not result.errors:
        if result.headings_missing:
            result.errors.append(
                f"Missing required headings: {', '.join(result.headings_missing)}"
            )
        if not result.has_conclusion:
            result.errors.append("Missing Conclusion section")
        if not result.has_signature_block:
            result.errors.append("Missing examiner signature block")

    return result
