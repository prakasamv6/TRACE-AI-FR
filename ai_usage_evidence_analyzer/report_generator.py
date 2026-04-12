"""
Forensic report generators.

Generates reports in Markdown, HTML, and JSON formats following the
SANS / UNCC forensic report standard:
  - Overview / Case Summary
  - Forensic Acquisition & Exam Preparation
  - Findings and Report (Forensic Analysis)
  - Conclusion
  - Examiner Signature

Uses OpenAI LLM (when available) for professional forensic narratives.
Every finding references evidence exhibits with E01 source paths.
No assumptions — only evidence-backed statements.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AIPlatform,
    AIModel,
    AIUsageFootprint,
    ArtifactRecord,
    CaseInfo,
    ComparativeMatrixRow,
    ConfidenceLevel,
    EvidenceCoverage,
    EvidenceClassification,
    EvidenceImageInfo,
    ForensicReport,
    ParserResult,
    TimelineEvent,
)
from .matrix import matrix_to_dicts
from .evidence_exhibit import (
    EvidenceExhibit,
    ExhibitManager,
    generate_exhibit_reference_md,
    generate_exhibit_reference_html,
)
from .llm_narrator import (
    generate_overview_narrative,
    generate_acquisition_narrative,
    generate_finding_narrative,
    generate_conclusion_narrative,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON Exporter
# ---------------------------------------------------------------------------

class JSONExporter:
    """Export forensic report as structured JSON."""

    def export(self, report: ForensicReport, output_path: str,
               exhibits: Optional[List[EvidenceExhibit]] = None):
        data = {
            "tool": "TRACE-AI-FR",
            "version": report.tool_version,
            "framework_name": report.framework_name,
            "generated_at": report.generated_at.isoformat(),
            "case_info": {
                "case_id": report.case_info.case_id,
                "case_name": report.case_info.case_name,
                "examiner": report.case_info.examiner,
                "organization": report.case_info.organization,
                "description": report.case_info.description,
            },
            "evidence_info": {
                "evidence_item_id": report.evidence_info.evidence_item_id,
                "image_path": report.evidence_info.image_path,
                "image_type": report.evidence_info.image_type.value,
                "image_size_bytes": report.evidence_info.image_size_bytes,
                "detected_os": report.evidence_info.detected_os.value,
                "user_profiles": report.evidence_info.user_profiles,
                "ewf_metadata": report.evidence_info.ewf_metadata,
                "errors": report.evidence_info.errors,
            },
            "evidence_coverage": self._coverage_to_dict(report.evidence_coverage),
            "carving_enabled": report.carving_enabled,
            "artifacts": [a.to_dict() for a in report.all_artifacts],
            "timeline": [
                {
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "event_type": e.event_type,
                    "description": e.description,
                    "platform": e.platform.value,
                    "access_mode": e.access_mode.value,
                    "confidence": e.confidence.value,
                    "classification": e.classification.value,
                }
                for e in report.timeline
            ],
            "ai_usage_footprints": [
                self._footprint_to_dict(fp) for fp in report.ai_footprints
            ],
            "fraues": [f.to_dict() for f in report.fraues],
            "comparative_matrix": matrix_to_dicts(report.matrix_rows),
            "parser_results": [
                {
                    "parser": pr.parser_name,
                    "version": pr.parser_version,
                    "status": pr.status.value,
                    "artifacts_found": len(pr.artifacts_found),
                    "errors": pr.errors,
                    "warnings": pr.warnings,
                    "processing_time_ms": pr.processing_time_ms,
                    "notes": pr.notes,
                }
                for pr in report.parser_results
            ],
            "governance_record": (
                report.governance_record.to_dict()
                if report.governance_record else None
            ),
            "scope_of_conclusion": report.scope_of_conclusion,
            "inference_boundaries": report.inference_boundaries,
            "analysis_notes": report.analysis_notes,
            "examination_questions": [
                {
                    "number": q.number,
                    "question": q.text,
                    "answer": q.answer,
                    "evidence_references": q.evidence_references,
                }
                for q in report.examination_questions
            ] if report.examination_questions else [],
            "fr_assessments": [
                fr.to_dict() for fr in report.fr_assessments
            ] if report.fr_assessments else [],
            "exhibits": [ex.to_dict() for ex in (exhibits or [])],
            # v5.0 artifact coverage ledger fields
            "artifact_coverage_ledger": [r.__dict__ for r in getattr(report, "artifact_coverage_ledger", [])],
            "coverage_gap_ledger": [r.__dict__ for r in getattr(report, "coverage_gap_ledger", [])],
            "parse_failure_ledger": [r.__dict__ for r in getattr(report, "parse_failure_ledger", [])],
            "unsupported_artifact_ledger": [r.__dict__ for r in getattr(report, "unsupported_artifact_ledger", [])],
            # Caveat enforcement metadata
            "evidentiary_notice": "",
            "ai_assistance_notice": (
                "Recommended Notice: Portions of this report were prepared with AI assistance. "
                "Review and validation by a qualified human investigator are strongly recommended "
                "before submission for any legal, forensic, or official purpose."
            ),
        }

        # Add global footer
        try:
            from .caveats import GLOBAL_REPORT_FOOTER
            data["evidentiary_notice"] = GLOBAL_REPORT_FOOTER
        except Exception:
            pass

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"JSON report exported: {output_path}")

    def _coverage_to_dict(self, cov: EvidenceCoverage) -> Dict:
        return {
            "image_type": cov.image_type.value,
            "full_disk_available": cov.full_disk_available,
            "partitions_accessible": cov.partitions_accessible,
            "partitions_total": cov.partitions_total,
            "encrypted_areas_detected": cov.encrypted_areas_detected,
            "carving_enabled": cov.carving_enabled,
            "os_detected": cov.os_detected.value,
            "user_profiles_found": cov.user_profiles_found,
            "browsers_detected": cov.browsers_detected,
            "native_apps_detected": cov.native_apps_detected,
            "artifact_families_available": cov.artifact_families_available,
            "artifact_families_missing": cov.artifact_families_missing,
            "parsers_succeeded": cov.parsers_succeeded,
            "parsers_failed": cov.parsers_failed,
            "parsers_not_applicable": cov.parsers_not_applicable,
            "parsers_stub": cov.parsers_stub,
            "coverage_notes": cov.coverage_notes,
            "limitations": cov.limitations,
        }

    def _footprint_to_dict(self, fp: AIUsageFootprint) -> Dict:
        return {
            "platform": fp.platform.value,
            "model": fp.model.value if fp.model else None,
            "access_mode": fp.access_mode.value if fp.access_mode else None,
            "total_artifacts": fp.total_artifacts,
            "direct_artifacts": fp.direct_artifacts,
            "inferred_artifacts": fp.inferred_artifacts,
            "earliest_activity": fp.earliest_activity.isoformat() if fp.earliest_activity else None,
            "latest_activity": fp.latest_activity.isoformat() if fp.latest_activity else None,
            "estimated_session_count": fp.estimated_session_count,
            "image_upload_indicators": fp.image_upload_indicators,
            "content_export_indicators": fp.content_export_indicators,
            "prompt_remnants_found": fp.prompt_remnants_found,
            "response_remnants_found": fp.response_remnants_found,
            "overall_confidence": fp.overall_confidence.value,
            "caveats": fp.caveats,
        }


# ---------------------------------------------------------------------------
# Markdown Report Generator — SANS / UNCC Forensic Report Standard
# with LLM-enhanced narratives and evidence exhibits
# ---------------------------------------------------------------------------

class MarkdownReportGenerator:
    """
    Generate a forensic-grade Markdown report following the SANS / UNCC
    standard structure with LLM-enhanced narratives and evidence exhibits.

    Structure:
      1. Header (lab, examiner, case number, date)
      2. Overview / Case Summary (LLM-enhanced)
      3. Forensic Acquisition & Exam Preparation (LLM-enhanced)
      4. Findings and Report — with numbered exhibits (LLM-enhanced)
      5. Conclusion (LLM-enhanced)
      6. Examiner Signature
    """

    def __init__(self):
        self.exhibit_manager: Optional[ExhibitManager] = None

    def generate(self, report: ForensicReport, output_path: str,
                 evidence_root: str = "",
                 exhibit_manager: Optional[ExhibitManager] = None):
        """
        Generate the Markdown report.

        Args:
            report: The ForensicReport data.
            output_path: Where to write the .md file.
            evidence_root: Root path of the evidence on disk (for exhibit capture).
            exhibit_manager: Pre-built ExhibitManager, or one will be created.
        """
        output_dir = os.path.dirname(output_path) or "."

        # Create exhibit manager if not provided
        if exhibit_manager:
            self.exhibit_manager = exhibit_manager
        else:
            self.exhibit_manager = ExhibitManager(
                output_dir=output_dir,
                evidence_source=report.evidence_info.image_path or "",
            )

        # Build exhibits from all artifacts
        self._build_exhibits(report, evidence_root)

        lines: List[str] = []
        self._header_block(lines, report)
        self._overview(lines, report)
        self._acquisition_and_preparation(lines, report)
        self._findings_and_report(lines, report)
        self._recovery_findings(lines, report)
        self._fraue_findings(lines, report)
        self._v4_evidence_sections(lines, report)
        self._artifact_coverage_ledger_section(lines, report)
        self._examination_questions_section(lines, report)
        self._fr_assessment_section(lines, report)
        self._ai_tool_checklist_section(lines, report)
        self._inference_boundaries(lines, report)
        self._conclusion(lines, report)
        self._exhibit_appendix(lines, report)
        self._signature_block(lines, report)

        os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logger.info(f"Markdown report generated: {output_path}")

    def _artifact_coverage_ledger_section(self, lines: List[str], report: ForensicReport):
        """Appendix: Artifact Coverage Ledger (v5.0)"""
        acl = getattr(report, "artifact_coverage_ledger", [])
        gap = getattr(report, "coverage_gap_ledger", [])
        fail = getattr(report, "parse_failure_ledger", [])
        unsup = getattr(report, "unsupported_artifact_ledger", [])
        if not (acl or gap or fail or unsup):
            return
        lines.append("# Artifact Coverage Ledger (v5.0)")
        lines.append("")
        if acl:
            lines.append("## Artifact Coverage Records")
            lines.append("| Platform | OS | User | Artifact Family | Parser | Path | Evidence Count | Confidence | Reason | Caveat |")
            lines.append("|----------|----|------|-----------------|--------|------|---------------|-----------|--------|--------|")
            for r in acl:
                lines.append(f"| {getattr(r, 'platform', '')} | {getattr(r, 'os', '')} | {getattr(r, 'user_profile', '')} | {getattr(r, 'artifact_family', '')} | {getattr(r, 'parser_used', '')} | {getattr(r, 'actual_path', '')} | {getattr(r, 'evidence_count', 0)} | {getattr(r, 'confidence_impact', '')} | {getattr(r, 'reason_code', '')} | {getattr(r, 'caveat_text', '')} |")
            lines.append("")
        if gap:
            lines.append("## Coverage Gaps")
            lines.append("| Platform | OS | User | Artifact Family | Expected Path | Reason | Confidence | Caveat |")
            lines.append("|----------|----|------|-----------------|--------------|--------|-----------|--------|")
            for r in gap:
                lines.append(f"| {getattr(r, 'platform', '')} | {getattr(r, 'os', '')} | {getattr(r, 'user_profile', '')} | {getattr(r, 'artifact_family', '')} | {getattr(r, 'expected_path', '')} | {getattr(r, 'gap_reason', '')} | {getattr(r, 'confidence_impact', '')} | {getattr(r, 'caveat_text', '')} |")
            lines.append("")
        if fail:
            lines.append("## Parse Failures")
            lines.append("| Platform | OS | User | Artifact Family | Path | Parser | Error | Caveat |")
            lines.append("|----------|----|------|-----------------|------|--------|-------|--------|")
            for r in fail:
                lines.append(f"| {getattr(r, 'platform', '')} | {getattr(r, 'os', '')} | {getattr(r, 'user_profile', '')} | {getattr(r, 'artifact_family', '')} | {getattr(r, 'path', '')} | {getattr(r, 'parser_used', '')} | {getattr(r, 'error_message', '')} | {getattr(r, 'caveat_text', '')} |")
            lines.append("")
        if unsup:
            lines.append("## Unsupported Artifact Locations")
            lines.append("| Platform | OS | User | Artifact Family | Path | Parser Needed | Notes |")
            lines.append("|----------|----|------|-----------------|------|--------------|-------|")
            for r in unsup:
                lines.append(f"| {getattr(r, 'platform', '')} | {getattr(r, 'os', '')} | {getattr(r, 'user_profile', '')} | {getattr(r, 'artifact_family', '')} | {getattr(r, 'path', '')} | {getattr(r, 'parser_needed', '')} | {getattr(r, 'notes', '')} |")
            lines.append("")

    def _build_exhibits(self, report: ForensicReport, evidence_root: str):
        """Create exhibits from all artifacts."""
        for art in report.all_artifacts:
            self.exhibit_manager.add_exhibit_from_artifact(art, evidence_root)

    # ------------------------------------------------------------------
    # Section 0 — Report Header
    # ------------------------------------------------------------------
    def _header_block(self, lines: List[str], report: ForensicReport):
        """Right-aligned header with lab, examiner, case number, date."""
        org = report.case_info.organization or "UNCC Forensics Lab"
        examiner = report.case_info.examiner or "Digital Forensics Examiner"
        case_id = report.case_info.case_id
        date_str = report.generated_at.strftime("%m-%d-%Y")

        lines.append(f"<div style=\"text-align:right\">")
        lines.append(f"{org}<br>")
        lines.append(f"{examiner}<br>")
        lines.append(f"Case #{case_id}<br>")
        lines.append(f"{date_str}")
        lines.append(f"</div>")
        lines.append("")

    # ------------------------------------------------------------------
    # Section 1 — Overview / Case Summary (LLM-enhanced)
    # ------------------------------------------------------------------
    def _overview(self, lines: List[str], report: ForensicReport):
        lines.append("# Overview")
        lines.append("")

        date_str = report.generated_at.strftime("%m/%d/%Y")
        narrative = generate_overview_narrative(
            case_name=report.case_info.case_name or "AI Usage Analysis",
            examiner=report.case_info.examiner or "this examiner",
            organization=report.case_info.organization or "the requesting agency",
            evidence_path=report.evidence_info.image_path or "submitted evidence",
            image_type=report.evidence_info.image_type.value,
            detected_os=report.evidence_info.detected_os.value,
            date_str=date_str,
            description=report.case_info.description or "",
        )
        lines.append(narrative)
        lines.append("")

    # ------------------------------------------------------------------
    # Section 2 — Forensic Acquisition & Exam Preparation (LLM-enhanced)
    # ------------------------------------------------------------------
    def _acquisition_and_preparation(self, lines: List[str], report: ForensicReport):
        lines.append("# Forensic Acquisition & Exam Preparation")
        lines.append("")

        ei = report.evidence_info
        parsers_used = [
            f"{pr.parser_name} v{pr.parser_version}" for pr in report.parser_results
        ]

        narrative = generate_acquisition_narrative(
            tool_version=report.tool_version,
            md5_hash=ei.md5_hash or "",
            sha1_hash=ei.sha1_hash or "",
            image_path=ei.image_path or "",
            image_type=ei.image_type.value,
            image_size_bytes=ei.image_size_bytes,
            detected_os=ei.detected_os.value,
            read_only=ei.read_only,
            parsers_used=parsers_used,
        )
        lines.append(narrative)
        lines.append("")

    # ------------------------------------------------------------------
    # Section 3 — Findings and Report (LLM-enhanced, exhibit-backed)
    # ------------------------------------------------------------------
    def _findings_and_report(self, lines: List[str], report: ForensicReport):
        lines.append("# Findings and Report (Forensic Analysis)")
        lines.append("")

        if not report.all_artifacts:
            lines.append("After completing the forensic analysis of the submitted evidence, "
                         "**no artifacts relating to AI platform usage were identified**.")
            lines.append("")
            lines.append("**IMPORTANT:** This negative finding must be interpreted in light of "
                         "the evidence coverage assessment below. Absence of evidence is not "
                         "evidence of absence.")
            lines.append("")
            self._evidence_coverage_subsection(lines, report)
            return

        total = len(report.all_artifacts)
        platforms_found = sorted(set(
            a.suspected_platform.value for a in report.all_artifacts
            if a.suspected_platform != AIPlatform.UNKNOWN
        ))
        direct = sum(1 for a in report.all_artifacts
                     if a.classification == EvidenceClassification.DIRECT)
        inferred = sum(1 for a in report.all_artifacts
                       if a.classification == EvidenceClassification.INFERRED)

        lines.append(
            f"After completing the forensic analysis of the submitted evidence, "
            f"**{total}** artifact(s) related to AI platform usage were identified. "
            f"The following AI platforms were detected: **{', '.join(platforms_found)}**."
        )
        lines.append("")
        lines.append(f"Of these, **{direct}** artifact(s) constitute direct evidence "
                      f"and **{inferred}** artifact(s) are inferred/indirect evidence. "
                      f"See supporting exhibits below.")
        lines.append("")

        finding_num = 1

        # --- a. AI Platform Summary Table ---
        lines.append(f"**{finding_num}. AI Platform Detection Summary**")
        lines.append("")
        lines.append("| AI Platform | Artifacts Found | Direct | Inferred | Highest Confidence |")
        lines.append("|-------------|-----------------|--------|----------|--------------------|")
        for platform_name in platforms_found:
            platform_arts = [a for a in report.all_artifacts
                             if a.suspected_platform.value == platform_name]
            p_direct = sum(1 for a in platform_arts
                          if a.classification == EvidenceClassification.DIRECT)
            p_inferred = len(platform_arts) - p_direct
            confidence_levels = [a.confidence for a in platform_arts]
            highest = "Unsupported"
            for level in (ConfidenceLevel.HIGH, ConfidenceLevel.MODERATE,
                          ConfidenceLevel.LOW, ConfidenceLevel.UNSUPPORTED):
                if level in confidence_levels:
                    highest = level.value
                    break
            lines.append(f"| {platform_name} | {len(platform_arts)} | {p_direct} | "
                          f"{p_inferred} | {highest} |")
        lines.append("")
        finding_num += 1

        # --- b. Per-platform detailed findings with LLM narrative + exhibits ---
        for fp in report.ai_footprints:
            platform_exhibits = self.exhibit_manager.get_exhibits_for_platform(fp.platform.value)

            # Build exhibit data for LLM
            exhibit_data = []
            for ex in platform_exhibits[:10]:
                exhibit_data.append({
                    "exhibit_number": ex.exhibit_number,
                    "description": ex.description,
                    "evidence_path": ex.full_evidence_reference,
                    "confidence": ex.confidence,
                    "timestamp": ex.timestamp or "N/A",
                })

            lines.append(f"**{finding_num}. {fp.platform.value} — Detailed Findings**")
            lines.append("")

            # LLM-generated narrative
            narrative = generate_finding_narrative(
                finding_number=finding_num,
                platform_name=fp.platform.value,
                total_artifacts=fp.total_artifacts,
                direct_count=fp.direct_artifacts,
                inferred_count=fp.inferred_artifacts,
                overall_confidence=fp.overall_confidence.value,
                access_mode=fp.access_mode.value if fp.access_mode else "Unknown",
                earliest_activity=(fp.earliest_activity.strftime('%Y-%m-%d %H:%M:%S UTC')
                                   if fp.earliest_activity else "N/A"),
                latest_activity=(fp.latest_activity.strftime('%Y-%m-%d %H:%M:%S UTC')
                                 if fp.latest_activity else "N/A"),
                estimated_sessions=fp.estimated_session_count,
                model_name=fp.model.value if fp.model else "Unknown",
                exhibits=exhibit_data,
                caveats=fp.caveats,
            )
            lines.append(narrative)
            lines.append("")

            # Embed exhibit references directly in findings
            if platform_exhibits:
                lines.append(f"**Supporting Evidence Exhibits:**")
                lines.append("")
                for ex in platform_exhibits:
                    lines.append(generate_exhibit_reference_md(ex))
                lines.append("")

            finding_num += 1

        # --- c. Browser vs. App Analysis ---
        from .models import AccessMode
        browser_arts = [a for a in report.all_artifacts
                        if a.suspected_access_mode == AccessMode.BROWSER]
        app_arts = [a for a in report.all_artifacts
                    if a.suspected_access_mode == AccessMode.NATIVE_APP]

        lines.append(f"**{finding_num}. Browser vs. Native App Analysis**")
        lines.append("")
        lines.append(f"- Browser-based artifacts: **{len(browser_arts)}**")
        lines.append(f"- Native app artifacts: **{len(app_arts)}**")
        if browser_arts and not app_arts:
            lines.append("- AI platforms appear to have been accessed exclusively via web browser.")
        elif app_arts and not browser_arts:
            lines.append("- AI platforms appear to have been accessed exclusively via native applications.")
        elif browser_arts and app_arts:
            lines.append("- AI platforms were accessed via both web browser and native applications.")
        lines.append("")
        finding_num += 1

        # --- d. Crime Scene Image Indicators ---
        image_arts = [
            a for a in report.all_artifacts
            if any(kw in (a.extracted_indicator or "").lower()
                   for kw in ["image", "upload", "photo", "camera",
                              "crime scene", "screenshot", "picture"])
        ]
        lines.append(f"**{finding_num}. Crime-Scene Image Analysis Indicators**")
        lines.append("")
        if image_arts:
            for art in image_arts:
                # Find corresponding exhibit
                art_exhibits = [
                    ex for ex in self.exhibit_manager.get_all()
                    if ex.evidence_path == art.artifact_path
                    and ex.platform == art.suspected_platform.value
                ]
                ex_ref = f" (Exhibit {art_exhibits[0].exhibit_number})" if art_exhibits else ""
                lines.append(f"- **{art.suspected_platform.value}:** "
                              f"{art.extracted_indicator[:150]} "
                              f"(Confidence: {art.confidence.value}){ex_ref}")
                if art_exhibits:
                    lines.append(f"  - E01 Path: `{art_exhibits[0].full_evidence_reference}`")
            lines.append("")
        else:
            lines.append("No direct evidence of crime-scene image upload or analysis was identified.")
            lines.append("")
            lines.append("*Note: Image-analysis activity should only be concluded when supported "
                         "by uploads, file references, session records, app traces, screenshots, "
                         "or timestamp correlation.*")
            lines.append("")
        finding_num += 1

        # --- e. Timeline ---
        lines.append(f"**{finding_num}. Timeline of AI-Related Activity**")
        lines.append("")
        if report.timeline:
            lines.append("| # | Timestamp (UTC) | Platform | Event | Confidence | Exhibit |")
            lines.append("|---|-----------------|----------|-------|------------|---------|")
            for idx, ev in enumerate(report.timeline[:50], 1):
                ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "N/A"
                desc_short = ev.description[:60] if ev.description else ""
                # Find exhibit for this event
                ex_ref = ""
                for ex in self.exhibit_manager.get_all():
                    if ex.platform == ev.platform.value and ex.timestamp == (
                        ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if ev.timestamp else None
                    ):
                        ex_ref = f"Ex. {ex.exhibit_number}"
                        break
                lines.append(f"| {idx} | {ts_str} | {ev.platform.value} | "
                              f"{desc_short} | {ev.confidence.value} | {ex_ref} |")
            if len(report.timeline) > 50:
                lines.append(f"| ... | ... | ... | ... | ... | ... |")
            lines.append("")
        else:
            lines.append("No timestamped AI-related events could be reconstructed from the evidence.")
            lines.append("")
        finding_num += 1

        # --- f. Comparative Artifact Matrix ---
        lines.append(f"**{finding_num}. Comparative Artifact Matrix**")
        lines.append("")
        if report.matrix_rows:
            lines.append("| Platform | Artifact Type | Access Mode | Evidentiary Value | "
                          "Confidence | Crime Scene Relevance |")
            lines.append("|----------|---------------|-------------|-------------------|"
                          "------------|----------------------|")
            for r in report.matrix_rows[:50]:
                lines.append(
                    f"| {r.platform.value} | {r.artifact_type} | {r.browser_vs_app.value} | "
                    f"{r.evidentiary_value} | {r.confidence.value} | "
                    f"{r.relevance_to_crime_scene[:40]} |"
                )
            if len(report.matrix_rows) > 50:
                lines.append(f"| ... | ... | ... | ... | ... | ... |")
            lines.append("")
        else:
            lines.append("No artifacts available for matrix construction.")
            lines.append("")
        finding_num += 1

        # --- g. Evidence Coverage ---
        self._evidence_coverage_subsection(lines, report)

    def _evidence_coverage_subsection(self, lines: List[str], report: ForensicReport):
        """Evidence coverage assessment sub-section."""
        cov = report.evidence_coverage
        lines.append("**Evidence Coverage Assessment**")
        lines.append("")
        lines.append(f"- Image Type: {cov.image_type.value}")
        lines.append(f"- Full Disk Available: {'Yes' if cov.full_disk_available else 'No'}")
        lines.append(f"- Partitions Accessible: {cov.partitions_accessible} / {cov.partitions_total}")
        lines.append(f"- Encrypted Areas: {'Detected' if cov.encrypted_areas_detected else 'Not detected'}")
        lines.append(f"- File Carving: {'Enabled' if cov.carving_enabled else 'Disabled'}")
        if cov.browsers_detected:
            lines.append(f"- Browsers Detected: {', '.join(cov.browsers_detected)}")
        if cov.artifact_families_available:
            lines.append(f"- Artifact Families Found: {', '.join(cov.artifact_families_available)}")
        if cov.artifact_families_missing:
            lines.append(f"- Artifact Families Missing: {', '.join(cov.artifact_families_missing)}")
        lines.append("")

        if cov.coverage_notes:
            for note in cov.coverage_notes:
                lines.append(f"- *{note}*")
            lines.append("")

        if cov.limitations:
            lines.append("**Limitations:**")
            for lim in cov.limitations:
                lines.append(f"- {lim}")
            lines.append("")

        if cov.parsers_stub:
            lines.append("**Stub Parsers (not fully implemented in this version):**")
            for ps in cov.parsers_stub:
                lines.append(f"- {ps}")
            lines.append("")

    # ------------------------------------------------------------------
    # Section 3b — FRAUE Findings (TRACE-AI-FR event-level findings)
    # ------------------------------------------------------------------
    def _fraue_findings(self, lines: List[str], report: ForensicReport):
        """FRAUE event-level findings section."""
        if not report.fraues:
            return

        lines.append("# Forensically Reconstructed AI-Use Events (FRAUEs)")
        lines.append("")
        lines.append(
            "Each FRAUE represents a time-bounded, platform-attributed episode of "
            "probable AI-system interaction, reconstructed from corroborated endpoint "
            "artifacts and reported with explicit confidence and uncertainty."
        )
        lines.append("")

        # Summary table
        lines.append("| FRAUE ID | Platform | Activity | Time Window | "
                      "Event Confidence | Claim Level | Artifacts |")
        lines.append("|----------|----------|----------|-------------|"
                      "-----------------|-------------|-----------|")
        for f in report.fraues:
            window = ""
            if f.window_start and f.window_end:
                window = (f"{f.window_start.strftime('%m/%d %H:%M')}"
                          f" — {f.window_end.strftime('%m/%d %H:%M')}")
            elif f.window_start:
                window = f.window_start.strftime("%m/%d %H:%M")
            lines.append(
                f"| {f.fraue_id} | {f.platform.value} | "
                f"{f.likely_activity_class or '—'} | {window or '—'} | "
                f"{f.event_confidence.value} | {f.claim_level.value} | "
                f"{len(f.artifact_ids)} |"
            )
        lines.append("")

        # Per-FRAUE detail
        for i, f in enumerate(report.fraues, 1):
            lines.append(f"### FRAUE {i}: {f.fraue_id}")
            lines.append("")
            lines.append(f"- **Platform:** {f.platform.value}")
            lines.append(f"- **Activity Class:** {f.likely_activity_class or 'Unclassified'}")
            lines.append(f"- **Event Confidence:** {f.event_confidence.value}")
            lines.append(f"- **Claim Level:** {f.claim_level.value}")
            lines.append(f"- **Corroboration Met:** {'Yes' if f.corroboration_met else 'No'}")
            lines.append(f"- **Persistence State:** {f.persistence_state.value}")
            lines.append(f"- **Artifact Families:** {f.artifact_family_count}")
            lines.append(f"- **Source Diversity:** {f.source_diversity} classes")
            cc = getattr(f, 'confidence_class', None)
            if cc:
                cc_val = cc.value if hasattr(cc, 'value') else str(cc)
                lines.append(f"- **Evidence Confidence Class:** {cc_val}")
            acq = getattr(f, 'acquisition_sources', None)
            if acq:
                lines.append(f"- **Acquisition Sources:** {', '.join(a.value if hasattr(a, 'value') else str(a) for a in acq)}")
            surf = getattr(f, 'platform_surfaces', None)
            if surf:
                lines.append(f"- **Platform Surfaces:** {', '.join(s.value if hasattr(s, 'value') else str(s) for s in surf)}")
            if f.caveats:
                lines.append(f"- **Caveats:**")
                for c in f.caveats:
                    lines.append(f"  - {c}")
            if f.alternative_explanations:
                lines.append(f"- **Alternative Explanations:**")
                for a in f.alternative_explanations:
                    lines.append(f"  - {a}")
            lines.append("")

    # ------------------------------------------------------------------
    # Section 3b.4 — v4.0 Evidence Sections
    # ------------------------------------------------------------------
    def _v4_evidence_sections(self, lines: List[str], report: ForensicReport):
        """Voice evidence, shared links, generated assets, confidence class summary."""
        # Voice evidence
        voice = getattr(report, 'voice_evidence', [])
        if voice:
            lines.append("# Voice / Audio Evidence")
            lines.append("")
            lines.append(f"{len(voice)} voice evidence record(s) identified.")
            lines.append("")
            lines.append("| Type | Platform | Source | Duration | Confidence |")
            lines.append("|------|----------|--------|----------|------------|")
            for v in voice:
                vtype = str(getattr(v, 'artifact_type', ''))
                vplat = str(getattr(v, 'platform', ''))
                vsrc = os.path.basename(str(getattr(v, 'source_path', '')))
                vdur = getattr(v, 'duration_seconds', None)
                vdur_s = f"{vdur:.0f}s" if vdur else "N/A"
                vconf = str(getattr(v, 'confidence', ''))
                lines.append(f"| {vtype} | {vplat} | {vsrc} | {vdur_s} | {vconf} |")
            lines.append("")

        # Shared links
        shared = getattr(report, 'shared_links', [])
        if shared:
            lines.append("# Shared AI Platform Links")
            lines.append("")
            lines.append(f"{len(shared)} shared link(s) detected in evidence.")
            lines.append("")
            for sl in shared:
                url = getattr(sl, 'url', 'N/A')
                plat = str(getattr(sl, 'platform', 'Unknown'))
                lines.append(f"- **[{plat}]** {url}")
            lines.append("")

        # Generated assets
        assets = getattr(report, 'generated_assets', [])
        if assets:
            lines.append("# AI-Generated Assets")
            lines.append("")
            lines.append(f"{len(assets)} AI-generated asset(s) detected.")
            lines.append("")
            for ga in assets:
                path = os.path.basename(str(getattr(ga, 'asset_path', 'N/A')))
                plat = str(getattr(ga, 'platform', 'Unknown'))
                c2pa = "Yes" if getattr(ga, 'c2pa_detected', False) else "No"
                lines.append(f"- **{path}** — Platform: {plat}, C2PA: {c2pa}")
            lines.append("")

        # Confidence class summary
        if report.fraues:
            cc_counts = {}
            for f in report.fraues:
                cc = getattr(f, 'confidence_class', None)
                label = cc.value if hasattr(cc, 'value') else str(cc) if cc else "UNCLASSIFIED"
                cc_counts[label] = cc_counts.get(label, 0) + 1
            if cc_counts:
                lines.append("# Evidence Confidence Class Summary")
                lines.append("")
                for label, count in sorted(cc_counts.items()):
                    lines.append(f"- **{label}:** {count} FRAUE(s)")
                lines.append("")

    # ------------------------------------------------------------------
    # Section 3b.5 — Examination Questions
    # ------------------------------------------------------------------
    def _examination_questions_section(self, lines: List[str], report: ForensicReport):
        """Examination questions and forensic answers."""
        if not report.examination_questions:
            return

        lines.append("# Examination Questions and Forensic Answers")
        lines.append("")
        lines.append("The following examination questions were provided via Word document "
                      "and answered based on the forensic analysis results.")
        lines.append("")

        for q in report.examination_questions:
            lines.append(f"## Question {q.number}")
            lines.append("")
            lines.append(f"**Q:** {q.text}")
            lines.append("")
            if q.answer:
                lines.append(f"**A:** {q.answer}")
            else:
                lines.append("**A:** No forensic answer could be determined from "
                             "the available evidence.")
            if q.evidence_references:
                lines.append("")
                lines.append("**Evidence References:**")
                for ref in q.evidence_references:
                    lines.append(f"- FRAUE `{ref}`")
            lines.append("")

    # ------------------------------------------------------------------
    # Section 3b.6 — Functional Requirements Assessment (FR-1 – FR-9)
    # ------------------------------------------------------------------
    def _fr_assessment_section(self, lines: List[str], report: ForensicReport):
        """Functional requirements assessment against AI-forensics research gaps."""
        if not report.fr_assessments:
            return

        lines.append("# Functional Requirements Assessment (FR-1 – FR-9)")
        lines.append("")
        lines.append(
            "The following assessment evaluates this analysis against 9 functional "
            "requirements derived from current AI-forensics research gaps "
            "(Magnet AXIOM, NIST Generative AI Profile, C2PA, academic literature)."
        )
        lines.append("")
        lines.append(
            "> **Research synthesis:** The state of the art has progressed from "
            "'no AI artifact support' to 'partial, app-specific artifact recovery,' "
            "but it still lacks an end-to-end AI-forensics evidence model that "
            "consistently unifies acquisition, session reconstruction, provenance, "
            "detector validation, third-party dependency tracing, and standardized "
            "evidentiary export."
        )
        lines.append("")

        # Summary table
        lines.append("## Assessment Summary")
        lines.append("")
        lines.append("| FR | Requirement | Status |")
        lines.append("|:---:|:---|:---|")
        for fr in report.fr_assessments:
            status = fr.status.value if hasattr(fr.status, "value") else str(fr.status)
            icon = {"Fully Addressed": "✅", "Partially Addressed": "⚠️",
                    "Gap Identified": "❌", "Not Applicable": "➖"}.get(status, "•")
            lines.append(f"| {fr.fr_id} | {fr.title} | {icon} {status} |")
        lines.append("")

        # Per-FR detail
        for fr in report.fr_assessments:
            status = fr.status.value if hasattr(fr.status, "value") else str(fr.status)
            lines.append(f"## {fr.fr_id}: {fr.title}")
            lines.append("")
            lines.append(f"**Status:** {status}")
            lines.append("")
            lines.append(f"*{fr.description}*")
            lines.append("")
            if fr.capability_summary:
                lines.append(f"**Capability:** {fr.capability_summary}")
                lines.append("")
            if fr.evidence_from_analysis:
                lines.append("**Evidence from analysis:**")
                for e in fr.evidence_from_analysis:
                    lines.append(f"- {e}")
                lines.append("")
            if fr.gaps:
                lines.append("**Identified gaps:**")
                for g in fr.gaps:
                    lines.append(f"- ⚠ {g}")
                lines.append("")

        # Caveats (shared across all FRs)
        if report.fr_assessments and report.fr_assessments[0].caveats:
            lines.append("## Key Caveats")
            lines.append("")
            for c in report.fr_assessments[0].caveats:
                lines.append(f"- {c}")
            lines.append("")

    # ------------------------------------------------------------------
    # AI Tool Checklist Section (v5.0)
    # ------------------------------------------------------------------
    def _ai_tool_checklist_section(self, lines: List[str], report: ForensicReport):
        """Appendix: AI Tool Inventory Checklist (v5.0)."""
        checklist = getattr(report, "forensic_checklist", [])
        if not checklist:
            return

        lines.append("# Appendix: AI Tool Inventory Checklist (v5.0)")
        lines.append("")
        lines.append(
            "> **IMPORTANT CAVEAT:** The presence of an AI tool installation, configuration "
            "file, or browser access record does NOT establish that the tool was actively used "
            "for any specific task. Presence of artifacts is NOT equivalent to use. "
            "Attribution of tool use to a specific individual requires corroborating evidence "
            "beyond installation artifacts. Negative findings are scoped to the evidence "
            "examined and do not exclude tool use via other devices, cloud accounts, "
            "or portable installations not present in the evidence."
        )
        lines.append("")

        n_found = sum(1 for e in checklist
                      if str(getattr(e, "evidence_status", "")).replace("EvidenceStatus.", "") == "FOUND")
        n_total = len(checklist)
        lines.append(f"**{n_found} of {n_total} registered AI tools detected in evidence.**")
        lines.append("")

        lines.append("## Summary Table")
        lines.append("")
        lines.append(
            "| Tool Name | Category | Evidence Status | Confidence | "
            "Execution Surface | Artifact Count | Key Caveats |"
        )
        lines.append(
            "|:----------|:---------|:----------------|:-----------|"
            ":-----------------|:--------------|:------------|"
        )
        for entry in checklist:
            status = str(getattr(entry, "evidence_status", "")).replace("EvidenceStatus.", "")
            icon = {"FOUND": "✅", "NOT_FOUND": "❌", "NOT_VERIFIED": "⚠️", "PARTIAL": "🔶"}.get(status, "•")
            caveats = [str(f).replace("CaveatFlag.", "") for f in (getattr(entry, "caveat_flags", []) or [])]
            key_caveats = ", ".join(caveats[:3]) if caveats else "—"
            lines.append(
                f"| {entry.tool_name} | {entry.category} | {icon} {status} "
                f"| {getattr(entry, 'confidence', 'N/A') or 'N/A'} "
                f"| {getattr(entry, 'execution_surface', '—') or '—'} "
                f"| {getattr(entry, 'artifact_count', 0)} "
                f"| {key_caveats} |"
            )
        lines.append("")

        # Detail entries for FOUND tools only
        found_entries = [
            e for e in checklist
            if str(getattr(e, "evidence_status", "")).replace("EvidenceStatus.", "") == "FOUND"
        ]
        if found_entries:
            lines.append("## Detected Tools — Detail")
            lines.append("")
            for entry in found_entries:
                lines.append(f"### {entry.tool_name}")
                lines.append("")
                lines.append(f"**Category:** {entry.category}")
                lines.append(f"**Detection Method:** {getattr(entry, 'detection_method', '—') or '—'}")
                lines.append(f"**Execution Surface:** {getattr(entry, 'execution_surface', '—') or '—'}")
                lines.append(f"**Inference Location:** {getattr(entry, 'inference_location', 'UNKNOWN') or 'UNKNOWN'}")
                corr = str(getattr(entry, "corroboration_level", "")).replace("CorroborationLevel.", "")
                attr = str(getattr(entry, "attribution_scope", "")).replace("AttributionScope.", "")
                lines.append(f"**Corroboration Level:** {corr}")
                lines.append(f"**Attribution Scope:** {attr}")
                if getattr(entry, "artifact_paths", None):
                    lines.append("**Matched Artifact Path(s):**")
                    for p in entry.artifact_paths:
                        lines.append(f"- `{p}`")
                caveats = [str(f).replace("CaveatFlag.", "") for f in (getattr(entry, "caveat_flags", []) or [])]
                if caveats:
                    lines.append("**Caveats:**")
                    for c in caveats:
                        lines.append(f"- {c}")
                # Resolved caveat language
                try:
                    from .caveats import get_caveat_text
                    caveat_texts = get_caveat_text(getattr(entry, "caveat_flags", []) or [])
                    if caveat_texts:
                        lines.append("")
                        lines.append("**Caveat Enforcement Notes:**")
                        for ct in caveat_texts:
                            lines.append(f"> ⚠ {ct}")
                except Exception:
                    pass
                if getattr(entry, "notes", ""):
                    lines.append(f"**Notes:** {entry.notes}")
                lines.append("")

        # Global report footer
        try:
            from .caveats import GLOBAL_REPORT_FOOTER
            lines.append("---")
            lines.append("")
            lines.append(f"> {GLOBAL_REPORT_FOOTER}")
            lines.append("")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Recovery Findings Section (v3.0)
    # ------------------------------------------------------------------
    def _recovery_findings(self, lines: List[str], report: ForensicReport):
        """Evidence health, recovery findings, carved artifacts, raw hits."""
        has_recovery = (
            getattr(report, "recovery_audit", None)
            or getattr(report, "carved_artifacts", None)
            or getattr(report, "raw_hits", None)
            or getattr(report, "partition_findings", None)
        )
        if not has_recovery:
            return

        lines.append("# Recovery and Evidence Health Findings")
        lines.append("")

        # Evidence Health Summary
        fs_health = getattr(report, "filesystem_health", None)
        access_tier = getattr(report, "evidence_access_tier", None)
        recovery_mode = getattr(report, "recovery_mode_used", None)

        if fs_health or access_tier or recovery_mode:
            lines.append("## Evidence Health Summary")
            lines.append("")
            if fs_health:
                lines.append(f"- **Filesystem Health:** {fs_health.value if hasattr(fs_health, 'value') else fs_health}")
            if access_tier:
                lines.append(f"- **Evidence Access Tier:** {access_tier.value if hasattr(access_tier, 'value') else access_tier}")
            if recovery_mode:
                lines.append(f"- **Recovery Mode:** {recovery_mode.value if hasattr(recovery_mode, 'value') else recovery_mode}")
            lines.append("")

        # Partition Findings
        pf = getattr(report, "partition_findings", None)
        if pf:
            lines.append("## Partition Findings")
            lines.append("")
            lines.append("| Index | Scheme | FS Type | Offset | Size | Health |")
            lines.append("|-------|--------|---------|--------|------|--------|")
            for f in pf:
                lines.append(
                    f"| {f.partition_index} | {f.scheme.value} | {f.fs_type_label} | "
                    f"{f.offset:#x} | {f.size_bytes:,} | {f.health.value} |"
                )
            lines.append("")

        # Carved Artifacts
        ca = getattr(report, "carved_artifacts", None)
        if ca:
            lines.append("## Carved Artifacts")
            lines.append("")
            lines.append(f"Total carved: **{len(ca)}**")
            lines.append("")
            lines.append("| Filename | Rule | Offset | Size | Validation | Confidence |")
            lines.append("|----------|------|--------|------|------------|------------|")
            for c in ca[:50]:
                lines.append(
                    f"| {c.carved_filename} | {c.signature_rule_used} | "
                    f"{c.offset:#x} | {c.recovered_size:,} | "
                    f"{c.validation.value} | {c.confidence_hint.value} |"
                )
            if len(ca) > 50:
                lines.append(f"| ... | *{len(ca) - 50} more* | | | | |")
            lines.append("")

        # Raw Hits
        rh = getattr(report, "raw_hits", None)
        if rh:
            lines.append("## Raw Byte Hits")
            lines.append("")
            lines.append(f"Total raw hits: **{len(rh)}**")
            lines.append("")
            lines.append("| Type | Pattern | Offset | Platform | Confidence |")
            lines.append("|------|---------|--------|----------|------------|")
            for h in rh[:50]:
                lines.append(
                    f"| {h.hit_type.value} | {h.matched_pattern} | "
                    f"{h.offset:#x} | {h.suspected_platform.value} | {h.confidence_hint.value} |"
                )
            if len(rh) > 50:
                lines.append(f"| ... | *{len(rh) - 50} more* | | | |")
            lines.append("")

        # Acquisition caveats
        acq = getattr(report, "acquisition_metadata", None)
        if acq:
            lines.append("## Acquisition Quality")
            lines.append("")
            lines.append(f"- **Quality:** {acq.quality.value}")
            if acq.percent_readable < 100.0:
                lines.append(f"- **Readable:** {acq.percent_readable:.1f}%")
            if acq.bad_sector_count > 0:
                lines.append(f"- **Bad Sectors:** {acq.bad_sector_count:,}")
            if acq.notes:
                lines.append(f"- **Notes:** {acq.notes}")
            lines.append("")

        # Recovery audit summary
        audit = getattr(report, "recovery_audit", None)
        if audit:
            lines.append("## Recovery Audit")
            lines.append("")
            if audit.caveats:
                lines.append("**Caveats:**")
                for c in audit.caveats:
                    lines.append(f"- {c}")
                lines.append("")
            if audit.provenance_note:
                lines.append(f"**Provenance:** {audit.provenance_note}")
                lines.append("")

        # Non-recovery limitations (Rule 6)
        lines.append("## Non-Recovery Limitations")
        lines.append("")
        lines.append(
            "Absence of recovered artifacts within this scope does **not** "
            "constitute proof that AI tools were not used. Recovery is bounded "
            "by filesystem health, acquisition quality, and the signature rules "
            "applied. See Inference Boundaries for full constraints."
        )
        lines.append("")

    # ------------------------------------------------------------------
    # Section 3c — Inference Boundaries & Governance
    # ------------------------------------------------------------------
    def _inference_boundaries(self, lines: List[str], report: ForensicReport):
        """Inference boundaries and scope of conclusion."""
        if not report.inference_boundaries and not report.scope_of_conclusion:
            return

        lines.append("# Inference Boundaries and Operational Controls")
        lines.append("")

        if report.inference_boundaries:
            lines.append("The following boundaries constrain all conclusions in this report:")
            lines.append("")
            for b in report.inference_boundaries:
                lines.append(f"- {b}")
            lines.append("")

        if report.scope_of_conclusion:
            lines.append("## Scope of Conclusion")
            lines.append("")
            lines.append(report.scope_of_conclusion)
            lines.append("")

        gov = report.governance_record
        if gov:
            lines.append("## Governance Record Summary")
            lines.append("")
            lines.append(f"- **Framework:** {gov.framework_name} v{gov.framework_version}")
            lines.append(f"- **Validation State:** {gov.validation_state.value}")
            lines.append(f"- **Collection Scope:** {gov.collection_scope or 'Not specified'}")
            if gov.known_blind_spots:
                lines.append("- **Known Blind Spots:**")
                for bs in gov.known_blind_spots:
                    lines.append(f"  - {bs}")
            if gov.required_disclosures:
                lines.append("- **Required Disclosures (Rule 11):**")
                for d in gov.required_disclosures:
                    lines.append(f"  - {d}")
            # v4.0 governance fields
            pcbs = getattr(gov, 'provider_capability_blind_spots', None)
            if pcbs:
                lines.append("- **Provider Capability Blind Spots:**")
                for bs in pcbs:
                    lines.append(f"  - {bs}")
            acq_bs = getattr(gov, 'acquisition_blind_spots', None)
            if acq_bs:
                lines.append("- **Acquisition Blind Spots:**")
                for bs in acq_bs:
                    lines.append(f"  - {bs}")
            sc = getattr(gov, 'surface_coverage_summary', None)
            if sc:
                lines.append("- **Platform Surface Coverage:**")
                for s in sc:
                    lines.append(f"  - {s}")
            des = getattr(gov, 'direct_evidence_summary', None)
            if des:
                lines.append("- **Direct Evidence:**")
                for s in des:
                    lines.append(f"  - {s}")
            ces = getattr(gov, 'corroborating_evidence_summary', None)
            if ces:
                lines.append("- **Corroborating Evidence:**")
                for s in ces:
                    lines.append(f"  - {s}")
            mes = getattr(gov, 'missing_evidence_summary', None)
            if mes:
                lines.append("- **Missing / Expected Evidence:**")
                for s in mes:
                    lines.append(f"  - {s}")
            ae = getattr(gov, 'alternative_explanations', None)
            if ae:
                lines.append("- **Alternative Explanations:**")
                for s in ae:
                    lines.append(f"  - {s}")
            lines.append("")

    # ------------------------------------------------------------------
    # Section 4 — Conclusion (LLM-enhanced)
    # ------------------------------------------------------------------
    def _conclusion(self, lines: List[str], report: ForensicReport):
        lines.append("# Conclusion")
        lines.append("")

        platforms_data = []
        for fp in report.ai_footprints:
            platforms_data.append({
                "name": fp.platform.value,
                "confidence": fp.overall_confidence.value,
                "total": fp.total_artifacts,
                "direct": fp.direct_artifacts,
            })

        narrative = generate_conclusion_narrative(
            platforms_found=platforms_data,
            total_artifacts=len(report.all_artifacts),
            carving_enabled=report.carving_enabled,
            full_disk=report.evidence_coverage.full_disk_available,
        )
        lines.append(narrative)
        lines.append("")

        # Global evidentiary caveat footer
        try:
            from .caveats import GLOBAL_REPORT_FOOTER
            lines.append("---")
            lines.append("")
            lines.append(f"> **Evidentiary Notice:** {GLOBAL_REPORT_FOOTER}")
            lines.append("")
        except Exception:
            pass

        # AI assistance disclosure
        lines.append("---")
        lines.append("")
        lines.append(
            "> **Recommended Notice:** Portions of this report were prepared with AI assistance. "
            "Review and validation by a qualified human investigator are strongly recommended "
            "before submission for any legal, forensic, or official purpose."
        )
        lines.append("")

    # ------------------------------------------------------------------
    # Exhibit Appendix
    # ------------------------------------------------------------------
    def _exhibit_appendix(self, lines: List[str], report: ForensicReport):
        """Appendix listing all exhibits with full E01 paths."""
        all_exhibits = self.exhibit_manager.get_all()
        if not all_exhibits:
            return

        lines.append("# Appendix: Evidence Exhibits")
        lines.append("")
        lines.append(f"*Total exhibits: {len(all_exhibits)}*")
        lines.append("")

        lines.append("| Exhibit # | Platform | Artifact Type | E01 Source Path | Confidence | Timestamp |")
        lines.append("|-----------|----------|---------------|-----------------|------------|-----------|")
        for ex in all_exhibits:
            ts = ex.timestamp or "N/A"
            lines.append(
                f"| {ex.exhibit_number} | {ex.platform} | {ex.artifact_family} | "
                f"`{ex.full_evidence_reference}` | {ex.confidence} | {ts} |"
            )
        lines.append("")

        # Detailed exhibit listing
        for ex in all_exhibits[:100]:
            lines.append(generate_exhibit_reference_md(ex))

        if len(all_exhibits) > 100:
            lines.append(f"*({len(all_exhibits) - 100} additional exhibits omitted. "
                         f"See JSON export for complete listing.)*")
            lines.append("")

    # ------------------------------------------------------------------
    # Section 5 — Signature Block
    # ------------------------------------------------------------------
    def _signature_block(self, lines: List[str], report: ForensicReport):
        lines.append("---")
        lines.append("")
        lines.append("Signed:")
        lines.append("")
        examiner = report.case_info.examiner or "Digital Forensics Examiner"
        org = report.case_info.organization or "UNCC Forensics Lab"
        lines.append(f"*{examiner}*")
        lines.append("")
        lines.append("_________________________")
        lines.append("")
        lines.append(f"{examiner}  ")
        lines.append(f"Digital Forensics Examiner  ")
        lines.append(f"{org}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated by TRACE-AI-FR v{report.tool_version}*  ")
        lines.append(f"*Generated on: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}*")


# ---------------------------------------------------------------------------
# HTML Report Generator — SANS / UNCC Forensic Report Standard
# ---------------------------------------------------------------------------

class HTMLReportGenerator:
    """Generate an interactive HTML forensic report with TRACE-AI-FR branding."""

    def generate(self, report: ForensicReport, output_path: str,
                 evidence_root: str = "",
                 exhibit_manager: Optional[ExhibitManager] = None):
        """Generate HTML report from the ForensicReport."""
        output_dir = os.path.dirname(output_path) or "."

        # Build the Markdown version first (also builds exhibits)
        md_gen = MarkdownReportGenerator()
        if not exhibit_manager:
            exhibit_manager = ExhibitManager(
                output_dir=output_dir,
                evidence_source=report.evidence_info.image_path or "",
            )
        md_gen.exhibit_manager = exhibit_manager
        md_gen._build_exhibits(report, evidence_root)

        md_lines: List[str] = []
        md_gen._header_block(md_lines, report)
        md_gen._overview(md_lines, report)
        md_gen._acquisition_and_preparation(md_lines, report)
        md_gen._findings_and_report(md_lines, report)
        md_gen._recovery_findings(md_lines, report)
        md_gen._fraue_findings(md_lines, report)
        md_gen._examination_questions_section(md_lines, report)
        md_gen._fr_assessment_section(md_lines, report)
        md_gen._ai_tool_checklist_section(md_lines, report)
        md_gen._inference_boundaries(md_lines, report)
        md_gen._conclusion(md_lines, report)
        md_gen._exhibit_appendix(md_lines, report)
        md_gen._signature_block(md_lines, report)

        md_content = "\n".join(md_lines)
        html_body = self._md_to_html(md_content)

        # Build FRAUE cards and governance sections
        fraue_html = self._build_fraue_section(report)
        governance_html = self._build_governance_section(report)
        dashboard_html = self._build_dashboard(report)

        html = self._wrap_html(
            title=f"TRACE-AI-FR — Case {report.case_info.case_id}",
            dashboard=dashboard_html,
            body=html_body,
            fraue_section=fraue_html,
            governance_section=governance_html,
            report=report,
        )

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"HTML report generated: {output_path}")

    def _build_dashboard(self, report: ForensicReport) -> str:
        """Build a visual stats dashboard."""
        artifact_count = len(report.all_artifacts)
        timeline_count = len(report.timeline)
        footprint_count = len(report.ai_footprints)
        fraue_count = len(report.fraues) if report.fraues else 0
        parser_count = len(report.parser_results)

        direct = sum(1 for a in report.all_artifacts
                     if a.classification == EvidenceClassification.DIRECT)
        inferred = artifact_count - direct

        platforms = sorted(set(
            a.suspected_platform.value for a in report.all_artifacts
            if a.suspected_platform != AIPlatform.UNKNOWN
        ))

        cards = f"""
        <div class="dashboard">
            <div class="stat-card stat-primary">
                <div class="stat-number">{artifact_count}</div>
                <div class="stat-label">Artifacts</div>
                <div class="stat-detail">{direct} direct · {inferred} inferred</div>
            </div>
            <div class="stat-card stat-accent">
                <div class="stat-number">{fraue_count}</div>
                <div class="stat-label">FRAUEs</div>
                <div class="stat-detail">Reconstructed Events</div>
            </div>
            <div class="stat-card stat-success">
                <div class="stat-number">{len(platforms)}</div>
                <div class="stat-label">Platforms</div>
                <div class="stat-detail">{', '.join(platforms) if platforms else 'None detected'}</div>
            </div>
            <div class="stat-card stat-info">
                <div class="stat-number">{timeline_count}</div>
                <div class="stat-label">Timeline Events</div>
                <div class="stat-detail">{parser_count} parsers run</div>
            </div>
        </div>
        """
        return cards

    def _build_fraue_section(self, report: ForensicReport) -> str:
        """Build FRAUE event cards."""
        if not report.fraues:
            return ""

        cards = []
        for f in report.fraues:
            ec = f.event_confidence.value
            ec_class = {"HIGH": "conf-high", "MODERATE": "conf-moderate",
                        "LOW": "conf-low"}.get(ec, "conf-insufficient")
            cl = f.claim_level.value

            window = ""
            if f.window_start and f.window_end:
                window = (f"{f.window_start.strftime('%Y-%m-%d %H:%M')} — "
                          f"{f.window_end.strftime('%Y-%m-%d %H:%M')} UTC")
            elif f.window_start:
                window = f.window_start.strftime("%Y-%m-%d %H:%M UTC")

            caveats_html = ""
            if f.caveats:
                items = "".join(f"<li>{c}</li>" for c in f.caveats[:5])
                caveats_html = f'<div class="fraue-caveats"><strong>Caveats:</strong><ul>{items}</ul></div>'

            alt_html = ""
            if f.alternative_explanations:
                items = "".join(f"<li>{a}</li>" for a in f.alternative_explanations[:3])
                alt_html = f'<div class="fraue-alternatives"><strong>Alternative Explanations:</strong><ul>{items}</ul></div>'

            cards.append(f"""
            <div class="fraue-card">
                <div class="fraue-header">
                    <span class="fraue-id">{f.fraue_id}</span>
                    <span class="fraue-badge {ec_class}">{ec}</span>
                </div>
                <div class="fraue-body">
                    <div class="fraue-meta">
                        <div class="fraue-field"><span class="field-label">Platform</span><span class="field-value">{f.platform.value}</span></div>
                        <div class="fraue-field"><span class="field-label">Activity</span><span class="field-value">{f.likely_activity_class or '—'}</span></div>
                        <div class="fraue-field"><span class="field-label">Claim Level</span><span class="field-value">{cl}</span></div>
                        <div class="fraue-field"><span class="field-label">Artifacts</span><span class="field-value">{len(f.artifact_ids)} ({f.artifact_family_count} families)</span></div>
                        <div class="fraue-field"><span class="field-label">Time Window</span><span class="field-value">{window or '—'}</span></div>
                        <div class="fraue-field"><span class="field-label">Corroborated</span><span class="field-value">{'Yes' if f.corroboration_met else 'No'}</span></div>
                        <div class="fraue-field"><span class="field-label">Persistence</span><span class="field-value">{f.persistence_state.value}</span></div>
                    </div>
                    {caveats_html}
                    {alt_html}
                </div>
            </div>
            """)

        return f"""
        <div class="section-fraues">
            <h1>Forensically Reconstructed AI-Use Events (FRAUEs)</h1>
            <p class="section-intro">Each FRAUE represents a time-bounded, platform-attributed episode
            of probable AI-system interaction, reconstructed from corroborated endpoint artifacts and
            reported with explicit confidence and uncertainty.</p>
            <div class="fraue-grid">{''.join(cards)}</div>
        </div>
        """

    def _build_governance_section(self, report: ForensicReport) -> str:
        """Build governance / inference boundaries section."""
        parts = []

        # Inference boundaries
        boundaries = report.inference_boundaries or []
        if boundaries:
            items = "".join(f"<li>{b}</li>" for b in boundaries)
            parts.append(f"""
            <div class="governance-block">
                <h2>Inference Boundaries & Operational Controls</h2>
                <p>The following boundaries constrain all conclusions in this report
                (TRACE-AI-FR Rules 1, 3, 4, 6, 7):</p>
                <ul class="governance-list">{items}</ul>
            </div>
            """)

        # Scope of conclusion
        if report.scope_of_conclusion:
            parts.append(f"""
            <div class="governance-block">
                <h2>Scope of Conclusion</h2>
                <div class="scope-text">{report.scope_of_conclusion}</div>
            </div>
            """)

        # Governance record summary
        gov = report.governance_record
        if gov:
            disclosures = "".join(f"<li>{d}</li>" for d in gov.required_disclosures) if gov.required_disclosures else "<li>None specified</li>"
            blind_spots = "".join(f"<li>{b}</li>" for b in gov.known_blind_spots) if gov.known_blind_spots else "<li>None identified</li>"
            rules = "".join(f"<li>{r}</li>" for r in gov.rules_applied[:12]) if gov.rules_applied else ""

            parts.append(f"""
            <div class="governance-block">
                <h2>Governance Record</h2>
                <div class="governance-grid">
                    <div class="gov-field"><strong>Framework:</strong> {gov.framework_name} v{gov.framework_version}</div>
                    <div class="gov-field"><strong>Validation State:</strong> {gov.validation_state.value}</div>
                    <div class="gov-field"><strong>Collection Scope:</strong> {gov.collection_scope or 'Not specified'}</div>
                    <div class="gov-field"><strong>Signature Version:</strong> {gov.signature_version or 'N/A'}</div>
                </div>
                <details class="gov-details">
                    <summary>Required Disclosures (Rule 11)</summary>
                    <ul>{disclosures}</ul>
                </details>
                <details class="gov-details">
                    <summary>Known Blind Spots</summary>
                    <ul>{blind_spots}</ul>
                </details>
                <details class="gov-details">
                    <summary>Framework Rules Applied ({len(gov.rules_applied)})</summary>
                    <ul>{rules}</ul>
                </details>""")
            # v4.0 HTML governance blocks
            pcbs = getattr(gov, 'provider_capability_blind_spots', None)
            if pcbs:
                pcbs_items = "".join(f"<li>{b}</li>" for b in pcbs)
                parts.append(f"""
                <details class="gov-details">
                    <summary>Provider Capability Blind Spots</summary>
                    <ul>{pcbs_items}</ul>
                </details>""")
            ae = getattr(gov, 'alternative_explanations', None)
            if ae:
                ae_items = "".join(f"<li>{a}</li>" for a in ae)
                parts.append(f"""
                <details class="gov-details">
                    <summary>Alternative Explanations</summary>
                    <ul>{ae_items}</ul>
                </details>""")
            parts.append("""
            </div>
            """)

        if not parts:
            return ""

        return f"""
        <div class="section-governance">
            <h1>Governance & Inference Boundaries</h1>
            {''.join(parts)}
        </div>
        """

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"HTML report generated: {output_path}")

    def _md_to_html(self, md: str) -> str:
        """Basic Markdown to HTML converter (no external deps)."""
        import re
        lines = md.split("\n")
        html_lines = []
        in_table = False
        in_list = False

        for line in lines:
            stripped = line.strip()

            # Headings
            if stripped.startswith("# "):
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append(f"<h1>{stripped[2:]}</h1>")
            elif stripped.startswith("## "):
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append(f"<h2>{stripped[3:]}</h2>")
            elif stripped.startswith("### "):
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append(f"<h3>{stripped[4:]}</h3>")

            # Table rows
            elif stripped.startswith("|"):
                if "|---" in stripped or "|----" in stripped:
                    continue  # Skip separator rows
                cells = [c.strip() for c in stripped.split("|")[1:-1]]
                if not in_table:
                    html_lines.append('<table class="forensic-table">')
                    tag = "th"
                    in_table = True
                else:
                    tag = "td"
                row_html = "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>"
                html_lines.append(row_html)

            # Horizontal rule
            elif stripped == "---":
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append("<hr>")

            # List items
            elif stripped.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                content = stripped[2:]
                content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', content)
                content = re.sub(r'`(.+?)`', r'<code>\1</code>', content)
                html_lines.append(f"<li>{content}</li>")

            # Bold text lines
            elif stripped.startswith("**") and stripped.endswith("**"):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append(f"<p><strong>{stripped[2:-2]}</strong></p>")

            # Italic / emphasis
            elif stripped.startswith("*") and stripped.endswith("*"):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(f"<p><em>{stripped[1:-1]}</em></p>")

            # Regular text
            elif stripped:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                processed = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', stripped)
                processed = re.sub(r'`(.+?)`', r'<code>\1</code>', processed)
                html_lines.append(f"<p>{processed}</p>")
            else:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False

        if in_table:
            html_lines.append("</table>")
        if in_list:
            html_lines.append("</ul>")

        return "\n".join(html_lines)

    def _wrap_html(self, title: str, dashboard: str, body: str,
                   fraue_section: str, governance_section: str,
                   report: ForensicReport) -> str:
        org = report.case_info.organization or "UNCC Forensics Lab"
        examiner = report.case_info.examiner or "Digital Forensics Examiner"
        case_id = report.case_info.case_id
        date_str = report.generated_at.strftime('%m-%d-%Y')
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-2: #334155;
            --border: #475569;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --primary: #3b82f6;
            --primary-dim: #1d4ed8;
            --accent: #8b5cf6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #06b6d4;
        }}
        *, *::before, *::after {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.7;
            font-size: 14px;
        }}
        /* --- Top navigation / brand bar --- */
        .topbar {{
            background: linear-gradient(135deg, var(--surface) 0%, var(--surface-2) 100%);
            border-bottom: 2px solid var(--primary);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(8px);
        }}
        .brand {{
            display: flex;
            align-items: baseline;
            gap: 8px;
        }}
        .brand-name {{
            font-size: 22px;
            font-weight: 800;
            letter-spacing: 1px;
        }}
        .brand-name .t {{ color: var(--info); }}
        .brand-name .a {{ color: var(--warning); }}
        .brand-name .f {{ color: var(--success); }}
        .brand-version {{
            font-size: 12px;
            color: var(--text-dim);
            background: var(--surface-2);
            padding: 2px 8px;
            border-radius: 10px;
        }}
        .topbar-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--text-dim);
            line-height: 1.4;
        }}
        /* --- Layout --- */
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px 32px 60px;
        }}
        /* --- Dashboard cards --- */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 24px 0 32px;
        }}
        .stat-card {{
            background: var(--surface);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: 800;
            line-height: 1;
        }}
        .stat-label {{
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin: 6px 0 2px;
            color: var(--text-dim);
        }}
        .stat-detail {{
            font-size: 11px;
            color: var(--text-dim);
        }}
        .stat-primary .stat-number {{ color: var(--primary); }}
        .stat-accent .stat-number {{ color: var(--accent); }}
        .stat-success .stat-number {{ color: var(--success); }}
        .stat-info .stat-number {{ color: var(--info); }}
        /* --- Tabs navigation --- */
        .tabs {{
            display: flex;
            gap: 0;
            border-bottom: 2px solid var(--border);
            margin: 32px 0 0;
            overflow-x: auto;
        }}
        .tab {{
            padding: 12px 24px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            color: var(--text-dim);
            border-bottom: 3px solid transparent;
            transition: all 0.2s;
            white-space: nowrap;
            user-select: none;
        }}
        .tab:hover {{ color: var(--text); background: var(--surface); }}
        .tab.active {{
            color: var(--primary);
            border-bottom-color: var(--primary);
            background: var(--surface);
        }}
        .tab-content {{
            display: none;
            padding: 24px 0;
            animation: fadeIn 0.3s ease;
        }}
        .tab-content.active {{ display: block; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
        /* --- Report body (converted Markdown) --- */
        .report-body h1 {{
            color: var(--primary);
            font-size: 22px;
            font-weight: 700;
            border-bottom: 2px solid var(--surface-2);
            padding-bottom: 8px;
            margin-top: 32px;
        }}
        .report-body h2 {{
            color: var(--info);
            font-size: 18px;
            margin-top: 24px;
        }}
        .report-body h3 {{
            color: var(--accent);
            font-size: 15px;
            margin-top: 18px;
        }}
        .report-body p {{
            margin: 8px 0;
        }}
        /* --- Tables --- */
        .forensic-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 13px;
            border-radius: 8px;
            overflow: hidden;
        }}
        .forensic-table th {{
            background: var(--primary-dim);
            color: white;
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .forensic-table td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--surface-2);
        }}
        .forensic-table tr:nth-child(even) {{ background: var(--surface); }}
        .forensic-table tr:hover {{ background: var(--surface-2); }}
        /* --- FRAUE cards --- */
        .section-fraues {{ margin-top: 0; }}
        .section-fraues .section-intro {{
            color: var(--text-dim);
            font-style: italic;
            margin-bottom: 20px;
        }}
        .fraue-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
            gap: 16px;
        }}
        .fraue-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .fraue-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }}
        .fraue-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: var(--surface-2);
            border-bottom: 1px solid var(--border);
        }}
        .fraue-id {{
            font-family: 'Courier New', monospace;
            font-weight: 700;
            font-size: 13px;
            color: var(--accent);
        }}
        .fraue-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .conf-high {{ background: rgba(34,197,94,0.2); color: var(--success); border: 1px solid var(--success); }}
        .conf-moderate {{ background: rgba(245,158,11,0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .conf-low {{ background: rgba(239,68,68,0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .conf-insufficient {{ background: rgba(148,163,184,0.2); color: var(--text-dim); border: 1px solid var(--border); }}
        .fraue-body {{ padding: 16px; }}
        .fraue-meta {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
        }}
        .fraue-field {{
            display: flex;
            flex-direction: column;
        }}
        .field-label {{
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-dim);
            font-weight: 600;
        }}
        .field-value {{
            font-size: 13px;
            color: var(--text);
        }}
        .fraue-caveats, .fraue-alternatives {{
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--surface-2);
            font-size: 12px;
            color: var(--text-dim);
        }}
        .fraue-caveats ul, .fraue-alternatives ul {{
            margin: 4px 0 0;
            padding-left: 18px;
        }}
        .fraue-caveats li, .fraue-alternatives li {{
            margin: 2px 0;
        }}
        /* --- Governance section --- */
        .section-governance {{ margin-top: 0; }}
        .governance-block {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            margin: 16px 0;
        }}
        .governance-block h2 {{
            color: var(--warning);
            font-size: 18px;
            margin: 0 0 12px;
        }}
        .governance-list {{
            padding-left: 20px;
        }}
        .governance-list li {{
            margin: 4px 0;
            color: var(--text-dim);
        }}
        .scope-text {{
            background: var(--surface-2);
            border-left: 4px solid var(--warning);
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
            font-style: italic;
            color: var(--text);
        }}
        .governance-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px 24px;
            margin-bottom: 16px;
            font-size: 13px;
        }}
        .gov-field {{ color: var(--text-dim); }}
        .gov-field strong {{ color: var(--text); }}
        .gov-details {{
            margin: 8px 0;
            border: 1px solid var(--surface-2);
            border-radius: 8px;
            overflow: hidden;
        }}
        .gov-details summary {{
            padding: 10px 16px;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            background: var(--surface-2);
            color: var(--text);
            user-select: none;
        }}
        .gov-details summary:hover {{ background: var(--border); }}
        .gov-details ul {{
            padding: 8px 16px 12px 32px;
            margin: 0;
            font-size: 12px;
            color: var(--text-dim);
        }}
        /* --- Code & misc --- */
        code {{
            background: var(--surface-2);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
            font-size: 12px;
            color: var(--info);
        }}
        hr {{
            border: none;
            border-top: 1px solid var(--border);
            margin: 32px 0;
        }}
        ul {{ padding-left: 24px; }}
        li {{ margin: 3px 0; }}
        strong {{ color: var(--text); }}
        blockquote {{
            background: var(--surface);
            border-left: 4px solid var(--accent);
            padding: 12px 16px;
            margin: 12px 0;
            border-radius: 0 8px 8px 0;
            font-size: 13px;
        }}
        .footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-dim);
            font-size: 12px;
            border-top: 1px solid var(--border);
            margin-top: 48px;
        }}
        /* --- Sticky sidebar TOC (large screens) --- */
        @media (min-width: 1400px) {{
            .container {{ max-width: 1400px; }}
        }}
        /* --- Print --- */
        @media print {{
            :root {{
                --bg: #fff;
                --surface: #f8f8f8;
                --surface-2: #eee;
                --border: #ccc;
                --text: #222;
                --text-dim: #666;
            }}
            .topbar {{ position: static; }}
            .tabs {{ display: none; }}
            .tab-content {{ display: block !important; }}
            .stat-card:hover, .fraue-card:hover {{ transform: none; box-shadow: none; }}
            body {{ font-size: 11pt; }}
        }}
    </style>
</head>
<body>
    <div class="topbar">
        <div class="brand">
            <span class="brand-name">
                <span class="t">TRACE</span>-<span class="a">AI</span>-<span class="f">FR</span>
            </span>
            <span class="brand-version">v{report.tool_version}</span>
        </div>
        <div class="topbar-meta">
            {org} &middot; {examiner}<br>
            Case #{case_id} &middot; {date_str}
        </div>
    </div>

    <div class="container">
        {dashboard}

        <div class="tabs">
            <div class="tab active" onclick="switchTab(event, 'tab-report')">Forensic Report</div>
            <div class="tab" onclick="switchTab(event, 'tab-fraues')">FRAUEs</div>
            <div class="tab" onclick="switchTab(event, 'tab-governance')">Governance</div>
        </div>

        <div id="tab-report" class="tab-content active">
            <div class="report-body">
                {body}
            </div>
        </div>

        <div id="tab-fraues" class="tab-content">
            {fraue_section or '<p style="color:var(--text-dim)">No FRAUEs reconstructed for this case.</p>'}
        </div>

        <div id="tab-governance" class="tab-content">
            {governance_section or '<p style="color:var(--text-dim)">No governance record available.</p>'}
        </div>
    </div>

    <div class="footer">
        TRACE-AI-FR v{report.tool_version} &middot;
        Generated {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')} &middot;
        {org}
    </div>

    <script>
        function switchTab(e, tabId) {{
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            e.target.classList.add('active');
        }}
    </script>
</body>
</html>"""
