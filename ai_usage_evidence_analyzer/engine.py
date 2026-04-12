"""
Main analysis engine - orchestrates the TRACE-AI-FR 8-layer forensic pipeline.

Layers:
1. Evidence Scope         - ingest + OS/profile detection
2. Acquisition/Provenance - hashing, image info
3. Parsing/Normalization  - parser execution + evidence-source-class / persistence
4. Correlation/Session    - timeline reconstruction + corroboration
5. Scoring/Adjudication   - artifact confidence → FRAUE event confidence
6. Reporting              - markdown / HTML / JSON / SQLite export
7. Validation             - validation runner (optional)
8. Governance             - governance record + scope-of-conclusion
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import time
import zipfile
from datetime import datetime
from typing import List, Optional

from .models import (
    AIPlatform,
    CaseInfo,
    EvidenceCoverage,
    EvidenceImageInfo,
    ForensicReport,
    ImageType,
    OSPlatform,
    ParserResult,
    ParserStatus,
    ProcessingLog,
    RecoveryMode,
    AcquisitionQuality,
)
from .e01_handler import E01Handler, MountedEvidenceHandler, E01BinaryScanner
from .parser_registry import registry
from .correlation import CorrelationEngine, assign_evidence_source_classes
from .confidence import ConfidenceScoringEngine
from .matrix import build_comparative_matrix
from .storage import SQLiteStorage
from .report_generator import JSONExporter, MarkdownReportGenerator, HTMLReportGenerator
from .evidence_exhibit import ExhibitManager
from .persistence import assign_persistence_states
from .adjudication import AdjudicationEngine
from .governance import build_governance_record, generate_scope_of_conclusion, export_governance_record
from .docx_parser import parse_questions_from_docx
from .docx_report import generate_docx_report
from .fr_assessment import assess_functional_requirements
from .capability_registry import capability_registry
from .voice_evidence import VoiceEvidenceEngine
from .parsers.shared_link_parser import SharedLinkParser
from .parsers.provider_export_parser import ProviderExportParser
from .parsers.generated_asset_parser import GeneratedAssetParser
from .models import ExaminationQuestion

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Main orchestrator for the TRACE-AI-FR forensic analysis framework.
    """

    def _aggregate_artifact_coverage_ledger(self):
        """Aggregate all v5.0 artifact coverage records from all parser results."""
        coverage_ledger = []
        gap_ledger = []
        failure_ledger = []
        unsupported_ledger = []
        for pr in self.all_parser_results:
            coverage_ledger.extend(pr.artifact_coverage)
            gap_ledger.extend(pr.coverage_gaps)
            failure_ledger.extend(pr.parse_failures)
            unsupported_ledger.extend(pr.unsupported_artifacts)
        return {
            "artifact_coverage": coverage_ledger,
            "coverage_gaps": gap_ledger,
            "parse_failures": failure_ledger,
            "unsupported_artifacts": unsupported_ledger,
        }

    def __init__(
        self,
        evidence_path: str,
        output_dir: str,
        case_name: str = "",
        examiner: str = "",
        organization: str = "",
        case_id: Optional[str] = None,
        carving_enabled: bool = False,
        input_mode: str = "auto",  # "e01", "mounted", "auto"
        questions_docx_path: str = "",
        # Recovery flags (v3.0)
        recovery_mode: str = "none",
        signature_pack: str = "",
        scan_unallocated: bool = False,
        raw_search: bool = False,
        partition_scan: bool = False,
        acquisition_quality: str = "unknown",
        acquisition_log: str = "",
        # v4.0 flags
        enable_voice_analysis: bool = False,
        import_transcripts: str = "",
        import_provider_exports: str = "",
        import_shared_links: bool = False,
        include_capability_matrix: bool = True,
        strict_repo_check: bool = False,
        allow_report_fallback: bool = True,
    ):
        self.evidence_path = os.path.abspath(evidence_path)
        self.output_dir = os.path.abspath(output_dir)
        self.carving_enabled = carving_enabled
        self.input_mode = input_mode

        self.case_info = CaseInfo(
            case_name=case_name,
            examiner=examiner,
            organization=organization,
        )
        if case_id:
            self.case_info.case_id = case_id

        self.evidence_info = EvidenceImageInfo()
        self.evidence_coverage = EvidenceCoverage(carving_enabled=carving_enabled)
        self.all_parser_results: List[ParserResult] = []
        self.logs: List[ProcessingLog] = []
        self._temp_dirs: List[str] = []  # Track temp dirs for cleanup
        self._e01_scanned_artifacts: List = []  # Artifacts from E01 binary scan
        self.questions_docx_path = questions_docx_path
        self._examination_questions: List[ExaminationQuestion] = []

        # Recovery configuration (v3.0)
        self._recovery_mode = RecoveryMode(recovery_mode) if recovery_mode in [m.value for m in RecoveryMode] else RecoveryMode.NONE
        self._signature_pack = signature_pack
        self._scan_unallocated = scan_unallocated
        self._raw_search = raw_search
        self._partition_scan = partition_scan
        self._acquisition_quality = AcquisitionQuality(acquisition_quality) if acquisition_quality in [q.value for q in AcquisitionQuality] else AcquisitionQuality.UNKNOWN
        self._acquisition_log = acquisition_log

        # v4.0 configuration
        self._enable_voice_analysis = enable_voice_analysis
        self._import_transcripts = import_transcripts
        self._import_provider_exports = import_provider_exports
        self._import_shared_links = import_shared_links
        self._include_capability_matrix = include_capability_matrix
        self._strict_repo_check = strict_repo_check
        self._allow_report_fallback = allow_report_fallback

        # Import parsers to trigger registration
        from . import parsers  # noqa: F401

    def run(self) -> ForensicReport:
        """Execute the complete analysis pipeline."""
        start_time = time.time()
        self._log("INFO", "engine", "=" * 60)
        self._log("INFO", "engine", "TRACE-AI-FR Forensic Analysis Started")
        self._log("INFO", "engine", f"Evidence: {self.evidence_path}")
        self._log("INFO", "engine", f"Output: {self.output_dir}")
        self._log("INFO", "engine", "=" * 60)

        # Step 1: Determine input mode and ingest evidence
        evidence_root, os_platform, user_profiles = self._ingest_evidence()
        self._evidence_root = evidence_root or ""

        # Handle E01 binary scan mode: evidence_root may be a temp dir with
        # no actual files — but _e01_scanned_artifacts has the artifacts.
        e01_scan_mode = bool(self._e01_scanned_artifacts)

        if not evidence_root and not e01_scan_mode:
            self._log("ERROR", "engine", "Failed to access evidence. Aborting.")
            return self._build_empty_report()

        # Step 2: Detect evidence coverage
        if evidence_root:
            self._assess_coverage(evidence_root, os_platform, user_profiles)

        # Step 3: Run parsers for each user profile
        all_artifacts = []

        # Inject E01 binary-scanned artifacts first
        if e01_scan_mode:
            all_artifacts.extend(self._e01_scanned_artifacts)
            self._log("INFO", "engine",
                       f"Injected {len(self._e01_scanned_artifacts)} artifacts "
                       f"from E01 binary scanner")
            # Create a synthetic parser result for tracking
            from .models import ParserResult, ParserStatus
            scan_result = ParserResult(
                parser_name="E01BinaryScanner",
                status=ParserStatus.SUCCESS,
                artifacts_found=list(self._e01_scanned_artifacts),
                notes=f"E01 binary scan: {len(self._e01_scanned_artifacts)} artifacts",
            )
            self.all_parser_results.append(scan_result)

        if evidence_root:
            for profile in user_profiles:
                self._log("INFO", "engine", f"Processing user profile: {profile}")
                results = registry.execute_all(
                    os_platform=os_platform,
                    evidence_root=evidence_root,
                    user_profile=profile,
                    case_id=self.case_info.case_id,
                    evidence_item_id=self.evidence_info.evidence_item_id,
                    source_image=self.evidence_info.image_path,
                )
                self.all_parser_results.extend(results)
                for r in results:
                    all_artifacts.extend(r.artifacts_found)

            # If no user profiles found, try with empty profile (root-level scan)
            if not user_profiles:
                self._log("INFO", "engine", "No user profiles found. Running root-level scan.")
                results = registry.execute_all(
                    os_platform=os_platform,
                    evidence_root=evidence_root,
                    user_profile="",
                    case_id=self.case_info.case_id,
                    evidence_item_id=self.evidence_info.evidence_item_id,
                    source_image=self.evidence_info.image_path,
                )
                self.all_parser_results.extend(results)
                for r in results:
                    all_artifacts.extend(r.artifacts_found)

        self._log("INFO", "engine", f"Total artifacts found: {len(all_artifacts)}")

        # Step 3b: Recovery pipeline (v3.0)
        recovery_audit = None
        carved_artifacts = []
        raw_hits = []
        partition_findings = []
        acquisition_metadata = None
        fs_health = None
        access_tier = None

        if self._recovery_mode != RecoveryMode.NONE or self._scan_unallocated or self._raw_search or self._partition_scan:
            self._log("INFO", "engine", f"Running recovery pipeline (mode={self._recovery_mode.value})...")
            recovery_audit, carved_artifacts, raw_hits, partition_findings, acquisition_metadata, fs_health, access_tier = (
                self._run_recovery_pipeline(all_artifacts)
            )

        # Step 4: Update coverage with parser outcomes
        self._update_coverage_from_parsers()

        # Step 4b: v4.0 — provider export, shared link, generated asset, voice pipelines
        voice_records = []
        shared_links = []
        generated_assets = []

        if evidence_root:
            # Provider export scanning
            self._log("INFO", "engine", "Scanning for provider exports (v4.0)...")
            pe_parser = ProviderExportParser(
                evidence_root=evidence_root,
                case_id=self.case_info.case_id,
                evidence_item_id=self.evidence_info.evidence_item_id,
                source_image=self.evidence_info.image_path,
            )
            pe_artifacts = pe_parser.scan()
            all_artifacts.extend(pe_artifacts)
            self._log("INFO", "engine", f"Provider exports: {len(pe_artifacts)} artifact(s)")

            # Shared link scanning
            if self._import_shared_links:
                self._log("INFO", "engine", "Scanning for shared AI links (v4.0)...")
                sl_parser = SharedLinkParser(
                    evidence_root=evidence_root,
                    case_id=self.case_info.case_id,
                    evidence_item_id=self.evidence_info.evidence_item_id,
                    source_image=self.evidence_info.image_path,
                )
                shared_links = sl_parser.scan()
                all_artifacts.extend(sl_parser.artifacts)
                self._log("INFO", "engine", f"Shared links: {len(shared_links)}")

            # Generated asset scanning
            self._log("INFO", "engine", "Scanning for generated assets (v4.0)...")
            ga_parser = GeneratedAssetParser(
                evidence_root=evidence_root,
                case_id=self.case_info.case_id,
                evidence_item_id=self.evidence_info.evidence_item_id,
                source_image=self.evidence_info.image_path,
            )
            generated_assets = ga_parser.scan()
            all_artifacts.extend(ga_parser.artifacts)
            self._log("INFO", "engine", f"Generated assets: {len(generated_assets)}")

        # Voice evidence pipeline
        if self._enable_voice_analysis or self._import_transcripts:
            self._log("INFO", "engine", "Running voice evidence pipeline (v4.0)...")
            ve = VoiceEvidenceEngine(
                case_id=self.case_info.case_id,
                evidence_item_id=self.evidence_info.evidence_item_id,
                source_image=self.evidence_info.image_path,
            )
            if self._import_transcripts and os.path.isdir(self._import_transcripts):
                voice_records = ve.import_transcripts(self._import_transcripts)
                all_artifacts.extend(ve.voice_artifacts)
                self._log("INFO", "engine", f"Voice transcripts imported: {len(voice_records)}")
            if self._enable_voice_analysis and evidence_root:
                scan_records = ve.scan_evidence_for_voice(evidence_root)
                voice_records.extend(scan_records)
                all_artifacts.extend(ve.voice_artifacts)
                self._log("INFO", "engine", f"Voice artifacts scanned: {len(scan_records)}")

        # Layer 3b: Assign evidence-source-class and persistence state
        self._log("INFO", "engine", "Assigning evidence source classes (Rule 8)...")
        assign_evidence_source_classes(all_artifacts)
        self._log("INFO", "engine", "Assigning persistence states (Rule 7)...")
        assign_persistence_states(all_artifacts)

        # Step 5: Correlate artifacts
        self._log("INFO", "engine", "Running correlation engine...")
        correlator = CorrelationEngine(all_artifacts)
        timeline = correlator.run()

        # Step 6: Score artifact-level confidence
        self._log("INFO", "engine", "Running confidence scoring...")
        scorer = ConfidenceScoringEngine(all_artifacts, self.evidence_coverage)
        scored_artifacts = scorer.score_all()
        footprints = scorer.build_footprints()

        # Step 7: Build comparative matrix
        self._log("INFO", "engine", "Building comparative artifact matrix...")
        matrix_rows = build_comparative_matrix(scored_artifacts, self.evidence_coverage)

        # Layer 5: Adjudication — build FRAUEs with event-level confidence
        self._log("INFO", "engine", "Running TRACE-AI-FR adjudication engine...")
        coverage_sufficient = (
            self.evidence_info.image_type not in (ImageType.TRIAGE, ImageType.PARTIAL)
        )
        adjudicator = AdjudicationEngine(scored_artifacts, coverage_sufficient)
        fraues = adjudicator.adjudicate()
        self._log("INFO", "engine",
                   f"Adjudication complete: {len(fraues)} FRAUEs reconstructed")

        # Parse examination questions from Word document (if provided)
        if self.questions_docx_path:
            self._log("INFO", "engine",
                       f"Parsing questions from: {self.questions_docx_path}")
            try:
                self._examination_questions = parse_questions_from_docx(
                    self.questions_docx_path
                )
                self._log("INFO", "engine",
                           f"Loaded {len(self._examination_questions)} examination questions")
                # Auto-answer questions based on analysis results
                self._answer_questions(scored_artifacts, footprints, fraues, timeline)
            except Exception as exc:
                self._log("WARNING", "engine",
                           f"Failed to parse questions document: {exc}")

        # Step 8: Assemble report
        coverage_ledger = self._aggregate_artifact_coverage_ledger()
        report = ForensicReport(
            case_info=self.case_info,
            evidence_info=self.evidence_info,
            evidence_coverage=self.evidence_coverage,
            all_artifacts=scored_artifacts,
            timeline=timeline,
            ai_footprints=footprints,
            matrix_rows=matrix_rows,
            parser_results=self.all_parser_results,
            processing_logs=self.logs,
            carving_enabled=self.carving_enabled,
            fraues=fraues,
            examination_questions=self._examination_questions,
            # Recovery fields (v3.0)
            recovered_artifacts=[],
            carved_artifacts=carved_artifacts,
            raw_hits=raw_hits,
            partition_findings=partition_findings,
            recovery_audit=recovery_audit,
            acquisition_metadata=acquisition_metadata,
            filesystem_health=fs_health,
            evidence_access_tier=access_tier,
            recovery_mode_used=self._recovery_mode if self._recovery_mode != RecoveryMode.NONE else None,
            # v4.0 fields
            voice_evidence=voice_records,
            shared_links=shared_links,
            generated_assets=generated_assets,
            # v5.0 artifact coverage ledger
            artifact_coverage_ledger=coverage_ledger["artifact_coverage"],
            coverage_gap_ledger=coverage_ledger["coverage_gaps"],
            parse_failure_ledger=coverage_ledger["parse_failures"],
            unsupported_artifact_ledger=coverage_ledger["unsupported_artifacts"],
        )

        # Layer 8: Governance — build governance record and scope of conclusion
        # (needs the assembled report object)
        self._log("INFO", "engine", "Building governance record (Layer 8)...")
        governance_record = build_governance_record(
            report=report,
            parser_results=self.all_parser_results,
            evidence_coverage=self.evidence_coverage,
        )
        scope_of_conclusion = generate_scope_of_conclusion(report)
        report.governance_record = governance_record
        report.scope_of_conclusion = scope_of_conclusion
        report.inference_boundaries = governance_record.inference_boundaries.copy()

        # Add analysis notes
        if not self.carving_enabled:
            report.analysis_notes.append(
                "File carving was disabled. Analysis was limited to recoverable "
                "structured artifacts."
            )
        if self.evidence_coverage.image_type in (ImageType.TRIAGE, ImageType.PARTIAL):
            report.analysis_notes.append(
                "Evidence source is a triage/partial collection. Some artifacts "
                "may be absent due to limited evidence coverage."
            )

        # FR Assessment: evaluate 9 functional requirements
        self._log("INFO", "engine", "Evaluating functional requirements (FR-1 through FR-9)...")
        report.fr_assessments = assess_functional_requirements(report)
        fully = sum(1 for a in report.fr_assessments if a.status.value == "Fully Addressed")
        partial = sum(1 for a in report.fr_assessments if a.status.value == "Partially Addressed")
        self._log("INFO", "engine",
                   f"FR assessment: {fully} fully addressed, {partial} partially addressed, "
                   f"{len(report.fr_assessments) - fully - partial} gaps")

        # v5.0: AI Tool Inventory Checklist
        self._log("INFO", "engine", "Running AI tool inventory scan (v5.0)...")
        report.forensic_checklist = self._run_ai_tool_checklist(
            evidence_root=evidence_root,
            os_platform=os_platform,
            user_profiles=user_profiles,
        )
        n_found = sum(1 for e in report.forensic_checklist if getattr(e, "evidence_status", None) and str(e.evidence_status) in ("FOUND", "EvidenceStatus.FOUND"))
        self._log("INFO", "engine",
                   f"AI tool checklist: {n_found}/{len(report.forensic_checklist)} tools detected")

        # Step 9: Export outputs
        self._log("INFO", "engine", "Exporting reports...")
        self._export_all(report)

        elapsed = time.time() - start_time
        self._log("INFO", "engine", f"Analysis completed in {elapsed:.1f} seconds")
        self._log("INFO", "engine", f"Artifacts: {len(scored_artifacts)}, "
                   f"Timeline events: {len(timeline)}, "
                   f"AI footprints: {len(footprints)}, "
                   f"FRAUEs: {len(fraues)}")

        # Cleanup temp directories (from ZIP extraction)
        self._cleanup_temp()

        return report

    # -----------------------------------------------------------------------
    # v5.0: AI Tool Inventory Checklist
    # -----------------------------------------------------------------------

    def _run_ai_tool_checklist(
        self,
        evidence_root,
        os_platform,
        user_profiles,
    ):
        """
        Run the AIToolScannerParser against the evidence and return a list of
        ForensicChecklistEntry objects for every registered AI tool.
        """
        from .parsers.ai_tool_scanner import AIToolScannerParser
        import os as _os

        config_path = _os.path.join(
            _os.path.dirname(_os.path.dirname(__file__)),
            "config", "ai_tool_inventory.yaml",
        )
        if not _os.path.isfile(config_path):
            self._log("WARNING", "engine",
                       f"AI tool inventory YAML not found at {config_path}. "
                       "Skipping checklist generation.")
            return []

        # Resolve user profile basenames for path expansion
        profile_names = []
        for p in (user_profiles or []):
            if p:
                profile_names.append(_os.path.basename(p))

        scanner = AIToolScannerParser(
            evidence_root=evidence_root or "",
            user_profile=user_profiles[0] if user_profiles else "",
            case_id=self.case_info.case_id,
            evidence_item_id=self.evidence_info.evidence_item_id,
            source_image=self.evidence_info.image_path,
            os_platform=os_platform,
            user_profiles=profile_names,
            config_path=config_path,
        )

        try:
            scanner_result = scanner.parse()
            self.all_parser_results.append(scanner_result)
        except Exception as exc:
            self._log("WARNING", "engine",
                       f"AI tool scanner failed: {exc}")
            return []

        return scanner.checklist_entries

    # -----------------------------------------------------------------------
    # Recovery Pipeline (v3.0)
    # -----------------------------------------------------------------------

    def _run_recovery_pipeline(self, all_artifacts):
        """Run the recovery engine and inject recovered artifacts."""
        from .recovery import RecoveryEngine

        # Determine stream — for E01 we use the raw handler, for dirs skip
        stream = self._open_evidence_stream()
        if not stream:
            self._log("WARNING", "engine",
                       "Cannot open evidence as raw stream for recovery; skipping.")
            return None, [], [], [], None, None, None

        try:
            engine = RecoveryEngine(
                evidence_id=self.evidence_info.evidence_item_id,
                output_dir=os.path.join(self.output_dir, "recovery"),
                recovery_mode=self._recovery_mode,
                signature_pack_path=self._signature_pack,
                acquisition_quality=self._acquisition_quality,
                acquisition_log_path=self._acquisition_log,
                scan_unallocated=self._scan_unallocated,
                raw_search=self._raw_search,
                partition_scan=self._partition_scan,
            )
            audit = engine.run(stream)

            # Convert carved artifacts to ArtifactRecords and inject
            if engine.carved_artifacts:
                from .parsers.recovery_parsers import CarvedArtifactParser
                parser = CarvedArtifactParser(
                    evidence_root=self._evidence_root,
                    case_id=self.case_info.case_id,
                    evidence_item_id=self.evidence_info.evidence_item_id,
                    source_image=self.evidence_info.image_path,
                    carved_artifacts=engine.carved_artifacts,
                )
                result = parser.parse()
                self.all_parser_results.append(result)
                all_artifacts.extend(result.artifacts_found)
                self._log("INFO", "engine",
                           f"Recovery: {len(result.artifacts_found)} carved artifact records injected")

            # Convert raw hits to ArtifactRecords and inject
            if engine.raw_hits:
                from .parsers.recovery_parsers import RawHitParser
                parser = RawHitParser(
                    evidence_root=self._evidence_root,
                    case_id=self.case_info.case_id,
                    evidence_item_id=self.evidence_info.evidence_item_id,
                    source_image=self.evidence_info.image_path,
                    raw_hits=engine.raw_hits,
                )
                result = parser.parse()
                self.all_parser_results.append(result)
                all_artifacts.extend(result.artifacts_found)
                self._log("INFO", "engine",
                           f"Recovery: {len(result.artifacts_found)} raw hit records injected")

            return (
                audit,
                engine.carved_artifacts,
                engine.raw_hits,
                engine.partition_findings,
                engine.acquisition_metadata,
                engine.filesystem_health,
                engine.evidence_access_tier,
            )
        finally:
            if hasattr(stream, 'close'):
                stream.close()

    def _open_evidence_stream(self):
        """Open the evidence as a raw binary stream for recovery scanning."""
        import io
        path = self.evidence_path

        # E01 images — try pyewf
        if path.lower().endswith(('.e01', '.ex01')):
            try:
                import pyewf
                filenames = pyewf.glob(path)
                handle = pyewf.handle()
                handle.open(filenames)
                # Wrap in a file-like object
                return _EWFStream(handle)
            except Exception:
                self._log("DEBUG", "engine", "Cannot open E01 as raw stream via pyewf")
                return None

        # Raw image or dd
        if os.path.isfile(path):
            try:
                return open(path, "rb")
            except OSError:
                return None

        return None

    # -----------------------------------------------------------------------
    # Evidence Ingestion
    # -----------------------------------------------------------------------

    def _ingest_evidence(self):
        """Ingest evidence and return (evidence_root, os_platform, user_profiles)."""

        # Determine input mode
        if self.input_mode == "auto":
            if self.evidence_path.lower().endswith((".e01", ".ex01")):
                self.input_mode = "e01"
            elif self.evidence_path.lower().endswith(".zip"):
                self.input_mode = "zip"
            elif os.path.isdir(self.evidence_path):
                self.input_mode = "mounted"
            else:
                self._log("ERROR", "engine",
                           f"Cannot determine input type: {self.evidence_path}")
                return None, OSPlatform.UNKNOWN, []

        if self.input_mode == "e01":
            return self._ingest_e01()
        elif self.input_mode == "zip":
            return self._ingest_zip()
        else:
            return self._ingest_mounted()

    def _ingest_e01(self):
        """Ingest from E01 image."""
        self._log("INFO", "engine", "Ingesting E01 image...")
        handler = E01Handler(self.evidence_path)
        self.evidence_info = handler.open()
        self.logs.extend(handler.get_logs())

        if self.evidence_info.errors:
            # E01 native parsing may not be available
            # Try falling back to mounted if there's a companion directory
            base = os.path.splitext(self.evidence_path)[0]
            for suffix in ["_mount", "_extracted", ""]:
                candidate = base + suffix
                if os.path.isdir(candidate):
                    self._log("INFO", "engine",
                               f"E01 native parsing unavailable. "
                               f"Using companion directory: {candidate}")
                    return self._ingest_mounted_path(candidate)

            # No companion dir — fall back to binary scan mode
            self._log("INFO", "engine",
                       "No companion directory found. Running E01 binary "
                       "scanner to extract AI-platform evidence from raw bytes.")
            return self._ingest_e01_binary_scan()

        # Try to detect partitions and mount
        handler.detect_partitions()
        self.logs.extend(handler.get_logs())

        # For MVP without full mount support, check for extracted companion directory
        base = os.path.splitext(self.evidence_path)[0]
        for suffix in ["_mount", "_extracted", "_files", ""]:
            candidate = base + suffix
            if os.path.isdir(candidate):
                return self._ingest_mounted_path(candidate)

        # pyewf available but no companion dir — still use binary scan
        self._log("INFO", "engine",
                   "E01 opened with pyewf but no mounted filesystem available. "
                   "Running binary scanner as fallback.")
        return self._ingest_e01_binary_scan()

    def _ingest_e01_binary_scan(self):
        """
        Fallback: scan E01 raw bytes for AI-platform evidence.

        Creates a minimal temp evidence directory and injects any artifacts
        found via the binary scanner into the pipeline.
        """
        scanner = E01BinaryScanner(
            e01_path=self.evidence_path,
            source_image=f"E01:{os.path.basename(self.evidence_path)}",
            case_id=self.case_info.case_id,
            evidence_item_id=self.evidence_info.evidence_item_id,
        )
        scanned_artifacts = scanner.scan()
        self.logs.extend(scanner.get_logs())
        self._e01_scanned_artifacts = scanned_artifacts

        if not scanned_artifacts:
            self._log("WARNING", "engine",
                       "E01 binary scan found no AI-platform artifacts. "
                       "For full analysis, mount the E01 with FTK Imager or "
                       "Arsenal Image Mounter and point the tool at the "
                       "mounted directory.")
            # Still build a minimal report so the GUI has something to show
            self.evidence_info.image_path = self.evidence_path
            self.evidence_info.image_type = ImageType.FULL_DISK
            return None, OSPlatform.UNKNOWN, []

        self._log("INFO", "engine",
                   f"E01 binary scan found {len(scanned_artifacts)} artifacts. "
                   f"Building analysis from scanned evidence.")

        # Create a temp directory so the rest of the pipeline works
        temp_dir = tempfile.mkdtemp(prefix="aiuea_e01scan_")
        self._temp_dirs.append(temp_dir)

        # Set evidence info
        self.evidence_info.image_path = self.evidence_path
        self.evidence_info.image_type = ImageType.FULL_DISK
        self.evidence_info.detected_os = OSPlatform.WINDOWS

        return temp_dir, OSPlatform.WINDOWS, []

    def _ingest_mounted(self):
        """Ingest from mounted directory."""
        return self._ingest_mounted_path(self.evidence_path)

    def _ingest_zip(self):
        """Extract a ZIP evidence archive to a temp directory, then ingest."""
        if not os.path.isfile(self.evidence_path):
            self._log("ERROR", "engine", f"ZIP file not found: {self.evidence_path}")
            return None, OSPlatform.UNKNOWN, []

        if not zipfile.is_zipfile(self.evidence_path):
            self._log("ERROR", "engine",
                       f"File is not a valid ZIP archive: {self.evidence_path}")
            return None, OSPlatform.UNKNOWN, []

        self._log("INFO", "engine",
                   f"Extracting ZIP evidence: {self.evidence_path}")

        # Create a temp directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="aiuea_zip_")
        self._temp_dirs.append(temp_dir)

        try:
            with zipfile.ZipFile(self.evidence_path, "r") as zf:
                # Security: check for path traversal (zip-slip)
                for member in zf.namelist():
                    member_path = os.path.realpath(
                        os.path.join(temp_dir, member)
                    )
                    if not member_path.startswith(os.path.realpath(temp_dir)):
                        self._log("ERROR", "engine",
                                   f"ZIP member has unsafe path (zip-slip): {member}")
                        return None, OSPlatform.UNKNOWN, []

                zf.extractall(temp_dir)
                member_count = len(zf.namelist())

            self._log("INFO", "engine",
                       f"Extracted {member_count} files to temp directory")

        except zipfile.BadZipFile as exc:
            self._log("ERROR", "engine", f"Bad ZIP file: {exc}")
            return None, OSPlatform.UNKNOWN, []
        except Exception as exc:
            self._log("ERROR", "engine", f"ZIP extraction failed: {exc}")
            return None, OSPlatform.UNKNOWN, []

        # Check if the zip contains a single top-level directory
        top_items = os.listdir(temp_dir)
        if len(top_items) == 1 and os.path.isdir(
            os.path.join(temp_dir, top_items[0])
        ):
            extract_root = os.path.join(temp_dir, top_items[0])
        else:
            extract_root = temp_dir

        # Record the original ZIP as the evidence source
        self.evidence_info.image_path = self.evidence_path
        self.evidence_info.image_format = "ZIP Archive"

        # Compute hash of the original ZIP
        self._hash_zip(self.evidence_path)

        return self._ingest_mounted_path(extract_root)

    def _hash_zip(self, zip_path: str):
        """Compute MD5 and SHA-1 of the original ZIP for integrity."""
        import hashlib
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        try:
            with open(zip_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
            self.evidence_info.md5_hash = md5.hexdigest()
            self.evidence_info.sha1_hash = sha1.hexdigest()
            self._log("INFO", "engine",
                       f"ZIP MD5: {self.evidence_info.md5_hash}")
            self._log("INFO", "engine",
                       f"ZIP SHA-1: {self.evidence_info.sha1_hash}")
        except Exception as exc:
            self._log("WARNING", "engine", f"Failed to hash ZIP: {exc}")

    def _ingest_mounted_path(self, path: str):
        """Ingest from a specific directory path."""
        handler = MountedEvidenceHandler(path)
        if not handler.validate():
            return None, OSPlatform.UNKNOWN, []

        os_platform = handler.detect_os_platform()
        user_profiles = handler.find_user_profiles()

        self.evidence_info.image_path = path
        self.evidence_info.detected_os = os_platform
        self.evidence_info.user_profiles = user_profiles
        self.evidence_info.processing_start = datetime.utcnow()

        # Determine image type heuristic
        if os.path.exists(os.path.join(path, "Windows")) or \
           os.path.exists(os.path.join(path, "System")):
            self.evidence_info.image_type = ImageType.FULL_DISK
        elif os.path.exists(os.path.join(path, "Users")):
            self.evidence_info.image_type = ImageType.LOGICAL
        else:
            self.evidence_info.image_type = ImageType.PARTIAL

        self.logs.extend(handler.get_logs())
        self._log("INFO", "engine",
                   f"Evidence loaded: OS={os_platform.value}, "
                   f"Profiles={user_profiles}, Type={self.evidence_info.image_type.value}")

        return path, os_platform, user_profiles

    # -----------------------------------------------------------------------
    # Evidence Coverage
    # -----------------------------------------------------------------------

    def _assess_coverage(self, evidence_root: str, os_platform: OSPlatform,
                         user_profiles: List[str]):
        """Assess what the evidence actually contains."""
        self.evidence_coverage.image_type = self.evidence_info.image_type
        self.evidence_coverage.os_detected = os_platform
        self.evidence_coverage.user_profiles_found = user_profiles
        self.evidence_coverage.full_disk_available = (
            self.evidence_info.image_type == ImageType.FULL_DISK
        )

        # Check for browsers
        browsers_found = []
        for profile in user_profiles:
            user_base = os.path.join(evidence_root, "Users", profile)
            browser_checks = {
                "Chrome": [
                    os.path.join(user_base, "AppData/Local/Google/Chrome/User Data"),
                    os.path.join(user_base, "Library/Application Support/Google/Chrome"),
                ],
                "Edge": [
                    os.path.join(user_base, "AppData/Local/Microsoft/Edge/User Data"),
                ],
                "Firefox": [
                    os.path.join(user_base, "AppData/Roaming/Mozilla/Firefox/Profiles"),
                    os.path.join(user_base, "Library/Application Support/Firefox/Profiles"),
                ],
                "Brave": [
                    os.path.join(user_base, "AppData/Local/BraveSoftware/Brave-Browser/User Data"),
                ],
                "Safari": [
                    os.path.join(user_base, "Library/Safari"),
                ],
            }
            for browser, paths in browser_checks.items():
                for p in paths:
                    if os.path.isdir(p) and browser not in browsers_found:
                        browsers_found.append(browser)

        self.evidence_coverage.browsers_detected = browsers_found

        # Add coverage notes
        if not self.carving_enabled:
            self.evidence_coverage.coverage_notes.append(
                "File carving was disabled. Only structured, recoverable artifacts "
                "were analyzed."
            )

        if self.evidence_info.image_type in (ImageType.TRIAGE, ImageType.PARTIAL):
            self.evidence_coverage.limitations.append(
                "Evidence source is a triage or partial collection. "
                "Negative findings may be due to limited collection scope."
            )

        if not user_profiles:
            self.evidence_coverage.limitations.append(
                "No user profiles detected. Analysis scope is limited."
            )

    def _update_coverage_from_parsers(self):
        """Update evidence coverage based on parser outcomes."""
        for pr in self.all_parser_results:
            if pr.status == ParserStatus.SUCCESS:
                self.evidence_coverage.parsers_succeeded.append(pr.parser_name)
            elif pr.status == ParserStatus.FAILED:
                self.evidence_coverage.parsers_failed.append(pr.parser_name)
            elif pr.status == ParserStatus.NOT_APPLICABLE:
                self.evidence_coverage.parsers_not_applicable.append(pr.parser_name)
            elif pr.status == ParserStatus.STUB:
                self.evidence_coverage.parsers_stub.append(pr.parser_name)

        # Determine artifact families found/missing
        families_found = set()
        for pr in self.all_parser_results:
            for art in pr.artifacts_found:
                families_found.add(art.artifact_family.value)

        self.evidence_coverage.artifact_families_available = sorted(families_found)

        all_families = {
            "Browser History", "Browser Downloads", "Browser Cookies",
            "Browser Local Storage", "Browser Cache", "Native Application",
            "OS Execution Trace", "OS Recent Files", "OS Registry",
            "OS Event Log", "OS Plist", "OS Unified Log",
            "File System", "User Content", "Screenshot",
        }
        missing = all_families - families_found
        self.evidence_coverage.artifact_families_missing = sorted(missing)

    # -----------------------------------------------------------------------
    # Report Export
    # -----------------------------------------------------------------------

    def _export_all(self, report: ForensicReport):
        """Export all output formats."""
        os.makedirs(self.output_dir, exist_ok=True)

        case_prefix = report.case_info.case_id

        # Build exhibit manager from all artifacts
        exhibit_mgr = ExhibitManager(
            output_dir=self.output_dir,
            evidence_source=report.evidence_info.image_path or "",
        )
        evidence_root = getattr(self, '_evidence_root', "")
        for art in report.all_artifacts:
            exhibit_mgr.add_exhibit_from_artifact(art, evidence_root)
        exhibits = exhibit_mgr.get_all()

        # SQLite
        db_path = os.path.join(self.output_dir, f"{case_prefix}_findings.sqlite")
        storage = SQLiteStorage(db_path)
        storage.initialize()
        storage.export_report(report)
        storage.close()
        self._log("INFO", "engine", f"SQLite: {db_path}")

        # JSON
        json_path = os.path.join(self.output_dir, f"{case_prefix}_findings.json")
        JSONExporter().export(report, json_path, exhibits=exhibits)
        self._log("INFO", "engine", f"JSON: {json_path}")

        # Markdown
        md_path = os.path.join(self.output_dir, f"{case_prefix}_report.md")
        MarkdownReportGenerator().generate(
            report, md_path,
            evidence_root=evidence_root,
            exhibit_manager=exhibit_mgr,
        )
        self._log("INFO", "engine", f"Markdown: {md_path}")

        # HTML
        html_path = os.path.join(self.output_dir, f"{case_prefix}_report.html")
        HTMLReportGenerator().generate(
            report, html_path,
            evidence_root=evidence_root,
            exhibit_manager=exhibit_mgr,
        )
        self._log("INFO", "engine", f"HTML: {html_path}")

        # Governance Record (standalone JSON)
        if report.governance_record:
            export_governance_record(
                report.governance_record, self.output_dir, case_prefix
            )
            self._log("INFO", "engine", f"Governance: {case_prefix}_governance_record.json")

        # DOCX — Primary report format (v4.0, Caveat 11)
        docx_path = os.path.join(self.output_dir, f"{case_prefix}_report.docx")
        try:
            generate_docx_report(
                report=report,
                output_path=docx_path,
                examiner_name=report.case_info.examiner or "",
                examination_name=report.case_info.case_name or "",
                organization=report.case_info.organization or "University of North Carolina at Charlotte",
            )
            report.docx_generated = True
            report.docx_path = docx_path
            self._log("INFO", "engine", f"DOCX (primary): {docx_path}")
        except Exception as exc:
            report.docx_generated = False
            report.report_fallback_used = True
            report.report_fallback_reason = f"DOCX generation failed: {exc}"
            self._log("WARNING", "engine",
                       f"DOCX generation failed: {exc}. "
                       f"Markdown and HTML reports remain available.")

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _answer_questions(self, artifacts, footprints, fraues, timeline):
        """Auto-answer examination questions based on analysis results."""
        # Build a summary of what we found
        platforms_found = set()
        for fp in footprints:
            name = fp.platform.value if hasattr(fp.platform, "value") else str(fp.platform)
            platforms_found.add(name)

        artifact_families = set()
        for a in artifacts:
            fam = a.artifact_family.value if hasattr(a.artifact_family, "value") else str(a.artifact_family)
            artifact_families.add(fam)

        n_artifacts = len(artifacts)
        n_fraues = len(fraues)
        n_timeline = len(timeline)
        platforms_str = ", ".join(sorted(platforms_found)) if platforms_found else "none detected"

        # Keyword-based answering heuristics
        _KW_PLATFORM = re.compile(
            r"(chatgpt|openai|claude|anthropic|gemini|google\s*ai|"
            r"copilot|bard|perplexity|meta\s*ai|grok|xai|poe|quora|"
            r"ai\s*platform|ai\s*tool|ai\s*service|"
            r"artificial\s*intelligence|llm|large\s*language)", re.I,
        )
        _KW_BROWSER = re.compile(
            r"(browser|chrome|edge|firefox|brave|safari|web\s*history|"
            r"cookie|download|url|website|visited)", re.I,
        )
        _KW_EVIDENCE = re.compile(
            r"(evidence|artifact|trace|indicator|proof|sign|suggest)", re.I,
        )
        _KW_TIMELINE = re.compile(
            r"(when|time|date|timeline|chronolog|sequence|order|first|last)", re.I,
        )
        _KW_FREQUENCY = re.compile(
            r"(how\s*(many|much|often|frequent)|count|number\s*of|total)", re.I,
        )

        for q in self._examination_questions:
            parts = []
            text = q.text

            if _KW_PLATFORM.search(text):
                if platforms_found:
                    parts.append(
                        f"AI platforms detected in the evidence: {platforms_str}. "
                        f"{n_fraues} forensic reconstruction(s) of AI usage events "
                        f"(FRAUEs) were identified."
                    )
                    for fp in footprints:
                        pname = fp.platform.value if hasattr(fp.platform, "value") else str(fp.platform)
                        conf = fp.overall_confidence.value if hasattr(fp.overall_confidence, "value") else str(fp.overall_confidence)
                        parts.append(
                            f"  - {pname}: {fp.total_artifacts} artifacts, "
                            f"confidence={conf}"
                        )
                else:
                    parts.append(
                        "No AI platform usage was detected in the analyzed evidence."
                    )

            if _KW_BROWSER.search(text):
                browser_arts = [
                    a for a in artifacts
                    if "BROWSER" in (
                        a.artifact_family.value if hasattr(a.artifact_family, "value")
                        else str(a.artifact_family)
                    ).upper()
                ]
                if browser_arts:
                    parts.append(
                        f"{len(browser_arts)} browser-related artifacts were found, "
                        f"including history entries, cookies, and/or downloads."
                    )
                else:
                    parts.append("No browser-related artifacts were found.")

            if _KW_TIMELINE.search(text):
                if timeline:
                    first = min(
                        (e.timestamp for e in timeline if e.timestamp),
                        default=None,
                    )
                    last = max(
                        (e.timestamp for e in timeline if e.timestamp),
                        default=None,
                    )
                    parts.append(
                        f"The forensic timeline contains {n_timeline} events"
                    )
                    if first and last:
                        parts.append(
                            f" spanning from {first.strftime('%Y-%m-%d %H:%M:%S')} "
                            f"to {last.strftime('%Y-%m-%d %H:%M:%S')}."
                        )
                    else:
                        parts.append(".")
                else:
                    parts.append("No timeline events could be reconstructed.")

            if _KW_FREQUENCY.search(text):
                parts.append(
                    f"Total artifacts: {n_artifacts}. "
                    f"Platforms detected: {len(platforms_found)}. "
                    f"FRAUEs: {n_fraues}. "
                    f"Timeline events: {n_timeline}."
                )

            if _KW_EVIDENCE.search(text) and not parts:
                if n_artifacts > 0:
                    parts.append(
                        f"The analysis found {n_artifacts} artifact(s) across "
                        f"{len(artifact_families)} artifact families. "
                        f"Platforms detected: {platforms_str}."
                    )
                else:
                    parts.append(
                        "No artifacts indicative of AI usage were found in "
                        "the evidence."
                    )

            if not parts:
                # Generic answer when no keywords matched
                parts.append(
                    f"Based on the forensic analysis: {n_artifacts} artifact(s) "
                    f"were recovered, {n_fraues} FRAUE(s) reconstructed, "
                    f"across platforms: {platforms_str}. "
                    f"Refer to the full report for detailed findings."
                )

            q.answer = " ".join(parts)

            # Add evidence references from FRAUEs
            for f in fraues:
                pname = f.platform.value if hasattr(f.platform, "value") else str(f.platform)
                if pname.lower() in text.lower() or not _KW_PLATFORM.search(text):
                    q.evidence_references.append(f.fraue_id)
                    if len(q.evidence_references) >= 5:
                        break

    def _build_empty_report(self) -> ForensicReport:
        """Build a report when evidence could not be accessed."""
        report = ForensicReport(
            case_info=self.case_info,
            evidence_info=self.evidence_info,
            evidence_coverage=self.evidence_coverage,
            processing_logs=self.logs,
            carving_enabled=self.carving_enabled,
        )
        report.analysis_notes.append(
            "Evidence could not be accessed or parsed. No analysis was performed."
        )
        self._export_all(report)
        return report

    def _log(self, level: str, module: str, message: str):
        entry = ProcessingLog(
            timestamp=datetime.utcnow(),
            level=level,
            module=module,
            message=message,
        )
        self.logs.append(entry)
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{module}] {message}")

    def _cleanup_temp(self):
        """Remove temporary directories created during ZIP extraction."""
        for td in self._temp_dirs:
            try:
                shutil.rmtree(td, ignore_errors=True)
                logger.debug(f"Cleaned up temp dir: {td}")
            except Exception:
                pass
        self._temp_dirs.clear()


class _EWFStream:
    """Minimal file-like wrapper around a pyewf handle for recovery scanning."""

    def __init__(self, handle):
        self._handle = handle
        self._pos = 0
        self._size = handle.get_media_size()

    def read(self, size=-1):
        if size == -1:
            size = self._size - self._pos
        size = min(size, self._size - self._pos)
        if size <= 0:
            return b""
        data = self._handle.read(size)
        self._pos += len(data)
        return data

    def seek(self, offset, whence=0):
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        elif whence == 2:
            self._pos = self._size + offset
        self._pos = max(0, min(self._pos, self._size))
        self._handle.seek(self._pos)
        return self._pos

    def tell(self):
        return self._pos

    def close(self):
        try:
            self._handle.close()
        except Exception:
            pass
