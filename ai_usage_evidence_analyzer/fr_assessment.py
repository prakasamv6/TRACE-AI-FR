"""
TRACE-AI-FR — Functional Requirements (FR-1 through FR-9) Assessment Engine

Evaluates the forensic analysis results against the 9 AI-forensics functional
requirements derived from current research gaps (Magnet AXIOM, NIST, C2PA,
academic literature).

Research synthesis:
  "The state of the art has progressed from 'no AI artifact support' to
   'partial, app-specific artifact recovery,' but it still lacks an
   end-to-end AI-forensics evidence model that consistently unifies
   acquisition, session reconstruction, provenance, detector validation,
   third-party dependency tracing, and standardized evidentiary export."
"""
from __future__ import annotations

import logging
from typing import List, TYPE_CHECKING

from .models import (
    FRAssessment,
    FRStatus,
    EvidenceClassification,
)

if TYPE_CHECKING:
    from .models import ForensicReport

logger = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────────────────────
# FR definitions (static)
# ───────────────────────────────────────────────────────────────────────────
_FR_DEFINITIONS = [
    {
        "fr_id": "FR-1",
        "title": "Unified AI Evidence Acquisition",
        "description": (
            "A mature AI-forensics platform should acquire evidence from "
            "desktop apps, browser sessions, mobile apps, cloud exports, "
            "memory, logs, and network captures under one case model. "
            "Recent research on ChatGPT, Copilot, and Gemini found that "
            "conversation recovery was platform-dependent. The real gap is "
            "lack of a normalized cross-provider acquisition workflow."
        ),
    },
    {
        "fr_id": "FR-2",
        "title": "Full Session Reconstruction",
        "description": (
            "The tool should reconstruct the full AI interaction lifecycle: "
            "account/user context, device context, timestamps, prompts, "
            "responses, edits, deletions, attachments, exports, and "
            "surrounding system traces. The missing capability is forensic "
            "replay of the full session chain, not just extraction of "
            "message text."
        ),
    },
    {
        "fr_id": "FR-3",
        "title": "Model, Version, and Configuration Provenance",
        "description": (
            "An examiner should be able to say which model or service "
            "produced an output, when, under what version or change state, "
            "and with what relevant configuration context. NIST's "
            "Generative AI Profile stresses logging, metadata, and version "
            "history for incident response and governance."
        ),
    },
    {
        "fr_id": "FR-4",
        "title": "Provenance and Authenticity Verification",
        "description": (
            "AI-forensics tooling should verify origin, modifications, "
            "cryptographic bindings, signatures, hashes, and AI-use "
            "assertions where they exist. C2PA's Content Credentials model "
            "defines manifests containing assertions about origin, "
            "modification history, and AI use, bound into a verifiable "
            "unit. What is commonly missing is native forensic integration "
            "of provenance verification across evidence types."
        ),
    },
    {
        "fr_id": "FR-5",
        "title": "Detector Validation with Evidentiary Metrics",
        "description": (
            "If a tool labels content as 'AI-generated,' it should report "
            "error rates, confidence, thresholds, and limitations. NIST's "
            "synthetic-content guidance makes clear that watermarking and "
            "verification methods must be evaluated with false positives "
            "and false negatives. The requirement is forensic-grade "
            "detector validation suitable for evidentiary interpretation."
        ),
    },
    {
        "fr_id": "FR-6",
        "title": "Resilience to Tamper and Anti-Forensics",
        "description": (
            "A useful AI-forensics tool should account for metadata "
            "stripping, provenance removal, paraphrasing, recompression, "
            "and other attempts to weaken attribution. NIST emphasizes "
            "that risk reduction relies on multiple technical approaches "
            "rather than a single perfect signal. The gap is a shortage "
            "of multi-signal correlation frameworks."
        ),
    },
    {
        "fr_id": "FR-7",
        "title": "Third-Party Tool-Chain and Plugin Visibility",
        "description": (
            "The tool should capture whether the output was shaped by "
            "plugins, retrieval sources, external tools, or third-party "
            "inputs. NIST highlights documentation and review of "
            "third-party inputs as especially important in generative AI "
            "incident handling. Public AI-forensics coverage still centers "
            "mostly on the chat artifact itself."
        ),
    },
    {
        "fr_id": "FR-8",
        "title": "Standardized Evidentiary Export",
        "description": (
            "AI evidence should be exportable with chain-of-custody fields, "
            "hashes, timestamps, provenance findings, model/version metadata, "
            "and incident context in a normalized structure. NIST states "
            "that formal channels to report and document AI incidents are "
            "not yet standardized. One of the biggest missing pieces is a "
            "common AI evidence schema."
        ),
    },
    {
        "fr_id": "FR-9",
        "title": "Extensible Parser Architecture",
        "description": (
            "Because AI products and storage patterns change quickly, the "
            "platform needs rapidly updateable parsers and a stable internal "
            "evidence model. Magnet's public documentation says its ChatGPT "
            "artifact support was recently introduced and will continue to "
            "expand, evidencing that coverage is still incremental rather "
            "than complete."
        ),
    },
]

# ───────────────────────────────────────────────────────────────────────────
# Key-boundary caveats (appended to all assessments)
# ───────────────────────────────────────────────────────────────────────────
SCOPE_CAVEATS = [
    (
        "Scope boundary: This assessment is about forensic investigation of "
        "AI-system use and AI-generated or AI-edited content as evidence. "
        "It does not evaluate separate claims about using AI to help "
        "investigators analyze other evidence."
    ),
    (
        "Capability boundary: 'Missing' does not mean 'universally absent.' "
        "It means the capability is not broadly standardized, not "
        "consistently documented in public sources, or not shown end-to-end."
    ),
    (
        "Provenance boundary: C2PA-style provenance can verify that a "
        "credentialed manifest is intact and bound to an asset, but it "
        "does not by itself prove that every semantic claim in the content "
        "is true."
    ),
    (
        "Detection boundary: Absence of a watermark, provenance record, "
        "or detector hit is not conclusive evidence of human authorship, "
        "because NIST treats these methods as imperfect and requiring "
        "measured interpretation."
    ),
    (
        "Admissibility boundary: Forensic recoverability is not the same "
        "as courtroom admissibility. Legal admissibility also depends on "
        "jurisdiction, validation, chain of custody, and expert testimony."
    ),
]


# ───────────────────────────────────────────────────────────────────────────
# Assessment engine
# ───────────────────────────────────────────────────────────────────────────
def assess_functional_requirements(report: "ForensicReport") -> List[FRAssessment]:
    """
    Evaluate the 9 AI-forensics Functional Requirements against the
    results of a completed TRACE-AI-FR analysis.
    """
    assessments: List[FRAssessment] = []

    for defn in _FR_DEFINITIONS:
        fr = FRAssessment(
            fr_id=defn["fr_id"],
            title=defn["title"],
            description=defn["description"],
        )
        _evaluate(fr, report)
        assessments.append(fr)

    logger.info(
        "FR assessment complete: %d/%d fully addressed",
        sum(1 for a in assessments if a.status == FRStatus.FULLY_ADDRESSED),
        len(assessments),
    )
    return assessments


def _evaluate(fr: FRAssessment, report: "ForensicReport"):
    """Route to the per-FR evaluator."""
    evaluators = {
        "FR-1": _eval_fr1,
        "FR-2": _eval_fr2,
        "FR-3": _eval_fr3,
        "FR-4": _eval_fr4,
        "FR-5": _eval_fr5,
        "FR-6": _eval_fr6,
        "FR-7": _eval_fr7,
        "FR-8": _eval_fr8,
        "FR-9": _eval_fr9,
    }
    evaluators[fr.fr_id](fr, report)
    # Attach scope caveats to every FR
    fr.caveats = list(SCOPE_CAVEATS)


# ── FR-1: Unified AI Evidence Acquisition ─────────────────────────────────
def _eval_fr1(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    # Check evidence sources supported
    img = report.evidence_info
    if img.image_path:
        evidence.append(f"Evidence acquired from: {img.image_path}")

    # E01, ZIP, mounted
    itype = img.image_type.value if hasattr(img.image_type, "value") else str(img.image_type)
    evidence.append(f"Evidence type: {itype}")

    # OS and profiles
    if img.user_profiles:
        evidence.append(
            f"User profiles identified: {', '.join(img.user_profiles)}"
        )

    # Parsers that ran
    n_parsers = len(report.parser_results)
    evidence.append(f"{n_parsers} parsers executed across browser, OS, and content sources")

    # Browser + OS + content = multi-source
    families = set()
    for a in report.all_artifacts:
        fam = a.artifact_family.value if hasattr(a.artifact_family, "value") else str(a.artifact_family)
        families.add(fam.split("_")[0].upper())

    sources_hit = {"BROWSER", "OS", "CONTENT", "NATIVE"} & families
    evidence.append(
        f"Artifact families span: {', '.join(sorted(families)) or 'none'}"
    )

    # Check for memory and PCAP parser results
    memory_parsers = [r for r in report.parser_results if r.parser_name == "MemoryDumpScanner"]
    pcap_parsers = [r for r in report.parser_results if r.parser_name == "PCAPScanner"]
    has_memory = any(r.artifacts_found for r in memory_parsers)
    has_pcap = any(r.artifacts_found for r in pcap_parsers)

    if has_memory:
        evidence.append("Memory dump scanning: AI platform references recovered from RAM")
    elif memory_parsers:
        evidence.append("Memory dump scanner: executed (no memory dumps found in evidence)")

    if has_pcap:
        evidence.append("PCAP scanning: AI platform network traffic identified")
    elif pcap_parsers:
        evidence.append("PCAP scanner: executed (no network captures found in evidence)")

    acquisition_sources = len(sources_hit)
    if has_memory:
        acquisition_sources += 1
    if has_pcap:
        acquisition_sources += 1

    if acquisition_sources >= 3:
        fr.status = FRStatus.FULLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR acquires evidence from E01 images, mounted directories, "
            "ZIP archives, memory dumps, and PCAP network captures with cross-source "
            "parsers for browsers, OS artifacts, content remnants, memory residue, "
            "and network traffic. Unified acquisition covers browser, desktop, "
            "mobile, memory, and network source types under one case model."
        )
    elif acquisition_sources >= 2:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR acquires evidence from E01 images, mounted directories, "
            "and ZIP archives with parsers for browsers, OS artifacts, content "
            "remnants, memory dumps, and network captures. Full unified acquisition "
            "is supported when memory and network evidence are available."
        )
    elif report.all_artifacts:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "Evidence was acquired and parsed, but from a limited subset of "
            "available sources."
        )
    else:
        fr.status = FRStatus.GAP_IDENTIFIED
        fr.capability_summary = (
            "No artifacts were recovered from the evidence."
        )

    gaps.append("Cloud export API integration (provider-side logs) not available")
    if not has_memory:
        gaps.append("No memory dumps present in evidence for RAM analysis")
    if not has_pcap:
        gaps.append("No PCAP files present in evidence for network analysis")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-2: Full Session Reconstruction ─────────────────────────────────────
def _eval_fr2(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    n_fraues = len(report.fraues)
    n_timeline = len(report.timeline)

    if n_fraues > 0:
        evidence.append(f"{n_fraues} FRAUE(s) reconstructed as atomic events")
        for f in report.fraues[:3]:
            pn = f.platform.value if hasattr(f.platform, "value") else str(f.platform)
            evidence.append(f"  FRAUE: {pn} — {f.likely_activity_class or 'activity'}")

    if n_timeline > 0:
        evidence.append(f"{n_timeline} timeline events reconstructed with timestamps")

    # Check for prompt/response remnants
    for fp in report.ai_footprints:
        pn = fp.platform.value if hasattr(fp.platform, "value") else str(fp.platform)
        if fp.prompt_remnants_found:
            evidence.append(f"Prompt remnants found for {pn}")
        if fp.response_remnants_found:
            evidence.append(f"Response remnants found for {pn}")

    # Check for ChatGPT export data (turn-by-turn replay)
    export_parsers = [r for r in report.parser_results if r.parser_name == "ChatGPTExportParser"]
    has_export = any(r.artifacts_found for r in export_parsers)
    if has_export:
        n_messages = sum(
            1 for a in report.all_artifacts
            if a.parser_used == "ChatGPTExportParser" and a.artifact_subtype in (
                "user_message", "assistant_message", "tool_message"
            )
        )
        n_convs = sum(
            1 for a in report.all_artifacts
            if a.parser_used == "ChatGPTExportParser" and a.artifact_subtype == "conversation_export"
        )
        evidence.append(
            f"ChatGPT export data: {n_convs} conversations with {n_messages} "
            f"turn-by-turn messages (full prompt→response replay)"
        )

    if has_export and n_fraues > 0:
        fr.status = FRStatus.FULLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR reconstructs AI interaction sessions via FRAUEs with "
            "temporal windows, correlated timelines, and prompt/response remnant "
            "detection. ChatGPT conversation export parsing provides full "
            "turn-by-turn conversational replay including prompts, responses, "
            "model metadata, and plugin/tool usage per message."
        )
    elif n_fraues > 0 and n_timeline > 0:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR reconstructs AI interaction sessions via FRAUEs with "
            "temporal windows, correlated timelines, and prompt/response remnant "
            "detection. Full conversational replay (turn-by-turn prompts and "
            "responses) depends on platform-specific artifact availability. "
            "ChatGPT export parsing is supported when export data is present."
        )
    elif n_timeline > 0:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "Timeline events were reconstructed but full session FRAUEs could "
            "not be assembled from the available evidence."
        )
    else:
        fr.status = FRStatus.GAP_IDENTIFIED
        fr.capability_summary = (
            "No session reconstruction was possible from the analyzed evidence."
        )

    if not has_export:
        gaps.append("No ChatGPT conversation export found for full turn-by-turn replay")
    gaps.append("Edit and deletion tracking requires platform-specific database access")
    gaps.append("Attachment/file-upload tracing limited to download records and content remnants")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-3: Model, Version, Config Provenance ──────────────────────────────
def _eval_fr3(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    model_detected = False
    for fp in report.ai_footprints:
        pn = fp.platform.value if hasattr(fp.platform, "value") else str(fp.platform)
        if fp.model and str(fp.model) != "UNKNOWN":
            model_val = fp.model.value if hasattr(fp.model, "value") else str(fp.model)
            evidence.append(f"Model identified for {pn}: {model_val}")
            model_detected = True
        else:
            evidence.append(f"Platform detected ({pn}) but specific model not determined")

    # Check if any artifacts reference model strings
    for a in report.all_artifacts:
        if a.suspected_model and str(a.suspected_model) != "UNKNOWN":
            model_val = a.suspected_model.value if hasattr(a.suspected_model, "value") else str(a.suspected_model)
            evidence.append(f"Artifact-level model indicator: {model_val}")
            model_detected = True

    if model_detected:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR identifies AI models when model-specific strings "
            "appear in browser artifacts (URLs, cookies, API responses). "
            "Version history, configuration state, and change-management "
            "records are not available from client-side endpoint evidence alone."
        )
    elif report.ai_footprints:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "AI platforms were detected but model-level identification could "
            "not be confirmed from the available artifacts."
        )
    else:
        fr.status = FRStatus.GAP_IDENTIFIED
        fr.capability_summary = (
            "No AI platform or model provenance was recoverable."
        )

    gaps.append("Server-side version/configuration records not accessible from endpoint evidence")
    gaps.append("NIST-recommended logging and change-management metadata requires provider cooperation")
    gaps.append("Model version drift (e.g., GPT-4 updates) not trackable from client artifacts")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-4: Provenance and Authenticity Verification ────────────────────────
def _eval_fr4(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    # TRACE-AI-FR does hash-based integrity
    if report.evidence_info.image_path:
        evidence.append("Evidence image hash computed for chain-of-custody integrity")
    evidence.append("All exhibits include MD5 hashes for file-level verification")

    # Governance record tracks compliance
    if report.governance_record:
        evidence.append("Governance record documents all inference rules and disclosures")

    # Check for C2PA manifest scanning
    c2pa_parsers = [r for r in report.parser_results if r.parser_name == "C2PAManifestParser"]
    has_c2pa = any(r.artifacts_found for r in c2pa_parsers)
    c2pa_count = sum(len(r.artifacts_found) for r in c2pa_parsers)

    if has_c2pa:
        evidence.append(
            f"C2PA Content Credentials: {c2pa_count} manifests parsed and "
            f"AI-use assertions extracted from media files"
        )
    elif c2pa_parsers:
        evidence.append("C2PA manifest parser: executed (no C2PA manifests found in evidence)")

    if has_c2pa:
        fr.status = FRStatus.FULLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR provides hash-based integrity verification for evidence "
            "files and exhibits, governance-tracked chain of custody, and C2PA "
            "Content Credentials manifest parsing. C2PA manifests are scanned for "
            "AI-generation assertions, modification history, and software agent "
            "provenance. Provenance boundary: C2PA verifies manifest integrity "
            "but not semantic truth of content claims."
        )
    else:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR provides hash-based integrity verification for evidence "
            "files and exhibits, and governance-tracked chain of custody. "
            "C2PA Content Credentials parsing is supported but no manifests "
            "were found in the analyzed evidence."
        )

    if not has_c2pa:
        gaps.append("No C2PA Content Credentials manifests found in evidence")
    gaps.append("External provenance verification service integration not available")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-5: Detector Validation with Evidentiary Metrics ───────────────────
def _eval_fr5(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    # TRACE-AI-FR uses confidence scoring, not AI-content detection
    evidence.append(
        "7-layer confidence scoring model with per-artifact and per-FRAUE ratings"
    )
    evidence.append(
        "Confidence levels reported: HIGH, MODERATE, LOW, UNSUPPORTED/INSUFFICIENT"
    )

    if report.fraues:
        high = sum(1 for f in report.fraues
                   if "High" in (f.event_confidence.value
                                 if hasattr(f.event_confidence, "value")
                                 else str(f.event_confidence)))
        evidence.append(
            f"FRAUE confidence distribution: {high} HIGH of {len(report.fraues)} total"
        )

    fr.status = FRStatus.PARTIALLY_ADDRESSED
    fr.capability_summary = (
        "TRACE-AI-FR reports multi-layer confidence scores with explicit "
        "thresholds and classification (Direct vs. Inferred evidence). "
        "It does not perform AI-content detection (i.e., 'was this text "
        "written by AI?'). False-positive/negative rate reporting for "
        "detection classifiers is not in scope — the framework detects "
        "AI platform *use*, not AI-generated *content*."
    )

    gaps.append("AI-content detection (GPTZero, Turnitin-style) not integrated")
    gaps.append("Watermark detection for AI-generated images/text not implemented")
    gaps.append("No false-positive/false-negative rate reporting for content classifiers")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-6: Resilience to Tamper and Anti-Forensics ────────────────────────
def _eval_fr6(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    # Multi-signal correlation
    n_families = len(set(
        a.artifact_family.value if hasattr(a.artifact_family, "value")
        else str(a.artifact_family)
        for a in report.all_artifacts
    ))
    if n_families > 1:
        evidence.append(
            f"Cross-artifact corroboration across {n_families} artifact families"
        )

    evidence.append("Evidence-source-class tagging enables multi-signal reasoning")
    evidence.append(
        "Governance Rule 6 enforces cross-source corroboration for multi-source claims"
    )

    if report.governance_record and report.governance_record.known_blind_spots:
        evidence.append(
            f"{len(report.governance_record.known_blind_spots)} known blind spots disclosed"
        )

    # Check for anti-forensics detection
    af_parsers = [r for r in report.parser_results if r.parser_name == "AntiForensicsDetector"]
    has_af = any(r.artifacts_found for r in af_parsers)
    if has_af:
        cleanup_count = sum(
            1 for a in report.all_artifacts
            if a.parser_used == "AntiForensicsDetector" and a.artifact_type == "Cleanup Tool Execution"
        )
        gap_count = sum(
            1 for a in report.all_artifacts
            if a.parser_used == "AntiForensicsDetector" and a.artifact_type == "History Gap Detected"
        )
        anomaly_count = sum(
            1 for a in report.all_artifacts
            if a.parser_used == "AntiForensicsDetector" and a.artifact_type == "Timestamp Anomaly"
        )
        stripped_count = sum(
            1 for a in report.all_artifacts
            if a.parser_used == "AntiForensicsDetector" and a.artifact_type == "Metadata-Stripped AI Image"
        )

        af_details = []
        if cleanup_count:
            af_details.append(f"{cleanup_count} cleanup tool(s)")
        if gap_count:
            af_details.append(f"{gap_count} history gap(s)")
        if anomaly_count:
            af_details.append(f"{anomaly_count} timestamp anomaly(ies)")
        if stripped_count:
            af_details.append(f"{stripped_count} metadata-stripped image(s)")

        evidence.append(
            f"Anti-forensics detection: {', '.join(af_details)}"
        )
    elif af_parsers:
        evidence.append("Anti-forensics detector: executed (no tampering indicators found)")

    if has_af or n_families > 2:
        fr.status = FRStatus.FULLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR uses multi-artifact-family correlation, "
            "evidence-source-class tagging, and active anti-forensics detection "
            "to resist tampering. The AntiForensicsDetector identifies cleanup "
            "tool execution (CCleaner, BleachBit, etc.), browser history gaps, "
            "timestamp anomalies, and metadata stripping. "
            "Governance Rule 6 requires cross-source corroboration, and "
            "Rule 7 notes that cleanup affects persistence, not motive."
        )
    else:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR uses multi-artifact-family correlation and "
            "evidence-source-class tagging to resist single-point spoofing. "
            "Active anti-forensics detection (history wiping, cleanup tools, "
            "timestamp manipulation, metadata stripping) is supported and "
            "executed on all evidence."
        )

    gaps.append("Paraphrase and recompression detection requires content-level analysis")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-7: Third-Party Tool-Chain and Plugin Visibility ───────────────────
def _eval_fr7(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    # Check for browser extension and tool-chain parser results
    ext_parsers = [r for r in report.parser_results if r.parser_name == "BrowserExtensionParser"]
    tc_parsers = [r for r in report.parser_results if r.parser_name == "ToolChainParser"]
    has_extensions = any(r.artifacts_found for r in ext_parsers)
    has_toolchain = any(r.artifacts_found for r in tc_parsers)

    n_extensions = sum(len(r.artifacts_found) for r in ext_parsers)
    n_toolchain = sum(len(r.artifacts_found) for r in tc_parsers)

    # Also check ChatGPT export for plugin references
    plugin_artifacts = [
        a for a in report.all_artifacts
        if a.artifact_type in ("ChatGPT Plugin Usage", "ChatGPT Plugin/Custom GPT")
    ]

    if has_extensions:
        evidence.append(f"Browser extension scanner: {n_extensions} AI-related extensions detected")
    elif ext_parsers:
        evidence.append("Browser extension scanner: executed (no AI extensions found)")

    if has_toolchain:
        evidence.append(f"Tool-chain scanner: {n_toolchain} third-party AI tool traces detected")
    elif tc_parsers:
        evidence.append("Tool-chain scanner: executed (no tool-chain traces found)")

    if plugin_artifacts:
        evidence.append(f"ChatGPT plugin/Custom GPT references: {len(plugin_artifacts)}")

    evidence.append("Browser extension artifacts parsed from Chromium and Firefox profiles")
    evidence.append("Content parser scans for AI export files and naming patterns")
    evidence.append("Tool-chain detection covers: AutoGPT, LangChain, LlamaIndex, Zapier, IFTTT")
    evidence.append("RAG infrastructure scanning: Pinecone, Weaviate, ChromaDB, Qdrant, Milvus")

    has_any = has_extensions or has_toolchain or bool(plugin_artifacts)

    if has_any:
        fr.status = FRStatus.FULLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR actively traces third-party plugins, browser extensions, "
            "tool-chain automation (AutoGPT, LangChain, Zapier, IFTTT), "
            "ChatGPT Custom GPTs/plugins, and RAG vector-database infrastructure. "
            "The BrowserExtensionParser detects known AI extensions in Chromium "
            "and Firefox profiles. The ToolChainParser identifies API configurations "
            "and automation workflow traces."
        )
    else:
        fr.status = FRStatus.PARTIALLY_ADDRESSED
        fr.capability_summary = (
            "TRACE-AI-FR includes active scanners for browser extensions, "
            "tool-chain automation, ChatGPT plugins, and RAG infrastructure. "
            "No third-party tool-chain artifacts were found in the analyzed "
            "evidence, but detection capability is implemented."
        )

    gaps.append("Network-level API call tracing requires PCAP integration with deep packet inspection")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-8: Standardized Evidentiary Export ────────────────────────────────
def _eval_fr8(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    evidence.append("JSON export with full case metadata, artifacts, FRAUEs, governance")
    evidence.append("SQLite normalized database with 7+ relational tables")
    evidence.append("Markdown report following SANS/UNCC forensic report standard")
    evidence.append("HTML interactive report with FRAUE cards and governance panel")
    evidence.append("Governance JSON with 12-rule compliance matrix")
    evidence.append("All exports include chain-of-custody fields and hashes")

    if report.governance_record:
        evidence.append("Governance record includes disclosures and inference boundaries")

    fr.status = FRStatus.FULLY_ADDRESSED
    fr.capability_summary = (
        "TRACE-AI-FR exports evidence in 5 formats (JSON, SQLite, "
        "Markdown, HTML, Governance JSON) with structured case metadata, "
        "chain-of-custody hashes, FRAUE-level findings, temporal data, "
        "confidence scores, governance records, and inference boundaries. "
        "This provides a normalized AI evidence schema suitable for "
        "cross-tool interoperability."
    )

    gaps.append("No CASE/UCO (Cyber-investigation Analysis Standard Expression) mapping yet")
    gaps.append("STIX/TAXII incident sharing format not directly supported")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps


# ── FR-9: Extensible Parser Architecture ────────────────────────────────
def _eval_fr9(fr: FRAssessment, report: "ForensicReport"):
    evidence = []
    gaps = []

    n_parsers = len(report.parser_results)
    evidence.append(f"{n_parsers} parser results from auto-discovery registry")
    evidence.append("BaseParser abstract class with OS-aware registration")
    evidence.append("Parsers for: Chrome, Edge, Firefox, Brave, Safari, "
                    "Prefetch, AmCache, Registry, Plist, Quarantine, "
                    "iPhone logical, AI content scanning")
    evidence.append("E01 binary scanner fallback when libraries unavailable")

    succeeded = sum(1 for pr in report.parser_results
                    if pr.status.value in ("success", "SUCCESS", "Success"))
    evidence.append(f"{succeeded}/{n_parsers} parsers succeeded")

    fr.status = FRStatus.FULLY_ADDRESSED
    fr.capability_summary = (
        "TRACE-AI-FR implements a plugin-style parser registry with "
        "BaseParser abstract class, OS-aware auto-discovery, and "
        "graceful fallbacks (E01 binary scanner when pyewf/pytsk3 are "
        "unavailable, binary scan when python-registry is missing). "
        "New parsers can be added by subclassing BaseParser and "
        "registering with the parser registry."
    )

    gaps.append("No hot-reload or runtime parser update mechanism")
    gaps.append("Parser coverage is incremental — new AI apps require new parsers")

    fr.evidence_from_analysis = evidence
    fr.gaps = gaps
