"""
SQLite storage layer for normalized forensic findings.

Exports all artifact records, timeline events, matrix rows,
and case metadata to a structured SQLite database.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from .models import (
    ArtifactRecord,
    CaseInfo,
    ComparativeMatrixRow,
    EvidenceCoverage,
    EvidenceImageInfo,
    ForensicReport,
    ParserResult,
    TimelineEvent,
    AIUsageFootprint,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
-- AI Usage Evidence Analyzer - Normalized SQLite Schema
-- Version: 4.0.0

CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS case_info (
    case_id TEXT PRIMARY KEY,
    case_name TEXT,
    examiner TEXT,
    organization TEXT,
    description TEXT,
    created_at TEXT,
    tool_version TEXT
);

CREATE TABLE IF NOT EXISTS evidence_images (
    evidence_item_id TEXT PRIMARY KEY,
    case_id TEXT,
    image_path TEXT,
    image_type TEXT,
    image_format TEXT,
    image_size_bytes INTEGER,
    md5_hash TEXT,
    sha1_hash TEXT,
    sha256_hash TEXT,
    acquired_date TEXT,
    ewf_metadata TEXT,
    detected_os TEXT,
    user_profiles TEXT,
    processing_start TEXT,
    processing_end TEXT,
    read_only INTEGER DEFAULT 1,
    errors TEXT,
    FOREIGN KEY (case_id) REFERENCES case_info(case_id)
);

CREATE TABLE IF NOT EXISTS artifact_records (
    record_id TEXT PRIMARY KEY,
    case_id TEXT,
    evidence_item_id TEXT,
    source_image TEXT,
    partition_or_container TEXT,
    user_profile TEXT,
    artifact_family TEXT,
    artifact_type TEXT,
    artifact_subtype TEXT,
    artifact_path TEXT,
    parser_used TEXT,
    timestamp TEXT,
    timestamp_type TEXT,
    timezone_normalized INTEGER,
    timezone_info TEXT,
    extracted_indicator TEXT,
    suspected_platform TEXT,
    suspected_model TEXT,
    suspected_access_mode TEXT,
    classification TEXT,
    attribution_layer TEXT,
    confidence TEXT,
    corroborating_artifacts TEXT,
    notes TEXT,
    acquisition_source TEXT,
    platform_surface TEXT,
    evidence_source_class TEXT,
    related_voice_event_id TEXT,
    related_shared_link_id TEXT,
    related_generated_asset_id TEXT,
    FOREIGN KEY (case_id) REFERENCES case_info(case_id),
    FOREIGN KEY (evidence_item_id) REFERENCES evidence_images(evidence_item_id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,
    description TEXT,
    platform TEXT,
    access_mode TEXT,
    artifact_record_id TEXT,
    confidence TEXT,
    classification TEXT,
    FOREIGN KEY (artifact_record_id) REFERENCES artifact_records(record_id)
);

CREATE TABLE IF NOT EXISTS comparative_matrix (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT,
    user_profile TEXT,
    ai_tool_or_model TEXT,
    browser_vs_app TEXT,
    artifact_family TEXT,
    artifact_type TEXT,
    artifact_location TEXT,
    evidentiary_value TEXT,
    timestamp_quality TEXT,
    persistence_after_deletion TEXT,
    relevance_to_crime_scene TEXT,
    classification TEXT,
    confidence TEXT,
    evidence_coverage_caveat TEXT,
    comments TEXT
);

CREATE TABLE IF NOT EXISTS ai_usage_footprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT,
    model TEXT,
    access_mode TEXT,
    total_artifacts INTEGER,
    direct_artifacts INTEGER,
    inferred_artifacts INTEGER,
    earliest_activity TEXT,
    latest_activity TEXT,
    estimated_session_count INTEGER,
    image_upload_indicators INTEGER,
    content_export_indicators INTEGER,
    prompt_remnants_found INTEGER,
    response_remnants_found INTEGER,
    overall_confidence TEXT,
    caveats TEXT
);

CREATE TABLE IF NOT EXISTS parser_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parser_name TEXT,
    parser_version TEXT,
    status TEXT,
    artifacts_count INTEGER,
    errors TEXT,
    warnings TEXT,
    processing_time_ms REAL,
    paths_searched TEXT,
    paths_found TEXT,
    paths_missing TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS evidence_coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_type TEXT,
    full_disk_available INTEGER,
    partitions_accessible INTEGER,
    partitions_total INTEGER,
    encrypted_areas_detected INTEGER,
    carving_enabled INTEGER,
    os_detected TEXT,
    user_profiles_found TEXT,
    browsers_detected TEXT,
    native_apps_detected TEXT,
    artifact_families_available TEXT,
    artifact_families_missing TEXT,
    parsers_succeeded TEXT,
    parsers_failed TEXT,
    parsers_not_applicable TEXT,
    parsers_stub TEXT,
    coverage_notes TEXT,
    limitations TEXT
);

CREATE TABLE IF NOT EXISTS processing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    level TEXT,
    module TEXT,
    message TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_artifacts_platform ON artifact_records(suspected_platform);
CREATE INDEX IF NOT EXISTS idx_artifacts_confidence ON artifact_records(confidence);
CREATE INDEX IF NOT EXISTS idx_artifacts_family ON artifact_records(artifact_family);
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);

-- Recovery tables (v3.0)

CREATE TABLE IF NOT EXISTS carved_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_evidence_id TEXT,
    source_image_path TEXT,
    offset INTEGER,
    recovered_size INTEGER,
    signature_rule_used TEXT,
    carved_filename TEXT,
    temp_path TEXT,
    validation TEXT,
    recovery_mode TEXT,
    recovery_status TEXT,
    confidence_hint TEXT,
    extraction_timestamp TEXT,
    chain_of_custody_note TEXT
);

CREATE TABLE IF NOT EXISTS raw_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    offset INTEGER,
    length INTEGER,
    matched_pattern TEXT,
    hit_type TEXT,
    suspected_platform TEXT,
    confidence_hint TEXT,
    context_preview TEXT,
    scan_timestamp TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS partition_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    partition_index INTEGER,
    scheme TEXT,
    offset INTEGER,
    size_bytes INTEGER,
    fs_type_label TEXT,
    health TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS recovery_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    recovery_mode TEXT,
    started_at TEXT,
    ended_at TEXT,
    modes_applied TEXT,
    total_carved INTEGER,
    total_raw_hits INTEGER,
    partitions_found INTEGER,
    filesystem_health TEXT,
    evidence_access_tier TEXT,
    caveats TEXT,
    provenance_note TEXT
);

CREATE TABLE IF NOT EXISTS acquisition_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quality TEXT,
    imaging_tool TEXT,
    imaging_format TEXT,
    source_device TEXT,
    bad_sector_count INTEGER,
    total_sectors INTEGER,
    log_file_path TEXT,
    log_parsed INTEGER,
    percent_readable REAL,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_carved_evidence ON carved_artifacts(source_evidence_id);
CREATE INDEX IF NOT EXISTS idx_raw_hits_evidence ON raw_hits(evidence_id);

-- v4.0 tables

CREATE TABLE IF NOT EXISTS voice_evidence_records (
    record_id TEXT PRIMARY KEY,
    case_id TEXT,
    evidence_item_id TEXT,
    artifact_type TEXT,
    source_path TEXT,
    platform TEXT,
    transcript_snippet TEXT,
    duration_seconds REAL,
    speaker_count INTEGER,
    language TEXT,
    confidence TEXT,
    metadata_json TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS shared_link_records (
    record_id TEXT PRIMARY KEY,
    case_id TEXT,
    evidence_item_id TEXT,
    url TEXT,
    platform TEXT,
    link_type TEXT,
    source_artifact_id TEXT,
    discovered_in TEXT,
    context_snippet TEXT,
    is_accessible INTEGER,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS generated_asset_records (
    record_id TEXT PRIMARY KEY,
    case_id TEXT,
    evidence_item_id TEXT,
    asset_path TEXT,
    asset_type TEXT,
    platform TEXT,
    generation_method TEXT,
    c2pa_detected INTEGER,
    metadata_json TEXT,
    source_artifact_id TEXT,
    confidence TEXT,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_voice_platform ON voice_evidence_records(platform);
CREATE INDEX IF NOT EXISTS idx_shared_link_platform ON shared_link_records(platform);
CREATE INDEX IF NOT EXISTS idx_generated_asset_platform ON generated_asset_records(platform);
"""


class SQLiteStorage:
    """Manages export of forensic findings to SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def initialize(self):
        """Create the database and schema."""
        logger.info(f"Initializing SQLite database: {self.db_path}")
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(SCHEMA_SQL)
        self._conn.execute(
            "INSERT OR IGNORE INTO schema_version VALUES (?, ?, ?)",
            ("4.0.0", datetime.now().isoformat(), "v4.0 migration-safe schema"),
        )
        self._conn.commit()

    def export_report(self, report: ForensicReport):
        """Export a complete ForensicReport to SQLite."""
        if not self._conn:
            self.initialize()

        self._export_case_info(report.case_info, report.tool_version)
        self._export_evidence_info(report.evidence_info, report.case_info.case_id)
        self._export_artifacts(report.all_artifacts)
        self._export_timeline(report.timeline)
        self._export_matrix(report.matrix_rows)
        self._export_footprints(report.ai_footprints)
        self._export_parser_results(report.parser_results)
        self._export_coverage(report.evidence_coverage)
        self._export_logs(report.processing_logs)

        # Recovery tables (v3.0)
        if hasattr(report, "carved_artifacts") and report.carved_artifacts:
            self._export_carved_artifacts(report.carved_artifacts)
        if hasattr(report, "raw_hits") and report.raw_hits:
            self._export_raw_hits(report.raw_hits)
        if hasattr(report, "partition_findings") and report.partition_findings:
            self._export_partition_findings(report.partition_findings)
        if hasattr(report, "recovery_audit") and report.recovery_audit:
            self._export_recovery_audit(report.recovery_audit)
        if hasattr(report, "acquisition_metadata") and report.acquisition_metadata:
            self._export_acquisition_metadata(report.acquisition_metadata)

        # v4.0 tables
        if hasattr(report, "voice_evidence") and report.voice_evidence:
            self._export_voice_evidence(report.voice_evidence)
        if hasattr(report, "shared_links") and report.shared_links:
            self._export_shared_links(report.shared_links)
        if hasattr(report, "generated_assets") and report.generated_assets:
            self._export_generated_assets(report.generated_assets)

        self._conn.commit()
        logger.info(f"Report exported to SQLite: {self.db_path}")

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # -----------------------------------------------------------------------
    # Internal export methods
    # -----------------------------------------------------------------------

    def _export_case_info(self, case: CaseInfo, tool_version: str):
        self._conn.execute(
            "INSERT OR REPLACE INTO case_info VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case.case_id, case.case_name, case.examiner, case.organization,
             case.description, case.created_at.isoformat(), tool_version),
        )

    def _export_evidence_info(self, ei: EvidenceImageInfo, case_id: str):
        self._conn.execute(
            "INSERT OR REPLACE INTO evidence_images VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ei.evidence_item_id, case_id, ei.image_path,
                ei.image_type.value, ei.image_format, ei.image_size_bytes,
                ei.md5_hash, ei.sha1_hash, ei.sha256_hash,
                ei.acquired_date, json.dumps(ei.ewf_metadata),
                ei.detected_os.value, json.dumps(ei.user_profiles),
                ei.processing_start.isoformat() if ei.processing_start else None,
                ei.processing_end.isoformat() if ei.processing_end else None,
                1 if ei.read_only else 0,
                json.dumps(ei.errors),
            ),
        )

    def _export_artifacts(self, artifacts: List[ArtifactRecord]):
        for art in artifacts:
            self._conn.execute(
                "INSERT OR REPLACE INTO artifact_records VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    art.record_id, art.case_id, art.evidence_item_id,
                    art.source_image, art.partition_or_container,
                    art.user_profile, art.artifact_family.value,
                    art.artifact_type, art.artifact_subtype,
                    art.artifact_path, art.parser_used,
                    art.timestamp.isoformat() if art.timestamp else None,
                    art.timestamp_type.value, int(art.timezone_normalized),
                    art.timezone_info, art.extracted_indicator,
                    art.suspected_platform.value, art.suspected_model.value if art.suspected_model else None,
                    art.suspected_access_mode.value, art.classification.value,
                    art.attribution_layer.value, art.confidence.value,
                    json.dumps(art.corroborating_artifacts),
                    art.notes,
                    art.acquisition_source.value if art.acquisition_source else None,
                    art.platform_surface.value if art.platform_surface else None,
                    art.evidence_source_class.value if hasattr(art, 'evidence_source_class') and art.evidence_source_class else None,
                    art.related_voice_event_id,
                    art.related_shared_link_id,
                    art.related_generated_asset_id,
                ),
            )

    def _export_timeline(self, events: List[TimelineEvent]):
        for ev in events:
            self._conn.execute(
                "INSERT INTO timeline_events "
                "(timestamp, event_type, description, platform, access_mode, "
                "artifact_record_id, confidence, classification) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ev.timestamp.isoformat() if ev.timestamp else None,
                    ev.event_type, ev.description,
                    ev.platform.value, ev.access_mode.value,
                    ev.artifact_record_id, ev.confidence.value,
                    ev.classification.value,
                ),
            )

    def _export_matrix(self, rows: List[ComparativeMatrixRow]):
        for r in rows:
            self._conn.execute(
                "INSERT INTO comparative_matrix "
                "(platform, user_profile, ai_tool_or_model, browser_vs_app, "
                "artifact_family, artifact_type, artifact_location, "
                "evidentiary_value, timestamp_quality, persistence_after_deletion, "
                "relevance_to_crime_scene, classification, confidence, "
                "evidence_coverage_caveat, comments) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    r.platform.value, r.user_profile, r.ai_tool_or_model,
                    r.browser_vs_app.value, r.artifact_family.value,
                    r.artifact_type, r.artifact_location,
                    r.evidentiary_value, r.timestamp_quality,
                    r.persistence_after_deletion, r.relevance_to_crime_scene,
                    r.classification.value, r.confidence.value,
                    r.evidence_coverage_caveat, r.comments,
                ),
            )

    def _export_footprints(self, footprints: List[AIUsageFootprint]):
        for fp in footprints:
            self._conn.execute(
                "INSERT INTO ai_usage_footprints "
                "(platform, model, access_mode, total_artifacts, "
                "direct_artifacts, inferred_artifacts, earliest_activity, "
                "latest_activity, estimated_session_count, "
                "image_upload_indicators, content_export_indicators, "
                "prompt_remnants_found, response_remnants_found, "
                "overall_confidence, caveats) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fp.platform.value, fp.model.value if fp.model else None, fp.access_mode.value if fp.access_mode else None,
                    fp.total_artifacts, fp.direct_artifacts, fp.inferred_artifacts,
                    fp.earliest_activity.isoformat() if fp.earliest_activity else None,
                    fp.latest_activity.isoformat() if fp.latest_activity else None,
                    fp.estimated_session_count,
                    fp.image_upload_indicators, fp.content_export_indicators,
                    fp.prompt_remnants_found, fp.response_remnants_found,
                    fp.overall_confidence.value,
                    json.dumps(fp.caveats),
                ),
            )

    def _export_parser_results(self, results: List[ParserResult]):
        for pr in results:
            self._conn.execute(
                "INSERT INTO parser_results "
                "(parser_name, parser_version, status, artifacts_count, "
                "errors, warnings, processing_time_ms, paths_searched, "
                "paths_found, paths_missing, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pr.parser_name, pr.parser_version, pr.status.value,
                    len(pr.artifacts_found),
                    json.dumps(pr.errors), json.dumps(pr.warnings),
                    pr.processing_time_ms,
                    json.dumps(pr.artifact_paths_searched),
                    json.dumps(pr.artifact_paths_found),
                    json.dumps(pr.artifact_paths_missing),
                    pr.notes,
                ),
            )

    def _export_coverage(self, cov: EvidenceCoverage):
        self._conn.execute(
            "INSERT INTO evidence_coverage "
            "(image_type, full_disk_available, partitions_accessible, "
            "partitions_total, encrypted_areas_detected, carving_enabled, "
            "os_detected, user_profiles_found, browsers_detected, "
            "native_apps_detected, artifact_families_available, "
            "artifact_families_missing, parsers_succeeded, parsers_failed, "
            "parsers_not_applicable, parsers_stub, coverage_notes, limitations) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cov.image_type.value, int(cov.full_disk_available),
                cov.partitions_accessible, cov.partitions_total,
                int(cov.encrypted_areas_detected), int(cov.carving_enabled),
                cov.os_detected.value,
                json.dumps(cov.user_profiles_found),
                json.dumps(cov.browsers_detected),
                json.dumps(cov.native_apps_detected),
                json.dumps(cov.artifact_families_available),
                json.dumps(cov.artifact_families_missing),
                json.dumps(cov.parsers_succeeded),
                json.dumps(cov.parsers_failed),
                json.dumps(cov.parsers_not_applicable),
                json.dumps(cov.parsers_stub),
                json.dumps(cov.coverage_notes),
                json.dumps(cov.limitations),
            ),
        )

    def _export_logs(self, logs: List):
        for log in logs:
            self._conn.execute(
                "INSERT INTO processing_log (timestamp, level, module, message, details) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    log.timestamp.isoformat() if hasattr(log, 'timestamp') else None,
                    getattr(log, 'level', 'INFO'),
                    getattr(log, 'module', ''),
                    getattr(log, 'message', ''),
                    getattr(log, 'details', None),
                ),
            )

    # -------------------------------------------------------------------
    # Recovery export methods (v3.0)
    # -------------------------------------------------------------------

    def _export_carved_artifacts(self, carved):
        for ca in carved:
            self._conn.execute(
                "INSERT INTO carved_artifacts "
                "(source_evidence_id, source_image_path, offset, recovered_size, "
                "signature_rule_used, carved_filename, temp_path, validation, "
                "recovery_mode, recovery_status, confidence_hint, "
                "extraction_timestamp, chain_of_custody_note) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ca.source_evidence_id, ca.source_image_path,
                    ca.offset, ca.recovered_size,
                    ca.signature_rule_used, ca.carved_filename,
                    ca.temp_path, ca.validation.value,
                    ca.recovery_mode.value, ca.recovery_status.value,
                    ca.confidence_hint.value,
                    ca.extraction_timestamp.isoformat() if ca.extraction_timestamp else None,
                    ca.chain_of_custody_note,
                ),
            )

    def _export_raw_hits(self, hits):
        for hit in hits:
            self._conn.execute(
                "INSERT INTO raw_hits "
                "(evidence_id, offset, length, matched_pattern, hit_type, "
                "suspected_platform, confidence_hint, context_preview, "
                "scan_timestamp, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hit.evidence_id, hit.offset, hit.length,
                    hit.matched_pattern, hit.hit_type.value,
                    hit.suspected_platform.value, hit.confidence_hint.value,
                    hit.context_preview,
                    hit.scan_timestamp.isoformat() if hit.scan_timestamp else None,
                    hit.notes,
                ),
            )

    def _export_partition_findings(self, findings):
        for pf in findings:
            self._conn.execute(
                "INSERT INTO partition_findings "
                "(evidence_id, partition_index, scheme, offset, size_bytes, "
                "fs_type_label, health, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pf.evidence_id, pf.partition_index,
                    pf.scheme.value, pf.offset, pf.size_bytes,
                    pf.fs_type_label, pf.health.value, pf.notes,
                ),
            )

    def _export_recovery_audit(self, audit):
        if not audit:
            return
        self._conn.execute(
            "INSERT INTO recovery_audit "
            "(evidence_id, recovery_mode, started_at, ended_at, "
            "modes_applied, total_carved, total_raw_hits, partitions_found, "
            "filesystem_health, evidence_access_tier, caveats, provenance_note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                audit.evidence_id, audit.recovery_mode.value,
                audit.started_at.isoformat() if audit.started_at else None,
                audit.ended_at.isoformat() if audit.ended_at else None,
                json.dumps(audit.modes_applied),
                audit.total_carved, audit.total_raw_hits,
                audit.partitions_found,
                audit.filesystem_health.value,
                audit.evidence_access_tier.value,
                json.dumps(audit.caveats),
                audit.provenance_note,
            ),
        )

    def _export_acquisition_metadata(self, meta):
        if not meta:
            return
        self._conn.execute(
            "INSERT INTO acquisition_metadata "
            "(quality, imaging_tool, imaging_format, source_device, "
            "bad_sector_count, total_sectors, log_file_path, log_parsed, "
            "percent_readable, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                meta.quality.value, meta.imaging_tool, meta.imaging_format,
                meta.source_device, meta.bad_sector_count, meta.total_sectors,
                meta.log_file_path, int(meta.log_parsed),
                meta.percent_readable, meta.notes,
            ),
        )

    # -------------------------------------------------------------------
    # v4.0 export methods
    # -------------------------------------------------------------------

    def _export_voice_evidence(self, records):
        for rec in records:
            self._conn.execute(
                "INSERT OR REPLACE INTO voice_evidence_records VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    getattr(rec, 'record_id', None),
                    getattr(rec, 'case_id', None),
                    getattr(rec, 'evidence_item_id', None),
                    getattr(rec, 'artifact_type', '').value if hasattr(getattr(rec, 'artifact_type', None), 'value') else str(getattr(rec, 'artifact_type', '')),
                    getattr(rec, 'source_path', None),
                    getattr(rec, 'platform', '').value if hasattr(getattr(rec, 'platform', None), 'value') else str(getattr(rec, 'platform', '')),
                    getattr(rec, 'transcript_snippet', None),
                    getattr(rec, 'duration_seconds', None),
                    getattr(rec, 'speaker_count', None),
                    getattr(rec, 'language', None),
                    getattr(rec, 'confidence', '').value if hasattr(getattr(rec, 'confidence', None), 'value') else str(getattr(rec, 'confidence', '')),
                    json.dumps(getattr(rec, 'metadata', {})) if getattr(rec, 'metadata', None) else None,
                    getattr(rec, 'created_at', datetime.now()).isoformat() if getattr(rec, 'created_at', None) else datetime.now().isoformat(),
                ),
            )

    def _export_shared_links(self, records):
        for rec in records:
            self._conn.execute(
                "INSERT OR REPLACE INTO shared_link_records VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    getattr(rec, 'record_id', None),
                    getattr(rec, 'case_id', None),
                    getattr(rec, 'evidence_item_id', None),
                    getattr(rec, 'url', None),
                    getattr(rec, 'platform', '').value if hasattr(getattr(rec, 'platform', None), 'value') else str(getattr(rec, 'platform', '')),
                    getattr(rec, 'link_type', None),
                    getattr(rec, 'source_artifact_id', None),
                    getattr(rec, 'discovered_in', None),
                    getattr(rec, 'context_snippet', None),
                    1 if getattr(rec, 'is_accessible', False) else 0,
                    getattr(rec, 'created_at', datetime.now()).isoformat() if getattr(rec, 'created_at', None) else datetime.now().isoformat(),
                ),
            )

    def _export_generated_assets(self, records):
        for rec in records:
            self._conn.execute(
                "INSERT OR REPLACE INTO generated_asset_records VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    getattr(rec, 'record_id', None),
                    getattr(rec, 'case_id', None),
                    getattr(rec, 'evidence_item_id', None),
                    getattr(rec, 'asset_path', None),
                    getattr(rec, 'asset_type', None),
                    getattr(rec, 'platform', '').value if hasattr(getattr(rec, 'platform', None), 'value') else str(getattr(rec, 'platform', '')),
                    getattr(rec, 'generation_method', None),
                    1 if getattr(rec, 'c2pa_detected', False) else 0,
                    json.dumps(getattr(rec, 'metadata', {})) if getattr(rec, 'metadata', None) else None,
                    getattr(rec, 'source_artifact_id', None),
                    getattr(rec, 'confidence', '').value if hasattr(getattr(rec, 'confidence', None), 'value') else str(getattr(rec, 'confidence', '')),
                    getattr(rec, 'created_at', datetime.now()).isoformat() if getattr(rec, 'created_at', None) else datetime.now().isoformat(),
                ),
            )
