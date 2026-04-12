"""
macOS artifact parsers.

Parses macOS-specific forensic artifacts including:
- Plist files (application preferences, recent items)
- Quarantine events database
- Application Support directories
- Launch Services / recent applications
- Spotlight metadata (stub)
- Unified logs (stub)
"""

from __future__ import annotations

import os
import plistlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..models import (
    AccessMode,
    AIPlatform,
    ArtifactFamily,
    ArtifactRecord,
    AttributionLayer,
    ConfidenceLevel,
    EvidenceClassification,
    OSPlatform,
    ParserResult,
    ParserStatus,
    TimestampType,
)
from ..parser_registry import BaseParser, register_parser
from ..parsers.browser_parsers import query_sqlite
from ..signatures import ALL_SIGNATURES, match_domain, match_model_string


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def cocoa_time_to_datetime(seconds: float) -> Optional[datetime]:
    """Convert Cocoa/Core Data timestamp to datetime."""
    if not seconds:
        return None
    try:
        return COCOA_EPOCH + timedelta(seconds=seconds)
    except (OverflowError, OSError):
        return None


# ---------------------------------------------------------------------------
# Quarantine Events Parser
# ---------------------------------------------------------------------------

@register_parser
class QuarantineEventsParser(BaseParser):
    """Parse macOS quarantine events database for AI-related downloads."""

    PARSER_NAME = "macOSQuarantineParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.MACOS]
    ARTIFACT_FAMILY = "File System"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        qe_db = os.path.join(
            self.evidence_root, "Users", self.user_profile,
            "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2"
        )
        paths_searched.append(qe_db)

        if not os.path.isfile(qe_db):
            paths_missing.append(qe_db)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Quarantine events database not found.",
            )

        paths_found.append(qe_db)

        try:
            rows = query_sqlite(
                qe_db,
                "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, "
                "LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString, "
                "LSQuarantineOriginURLString, LSQuarantineSenderName, "
                "LSQuarantineSenderAddress, LSQuarantineTypeNumber "
                "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC"
            )

            for row in rows:
                origin_url = row.get("LSQuarantineOriginURLString", "") or ""
                data_url = row.get("LSQuarantineDataURLString", "") or ""
                agent = row.get("LSQuarantineAgentName", "") or ""
                combined = f"{origin_url} {data_url} {agent}"

                platform = match_domain(combined)
                if not platform:
                    continue

                ts_raw = row.get("LSQuarantineTimeStamp")
                ts = cocoa_time_to_datetime(ts_raw) if ts_raw else None

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile,
                    artifact_family=ArtifactFamily.FILE_SYSTEM,
                    artifact_type="Quarantine Event",
                    artifact_subtype="Download Source",
                    artifact_path=qe_db,
                    parser_used=self.PARSER_NAME,
                    timestamp=ts,
                    timestamp_type=TimestampType.CREATED,
                    timezone_normalized=True if ts else False,
                    timezone_info="UTC (Cocoa epoch)" if ts else "",
                    extracted_indicator=f"Origin: {origin_url}, Data: {data_url}, Agent: {agent}",
                    suspected_platform=platform,
                    suspected_access_mode=AccessMode.BROWSER,
                    classification=EvidenceClassification.DIRECT,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.MODERATE,
                    notes="Quarantine event records download source information.",
                )
                artifacts.append(record)

        except Exception as exc:
            errors.append(f"Quarantine events parse error: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )


# ---------------------------------------------------------------------------
# macOS Application Support Parser
# ---------------------------------------------------------------------------

@register_parser
class MacOSAppSupportParser(BaseParser):
    """Check macOS Application Support directories for AI native app artifacts."""

    PARSER_NAME = "macOSAppSupportParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Native Application"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)

        for sig in ALL_SIGNATURES:
            for folder_template in sig.app_support_folders_macos:
                # Replace ~/Library with the user's Library
                folder = folder_template.replace("~/", "")
                full_path = os.path.join(user_base, folder)
                paths_searched.append(full_path)

                if os.path.isdir(full_path):
                    paths_found.append(full_path)

                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.NATIVE_APP,
                        artifact_type="App Support Directory",
                        artifact_subtype="macOS Application Support",
                        artifact_path=full_path,
                        parser_used=self.PARSER_NAME,
                        extracted_indicator=f"App support found: {folder}",
                        suspected_platform=sig.platform,
                        suspected_access_mode=AccessMode.NATIVE_APP,
                        classification=EvidenceClassification.DIRECT,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.MODERATE,
                        notes="Application support directory present. Indicates installation.",
                    )
                    artifacts.append(record)

                    # Scan for databases and config files
                    try:
                        for root, dirs, files in os.walk(full_path):
                            for f in files:
                                fp = os.path.join(root, f)
                                if f.endswith((".db", ".sqlite", ".sqlite3", ".json", ".plist", ".log")):
                                    try:
                                        with open(fp, "rb") as fh:
                                            data = fh.read(1024 * 512)
                                        text = data.decode("utf-8", errors="replace")
                                        model = match_model_string(text)
                                        if model:
                                            record = ArtifactRecord(
                                                case_id=self.case_id,
                                                evidence_item_id=self.evidence_item_id,
                                                source_image=self.source_image,
                                                user_profile=self.user_profile,
                                                artifact_family=ArtifactFamily.NATIVE_APP,
                                                artifact_type="App Data File",
                                                artifact_subtype="Model String",
                                                artifact_path=fp,
                                                parser_used=self.PARSER_NAME,
                                                extracted_indicator=f"Model: {model.value} in {f}",
                                                suspected_platform=sig.platform,
                                                suspected_model=model,
                                                suspected_access_mode=AccessMode.NATIVE_APP,
                                                classification=EvidenceClassification.DIRECT,
                                                attribution_layer=AttributionLayer.MODEL,
                                                confidence=ConfidenceLevel.MODERATE,
                                            )
                                            artifacts.append(record)
                                    except Exception:
                                        pass
                    except Exception as exc:
                        errors.append(f"Error scanning {full_path}: {exc}")
                else:
                    paths_missing.append(full_path)

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )


# ---------------------------------------------------------------------------
# macOS Plist / Recent Items Parser
# ---------------------------------------------------------------------------

@register_parser
class MacOSRecentItemsParser(BaseParser):
    """Parse macOS plist files for recent application and file access related to AI tools."""

    PARSER_NAME = "macOSRecentItemsParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.MACOS]
    ARTIFACT_FAMILY = "OS Recent Files"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)

        # Check com.apple.recentitems.plist
        recent_plist = os.path.join(
            user_base, "Library", "Preferences", "com.apple.recentitems.plist"
        )
        paths_searched.append(recent_plist)

        if os.path.isfile(recent_plist):
            paths_found.append(recent_plist)
            try:
                with open(recent_plist, "rb") as f:
                    plist_data = plistlib.load(f)

                # Scan for AI-related entries
                self._scan_plist_recursive(plist_data, recent_plist, artifacts)

            except Exception as exc:
                errors.append(f"Error parsing {recent_plist}: {exc}")
        else:
            paths_missing.append(recent_plist)

        # Scan all plists in Preferences for AI bundle IDs
        prefs_dir = os.path.join(user_base, "Library", "Preferences")
        if os.path.isdir(prefs_dir):
            for fname in os.listdir(prefs_dir):
                if not fname.endswith(".plist"):
                    continue
                # Check if the plist name matches an AI bundle ID
                for sig in ALL_SIGNATURES:
                    for bid in sig.bundle_ids:
                        if bid.lower() in fname.lower():
                            fpath = os.path.join(prefs_dir, fname)
                            paths_found.append(fpath)
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.OS_PLIST,
                                artifact_type="Preferences Plist",
                                artifact_subtype="Bundle ID Match",
                                artifact_path=fpath,
                                parser_used=self.PARSER_NAME,
                                extracted_indicator=f"Plist: {fname} matches {bid}",
                                suspected_platform=sig.platform,
                                suspected_access_mode=AccessMode.NATIVE_APP,
                                classification=EvidenceClassification.DIRECT,
                                attribution_layer=AttributionLayer.PLATFORM,
                                confidence=ConfidenceLevel.MODERATE,
                                notes="Plist matching AI app bundle ID found.",
                            )
                            artifacts.append(record)
                            break

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )

    def _scan_plist_recursive(self, data, source_path: str, artifacts: List[ArtifactRecord]):
        """Recursively scan plist data for AI-related strings."""
        if isinstance(data, dict):
            for k, v in data.items():
                self._check_plist_value(str(k), source_path, artifacts)
                self._scan_plist_recursive(v, source_path, artifacts)
        elif isinstance(data, list):
            for item in data:
                self._scan_plist_recursive(item, source_path, artifacts)
        elif isinstance(data, str):
            self._check_plist_value(data, source_path, artifacts)

    def _check_plist_value(self, value: str, source_path: str, artifacts: List[ArtifactRecord]):
        platform = match_domain(value)
        if not platform:
            for sig in ALL_SIGNATURES:
                for app in sig.app_names_macos + sig.bundle_ids:
                    if app.lower() in value.lower():
                        platform = sig.platform
                        break
                if platform:
                    break

        if platform:
            record = ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                user_profile=self.user_profile,
                artifact_family=ArtifactFamily.OS_PLIST,
                artifact_type="Plist Value",
                artifact_subtype="AI Reference",
                artifact_path=source_path,
                parser_used=self.PARSER_NAME,
                extracted_indicator=value[:200],
                suspected_platform=platform,
                classification=EvidenceClassification.INFERRED,
                attribution_layer=AttributionLayer.PLATFORM,
                confidence=ConfidenceLevel.LOW,
                notes="Value found in plist file. Requires corroboration.",
            )
            artifacts.append(record)


# ---------------------------------------------------------------------------
# macOS Unified Log Parser
# ---------------------------------------------------------------------------

@register_parser
class MacOSUnifiedLogParser(BaseParser):
    """
    Parse macOS Unified Logs for AI-related activity.

    Attempts to parse:
    - .tracev3 files from /private/var/db/diagnostics
    - Exported log show text files
    - Persistent log files from /var/db/uuidtext
    
    Searches for AI-related process names, domains, and activity.
    Full parsing requires macos-unifiedlogs tool or log show exports.
    Falls back to binary/text string scanning.
    """

    PARSER_NAME = "macOSUnifiedLogParser"
    PARSER_VERSION = "2.0.0"
    SUPPORTED_OS = [OSPlatform.MACOS]
    ARTIFACT_FAMILY = "OS Unified Log"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        # Primary unified log locations
        log_locations = [
            os.path.join(self.evidence_root, "private", "var", "db", "diagnostics"),
            os.path.join(self.evidence_root, "var", "db", "diagnostics"),
            os.path.join(self.evidence_root, "private", "var", "db", "uuidtext"),
            os.path.join(self.evidence_root, "var", "db", "uuidtext"),
            # Also check for exported log files
            os.path.join(self.evidence_root, "Users", self.user_profile, "Desktop"),
            os.path.join(self.evidence_root, "Users", self.user_profile, "Downloads"),
        ]

        found_log_data = False
        
        for log_dir in log_locations:
            paths_searched.append(log_dir)
            
            if not os.path.exists(log_dir):
                paths_missing.append(log_dir)
                continue
                
            paths_found.append(log_dir)
            found_log_data = True
            
            # Scan directory for log files
            try:
                for root, dirs, files in os.walk(log_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        
                        # Check for tracev3 files (binary unified logs)
                        if fname.endswith('.tracev3'):
                            self._scan_binary_log(fpath, fname, artifacts, errors)
                        
                        # Check for exported text logs
                        elif fname.endswith('.log') or fname.endswith('.txt'):
                            if 'system' in fname.lower() or 'log' in fname.lower():
                                self._scan_text_log(fpath, fname, artifacts, errors)
                        
                        # Check for logarchive files
                        elif fname.endswith('.logarchive') or 'logarchive' in fname.lower():
                            self._scan_binary_log(fpath, fname, artifacts, errors)
                            
            except Exception as exc:
                errors.append(f"Error scanning {log_dir}: {exc}")

        if not found_log_data:
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Unified log directories not found.",
            )

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.PARTIAL
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes="Unified logs parsed via string scanning. For full structured parsing, "
                  "use 'log show' or macos-unifiedlogs tool to export before acquisition.",
        )

    def _scan_binary_log(self, log_path: str, log_name: str,
                         artifacts: List, errors: List) -> None:
        """Scan binary unified log files for AI-related strings."""
        try:
            with open(log_path, "rb") as f:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB
                chunk_count = 0
                max_chunks = 50  # Limit to avoid excessive processing
                
                while chunk_count < max_chunks:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    chunk_count += 1
                    
                    # Try to decode as UTF-8/UTF-16 and search
                    for encoding in ("utf-8", "utf-16-le"):
                        try:
                            text = data.decode(encoding, errors="replace")
                            
                            # Search for AI-related patterns
                            for sig in ALL_SIGNATURES:
                                # Check domains
                                for domain in sig.domains:
                                    if domain.lower() in text.lower():
                                        idx = text.lower().find(domain.lower())
                                        context_start = max(0, idx - 100)
                                        context_end = min(len(text), idx + len(domain) + 200)
                                        context = text[context_start:context_end].strip()
                                        
                                        record = ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.OS_UNIFIED_LOG,
                                            artifact_type="macOS Unified Log",
                                            artifact_subtype="Binary String Match",
                                            artifact_path=log_path,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=f"Domain: {domain}",
                                            suspected_platform=sig.platform,
                                            suspected_access_mode=AccessMode.UNKNOWN,
                                            classification=EvidenceClassification.CIRCUMSTANTIAL,
                                            attribution_layer=AttributionLayer.PLATFORM,
                                            confidence=ConfidenceLevel.LOW,
                                            notes=f"Unified log binary scan. Context: {context[:150]}",
                                        )
                                        artifacts.append(record)
                                
                                # Check process names (macOS applications)
                                for proc in sig.process_names:
                                    if proc.lower() in text.lower():
                                        record = ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.OS_UNIFIED_LOG,
                                            artifact_type="macOS Unified Log",
                                            artifact_subtype="Process Match",
                                            artifact_path=log_path,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=f"Process: {proc}",
                                            suspected_platform=sig.platform,
                                            suspected_access_mode=AccessMode.NATIVE_APP,
                                            classification=EvidenceClassification.CIRCUMSTANTIAL,
                                            attribution_layer=AttributionLayer.PLATFORM,
                                            confidence=ConfidenceLevel.MODERATE,
                                            notes=f"Process name in unified log: {proc}",
                                        )
                                        artifacts.append(record)
                                        
                        except Exception:
                            continue
                            
        except Exception as exc:
            errors.append(f"Error scanning binary log {log_name}: {exc}")

    def _scan_text_log(self, log_path: str, log_name: str,
                       artifacts: List, errors: List) -> None:
        """Scan exported text log files for AI-related content."""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                line_count = 0
                max_lines = 100000  # Limit lines to avoid excessive processing
                
                for line in f:
                    if line_count > max_lines:
                        break
                    line_count += 1
                    
                    line_lower = line.lower()
                    
                    # Search for AI-related patterns in each line
                    for sig in ALL_SIGNATURES:
                        matched = False
                        indicator = ""
                        
                        # Check domains
                        for domain in sig.domains:
                            if domain.lower() in line_lower:
                                matched = True
                                indicator = f"Domain: {domain}"
                                break
                        
                        # Check process names
                        if not matched:
                            for proc in sig.process_names:
                                if proc.lower() in line_lower:
                                    matched = True
                                    indicator = f"Process: {proc}"
                                    break
                        
                        if matched:
                            # Try to extract timestamp from log line
                            timestamp = None
                            # Common macOS log format: YYYY-MM-DD HH:MM:SS.microseconds
                            import re
                            ts_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                            if ts_match:
                                try:
                                    timestamp = datetime.strptime(ts_match.group(1), 
                                                                "%Y-%m-%d %H:%M:%S")
                                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                                except Exception:
                                    pass
                            
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.OS_UNIFIED_LOG,
                                artifact_type="macOS Unified Log",
                                artifact_subtype="Text Log Entry",
                                artifact_path=log_path,
                                parser_used=self.PARSER_NAME,
                                timestamp=timestamp,
                                timestamp_type=TimestampType.CREATED,
                                timezone_normalized=True if timestamp else False,
                                extracted_indicator=indicator,
                                suspected_platform=sig.platform,
                                suspected_access_mode=AccessMode.UNKNOWN,
                                classification=EvidenceClassification.CIRCUMSTANTIAL,
                                attribution_layer=AttributionLayer.PLATFORM,
                                confidence=ConfidenceLevel.MODERATE,
                                notes=f"Log entry: {line.strip()[:200]}",
                            )
                            artifacts.append(record)
                            
        except Exception as exc:
            errors.append(f"Error scanning text log {log_name}: {exc}")
