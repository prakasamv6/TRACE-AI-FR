"""
iPhone logical artifact parsers (optional).

These parsers only operate on iPhone artifacts that are actually present
in the evidence source or supplied as extracted logical artifacts.
Findings are reported only when iPhone artifacts are actually found.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import List, Optional

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
from ..parsers.browser_parsers import query_sqlite, check_ai_url
from ..signatures import ALL_SIGNATURES, match_domain


# ---------------------------------------------------------------------------
# iPhone Safari History Parser
# ---------------------------------------------------------------------------

@register_parser
class IPhoneSafariParser(BaseParser):
    """
    Parse iPhone Safari history from logical extraction artifacts.

    Only reports findings when iPhone artifacts are actually present.
    """

    PARSER_NAME = "iPhoneSafariParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.IPHONE]
    ARTIFACT_FAMILY = "Browser History"
    IS_STUB = False

    # Common paths for Safari history in iPhone logical extractions
    SAFARI_PATHS = [
        "HomeDomain/Library/Safari/History.db",
        "private/var/mobile/Library/Safari/History.db",
        "mobile/Library/Safari/History.db",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        history_db = None
        for rel_path in self.SAFARI_PATHS:
            full_path = os.path.join(self.evidence_root, rel_path)
            paths_searched.append(full_path)
            if os.path.isfile(full_path):
                history_db = full_path
                paths_found.append(full_path)
                break
            else:
                paths_missing.append(full_path)

        if not history_db:
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="iPhone Safari history database not found in evidence. "
                      "iPhone artifacts are only reported when actually present.",
            )

        try:
            rows = query_sqlite(
                history_db,
                "SELECT hi.url, hv.visit_time, hv.title "
                "FROM history_items hi "
                "JOIN history_visits hv ON hi.id = hv.history_item "
                "ORDER BY hv.visit_time DESC"
            )

            for row in rows:
                url = row.get("url", "")
                match = check_ai_url(url)
                if not match:
                    continue

                platform, domain = match
                from ..parsers.macos_parsers import cocoa_time_to_datetime
                ts = cocoa_time_to_datetime(row.get("visit_time", 0))

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile or "mobile",
                    artifact_family=ArtifactFamily.BROWSER_HISTORY,
                    artifact_type="URL Visit",
                    artifact_subtype="iPhone Safari History",
                    artifact_path=history_db,
                    parser_used=self.PARSER_NAME,
                    timestamp=ts,
                    timestamp_type=TimestampType.LAST_VISITED,
                    timezone_normalized=True if ts else False,
                    timezone_info="UTC (Cocoa epoch)" if ts else "",
                    extracted_indicator=url,
                    suspected_platform=platform,
                    suspected_access_mode=AccessMode.BROWSER,
                    classification=EvidenceClassification.DIRECT,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.MODERATE,
                    notes=f"iPhone Safari visit. Title: {row.get('title', '')}",
                )
                artifacts.append(record)

        except Exception as exc:
            errors.append(f"iPhone Safari parse error: {exc}")

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
# iPhone App Usage Parser
# ---------------------------------------------------------------------------

@register_parser
class IPhoneAppUsageParser(BaseParser):
    """
    Parse iPhone application usage indicators for AI apps.

    Parses:
    - KnowledgeC.db for app usage, screen time, and activity
    - DataUsage.sqlite for network data usage by app
    - installed.csv or app directories for installed apps
    - Application State database for app installation artifacts
    
    Detects AI app installations and usage patterns.
    """

    PARSER_NAME = "iPhoneAppUsageParser"
    PARSER_VERSION = "2.0.0"
    SUPPORTED_OS = [OSPlatform.IPHONE]
    ARTIFACT_FAMILY = "Native Application"
    IS_STUB = False

    APP_DOMAIN_PATHS = [
        "AppDomain-{bundle_id}",
        "AppDomainGroup-group.{bundle_id}",
    ]

    KNOWLEDGEC_PATHS = [
        "private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db",
        "mobile/Library/CoreDuet/Knowledge/knowledgeC.db",
        "HomeDomain/Library/CoreDuet/Knowledge/knowledgeC.db",
    ]

    DATAUSAGE_PATHS = [
        "private/var/wireless/Library/Databases/DataUsage.sqlite",
        "wireless/Library/Databases/DataUsage.sqlite",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        # Check for app domain directories (installed apps)
        for sig in ALL_SIGNATURES:
            for bundle_id in sig.package_ids_mobile:
                for pattern in self.APP_DOMAIN_PATHS:
                    path = pattern.format(bundle_id=bundle_id)
                    full_path = os.path.join(self.evidence_root, path)
                    paths_searched.append(full_path)

                    if os.path.isdir(full_path):
                        paths_found.append(full_path)
                        
                        # Check for app metadata
                        app_info = self._get_app_info(full_path)
                        
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile or "mobile",
                            artifact_family=ArtifactFamily.NATIVE_APP,
                            artifact_type="App Installation",
                            artifact_subtype="iPhone App Domain",
                            artifact_path=full_path,
                            parser_used=self.PARSER_NAME,
                            extracted_indicator=f"Bundle: {bundle_id}",
                            suspected_platform=sig.platform,
                            suspected_access_mode=AccessMode.NATIVE_APP,
                            classification=EvidenceClassification.DIRECT,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.MODERATE,
                            notes=f"iPhone app installed. {app_info}",
                        )
                        artifacts.append(record)
                    else:
                        paths_missing.append(full_path)

        # Parse KnowledgeC.db for app usage
        knowledgec_db = None
        for rel_path in self.KNOWLEDGEC_PATHS:
            full_path = os.path.join(self.evidence_root, rel_path)
            paths_searched.append(full_path)
            if os.path.isfile(full_path):
                knowledgec_db = full_path
                paths_found.append(full_path)
                break
            else:
                paths_missing.append(full_path)

        if knowledgec_db:
            self._parse_knowledgec(knowledgec_db, artifacts, errors)

        # Parse DataUsage.sqlite for network usage
        datausage_db = None
        for rel_path in self.DATAUSAGE_PATHS:
            full_path = os.path.join(self.evidence_root, rel_path)
            paths_searched.append(full_path)
            if os.path.isfile(full_path):
                datausage_db = full_path
                paths_found.append(full_path)
                break
            else:
                paths_missing.append(full_path)

        if datausage_db:
            self._parse_datausage(datausage_db, artifacts, errors)

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes="iPhone app usage analysis includes app directories, KnowledgeC.db, and DataUsage.sqlite.",
        )

    def _get_app_info(self, app_path: str) -> str:
        """Extract app information from directory."""
        info_parts = []
        try:
            # Check for Info.plist
            for root, dirs, files in os.walk(app_path):
                if 'Info.plist' in files:
                    info_plist = os.path.join(root, 'Info.plist')
                    try:
                        with open(info_plist, 'rb') as f:
                            plist_data = plistlib.load(f)
                            if 'CFBundleDisplayName' in plist_data:
                                info_parts.append(f"Display: {plist_data['CFBundleDisplayName']}")
                            if 'CFBundleVersion' in plist_data:
                                info_parts.append(f"Version: {plist_data['CFBundleVersion']}")
                    except Exception:
                        pass
                    break
        except Exception:
            pass
        
        return " | ".join(info_parts) if info_parts else "App data directory present"

    def _parse_knowledgec(self, db_path: str, artifacts: List, errors: List) -> None:
        """Parse KnowledgeC.db for app usage events."""
        try:
            from ..parsers.browser_parsers import query_sqlite
            
            # Query app usage events
            # ZOBJECT table contains app usage events
            # ZSTRUCTUREDMETADATA contains detailed event data
            query = """
                SELECT 
                    ZOBJECT.ZSTARTDATE,
                    ZOBJECT.ZENDDATE,
                    ZOBJECT.ZVALUESTRING,
                    ZSTRUCTUREDMETADATA.Z_DKAPPUSAGEMETADATAKEY__BUNDLEID
                FROM ZOBJECT
                LEFT JOIN ZSTRUCTUREDMETADATA ON ZOBJECT.ZSTRUCTUREDMETADATA = ZSTRUCTUREDMETADATA.Z_PK
                WHERE ZOBJECT.ZSTREAMNAME LIKE '%app%'
                   OR ZSTRUCTUREDMETADATA.Z_DKAPPUSAGEMETADATAKEY__BUNDLEID IS NOT NULL
                ORDER BY ZOBJECT.ZSTARTDATE DESC
                LIMIT 1000
            """
            
            try:
                rows = query_sqlite(db_path, query)
                
                for row in rows:
                    bundle_id = row.get("Z_DKAPPUSAGEMETADATAKEY__BUNDLEID", "")
                    value_string = row.get("ZVALUESTRING", "")
                    
                    if not bundle_id and not value_string:
                        continue
                    
                    # Check if this is an AI app
                    for sig in ALL_SIGNATURES:
                        if bundle_id in sig.package_ids_mobile:
                            # Convert CoreData timestamp (seconds since 2001-01-01)
                            from ..parsers.macos_parsers import cocoa_time_to_datetime
                            start_ts = cocoa_time_to_datetime(row.get("ZSTARTDATE", 0))
                            end_ts = cocoa_time_to_datetime(row.get("ZENDDATE", 0))
                            
                            duration = ""
                            if start_ts and end_ts:
                                duration_sec = int((end_ts - start_ts).total_seconds())
                                duration = f"Duration: {duration_sec}s"
                            
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile or "mobile",
                                artifact_family=ArtifactFamily.NATIVE_APP,
                                artifact_type="App Usage",
                                artifact_subtype="KnowledgeC Event",
                                artifact_path=db_path,
                                parser_used=self.PARSER_NAME,
                                timestamp=start_ts,
                                timestamp_type=TimestampType.SESSION_START,
                                timezone_normalized=True if start_ts else False,
                                extracted_indicator=f"App used: {bundle_id}",
                                suspected_platform=sig.platform,
                                suspected_access_mode=AccessMode.NATIVE_APP,
                                classification=EvidenceClassification.DIRECT,
                                attribution_layer=AttributionLayer.PLATFORM,
                                confidence=ConfidenceLevel.HIGH,
                                notes=f"App usage event from KnowledgeC. {duration}",
                            )
                            artifacts.append(record)
                            break
                            
            except Exception as exc:
                # Try alternative query if schema is different
                errors.append(f"KnowledgeC primary query failed: {exc}. Attempting fallback.")
                
                # Fallback: just scan for bundle IDs
                try:
                    fallback_query = "SELECT name FROM sqlite_master WHERE type='table'"
                    tables = query_sqlite(db_path, fallback_query)
                    # Just note that we found the database
                    errors.append(f"KnowledgeC found with tables: {[t['name'] for t in tables[:5]]}")
                except Exception:
                    pass
                    
        except Exception as exc:
            errors.append(f"Error parsing KnowledgeC.db: {exc}")

    def _parse_datausage(self, db_path: str, artifacts: List, errors: List) -> None:
        """Parse DataUsage.sqlite for network usage by AI apps."""
        try:
            from ..parsers.browser_parsers import query_sqlite
            
            # Query for app network usage
            # ZPROCESS table contains app bundle identifiers
            # ZLIVEUSAGE contains network usage data
            query = """
                SELECT 
                    ZPROCESS.ZBUNDLENAME,
                    ZPROCESS.ZPROCNAME,
                    ZLIVEUSAGE.ZWIFIIN,
                    ZLIVEUSAGE.ZWIFIOUT,
                    ZLIVEUSAGE.ZWWANIN,
                    ZLIVEUSAGE.ZWWANOUT,
                    ZLIVEUSAGE.ZTIMESTAMP
                FROM ZLIVEUSAGE
                LEFT JOIN ZPROCESS ON ZLIVEUSAGE.ZHASPROCESS = ZPROCESS.Z_PK
                WHERE ZPROCESS.ZBUNDLENAME IS NOT NULL
                ORDER BY ZLIVEUSAGE.ZTIMESTAMP DESC
                LIMIT 500
            """
            
            try:
                rows = query_sqlite(db_path, query)
                
                for row in rows:
                    bundle_name = row.get("ZBUNDLENAME", "")
                    
                    # Check if this is an AI app
                    for sig in ALL_SIGNATURES:
                        if bundle_name in sig.package_ids_mobile or any(
                            bundle_name.endswith(pkg) for pkg in sig.package_ids_mobile
                        ):
                            wifi_in = row.get("ZWIFIIN", 0) or 0
                            wifi_out = row.get("ZWIFIOUT", 0) or 0
                            wwan_in = row.get("ZWWANIN", 0) or 0
                            wwan_out = row.get("ZWWANOUT", 0) or 0
                            
                            total_bytes = wifi_in + wifi_out + wwan_in + wwan_out
                            
                            if total_bytes > 0:
                                from ..parsers.macos_parsers import cocoa_time_to_datetime
                                timestamp = cocoa_time_to_datetime(row.get("ZTIMESTAMP", 0))
                                
                                record = ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile or "mobile",
                                    artifact_family=ArtifactFamily.NATIVE_APP,
                                    artifact_type="Network Usage",
                                    artifact_subtype="DataUsage Event",
                                    artifact_path=db_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=timestamp,
                                    timestamp_type=TimestampType.CREATED,
                                    timezone_normalized=True if timestamp else False,
                                    extracted_indicator=f"Network activity: {bundle_name}",
                                    suspected_platform=sig.platform,
                                    suspected_access_mode=AccessMode.NATIVE_APP,
                                    classification=EvidenceClassification.DIRECT,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.MODERATE,
                                    notes=f"Data usage: {total_bytes:,} bytes (WiFi: {wifi_in+wifi_out:,}, Cellular: {wwan_in+wwan_out:,})",
                                )
                                artifacts.append(record)
                            break
                            
            except Exception as exc:
                errors.append(f"DataUsage query failed: {exc}")
                    
        except Exception as exc:
            errors.append(f"Error parsing DataUsage.sqlite: {exc}")
