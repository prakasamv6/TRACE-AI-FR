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
# iPhone App Usage Parser (Stub)
# ---------------------------------------------------------------------------

@register_parser
class IPhoneAppUsageParser(BaseParser):
    """
    Parse iPhone application usage indicators for AI apps.

    STUB: Checks for known bundle IDs and app directories in logical extractions.
    Full implementation requires parsing of DataUsage.sqlite, KnowledgeC.db, etc.
    """

    PARSER_NAME = "iPhoneAppUsageParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.IPHONE]
    ARTIFACT_FAMILY = "Native Application"
    IS_STUB = True

    APP_DOMAIN_PATHS = [
        "AppDomain-{bundle_id}",
        "AppDomainGroup-group.{bundle_id}",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        for sig in ALL_SIGNATURES:
            for bundle_id in sig.package_ids_mobile:
                for pattern in self.APP_DOMAIN_PATHS:
                    path = pattern.format(bundle_id=bundle_id)
                    full_path = os.path.join(self.evidence_root, path)
                    paths_searched.append(full_path)

                    if os.path.isdir(full_path):
                        paths_found.append(full_path)
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile or "mobile",
                            artifact_family=ArtifactFamily.NATIVE_APP,
                            artifact_type="App Domain Directory",
                            artifact_subtype="iPhone Logical",
                            artifact_path=full_path,
                            parser_used=self.PARSER_NAME,
                            extracted_indicator=f"Bundle: {bundle_id}, Path: {path}",
                            suspected_platform=sig.platform,
                            suspected_access_mode=AccessMode.NATIVE_APP,
                            classification=EvidenceClassification.DIRECT,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.MODERATE,
                            notes="iPhone app domain directory found. Indicates installation. "
                                  "Full app data parsing is a stub in the MVP.",
                        )
                        artifacts.append(record)
                    else:
                        paths_missing.append(full_path)

        status = ParserStatus.STUB if not artifacts else ParserStatus.SUCCESS
        return self._make_result(
            status=status,
            artifacts=artifacts,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes="iPhone app usage parsing is partially implemented. "
                  "Full KnowledgeC/DataUsage analysis requires additional parsers.",
        )
