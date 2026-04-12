"""
Android and Samsung device artifact parsers.

Parses Android-specific forensic artifacts including:
- Chrome browser history and downloads
- App installation and usage (packages.xml, UsageStatsService)
- SMS/MMS databases
- Call logs
- App data directories
- System logs (logcat exports)
- Network usage (NetworkStats)
- Samsung-specific artifacts (Samsung Internet, Samsung Notes, etc.)
"""

from __future__ import annotations

import os
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
from ..parsers.browser_parsers import query_sqlite, check_ai_url
from ..signatures import ALL_SIGNATURES, match_domain


# ---------------------------------------------------------------------------
# Android Epoch Helper
# ---------------------------------------------------------------------------

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def unix_ms_to_datetime(ms: int) -> Optional[datetime]:
    """Convert Unix timestamp in milliseconds to datetime."""
    if not ms or ms <= 0:
        return None
    try:
        return UNIX_EPOCH + timedelta(milliseconds=ms)
    except (OverflowError, OSError):
        return None


def unix_sec_to_datetime(sec: int) -> Optional[datetime]:
    """Convert Unix timestamp in seconds to datetime."""
    if not sec or sec <= 0:
        return None
    try:
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    except (OverflowError, OSError):
        return None


# ---------------------------------------------------------------------------
# Android Chrome Browser Parser
# ---------------------------------------------------------------------------

@register_parser
class AndroidChromeParser(BaseParser):
    """
    Parse Android Chrome browser history from logical extraction.

    Looks for Chrome databases in typical Android paths.
    """

    PARSER_NAME = "AndroidChromeParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.ANDROID]
    ARTIFACT_FAMILY = "Browser History"
    IS_STUB = False

    CHROME_PATHS = [
        "data/data/com.android.chrome/app_chrome/Default/History",
        "data/com.android.chrome/app_chrome/Default/History",
        "apps/com.android.chrome/app_chrome/Default/History",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        history_db = None
        for rel_path in self.CHROME_PATHS:
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
                notes="Android Chrome history database not found in evidence.",
            )

        try:
            rows = query_sqlite(
                history_db,
                "SELECT url, title, last_visit_time, visit_count "
                "FROM urls ORDER BY last_visit_time DESC"
            )

            for row in rows:
                url = row.get("url", "")
                match = check_ai_url(url)
                if not match:
                    continue

                platform, domain = match
                # Chrome on Android uses WebKit time (microseconds since 1601-01-01)
                webkit_time = row.get("last_visit_time", 0)
                timestamp = None
                if webkit_time:
                    try:
                        # WebKit epoch is 1601-01-01, convert to Unix epoch
                        unix_microseconds = webkit_time - 11644473600000000
                        timestamp = datetime.fromtimestamp(
                            unix_microseconds / 1000000, tz=timezone.utc
                        )
                    except (OverflowError, OSError):
                        pass

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile or "android",
                    artifact_family=ArtifactFamily.BROWSER_HISTORY,
                    artifact_type="URL Visit",
                    artifact_subtype="Android Chrome History",
                    artifact_path=history_db,
                    parser_used=self.PARSER_NAME,
                    timestamp=timestamp,
                    timestamp_type=TimestampType.LAST_VISITED,
                    timezone_normalized=True if timestamp else False,
                    timezone_info="UTC (WebKit epoch)" if timestamp else "",
                    extracted_indicator=url,
                    suspected_platform=platform,
                    suspected_access_mode=AccessMode.BROWSER,
                    classification=EvidenceClassification.DIRECT,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.MODERATE,
                    notes=f"Android Chrome visit. Title: {row.get('title', '')}. "
                          f"Visit count: {row.get('visit_count', 0)}",
                )
                artifacts.append(record)

        except Exception as exc:
            errors.append(f"Android Chrome parse error: {exc}")

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
# Samsung Internet Browser Parser
# ---------------------------------------------------------------------------

@register_parser
class SamsungInternetParser(BaseParser):
    """
    Parse Samsung Internet browser history from Samsung devices.

    Samsung Internet uses its own browser database structure.
    """

    PARSER_NAME = "SamsungInternetParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.ANDROID]
    ARTIFACT_FAMILY = "Browser History"
    IS_STUB = False

    SAMSUNG_BROWSER_PATHS = [
        "data/data/com.sec.android.app.sbrowser/databases/browser.db",
        "data/com.sec.android.app.sbrowser/databases/browser.db",
        "apps/com.sec.android.app.sbrowser/databases/browser.db",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        browser_db = None
        for rel_path in self.SAMSUNG_BROWSER_PATHS:
            full_path = os.path.join(self.evidence_root, rel_path)
            paths_searched.append(full_path)
            if os.path.isfile(full_path):
                browser_db = full_path
                paths_found.append(full_path)
                break
            else:
                paths_missing.append(full_path)

        if not browser_db:
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Samsung Internet browser database not found in evidence.",
            )

        try:
            # Samsung browser typically has 'browser' or 'history' table
            rows = query_sqlite(
                browser_db,
                "SELECT url, title, date, visits FROM browser ORDER BY date DESC"
            )

            for row in rows:
                url = row.get("url", "")
                match = check_ai_url(url)
                if not match:
                    continue

                platform, domain = match
                timestamp = unix_ms_to_datetime(row.get("date", 0))

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile or "android",
                    artifact_family=ArtifactFamily.BROWSER_HISTORY,
                    artifact_type="URL Visit",
                    artifact_subtype="Samsung Internet History",
                    artifact_path=browser_db,
                    parser_used=self.PARSER_NAME,
                    timestamp=timestamp,
                    timestamp_type=TimestampType.LAST_VISITED,
                    timezone_normalized=True if timestamp else False,
                    timezone_info="UTC" if timestamp else "",
                    extracted_indicator=url,
                    suspected_platform=platform,
                    suspected_access_mode=AccessMode.BROWSER,
                    classification=EvidenceClassification.DIRECT,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.MODERATE,
                    notes=f"Samsung Internet visit. Title: {row.get('title', '')}. "
                          f"Visits: {row.get('visits', 0)}",
                )
                artifacts.append(record)

        except Exception as exc:
            errors.append(f"Samsung Internet parse error: {exc}")

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
# Android App Installation and Usage Parser
# ---------------------------------------------------------------------------

@register_parser
class AndroidAppUsageParser(BaseParser):
    """
    Parse Android application installation and usage data.

    Examines:
    - packages.xml for installed apps
    - UsageStatsService databases for app usage
    - App data directories for AI apps
    - NetworkStats for network usage by app
    """

    PARSER_NAME = "AndroidAppUsageParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.ANDROID]
    ARTIFACT_FAMILY = "Native Application"
    IS_STUB = False

    PACKAGES_PATHS = [
        "data/system/packages.xml",
        "system/packages.xml",
    ]

    USAGE_STATS_PATHS = [
        "data/system/usagestats",
        "system/usagestats",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        # Parse packages.xml for installed apps
        packages_xml = None
        for rel_path in self.PACKAGES_PATHS:
            full_path = os.path.join(self.evidence_root, rel_path)
            paths_searched.append(full_path)
            if os.path.isfile(full_path):
                packages_xml = full_path
                paths_found.append(full_path)
                break
            else:
                paths_missing.append(full_path)

        if packages_xml:
            self._parse_packages_xml(packages_xml, artifacts, errors)

        # Check for AI app data directories
        for sig in ALL_SIGNATURES:
            for package_id in sig.package_ids_mobile:
                # Android app data paths
                app_paths = [
                    f"data/data/{package_id}",
                    f"data/app/{package_id}",
                    f"apps/{package_id}",
                ]
                
                for app_path_template in app_paths:
                    full_path = os.path.join(self.evidence_root, app_path_template)
                    paths_searched.append(full_path)

                    if os.path.isdir(full_path):
                        paths_found.append(full_path)
                        
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile or "android",
                            artifact_family=ArtifactFamily.NATIVE_APP,
                            artifact_type="App Installation",
                            artifact_subtype="Android App Directory",
                            artifact_path=full_path,
                            parser_used=self.PARSER_NAME,
                            extracted_indicator=f"Package: {package_id}",
                            suspected_platform=sig.platform,
                            suspected_access_mode=AccessMode.NATIVE_APP,
                            classification=EvidenceClassification.DIRECT,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.MODERATE,
                            notes=f"Android app data directory present for {package_id}",
                        )
                        artifacts.append(record)
                    else:
                        paths_missing.append(full_path)

        # Parse usage stats if available
        for rel_path in self.USAGE_STATS_PATHS:
            full_path = os.path.join(self.evidence_root, rel_path)
            paths_searched.append(full_path)
            
            if os.path.isdir(full_path):
                paths_found.append(full_path)
                self._parse_usage_stats(full_path, artifacts, errors)
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
            notes="Android app analysis includes packages.xml, app directories, and usage stats.",
        )

    def _parse_packages_xml(self, xml_path: str, artifacts: List, errors: List) -> None:
        """Parse packages.xml for installed AI apps."""
        try:
            import xml.etree.ElementTree as ET
            
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Find all package elements
            for package in root.findall('.//package'):
                package_name = package.get('name', '')
                
                # Check if this is an AI app
                for sig in ALL_SIGNATURES:
                    if package_name in sig.package_ids_mobile:
                        install_time = package.get('it', '')  # install time
                        update_time = package.get('ut', '')   # update time
                        
                        # Parse timestamps (usually in hex milliseconds)
                        timestamp = None
                        if install_time:
                            try:
                                install_ms = int(install_time, 16) if install_time.startswith('0x') else int(install_time)
                                timestamp = unix_ms_to_datetime(install_ms)
                            except (ValueError, TypeError):
                                pass
                        
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile or "android",
                            artifact_family=ArtifactFamily.NATIVE_APP,
                            artifact_type="App Installation",
                            artifact_subtype="packages.xml Entry",
                            artifact_path=xml_path,
                            parser_used=self.PARSER_NAME,
                            timestamp=timestamp,
                            timestamp_type=TimestampType.CREATED,
                            timezone_normalized=True if timestamp else False,
                            extracted_indicator=f"Package: {package_name}",
                            suspected_platform=sig.platform,
                            suspected_access_mode=AccessMode.NATIVE_APP,
                            classification=EvidenceClassification.DIRECT,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.HIGH,
                            notes=f"App installed from packages.xml. Code path: {package.get('codePath', '')}",
                        )
                        artifacts.append(record)
                        break
                        
        except Exception as exc:
            errors.append(f"Error parsing packages.xml: {exc}")

    def _parse_usage_stats(self, stats_dir: str, artifacts: List, errors: List) -> None:
        """Parse usage stats XML files for app usage events."""
        try:
            import xml.etree.ElementTree as ET
            
            # Iterate through usage stats files (usually organized by year)
            for root_dir, dirs, files in os.walk(stats_dir):
                for fname in files:
                    if not fname.endswith('.xml'):
                        continue
                    
                    fpath = os.path.join(root_dir, fname)
                    try:
                        tree = ET.parse(fpath)
                        root = tree.getroot()
                        
                        # Find package usage entries
                        for pkg in root.findall('.//pkg'):
                            package_name = pkg.get('name', '')
                            
                            # Check if this is an AI app
                            for sig in ALL_SIGNATURES:
                                if package_name in sig.package_ids_mobile:
                                    last_time = pkg.get('lt', '')  # last time used
                                    
                                    timestamp = None
                                    if last_time:
                                        try:
                                            last_ms = int(last_time)
                                            timestamp = unix_ms_to_datetime(last_ms)
                                        except (ValueError, TypeError):
                                            pass
                                    
                                    record = ArtifactRecord(
                                        case_id=self.case_id,
                                        evidence_item_id=self.evidence_item_id,
                                        source_image=self.source_image,
                                        user_profile=self.user_profile or "android",
                                        artifact_family=ArtifactFamily.NATIVE_APP,
                                        artifact_type="App Usage",
                                        artifact_subtype="UsageStats Event",
                                        artifact_path=fpath,
                                        parser_used=self.PARSER_NAME,
                                        timestamp=timestamp,
                                        timestamp_type=TimestampType.ACCESSED,
                                        timezone_normalized=True if timestamp else False,
                                        extracted_indicator=f"App used: {package_name}",
                                        suspected_platform=sig.platform,
                                        suspected_access_mode=AccessMode.NATIVE_APP,
                                        classification=EvidenceClassification.DIRECT,
                                        attribution_layer=AttributionLayer.PLATFORM,
                                        confidence=ConfidenceLevel.HIGH,
                                        notes=f"App usage from UsageStatsService",
                                    )
                                    artifacts.append(record)
                                    break
                                    
                    except Exception as exc:
                        errors.append(f"Error parsing usage stats file {fname}: {exc}")
                        
        except Exception as exc:
            errors.append(f"Error scanning usage stats directory: {exc}")


# ---------------------------------------------------------------------------
# Android System Log Parser
# ---------------------------------------------------------------------------

@register_parser
class AndroidSystemLogParser(BaseParser):
    """
    Parse Android system logs (logcat exports) for AI-related activity.

    Searches for:
    - App launch events
    - Network connections to AI services
    - Package manager events
    """

    PARSER_NAME = "AndroidSystemLogParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.ANDROID]
    ARTIFACT_FAMILY = "OS Event Log"
    IS_STUB = False

    LOGCAT_PATHS = [
        "logcat.txt",
        "system.log",
        "bugreport.txt",
        "dumpstate.txt",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        # Search for logcat files in root and common directories
        search_dirs = [
            self.evidence_root,
            os.path.join(self.evidence_root, "data", "local", "tmp"),
            os.path.join(self.evidence_root, "sdcard"),
        ]

        for search_dir in search_dirs:
            for log_name in self.LOGCAT_PATHS:
                log_path = os.path.join(search_dir, log_name)
                paths_searched.append(log_path)

                if os.path.isfile(log_path):
                    paths_found.append(log_path)
                    self._parse_logcat(log_path, artifacts, errors)
                else:
                    paths_missing.append(log_path)

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes="Android system log analysis via logcat export scanning.",
        )

    def _parse_logcat(self, log_path: str, artifacts: List, errors: List) -> None:
        """Parse logcat file for AI-related entries."""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                line_count = 0
                max_lines = 50000  # Limit to avoid excessive processing
                
                for line in f:
                    if line_count > max_lines:
                        break
                    line_count += 1
                    
                    line_lower = line.lower()
                    
                    # Search for AI package names or domains
                    for sig in ALL_SIGNATURES:
                        matched = False
                        indicator = ""
                        
                        # Check for package IDs
                        for pkg in sig.package_ids_mobile:
                            if pkg.lower() in line_lower:
                                matched = True
                                indicator = f"Package: {pkg}"
                                break
                        
                        # Check for domains
                        if not matched:
                            for domain in sig.domains:
                                if domain.lower() in line_lower:
                                    matched = True
                                    indicator = f"Domain: {domain}"
                                    break
                        
                        if matched:
                            # Try to extract timestamp from logcat line
                            # Format: MM-DD HH:MM:SS.mmm
                            timestamp = None
                            ts_match = re.search(r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
                            if ts_match:
                                try:
                                    # Add current year (logcat doesn't include year)
                                    current_year = datetime.now().year
                                    ts_str = f"{current_year}-{ts_match.group(1)}"
                                    timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                                except Exception:
                                    pass
                            
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile or "android",
                                artifact_family=ArtifactFamily.OS_EVENT_LOG,
                                artifact_type="Android System Log",
                                artifact_subtype="Logcat Entry",
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
                                confidence=ConfidenceLevel.LOW,
                                notes=f"Logcat entry: {line.strip()[:200]}",
                            )
                            artifacts.append(record)
                            break
                            
        except Exception as exc:
            errors.append(f"Error parsing logcat file: {exc}")
