"""
Browser artifact parsers for Chrome, Edge, Firefox, Brave, and Safari.

Parses browser history, downloads, cookies, local storage, cache metadata,
and session data to identify AI platform usage.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import (
    AccessMode,
    AIPlatform,
    AIModel,
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
from ..signatures import (
    ALL_SIGNATURES,
    DOMAIN_TO_PLATFORM,
    match_domain,
    match_model_string,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FIREFOX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def chrome_time_to_datetime(microseconds: int) -> Optional[datetime]:
    """Convert Chrome/WebKit timestamp (microseconds since 1601-01-01) to datetime."""
    if not microseconds or microseconds <= 0:
        return None
    try:
        return CHROME_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, OSError):
        return None


def firefox_time_to_datetime(microseconds: int) -> Optional[datetime]:
    """Convert Firefox timestamp (microseconds since Unix epoch) to datetime."""
    if not microseconds or microseconds <= 0:
        return None
    try:
        return FIREFOX_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, OSError):
        return None


def safe_copy_db(db_path: str) -> Optional[str]:
    """
    Copy an SQLite database to a temp location for safe read-only access.
    This avoids lock issues with WAL-mode databases.
    """
    if not os.path.isfile(db_path):
        return None
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
        tmp.close()
        shutil.copy2(db_path, tmp.name)
        # Also copy WAL and SHM if present
        for ext in ("-wal", "-shm"):
            wal = db_path + ext
            if os.path.isfile(wal):
                shutil.copy2(wal, tmp.name + ext)
        return tmp.name
    except Exception:
        return None


def query_sqlite(db_path: str, query: str, params: tuple = ()) -> List[Dict]:
    """Execute a read-only query on a copied SQLite DB."""
    tmp_path = safe_copy_db(db_path)
    if not tmp_path:
        return []
    try:
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp_path)
            for ext in ("-wal", "-shm"):
                p = tmp_path + ext
                if os.path.isfile(p):
                    os.unlink(p)
        except OSError:
            pass


def check_ai_url(url: str) -> Optional[Tuple[AIPlatform, str]]:
    """Check if a URL corresponds to a known AI platform. Returns (platform, matched_domain)."""
    if not url:
        return None
    platform = match_domain(url)
    if platform:
        for sig in ALL_SIGNATURES:
            if sig.platform == platform:
                for domain in sig.domains:
                    if domain.lower() in url.lower():
                        return (platform, domain)
    return None


# ---------------------------------------------------------------------------
# Browser Profile Path Configs
# ---------------------------------------------------------------------------

BROWSER_PROFILES = {
    "Chrome": {
        "windows": "AppData/Local/Google/Chrome/User Data",
        "macos": "Library/Application Support/Google/Chrome",
        "profile_pattern": r"^(Default|Profile \d+)$",
        "history_db": "History",
        "cookies_db": "Cookies",
        "local_storage_dir": "Local Storage/leveldb",
        "cache_dir": "Cache/Cache_Data",
        "time_converter": chrome_time_to_datetime,
    },
    "Edge": {
        "windows": "AppData/Local/Microsoft/Edge/User Data",
        "macos": "Library/Application Support/Microsoft Edge",
        "profile_pattern": r"^(Default|Profile \d+)$",
        "history_db": "History",
        "cookies_db": "Cookies",
        "local_storage_dir": "Local Storage/leveldb",
        "cache_dir": "Cache/Cache_Data",
        "time_converter": chrome_time_to_datetime,
    },
    "Brave": {
        "windows": "AppData/Local/BraveSoftware/Brave-Browser/User Data",
        "macos": "Library/Application Support/BraveSoftware/Brave-Browser",
        "profile_pattern": r"^(Default|Profile \d+)$",
        "history_db": "History",
        "cookies_db": "Cookies",
        "local_storage_dir": "Local Storage/leveldb",
        "cache_dir": "Cache/Cache_Data",
        "time_converter": chrome_time_to_datetime,
    },
    "Firefox": {
        "windows": "AppData/Roaming/Mozilla/Firefox/Profiles",
        "macos": "Library/Application Support/Firefox/Profiles",
        "profile_pattern": r".*\.default.*|.*\.dev-edition.*",
        "history_db": "places.sqlite",
        "cookies_db": "cookies.sqlite",
        "local_storage_dir": "storage/default",
        "cache_dir": "cache2/entries",
        "time_converter": firefox_time_to_datetime,
    },
    "Safari": {
        "macos": "Library/Safari",
        "profile_pattern": None,  # Safari doesn't use profile dirs the same way
        "history_db": "History.db",
        "cookies_db": "Cookies.binarycookies",
        "time_converter": chrome_time_to_datetime,  # Safari uses Cocoa epoch
    },
}


# ---------------------------------------------------------------------------
# Chromium History Parser (Chrome, Edge, Brave)
# ---------------------------------------------------------------------------

@register_parser
class ChromiumHistoryParser(BaseParser):
    """Parse Chromium-based browser history (Chrome, Edge, Brave) for AI usage."""

    PARSER_NAME = "ChromiumHistoryParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Browser History"
    IS_STUB = False

    BROWSERS = ["Chrome", "Edge", "Brave"]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        warnings: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        for browser_name in self.BROWSERS:
            config = BROWSER_PROFILES[browser_name]
            results = self._parse_browser(browser_name, config,
                                          paths_searched, paths_found, paths_missing,
                                          errors, warnings)
            artifacts.extend(results)

        status = ParserStatus.SUCCESS if artifacts else (
            ParserStatus.NOT_APPLICABLE if not paths_found else ParserStatus.SUCCESS
        )

        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            warnings=warnings,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            artifact_coverage=[],
            coverage_gaps=[],
            parse_failures=[],
            unsupported_artifacts=[],
        )

    def _parse_browser(
        self, browser_name: str, config: Dict,
        paths_searched: List, paths_found: List, paths_missing: List,
        errors: List, warnings: List,
    ) -> List[ArtifactRecord]:
        artifacts = []
        # Determine the browser data path
        os_key = "windows" if os.path.exists(
            os.path.join(self.evidence_root, "Users")
        ) and os.path.exists(
            os.path.join(self.evidence_root, "Users", self.user_profile, "AppData")
        ) else "macos"

        if os_key not in config:
            return artifacts

        browser_base = os.path.join(
            self.evidence_root, "Users", self.user_profile, config[os_key]
        )
        paths_searched.append(browser_base)

        if not os.path.isdir(browser_base):
            paths_missing.append(browser_base)
            return artifacts

        paths_found.append(browser_base)

        # Discover profile directories
        profiles = []
        pattern = config.get("profile_pattern", "")
        if pattern:
            for item in os.listdir(browser_base):
                if re.match(pattern, item) and os.path.isdir(os.path.join(browser_base, item)):
                    profiles.append(item)

        if not profiles:
            profiles = [""]  # root-level for Safari-like layouts

        for profile in profiles:
            profile_path = os.path.join(browser_base, profile) if profile else browser_base

            # --- History ---
            history_db = os.path.join(profile_path, config["history_db"])
            paths_searched.append(history_db)

            if os.path.isfile(history_db):
                paths_found.append(history_db)
                try:
                    history_artifacts = self._parse_chromium_history(
                        history_db, browser_name, profile, config["time_converter"]
                    )
                    artifacts.extend(history_artifacts)
                except Exception as exc:
                    errors.append(f"{browser_name}/{profile} history parse error: {exc}")
            else:
                paths_missing.append(history_db)

            # --- Downloads ---
            if os.path.isfile(history_db):
                try:
                    dl_artifacts = self._parse_chromium_downloads(
                        history_db, browser_name, profile, config["time_converter"]
                    )
                    artifacts.extend(dl_artifacts)
                except Exception as exc:
                    errors.append(f"{browser_name}/{profile} downloads parse error: {exc}")

            # --- Cookies ---
            cookies_db = os.path.join(profile_path, config["cookies_db"])
            paths_searched.append(cookies_db)
            if os.path.isfile(cookies_db):
                paths_found.append(cookies_db)
                try:
                    cookie_artifacts = self._parse_chromium_cookies(
                        cookies_db, browser_name, profile, config["time_converter"]
                    )
                    artifacts.extend(cookie_artifacts)
                except Exception as exc:
                    errors.append(f"{browser_name}/{profile} cookies parse error: {exc}")
            else:
                paths_missing.append(cookies_db)

            # --- Local Storage (LevelDB key scan) ---
            ls_dir = os.path.join(profile_path, config.get("local_storage_dir", ""))
            if ls_dir and os.path.isdir(ls_dir):
                paths_found.append(ls_dir)
                try:
                    ls_artifacts = self._scan_local_storage(
                        ls_dir, browser_name, profile
                    )
                    artifacts.extend(ls_artifacts)
                except Exception as exc:
                    warnings.append(f"{browser_name}/{profile} local storage scan error: {exc}")

        return artifacts

    def _parse_chromium_history(
        self, db_path: str, browser: str, profile: str,
        time_conv,
    ) -> List[ArtifactRecord]:
        artifacts = []
        rows = query_sqlite(
            db_path,
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        )
        for row in rows:
            url = row.get("url", "")
            match = check_ai_url(url)
            if not match:
                continue

            platform, matched_domain = match
            ts = time_conv(row.get("last_visit_time", 0))

            record = ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                partition_or_container="",
                user_profile=self.user_profile,
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                artifact_type="URL Visit",
                artifact_subtype=f"{browser} History",
                artifact_path=db_path,
                parser_used=self.PARSER_NAME,
                timestamp=ts,
                timestamp_type=TimestampType.LAST_VISITED,
                timezone_normalized=True if ts else False,
                timezone_info="UTC (Chrome epoch)" if ts else "",
                extracted_indicator=url,
                suspected_platform=platform,
                suspected_model=match_model_string(url) or AIModel.UNKNOWN,
                suspected_access_mode=AccessMode.BROWSER,
                classification=EvidenceClassification.DIRECT,
                attribution_layer=AttributionLayer.PLATFORM,
                confidence=ConfidenceLevel.MODERATE,
                notes=f"Visit count: {row.get('visit_count', 0)}, Title: {row.get('title', '')}",
            )
            artifacts.append(record)

        return artifacts

    def _parse_chromium_downloads(
        self, db_path: str, browser: str, profile: str, time_conv,
    ) -> List[ArtifactRecord]:
        artifacts = []
        rows = query_sqlite(
            db_path,
            "SELECT target_path, tab_url, total_bytes, start_time, end_time, "
            "mime_type, original_mime_type FROM downloads ORDER BY start_time DESC"
        )

        for row in rows:
            tab_url = row.get("tab_url", "")
            target_path = row.get("target_path", "")
            combined = f"{tab_url} {target_path}"

            platform_match = check_ai_url(tab_url)
            filename_match = self._check_ai_download_filename(target_path)

            if not platform_match and not filename_match:
                continue

            platform = platform_match[0] if platform_match else filename_match
            ts = time_conv(row.get("start_time", 0))

            record = ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                user_profile=self.user_profile,
                artifact_family=ArtifactFamily.BROWSER_DOWNLOADS,
                artifact_type="Download",
                artifact_subtype=f"{browser} Download",
                artifact_path=db_path,
                parser_used=self.PARSER_NAME,
                timestamp=ts,
                timestamp_type=TimestampType.CREATED,
                timezone_normalized=True if ts else False,
                timezone_info="UTC (Chrome epoch)" if ts else "",
                extracted_indicator=f"URL: {tab_url} -> {target_path}",
                suspected_platform=platform,
                suspected_access_mode=AccessMode.BROWSER,
                classification=EvidenceClassification.DIRECT,
                attribution_layer=AttributionLayer.PLATFORM,
                confidence=ConfidenceLevel.MODERATE,
                notes=f"Size: {row.get('total_bytes', 0)}, MIME: {row.get('mime_type', '')}",
            )
            artifacts.append(record)

        return artifacts

    def _parse_chromium_cookies(
        self, db_path: str, browser: str, profile: str, time_conv,
    ) -> List[ArtifactRecord]:
        artifacts = []
        rows = query_sqlite(
            db_path,
            "SELECT host_key, name, path, creation_utc, last_access_utc, "
            "expires_utc, is_secure, is_httponly FROM cookies"
        )

        for row in rows:
            host = row.get("host_key", "")
            # Check if cookie domain matches an AI platform
            platform = None
            for sig in ALL_SIGNATURES:
                for cd in sig.cookie_domains:
                    if cd in host or host.endswith(cd.lstrip(".")):
                        platform = sig.platform
                        break
                if platform:
                    break

            if not platform:
                continue

            ts = time_conv(row.get("last_access_utc", 0) or row.get("creation_utc", 0))

            record = ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                user_profile=self.user_profile,
                artifact_family=ArtifactFamily.BROWSER_COOKIES,
                artifact_type="Cookie",
                artifact_subtype=f"{browser} Cookie",
                artifact_path=db_path,
                parser_used=self.PARSER_NAME,
                timestamp=ts,
                timestamp_type=TimestampType.LAST_VISITED,
                timezone_normalized=True if ts else False,
                timezone_info="UTC (Chrome epoch)" if ts else "",
                extracted_indicator=f"{host} / {row.get('name', '')}",
                suspected_platform=platform,
                suspected_access_mode=AccessMode.BROWSER,
                classification=EvidenceClassification.DIRECT,
                attribution_layer=AttributionLayer.PLATFORM,
                confidence=ConfidenceLevel.LOW,
                notes="Cookie alone is not sufficient to conclude substantive AI use.",
            )
            artifacts.append(record)

        return artifacts

    def _scan_local_storage(
        self, ls_dir: str, browser: str, profile: str,
    ) -> List[ArtifactRecord]:
        """Scan LevelDB local storage for AI-related keys via string matching."""
        artifacts = []
        # Scan .log and .ldb files for AI-related strings
        for fname in os.listdir(ls_dir):
            fpath = os.path.join(ls_dir, fname)
            if not os.path.isfile(fpath):
                continue
            if not fname.endswith((".log", ".ldb")):
                continue
            try:
                with open(fpath, "rb") as f:
                    data = f.read(1024 * 1024)  # Read up to 1MB
                text = data.decode("utf-8", errors="replace")
                for sig in ALL_SIGNATURES:
                    for key in sig.local_storage_keys:
                        if key.lower() in text.lower():
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.BROWSER_LOCAL_STORAGE,
                                artifact_type="Local Storage Key",
                                artifact_subtype=f"{browser} Local Storage",
                                artifact_path=fpath,
                                parser_used=self.PARSER_NAME,
                                extracted_indicator=f"Key match: '{key}' in {fname}",
                                suspected_platform=sig.platform,
                                suspected_access_mode=AccessMode.BROWSER,
                                classification=EvidenceClassification.INFERRED,
                                attribution_layer=AttributionLayer.PLATFORM,
                                confidence=ConfidenceLevel.LOW,
                                notes="Local storage key match is a weak indicator. "
                                      "Corroboration required.",
                            )
                            artifacts.append(record)
                            break  # one match per sig per file is enough
            except Exception:
                continue

        return artifacts

    def _check_ai_download_filename(self, path: str) -> Optional[AIPlatform]:
        """Check if a download filename matches AI export patterns."""
        if not path:
            return None
        fname = os.path.basename(path).lower()
        for sig in ALL_SIGNATURES:
            for pattern in sig.download_patterns:
                if re.search(pattern, fname, re.IGNORECASE):
                    return sig.platform
        return None


# ---------------------------------------------------------------------------
# Firefox History Parser
# ---------------------------------------------------------------------------

@register_parser
class FirefoxHistoryParser(BaseParser):
    """Parse Firefox browser history for AI usage."""

    PARSER_NAME = "FirefoxHistoryParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Browser History"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        warnings: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        config = BROWSER_PROFILES["Firefox"]

        # Determine OS
        os_key = "windows"
        appdata_path = os.path.join(
            self.evidence_root, "Users", self.user_profile,
            "AppData/Roaming/Mozilla/Firefox/Profiles"
        )
        library_path = os.path.join(
            self.evidence_root, "Users", self.user_profile,
            "Library/Application Support/Firefox/Profiles"
        )

        if os.path.isdir(appdata_path):
            profiles_dir = appdata_path
        elif os.path.isdir(library_path):
            profiles_dir = library_path
        else:
            paths_searched.extend([appdata_path, library_path])
            paths_missing.extend([appdata_path, library_path])
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="No Firefox profile directory found.",
            )

        paths_searched.append(profiles_dir)
        paths_found.append(profiles_dir)

        # Find profiles
        for item in os.listdir(profiles_dir):
            profile_path = os.path.join(profiles_dir, item)
            if not os.path.isdir(profile_path):
                continue

            places_db = os.path.join(profile_path, "places.sqlite")
            paths_searched.append(places_db)

            if not os.path.isfile(places_db):
                paths_missing.append(places_db)
                continue

            paths_found.append(places_db)

            # Parse history
            try:
                rows = query_sqlite(
                    places_db,
                    "SELECT p.url, p.title, p.visit_count, p.last_visit_date "
                    "FROM moz_places p WHERE p.url IS NOT NULL "
                    "ORDER BY p.last_visit_date DESC"
                )
                for row in rows:
                    url = row.get("url", "")
                    match = check_ai_url(url)
                    if not match:
                        continue

                    platform, domain = match
                    ts = firefox_time_to_datetime(row.get("last_visit_date", 0))

                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.BROWSER_HISTORY,
                        artifact_type="URL Visit",
                        artifact_subtype="Firefox History",
                        artifact_path=places_db,
                        parser_used=self.PARSER_NAME,
                        timestamp=ts,
                        timestamp_type=TimestampType.LAST_VISITED,
                        timezone_normalized=True if ts else False,
                        timezone_info="UTC (Unix µs)" if ts else "",
                        extracted_indicator=url,
                        suspected_platform=platform,
                        suspected_model=match_model_string(url) or AIModel.UNKNOWN,
                        suspected_access_mode=AccessMode.BROWSER,
                        classification=EvidenceClassification.DIRECT,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.MODERATE,
                        notes=f"Visit count: {row.get('visit_count', 0)}, "
                              f"Title: {row.get('title', '')}",
                    )
                    artifacts.append(record)
            except Exception as exc:
                errors.append(f"Firefox places.sqlite error: {exc}")

            # Parse downloads
            try:
                dl_rows = query_sqlite(
                    places_db,
                    "SELECT a.content AS target_path, p.url "
                    "FROM moz_annos a "
                    "JOIN moz_places p ON a.place_id = p.id "
                    "WHERE a.anno_attribute_id IN "
                    "(SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI')"
                )
                for row in dl_rows:
                    url = row.get("url", "")
                    target = row.get("target_path", "")
                    match = check_ai_url(url)
                    if match:
                        platform, _ = match
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.BROWSER_DOWNLOADS,
                            artifact_type="Download",
                            artifact_subtype="Firefox Download",
                            artifact_path=places_db,
                            parser_used=self.PARSER_NAME,
                            extracted_indicator=f"URL: {url} -> {target}",
                            suspected_platform=platform,
                            suspected_access_mode=AccessMode.BROWSER,
                            classification=EvidenceClassification.DIRECT,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.MODERATE,
                        )
                        artifacts.append(record)
            except Exception:
                pass  # download annotations may not exist

            # Parse cookies
            cookies_db = os.path.join(profile_path, "cookies.sqlite")
            if os.path.isfile(cookies_db):
                paths_found.append(cookies_db)
                try:
                    cookie_rows = query_sqlite(
                        cookies_db,
                        "SELECT host, name, path, creationTime, lastAccessed FROM moz_cookies"
                    )
                    for row in cookie_rows:
                        host = row.get("host", "")
                        platform = None
                        for sig in ALL_SIGNATURES:
                            for cd in sig.cookie_domains:
                                if cd in host or host.endswith(cd.lstrip(".")):
                                    platform = sig.platform
                                    break
                            if platform:
                                break
                        if not platform:
                            continue

                        ts = firefox_time_to_datetime(row.get("lastAccessed", 0))
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.BROWSER_COOKIES,
                            artifact_type="Cookie",
                            artifact_subtype="Firefox Cookie",
                            artifact_path=cookies_db,
                            parser_used=self.PARSER_NAME,
                            timestamp=ts,
                            timestamp_type=TimestampType.LAST_VISITED,
                            timezone_normalized=True if ts else False,
                            extracted_indicator=f"{host} / {row.get('name', '')}",
                            suspected_platform=platform,
                            suspected_access_mode=AccessMode.BROWSER,
                            classification=EvidenceClassification.DIRECT,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.LOW,
                            notes="Cookie alone is not sufficient to conclude substantive AI use.",
                        )
                        artifacts.append(record)
                except Exception as exc:
                    errors.append(f"Firefox cookies error: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            warnings=warnings,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )


# ---------------------------------------------------------------------------
# Safari History Parser (macOS stub + basic implementation)
# ---------------------------------------------------------------------------

@register_parser
class SafariHistoryParser(BaseParser):
    """Parse Safari browser history for AI usage (macOS)."""

    PARSER_NAME = "SafariHistoryParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Browser History"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        safari_dir = os.path.join(
            self.evidence_root, "Users", self.user_profile, "Library", "Safari"
        )
        paths_searched.append(safari_dir)

        if not os.path.isdir(safari_dir):
            paths_missing.append(safari_dir)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Safari directory not found.",
            )

        paths_found.append(safari_dir)
        history_db = os.path.join(safari_dir, "History.db")
        paths_searched.append(history_db)

        if not os.path.isfile(history_db):
            paths_missing.append(history_db)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_found=paths_found,
                paths_missing=paths_missing,
                notes="Safari History.db not found.",
            )

        paths_found.append(history_db)

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
                # Safari uses Cocoa epoch (seconds since 2001-01-01)
                vt = row.get("visit_time", 0)
                ts = None
                if vt:
                    try:
                        cocoa_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
                        ts = cocoa_epoch + timedelta(seconds=vt)
                    except Exception:
                        pass

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile,
                    artifact_family=ArtifactFamily.BROWSER_HISTORY,
                    artifact_type="URL Visit",
                    artifact_subtype="Safari History",
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
                    notes=f"Title: {row.get('title', '')}",
                )
                artifacts.append(record)

        except Exception as exc:
            errors.append(f"Safari History.db parse error: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )
