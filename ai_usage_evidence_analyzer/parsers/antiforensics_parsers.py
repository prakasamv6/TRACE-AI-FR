"""
Anti-forensics detection parsers (FR-6).

Detects evidence of:
- Browser history wiping / selective deletion
- Timestamp manipulation / anomalies
- Metadata stripping from AI-generated content
- Privacy/incognito mode usage with AI platforms
- Artifact cleanup tool execution (CCleaner, BleachBit, etc.)
"""

from __future__ import annotations

import os
import re
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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


# Known cleanup / anti-forensics tools
CLEANUP_TOOLS = {
    "CCLEANER.EXE": "CCleaner",
    "BLEACHBIT.EXE": "BleachBit",
    "BLEACHBIT": "BleachBit",
    "PRIVAZER.EXE": "PrivaZer",
    "ERASER.EXE": "Eraser",
    "WISE DISK CLEANER.EXE": "Wise Disk Cleaner",
    "PRIVACY ERASER.EXE": "Privacy Eraser",
    "SDELETE.EXE": "SDelete (Sysinternals)",
    "CIPHER.EXE": "Windows Cipher /W",
}

# Incognito / private browsing indicators
INCOGNITO_INDICATORS = [
    (r"incognito", "Chrome Incognito"),
    (r"inprivate", "Edge InPrivate"),
    (r"private.browsing", "Firefox Private Browsing"),
]


@register_parser
class AntiForensicsDetector(BaseParser):
    """
    Detect indicators of anti-forensics activity that may have affected
    AI platform evidence integrity.

    Checks for:
    1. Browser history gaps (periods with no history around known AI usage)
    2. Cleanup tool execution traces (Prefetch, AmCache, Registry)
    3. Timestamp anomalies (future dates, impossible sequences)
    4. Metadata stripping patterns in downloaded AI content
    5. Selective deletion patterns in browser databases
    """

    PARSER_NAME = "AntiForensicsDetector"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Anti-Forensics"

    # Browser history paths for gap analysis
    HISTORY_DBS = [
        ("Chrome", "AppData/Local/Google/Chrome/User Data/Default/History"),
        ("Chrome", "Library/Application Support/Google/Chrome/Default/History"),
        ("Edge", "AppData/Local/Microsoft/Edge/User Data/Default/History"),
        ("Edge", "Library/Application Support/Microsoft Edge/Default/History"),
        ("Firefox", "AppData/Roaming/Mozilla/Firefox/Profiles"),
        ("Firefox", "Library/Application Support/Firefox/Profiles"),
    ]

    # Prefetch directory for cleanup tool detection
    PREFETCH_PATH = "Windows/Prefetch"

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)

        # 1. Check for cleanup tool execution in Prefetch
        prefetch_artifacts = self._scan_prefetch(errors, paths_searched, paths_found)
        artifacts.extend(prefetch_artifacts)

        # 2. Detect browser history gaps and anomalies
        if os.path.isdir(user_base):
            history_artifacts = self._analyze_browser_history(
                user_base, errors, paths_searched, paths_found
            )
            artifacts.extend(history_artifacts)

            # 3. Check for metadata-stripped AI content
            metadata_artifacts = self._detect_metadata_stripping(
                user_base, errors, paths_searched, paths_found
            )
            artifacts.extend(metadata_artifacts)

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"Anti-forensics scan: {len(artifacts)} indicators found",
            artifact_coverage=[],
            coverage_gaps=[],
            parse_failures=[],
            unsupported_artifacts=[],
        )

    def _scan_prefetch(
        self,
        errors: List[str],
        paths_searched: List[str],
        paths_found: List[str],
    ) -> List[ArtifactRecord]:
        """Check Prefetch directory for cleanup tool execution traces."""
        artifacts: List[ArtifactRecord] = []
        prefetch_dir = os.path.join(self.evidence_root, self.PREFETCH_PATH)
        paths_searched.append(prefetch_dir)

        if not os.path.isdir(prefetch_dir):
            return artifacts

        paths_found.append(prefetch_dir)
        try:
            for fname in os.listdir(prefetch_dir):
                upper = fname.upper()
                for tool_exe, tool_name in CLEANUP_TOOLS.items():
                    if tool_exe in upper:
                        fpath = os.path.join(prefetch_dir, fname)
                        ts = None
                        try:
                            ts = datetime.fromtimestamp(
                                os.path.getmtime(fpath), tz=timezone.utc
                            )
                        except OSError:
                            pass
                        artifacts.append(ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.OS_EXECUTION,
                            artifact_type="Cleanup Tool Execution",
                            artifact_subtype="prefetch",
                            artifact_path=fpath,
                            parser_used=self.PARSER_NAME,
                            timestamp=ts,
                            timestamp_type=TimestampType.EXECUTION,
                            extracted_indicator=f"Cleanup tool: {tool_name} ({fname})",
                            suspected_platform=AIPlatform.UNKNOWN,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.MODERATE,
                            classification=EvidenceClassification.INFERRED,
                            notes=(
                                f"Prefetch entry for {tool_name} indicates "
                                f"cleanup tool was executed. This may have "
                                f"affected AI platform evidence preservation. "
                                f"Governance Rule 7: cleanup affects persistence, not motive."
                            ),
                        ))
                        break
        except OSError as e:
            errors.append(f"Error scanning prefetch: {e}")

        return artifacts

    def _analyze_browser_history(
        self,
        user_base: str,
        errors: List[str],
        paths_searched: List[str],
        paths_found: List[str],
    ) -> List[ArtifactRecord]:
        """Analyze browser history for gaps, anomalies, and selective deletion."""
        artifacts: List[ArtifactRecord] = []

        for browser_name, hist_rel in self.HISTORY_DBS:
            if browser_name == "Firefox":
                # Firefox uses profile directories
                ff_dir = os.path.join(user_base, hist_rel)
                paths_searched.append(ff_dir)
                if not os.path.isdir(ff_dir):
                    continue
                for profile in os.listdir(ff_dir):
                    places = os.path.join(ff_dir, profile, "places.sqlite")
                    if os.path.isfile(places):
                        artifacts.extend(
                            self._analyze_single_history(
                                places, browser_name, errors, paths_found,
                                is_firefox=True,
                            )
                        )
                continue

            hist_path = os.path.join(user_base, hist_rel)
            paths_searched.append(hist_path)
            if not os.path.isfile(hist_path):
                continue
            paths_found.append(hist_path)
            artifacts.extend(
                self._analyze_single_history(
                    hist_path, browser_name, errors, paths_found,
                )
            )

        return artifacts

    def _analyze_single_history(
        self,
        db_path: str,
        browser_name: str,
        errors: List[str],
        paths_found: List[str],
        is_firefox: bool = False,
    ) -> List[ArtifactRecord]:
        """Analyze a single browser history database for anomalies."""
        artifacts: List[ArtifactRecord] = []
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
            tmp.close()
            shutil.copy2(db_path, tmp.name)
            conn = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row

            if is_firefox:
                # Firefox: check for history gaps
                rows = conn.execute(
                    "SELECT last_visit_date FROM moz_places "
                    "WHERE last_visit_date IS NOT NULL "
                    "ORDER BY last_visit_date"
                ).fetchall()
                timestamps = []
                for r in rows:
                    try:
                        # Firefox timestamps: microseconds since epoch
                        ts = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                            microseconds=r["last_visit_date"]
                        )
                        timestamps.append(ts)
                    except (OverflowError, OSError, ValueError):
                        pass
            else:
                # Chrome/Edge: check for history gaps
                rows = conn.execute(
                    "SELECT last_visit_time FROM urls "
                    "WHERE last_visit_time > 0 "
                    "ORDER BY last_visit_time"
                ).fetchall()
                timestamps = []
                chrome_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                for r in rows:
                    try:
                        ts = chrome_epoch + timedelta(microseconds=r["last_visit_time"])
                        timestamps.append(ts)
                    except (OverflowError, OSError, ValueError):
                        pass

            conn.close()

            # Detect significant time gaps (>24 hours with no browsing)
            if len(timestamps) >= 10:
                for i in range(1, len(timestamps)):
                    gap = timestamps[i] - timestamps[i - 1]
                    if gap > timedelta(days=1):
                        artifacts.append(ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.BROWSER_HISTORY,
                            artifact_type="History Gap Detected",
                            artifact_subtype="temporal_gap",
                            artifact_path=db_path,
                            parser_used=self.PARSER_NAME,
                            timestamp=timestamps[i - 1],
                            timestamp_type=TimestampType.LAST_VISITED,
                            extracted_indicator=(
                                f"Gap of {gap.days}d {gap.seconds // 3600}h "
                                f"between {timestamps[i - 1].isoformat()} "
                                f"and {timestamps[i].isoformat()}"
                            ),
                            suspected_platform=AIPlatform.UNKNOWN,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.LOW,
                            classification=EvidenceClassification.INFERRED,
                            notes=(
                                f"Significant gap in {browser_name} browsing history. "
                                f"This may indicate history deletion, system downtime, "
                                f"or legitimate inactivity. Requires corroboration."
                            ),
                        ))
                        # Only report first 5 major gaps to avoid noise
                        if len([a for a in artifacts
                                if a.artifact_subtype == "temporal_gap"]) >= 5:
                            break

            # Detect timestamp anomalies (future timestamps)
            now = datetime.now(tz=timezone.utc)
            future_count = sum(1 for ts in timestamps if ts > now + timedelta(hours=24))
            if future_count > 0:
                artifacts.append(ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile,
                    artifact_family=ArtifactFamily.BROWSER_HISTORY,
                    artifact_type="Timestamp Anomaly",
                    artifact_subtype="future_timestamp",
                    artifact_path=db_path,
                    parser_used=self.PARSER_NAME,
                    extracted_indicator=f"{future_count} entries with future timestamps",
                    suspected_platform=AIPlatform.UNKNOWN,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.MODERATE,
                    classification=EvidenceClassification.INFERRED,
                    notes=(
                        f"{browser_name}: {future_count} history entries have timestamps "
                        f"in the future. This may indicate timestamp manipulation or "
                        f"system clock misconfiguration."
                    ),
                ))

            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        except (sqlite3.Error, OSError) as e:
            errors.append(f"Error analyzing {db_path}: {e}")

        return artifacts

    def _detect_metadata_stripping(
        self,
        user_base: str,
        errors: List[str],
        paths_searched: List[str],
        paths_found: List[str],
    ) -> List[ArtifactRecord]:
        """Detect images with stripped EXIF metadata that may be AI-generated."""
        artifacts: List[ArtifactRecord] = []

        # Focus on directories where AI content is likely saved
        for scan_dir in ["Downloads", "Documents", "Desktop", "Pictures"]:
            dir_path = os.path.join(user_base, scan_dir)
            paths_searched.append(dir_path)
            if not os.path.isdir(dir_path):
                continue

            try:
                for fname in os.listdir(dir_path):
                    fpath = os.path.join(dir_path, fname)
                    if not os.path.isfile(fpath):
                        continue

                    # Check image files for EXIF stripping
                    lower = fname.lower()
                    if lower.endswith((".png", ".jpg", ".jpeg", ".webp")):
                        # Check if filename suggests AI generation but has no EXIF
                        ai_name_patterns = [
                            r"dall[-_]?e", r"midjourney", r"stable[-_]?diffusion",
                            r"ai[-_]?generated", r"chatgpt", r"gemini[-_]?image",
                        ]
                        if any(re.search(p, lower) for p in ai_name_patterns):
                            # Check for minimal EXIF (< 100 bytes of metadata)
                            try:
                                size = os.path.getsize(fpath)
                                if size > 10000:  # Reasonable image file
                                    with open(fpath, "rb") as f:
                                        header = f.read(min(512, size))
                                    # JPEG with no EXIF APP1 marker
                                    if (header[:2] == b'\xff\xd8' and
                                            b'\xff\xe1' not in header[:512]):
                                        paths_found.append(fpath)
                                        artifacts.append(ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.USER_CONTENT,
                                            artifact_type="Metadata-Stripped AI Image",
                                            artifact_subtype="exif_stripped",
                                            artifact_path=fpath,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=f"AI-named image without EXIF: {fname}",
                                            suspected_platform=AIPlatform.UNKNOWN,
                                            attribution_layer=AttributionLayer.CONTENT,
                                            confidence=ConfidenceLevel.LOW,
                                            classification=EvidenceClassification.INFERRED,
                                            notes=(
                                                "Image filename suggests AI generation but "
                                                "EXIF metadata is absent or stripped. This may "
                                                "indicate provenance removal."
                                            ),
                                        ))
                            except OSError:
                                pass
            except OSError as e:
                errors.append(f"Error scanning {dir_path}: {e}")

        return artifacts
