"""
Content-based parsers for AI-attributable content indicators.

Scans user directories for:
- Export/transcript files from AI platforms
- Screenshots of AI sessions
- Prompt/response remnants in documents
- Files with AI-suggestive naming patterns
- Image upload references
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
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
from ..signatures import ALL_SIGNATURES, match_model_string


# ---------------------------------------------------------------------------
# AI Content Scanner
# ---------------------------------------------------------------------------

@register_parser
class AIContentScanner(BaseParser):
    """
    Scan user directories for AI-attributable content indicators.

    Checks Downloads, Documents, Desktop, and other user folders for:
    - Export files from ChatGPT, Claude, Gemini
    - Screenshots of AI sessions
    - Files with AI-suggestive names
    - Documents containing prompt/response remnants
    """

    PARSER_NAME = "AIContentScanner"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "User Content"
    IS_STUB = False

    SCAN_DIRS = [
        "Downloads",
        "Documents",
        "Desktop",
        "Pictures",
        "Pictures/Screenshots",
    ]

    # File extensions to scan for content
    TEXT_EXTENSIONS = {
        ".txt", ".md", ".json", ".csv", ".html", ".htm",
        ".py", ".js", ".ts", ".java", ".cpp", ".c",
        ".log", ".xml", ".yaml", ".yml",
    }

    IMAGE_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp",
    }

    MAX_FILE_SCAN_SIZE = 1024 * 1024  # 1 MB

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        warnings: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)
        if not os.path.isdir(user_base):
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                notes=f"User profile directory not found: {user_base}",
            )

        for scan_dir in self.SCAN_DIRS:
            dir_path = os.path.join(user_base, scan_dir)
            paths_searched.append(dir_path)

            if not os.path.isdir(dir_path):
                paths_missing.append(dir_path)
                continue

            paths_found.append(dir_path)

            try:
                for item in os.listdir(dir_path):
                    item_path = os.path.join(dir_path, item)
                    if not os.path.isfile(item_path):
                        continue

                    # 1. Check filename against AI export/download patterns
                    fn_match = self._check_filename_patterns(item)
                    if fn_match:
                        platform, pattern = fn_match
                        ts = self._get_file_timestamp(item_path)
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.USER_CONTENT,
                            artifact_type="AI Export/Download File",
                            artifact_subtype="Filename Pattern Match",
                            artifact_path=item_path,
                            parser_used=self.PARSER_NAME,
                            timestamp=ts,
                            timestamp_type=TimestampType.MODIFIED,
                            timezone_normalized=True if ts else False,
                            extracted_indicator=f"File: {item} (pattern: {pattern})",
                            suspected_platform=platform,
                            classification=EvidenceClassification.INFERRED,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.LOW,
                            notes="Filename suggestive of AI output. "
                                  "A filename alone is only a weak indicator "
                                  "unless corroborated.",
                        )
                        artifacts.append(record)

                    # 2. Check screenshot filenames
                    ss_match = self._check_screenshot_patterns(item)
                    if ss_match:
                        platform = ss_match
                        ts = self._get_file_timestamp(item_path)
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.SCREENSHOT,
                            artifact_type="Screenshot",
                            artifact_subtype="AI Session Screenshot",
                            artifact_path=item_path,
                            parser_used=self.PARSER_NAME,
                            timestamp=ts,
                            timestamp_type=TimestampType.MODIFIED,
                            timezone_normalized=True if ts else False,
                            extracted_indicator=f"Screenshot: {item}",
                            suspected_platform=platform,
                            classification=EvidenceClassification.INFERRED,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.LOW,
                            notes="Screenshot filename suggests AI session. "
                                  "Cannot confirm chronology without timestamp correlation.",
                        )
                        artifacts.append(record)

                    # 3. Scan text file contents for prompt/response indicators
                    ext = os.path.splitext(item)[1].lower()
                    if ext in self.TEXT_EXTENSIONS:
                        content_matches = self._scan_file_content(item_path)
                        for cm in content_matches:
                            ts = self._get_file_timestamp(item_path)
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.USER_CONTENT,
                                artifact_type="Content Indicator",
                                artifact_subtype=cm["type"],
                                artifact_path=item_path,
                                parser_used=self.PARSER_NAME,
                                timestamp=ts,
                                timestamp_type=TimestampType.MODIFIED,
                                timezone_normalized=True if ts else False,
                                extracted_indicator=cm["indicator"][:200],
                                suspected_platform=cm["platform"],
                                suspected_model=cm.get("model", None),
                                classification=EvidenceClassification.INFERRED,
                                attribution_layer=cm.get("attribution", AttributionLayer.PLATFORM),
                                confidence=ConfidenceLevel.LOW,
                                notes=cm.get("notes", ""),
                            )
                            artifacts.append(record)

            except Exception as exc:
                errors.append(f"Error scanning {dir_path}: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
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

    def _check_filename_patterns(self, filename: str) -> Optional[tuple]:
        """Check if a filename matches AI export/download patterns."""
        fn_lower = filename.lower()
        for sig in ALL_SIGNATURES:
            for pattern in sig.download_patterns + sig.export_patterns:
                if re.search(pattern, fn_lower, re.IGNORECASE):
                    return (sig.platform, pattern)
        return None

    def _check_screenshot_patterns(self, filename: str) -> Optional[AIPlatform]:
        """Check if a screenshot filename suggests AI session capture."""
        fn_lower = filename.lower()
        ext = os.path.splitext(filename)[1].lower()
        if ext not in self.IMAGE_EXTENSIONS:
            return None
        for sig in ALL_SIGNATURES:
            for pattern in sig.screenshot_patterns:
                if re.search(pattern, fn_lower, re.IGNORECASE):
                    return sig.platform
        return None

    def _scan_file_content(self, filepath: str) -> List[dict]:
        """Scan a text file for AI prompt/response indicators."""
        results = []
        try:
            size = os.path.getsize(filepath)
            if size > self.MAX_FILE_SCAN_SIZE:
                return results

            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Check for prompt indicators
            for sig in ALL_SIGNATURES:
                for indicator in sig.prompt_indicators:
                    if indicator.lower() in content.lower():
                        results.append({
                            "platform": sig.platform,
                            "type": "Prompt Remnant",
                            "indicator": f"Prompt indicator: '{indicator}' in {os.path.basename(filepath)}",
                            "attribution": AttributionLayer.PLATFORM,
                            "notes": "Prompt indicator string found in file content.",
                        })
                        break

                for indicator in sig.response_indicators:
                    if indicator.lower() in content.lower():
                        results.append({
                            "platform": sig.platform,
                            "type": "Response Remnant",
                            "indicator": f"Response indicator: '{indicator}' in {os.path.basename(filepath)}",
                            "attribution": AttributionLayer.PLATFORM,
                            "notes": "Response indicator string found in file content.",
                        })
                        break

            # Check for model-specific strings
            model = match_model_string(content)
            if model:
                # Determine platform from model
                platform = AIPlatform.UNKNOWN
                for sig in ALL_SIGNATURES:
                    if model in sig.model_strings:
                        platform = sig.platform
                        break

                results.append({
                    "platform": platform,
                    "model": model,
                    "type": "Model Reference",
                    "indicator": f"Model string: {model.value} in {os.path.basename(filepath)}",
                    "attribution": AttributionLayer.MODEL,
                    "notes": "Model identifier found in file content. Stronger than platform-only.",
                })

        except Exception:
            pass

        return results

    def _get_file_timestamp(self, path: str) -> Optional[datetime]:
        try:
            stat = os.stat(path)
            return datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        except Exception:
            return None
