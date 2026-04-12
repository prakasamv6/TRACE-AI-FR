"""
Shared Link Parser (v4.0).

Detects and catalogs shared AI-platform URLs found across evidence:
- Browser history (AI share/collaboration links)
- Downloaded files containing shared links
- Clipboard data with AI URLs
- Chat exports containing share URLs

Produces SharedLinkRecord instances.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime
from typing import List, Optional

from ..models import (
    AIPlatform,
    ArtifactFamily,
    ArtifactRecord,
    AcquisitionSource,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceSourceClass,
    PlatformSurface,
    SharedLinkRecord,
)
from ..signatures import ALL_AI_DOMAINS, DOMAIN_TO_PLATFORM

logger = logging.getLogger(__name__)

# Regex for detecting AI-platform share/collaboration URLs
_SHARE_URL_PATTERN = re.compile(
    r'(https?://(?:'
    r'chat\.openai\.com/share/[a-zA-Z0-9-]+'
    r'|chatgpt\.com/share/[a-zA-Z0-9-]+'
    r'|claude\.ai/share/[a-zA-Z0-9-]+'
    r'|bard\.google\.com/share/[a-zA-Z0-9-]+'
    r'|gemini\.google\.com/share/[a-zA-Z0-9-]+'
    r'|perplexity\.ai/search/[a-zA-Z0-9-]+'
    r'|poe\.com/s/[a-zA-Z0-9-]+'
    r'))',
    re.IGNORECASE,
)


class SharedLinkParser:
    """
    Parse evidence for shared AI platform links.
    """

    def __init__(
        self,
        evidence_root: str,
        case_id: str = "",
        evidence_item_id: str = "",
        source_image: str = "",
    ):
        self.evidence_root = evidence_root
        self.case_id = case_id
        self.evidence_item_id = evidence_item_id
        self.source_image = source_image
        self.shared_links: List[SharedLinkRecord] = []
        self.artifacts: List[ArtifactRecord] = []

    def scan(self) -> List[SharedLinkRecord]:
        """Scan evidence for shared AI links."""
        if not os.path.isdir(self.evidence_root):
            return []

        # Scan text-based files for shared links
        text_extensions = {".txt", ".json", ".csv", ".html", ".htm", ".md",
                          ".log", ".url", ".webloc"}
        for root, dirs, files in os.walk(self.evidence_root):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in text_extensions:
                    continue
                fpath = os.path.join(root, fname)
                self._scan_file_for_links(fpath)

        logger.info("Found %d shared link(s)", len(self.shared_links))
        return self.shared_links

    def _scan_file_for_links(self, fpath: str):
        """Scan a single text file for shared AI platform URLs."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(500_000)  # Cap at 500KB
        except OSError:
            return

        for match in _SHARE_URL_PATTERN.finditer(content):
            url = match.group(1)
            platform = self._url_to_platform(url)

            record = SharedLinkRecord(
                platform=platform,
                url=url,
                captured_from=fpath,
                linked_artifact_ids=[],
            )
            self.shared_links.append(record)

            # Create corresponding ArtifactRecord
            art = ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                artifact_type="Shared AI Link",
                artifact_subtype="share_url",
                artifact_path=fpath,
                parser_used="SharedLinkParser",
                extracted_indicator=url[:200],
                suspected_platform=platform,
                classification=EvidenceClassification.DIRECT,
                confidence=ConfidenceLevel.HIGH,
                evidence_source_class=EvidenceSourceClass.BROWSER_DERIVED,
                acquisition_source=AcquisitionSource.SHARED_LINK_CAPTURE,
                platform_surface=PlatformSurface.BROWSER_WEB,
                related_shared_link_id=record.link_id,
                notes=f"[SharedLink] Shared AI platform URL found in {os.path.basename(fpath)}",
            )
            self.artifacts.append(art)

    @staticmethod
    def _url_to_platform(url: str) -> AIPlatform:
        """Detect platform from a share URL."""
        url_lower = url.lower()
        if "openai.com" in url_lower or "chatgpt.com" in url_lower:
            return AIPlatform.CHATGPT
        if "claude.ai" in url_lower:
            return AIPlatform.CLAUDE
        if "gemini.google.com" in url_lower or "bard.google.com" in url_lower:
            return AIPlatform.GEMINI
        if "perplexity.ai" in url_lower:
            return AIPlatform.PERPLEXITY
        if "poe.com" in url_lower:
            return AIPlatform.POE
        return AIPlatform.UNKNOWN
