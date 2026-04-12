"""
Provider Export Parser (v4.0).

Parses first-party data exports from AI platforms:
- ChatGPT data export (conversations.json, user.json, etc.)
- Claude export archives
- Gemini Activity exports from Google Takeout
- Perplexity export JSON
- Other platform-specific export formats

The provider export is the strongest evidence source class — it is
supplied by the platform operator and is treated as canonical.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import (
    AIPlatform,
    AIModel,
    AccessMode,
    ArtifactFamily,
    ArtifactRecord,
    AcquisitionSource,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceSourceClass,
    PlatformSurface,
)

logger = logging.getLogger(__name__)

# Known export file patterns by platform
_CHATGPT_PATTERNS = ["conversations.json", "user.json", "model_comparisons.json",
                       "message_feedback.json", "chat.html"]
_CLAUDE_PATTERNS = ["conversations.json", "claude_conversations.json"]
_GEMINI_PATTERNS = ["My Activity", "BardActivity", "GeminiActivity"]
_PERPLEXITY_PATTERNS = ["search_history.json", "threads.json"]


class ProviderExportParser:
    """
    Parse first-party data exports from AI platforms.
    """

    def __init__(
        self,
        evidence_root: str,
        case_id: str = "",
        evidence_item_id: str = "",
        source_image: str = "",
        user_profile: str = "",
    ):
        self.evidence_root = evidence_root
        self.case_id = case_id
        self.evidence_item_id = evidence_item_id
        self.source_image = source_image
        self.user_profile = user_profile
        self.artifacts: List[ArtifactRecord] = []

    def scan(self) -> List[ArtifactRecord]:
        """Scan evidence for provider export files."""
        if not os.path.isdir(self.evidence_root):
            return []

        for root, dirs, files in os.walk(self.evidence_root):
            for fname in files:
                fpath = os.path.join(root, fname)
                self._try_parse(fpath, fname)

        logger.info("Provider export parser found %d artifact(s)", len(self.artifacts))
        return self.artifacts

    def _try_parse(self, fpath: str, fname: str):
        """Try to parse a file as a provider export."""
        fn_lower = fname.lower()

        # ChatGPT export
        if fn_lower in [p.lower() for p in _CHATGPT_PATTERNS]:
            self._parse_chatgpt_export(fpath, fname)
            return

        # Check if this looks like a ChatGPT conversations.json by structure
        if fn_lower == "conversations.json":
            self._parse_conversations_json(fpath, fname)
            return

        # Claude export
        if fn_lower in [p.lower() for p in _CLAUDE_PATTERNS]:
            self._parse_claude_export(fpath, fname)
            return

        # Gemini / Google Takeout
        parent_dir = os.path.basename(os.path.dirname(fpath))
        if parent_dir in _GEMINI_PATTERNS:
            self._parse_gemini_export(fpath, fname)
            return

        # Perplexity export
        if fn_lower in [p.lower() for p in _PERPLEXITY_PATTERNS]:
            self._parse_perplexity_export(fpath, fname)
            return

    def _parse_chatgpt_export(self, fpath: str, fname: str):
        """Parse ChatGPT data export files."""
        self._create_export_artifact(
            fpath=fpath,
            platform=AIPlatform.CHATGPT,
            artifact_subtype=f"chatgpt_export:{fname}",
            notes=f"[ProviderExport] ChatGPT first-party data export file: {fname}",
        )

        # Parse conversations.json for detailed content
        if fname.lower() == "conversations.json":
            self._parse_conversations_json(fpath, fname)

    def _parse_conversations_json(self, fpath: str, fname: str):
        """Parse a conversations.json file (ChatGPT or Claude format)."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        if not isinstance(data, list):
            return

        for conv in data[:500]:  # Cap at 500 conversations
            if not isinstance(conv, dict):
                continue

            title = conv.get("title", "")
            create_time = conv.get("create_time")
            model_slug = conv.get("model_slug", "") or conv.get("model", "")

            # Detect platform from structure
            platform = AIPlatform.CHATGPT
            if "claude" in str(conv.get("source", "")).lower():
                platform = AIPlatform.CLAUDE

            # Extract model
            model = self._slug_to_model(model_slug)

            timestamp = None
            if create_time:
                try:
                    timestamp = datetime.fromtimestamp(float(create_time))
                except (ValueError, TypeError, OSError):
                    pass

            self._create_export_artifact(
                fpath=fpath,
                platform=platform,
                model=model,
                timestamp=timestamp,
                artifact_subtype="conversation",
                extracted_indicator=f"Conversation: {title[:150]}" if title else "Conversation",
                notes=(
                    f"[ProviderExport] First-party conversation record. "
                    f"Model: {model_slug or 'unknown'}. "
                    f"This is the strongest evidence class — directly from the provider."
                ),
            )

    def _parse_claude_export(self, fpath: str, fname: str):
        """Parse Claude data export."""
        self._create_export_artifact(
            fpath=fpath,
            platform=AIPlatform.CLAUDE,
            artifact_subtype=f"claude_export:{fname}",
            notes=f"[ProviderExport] Claude first-party data export file: {fname}",
        )

    def _parse_gemini_export(self, fpath: str, fname: str):
        """Parse Gemini/Bard export from Google Takeout."""
        self._create_export_artifact(
            fpath=fpath,
            platform=AIPlatform.GEMINI,
            artifact_subtype=f"gemini_export:{fname}",
            notes=f"[ProviderExport] Gemini/Bard Google Takeout export: {fname}",
        )

    def _parse_perplexity_export(self, fpath: str, fname: str):
        """Parse Perplexity export."""
        self._create_export_artifact(
            fpath=fpath,
            platform=AIPlatform.PERPLEXITY,
            artifact_subtype=f"perplexity_export:{fname}",
            notes=f"[ProviderExport] Perplexity first-party data export: {fname}",
        )

    def _create_export_artifact(
        self,
        fpath: str,
        platform: AIPlatform,
        artifact_subtype: str = "",
        notes: str = "",
        extracted_indicator: str = "",
        model: Optional[AIModel] = None,
        timestamp: Optional[datetime] = None,
    ):
        """Create an ArtifactRecord for a provider export file."""
        if not extracted_indicator:
            extracted_indicator = f"Provider data export: {os.path.basename(fpath)}"

        stat = None
        try:
            stat = os.stat(fpath)
        except OSError:
            pass

        art = ArtifactRecord(
            case_id=self.case_id,
            evidence_item_id=self.evidence_item_id,
            source_image=self.source_image,
            user_profile=self.user_profile,
            artifact_family=ArtifactFamily.USER_CONTENT,
            artifact_type="Provider Export",
            artifact_subtype=artifact_subtype,
            artifact_path=fpath,
            parser_used="ProviderExportParser",
            timestamp=timestamp or (
                datetime.fromtimestamp(stat.st_mtime) if stat else None
            ),
            extracted_indicator=extracted_indicator,
            suspected_platform=platform,
            suspected_model=model or AIModel.UNKNOWN,
            suspected_access_mode=AccessMode.UNKNOWN,
            classification=EvidenceClassification.DIRECT,
            confidence=ConfidenceLevel.HIGH,
            evidence_source_class=EvidenceSourceClass.PROVIDER_EXPORT_DERIVED,
            acquisition_source=AcquisitionSource.PROVIDER_EXPORT,
            platform_surface=PlatformSurface.PROVIDER_EXPORT,
            notes=notes,
        )
        self.artifacts.append(art)

    @staticmethod
    def _slug_to_model(slug: str) -> AIModel:
        """Convert a model slug to AIModel enum."""
        from ..models import AIModel
        slug_lower = slug.lower()
        if "gpt-4o" in slug_lower:
            return AIModel.GPT_4O
        if "gpt-4" in slug_lower:
            return AIModel.GPT_4
        if "gpt-3" in slug_lower:
            return AIModel.GPT_3_5
        if "claude-3.5" in slug_lower or "claude-3-5" in slug_lower:
            return AIModel.CLAUDE_3_5_SONNET
        if "claude-3" in slug_lower:
            return AIModel.CLAUDE_3_OPUS
        if "gemini-1.5" in slug_lower:
            return AIModel.GEMINI_1_5_PRO
        if "gemini" in slug_lower:
            return AIModel.GEMINI_PRO
        return AIModel.UNKNOWN
