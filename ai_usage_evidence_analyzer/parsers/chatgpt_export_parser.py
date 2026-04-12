"""
ChatGPT conversation export parser (FR-2).

Parses ChatGPT's official conversation export (conversations.json from
Settings → Data Controls → Export Data) to reconstruct full session
histories with:
- Turn-by-turn prompt→response chains
- Model version per message
- Plugin/tool usage within conversations
- Attachment and file upload references
- Message edit and status tracking
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

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
from ..signatures import match_model_string


# Model slug → AIModel mapping for ChatGPT exports
MODEL_SLUG_MAP = {
    "gpt-4": AIModel.GPT4,
    "gpt-4-turbo": AIModel.GPT4_TURBO,
    "gpt-4o": AIModel.GPT4O,
    "gpt-4o-mini": AIModel.GPT4O,
    "gpt-4-browsing": AIModel.GPT4,
    "gpt-4-plugins": AIModel.GPT4,
    "gpt-4-code-interpreter": AIModel.GPT4,
    "gpt-4-gizmo": AIModel.GPT4,
}


@register_parser
class ChatGPTExportParser(BaseParser):
    """
    Parse ChatGPT conversation exports (conversations.json).
    Addresses FR-2: Full session reconstruction with turn-by-turn replay.

    ChatGPT's data export contains conversations.json with full conversation
    trees, message content, model metadata, plugin usage, and timestamps.
    This parser reconstructs complete session histories from these exports.
    """

    PARSER_NAME = "ChatGPTExportParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "User Content"

    # Locations where ChatGPT exports are typically saved
    EXPORT_LOCATIONS = [
        "Downloads",
        "Documents",
        "Desktop",
    ]

    MAX_EXPORT_SIZE = 500 * 1024 * 1024  # 500 MB safety limit

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)
        if not os.path.isdir(user_base):
            return self._make_result(status=ParserStatus.NOT_APPLICABLE,
                                     notes="User profile not found")

        # Search for conversations.json files
        for scan_dir in self.EXPORT_LOCATIONS:
            dir_path = os.path.join(user_base, scan_dir)
            paths_searched.append(dir_path)
            if not os.path.isdir(dir_path):
                continue

            # Direct conversations.json
            self._scan_directory(dir_path, artifacts, errors, paths_found)

            # Also check inside extracted ZIP exports (chatgpt-export/)
            try:
                for item in os.listdir(dir_path):
                    subdir = os.path.join(dir_path, item)
                    if os.path.isdir(subdir) and any(
                        kw in item.lower()
                        for kw in ["chatgpt", "openai", "export", "gpt"]
                    ):
                        self._scan_directory(subdir, artifacts, errors, paths_found)
            except OSError:
                pass

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"ChatGPT export: {len(artifacts)} artifacts from conversation data",
            artifact_coverage=[],
            coverage_gaps=[],
            parse_failures=[],
            unsupported_artifacts=[],
        )

    def _scan_directory(
        self,
        dir_path: str,
        artifacts: List[ArtifactRecord],
        errors: List[str],
        paths_found: List[str],
    ):
        """Scan a directory for conversations.json."""
        conv_path = os.path.join(dir_path, "conversations.json")
        if not os.path.isfile(conv_path):
            return

        try:
            file_size = os.path.getsize(conv_path)
            if file_size > self.MAX_EXPORT_SIZE:
                errors.append(f"Skipping oversized export: {conv_path} ({file_size} bytes)")
                return
        except OSError:
            return

        paths_found.append(conv_path)

        try:
            with open(conv_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            errors.append(f"Error reading {conv_path}: {e}")
            return

        if not isinstance(data, list):
            errors.append(f"Unexpected format in {conv_path}: expected JSON array")
            return

        # Process each conversation
        for conv in data:
            if not isinstance(conv, dict):
                continue
            conv_artifacts = self._parse_conversation(conv, conv_path)
            artifacts.extend(conv_artifacts)

    def _parse_conversation(
        self, conv: Dict, source_path: str
    ) -> List[ArtifactRecord]:
        """Parse a single ChatGPT conversation into artifacts."""
        artifacts: List[ArtifactRecord] = []

        conv_id = conv.get("id", "")
        title = conv.get("title", "Untitled")
        create_time = conv.get("create_time")
        update_time = conv.get("update_time")
        model_slug = conv.get("default_model_slug", "")
        plugin_ids = conv.get("plugin_ids") or []
        gizmo_id = conv.get("gizmo_id")

        # Convert timestamps
        ts_created = self._unix_to_datetime(create_time) if create_time else None
        ts_updated = self._unix_to_datetime(update_time) if update_time else None

        # Detect model
        model = MODEL_SLUG_MAP.get(model_slug, AIModel.UNKNOWN)
        if model == AIModel.UNKNOWN and model_slug:
            detected = match_model_string(model_slug)
            if detected:
                model = detected

        # Create conversation-level artifact
        plugin_info = ""
        if plugin_ids:
            plugin_info = f" | Plugins: {', '.join(plugin_ids[:5])}"
        if gizmo_id:
            plugin_info += f" | Custom GPT: {gizmo_id}"

        artifacts.append(ArtifactRecord(
            case_id=self.case_id,
            evidence_item_id=self.evidence_item_id,
            source_image=self.source_image,
            user_profile=self.user_profile,
            artifact_family=ArtifactFamily.USER_CONTENT,
            artifact_type="ChatGPT Conversation",
            artifact_subtype="conversation_export",
            artifact_path=source_path,
            parser_used=self.PARSER_NAME,
            timestamp=ts_created,
            timestamp_type=TimestampType.CREATED,
            extracted_indicator=(
                f"Conversation: '{title}' (ID: {conv_id[:16]}...) "
                f"Model: {model_slug or 'unknown'}{plugin_info}"
            ),
            suspected_platform=AIPlatform.CHATGPT,
            suspected_model=model,
            suspected_access_mode=AccessMode.BROWSER,
            attribution_layer=AttributionLayer.MODEL,
            confidence=ConfidenceLevel.HIGH,
            classification=EvidenceClassification.DIRECT,
            notes=(
                f"Full conversation from ChatGPT data export. "
                f"Created: {ts_created.isoformat() if ts_created else 'N/A'}, "
                f"Updated: {ts_updated.isoformat() if ts_updated else 'N/A'}. "
                f"Default model: {model_slug}."
            ),
        ))

        # Parse individual messages (turn-by-turn replay)
        mapping = conv.get("mapping", {})
        if isinstance(mapping, dict):
            message_count = 0
            for node_id, node in mapping.items():
                if not isinstance(node, dict):
                    continue
                message = node.get("message")
                if not isinstance(message, dict):
                    continue

                author_role = message.get("author", {}).get("role", "")
                if author_role not in ("user", "assistant", "tool"):
                    continue

                content = message.get("content", {})
                parts = content.get("parts", []) if isinstance(content, dict) else []
                msg_text = ""
                for part in parts:
                    if isinstance(part, str):
                        msg_text += part
                    elif isinstance(part, dict):
                        # Image or file attachment
                        content_type = part.get("content_type", "")
                        if content_type:
                            msg_text += f"[{content_type}]"

                msg_create_time = message.get("create_time")
                msg_ts = self._unix_to_datetime(msg_create_time) if msg_create_time else None

                # Per-message model metadata
                msg_metadata = message.get("metadata", {})
                msg_model = msg_metadata.get("model_slug", "") if isinstance(msg_metadata, dict) else ""

                msg_model_enum = AIModel.UNKNOWN
                if msg_model:
                    msg_model_enum = MODEL_SLUG_MAP.get(msg_model, AIModel.UNKNOWN)

                # Detect tool/plugin usage in message
                tool_name = ""
                if author_role == "tool":
                    tool_name = message.get("author", {}).get("name", "unknown_tool")

                # Create artifact for significant messages (prompts and responses)
                subtype = f"{author_role}_message"
                indicator = f"[{author_role.upper()}] "
                if tool_name:
                    indicator += f"(Tool: {tool_name}) "
                indicator += msg_text[:300] if msg_text else "(empty)"

                artifacts.append(ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile,
                    artifact_family=ArtifactFamily.USER_CONTENT,
                    artifact_type="ChatGPT Message",
                    artifact_subtype=subtype,
                    artifact_path=source_path,
                    parser_used=self.PARSER_NAME,
                    timestamp=msg_ts,
                    timestamp_type=TimestampType.CREATED,
                    extracted_indicator=indicator[:1000],
                    suspected_platform=AIPlatform.CHATGPT,
                    suspected_model=msg_model_enum if msg_model_enum != AIModel.UNKNOWN else model,
                    suspected_access_mode=AccessMode.BROWSER,
                    attribution_layer=AttributionLayer.CONTENT,
                    confidence=ConfidenceLevel.HIGH,
                    classification=EvidenceClassification.DIRECT,
                    notes=(
                        f"Turn in conversation '{title}'. "
                        f"Role: {author_role}, Model: {msg_model or model_slug}. "
                        f"{'Tool call: ' + tool_name + '. ' if tool_name else ''}"
                        f"Content length: {len(msg_text)} chars."
                    ),
                ))

                message_count += 1
                if message_count >= 500:  # Safety limit per conversation
                    break

        # Track plugin usage as separate artifacts
        for pid in plugin_ids:
            artifacts.append(ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                user_profile=self.user_profile,
                artifact_family=ArtifactFamily.USER_CONTENT,
                artifact_type="ChatGPT Plugin Usage",
                artifact_subtype="plugin_reference",
                artifact_path=source_path,
                parser_used=self.PARSER_NAME,
                timestamp=ts_created,
                timestamp_type=TimestampType.CREATED,
                extracted_indicator=f"Plugin: {pid} in conversation '{title}'",
                suspected_platform=AIPlatform.CHATGPT,
                suspected_model=model,
                attribution_layer=AttributionLayer.PLATFORM,
                confidence=ConfidenceLevel.HIGH,
                classification=EvidenceClassification.DIRECT,
                notes=(
                    f"Plugin '{pid}' was active in conversation '{title}'. "
                    f"This indicates third-party tool-chain involvement (FR-7)."
                ),
            ))

        return artifacts

    @staticmethod
    def _unix_to_datetime(ts) -> Optional[datetime]:
        """Convert a Unix timestamp to datetime."""
        if ts is None:
            return None
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
