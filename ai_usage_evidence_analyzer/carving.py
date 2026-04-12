"""
Signature-based file carving engine.

Implements header/footer carving with optional internal-structure
validation, configurable signature packs, and batch carving with
match provenance.  Every carved output preserves source offset,
recovered size, and the rule used — no fabricated filenames.

Carved artifacts receive synthetic names like `carved_0x1A000.jpg`
to maintain provenance transparency.
"""

from __future__ import annotations

import logging
import os
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import BinaryIO, Dict, List, Optional, Tuple

from .models import (
    AIPlatform,
    CarvedArtifact,
    CarvingValidation,
    ConfidenceLevel,
    RecoveryMode,
    RecoveryStatus,
    SignatureRule,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default signature rules
# ---------------------------------------------------------------------------

DEFAULT_SIGNATURES: List[SignatureRule] = [
    # Images
    SignatureRule(
        name="JPEG", extension="jpg",
        header=b"\xff\xd8\xff", footer=b"\xff\xd9",
        max_size=30 * 1024 * 1024,
        description="JPEG image",
    ),
    SignatureRule(
        name="PNG", extension="png",
        header=b"\x89PNG\r\n\x1a\n",
        footer=b"\x00\x00\x00\x00IEND\xaeB`\x82",
        max_size=30 * 1024 * 1024,
        description="PNG image",
    ),
    SignatureRule(
        name="GIF", extension="gif",
        header=b"GIF8", footer=b"\x00\x3b",
        max_size=10 * 1024 * 1024,
        description="GIF image",
    ),
    SignatureRule(
        name="BMP", extension="bmp",
        header=b"BM", footer=b"",
        max_size=30 * 1024 * 1024,
        description="BMP image",
    ),
    SignatureRule(
        name="WEBP", extension="webp",
        header=b"RIFF", footer=b"",
        max_size=30 * 1024 * 1024,
        description="WebP image (RIFF container)",
    ),
    # Documents
    SignatureRule(
        name="PDF", extension="pdf",
        header=b"%PDF-", footer=b"%%EOF",
        max_size=100 * 1024 * 1024,
        description="PDF document",
    ),
    SignatureRule(
        name="DOCX", extension="docx",
        header=b"PK\x03\x04", footer=b"",
        max_size=50 * 1024 * 1024,
        validate_internal=True,
        description="Office Open XML / ZIP container (DOCX/XLSX/PPTX)",
    ),
    SignatureRule(
        name="ZIP", extension="zip",
        header=b"PK\x03\x04", footer=b"",
        max_size=100 * 1024 * 1024,
        description="ZIP archive",
    ),
    # Data formats
    SignatureRule(
        name="SQLite", extension="sqlite",
        header=b"SQLite format 3\x00",
        footer=b"",
        max_size=500 * 1024 * 1024,
        description="SQLite database",
    ),
    SignatureRule(
        name="JSON", extension="json",
        header=b'{"', footer=b"",
        max_size=50 * 1024 * 1024,
        description="JSON document (opening brace)",
    ),
    SignatureRule(
        name="HTML", extension="html",
        header=b"<!DOCTYPE html", footer=b"</html>",
        max_size=20 * 1024 * 1024,
        description="HTML document",
    ),
    SignatureRule(
        name="HTML_lower", extension="html",
        header=b"<html", footer=b"</html>",
        max_size=20 * 1024 * 1024,
        description="HTML document (lowercase)",
    ),
    # AI-related exports
    SignatureRule(
        name="ChatGPT_Export", extension="json",
        header=b'[{"title":', footer=b"",
        max_size=100 * 1024 * 1024,
        validate_internal=True,
        description="ChatGPT conversation export (JSON array)",
    ),
    SignatureRule(
        name="Markdown_AI", extension="md",
        header=b"# ", footer=b"",
        max_size=10 * 1024 * 1024,
        description="Markdown document (potential AI transcript)",
    ),
]

# Patterns that hint at AI-platform origin in carved content
AI_CONTENT_MARKERS = [
    (b"chatgpt", AIPlatform.CHATGPT),
    (b"openai", AIPlatform.CHATGPT),
    (b"chat.openai.com", AIPlatform.CHATGPT),
    (b"anthropic", AIPlatform.CLAUDE),
    (b"claude.ai", AIPlatform.CLAUDE),
    (b"gemini.google.com", AIPlatform.GEMINI),
    (b"bard.google.com", AIPlatform.GEMINI),
]


# ---------------------------------------------------------------------------
# Signature Rule Engine
# ---------------------------------------------------------------------------

class SignatureRuleEngine:
    """
    Performs header/footer file carving on a raw byte stream.

    Usage:
        engine = SignatureRuleEngine(signatures=DEFAULT_SIGNATURES)
        results = engine.carve(stream, evidence_id, output_dir)
    """

    def __init__(
        self,
        signatures: Optional[List[SignatureRule]] = None,
        read_chunk: int = 4096,
    ):
        self.signatures = signatures or list(DEFAULT_SIGNATURES)
        self._read_chunk = read_chunk
        self._max_header = max(
            (len(s.header) for s in self.signatures), default=16
        )

    def carve(
        self,
        stream: BinaryIO,
        evidence_id: str = "",
        output_dir: str = "",
        max_hits: int = 5000,
    ) -> List[CarvedArtifact]:
        """
        Scan *stream* for file signatures and carve matching regions.

        Returns a list of CarvedArtifact records.  Carved data is
        written to *output_dir* using synthetic offset-based filenames.
        """
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="trace_carve_")
        os.makedirs(output_dir, exist_ok=True)

        results: List[CarvedArtifact] = []
        stream.seek(0, 2)
        stream_size = stream.tell()
        stream.seek(0)

        buf = b""
        global_offset = 0
        hits = 0

        while True:
            chunk = stream.read(self._read_chunk)
            if not chunk:
                break
            buf += chunk

            for sig in self.signatures:
                if hits >= max_hits:
                    break
                search_start = 0
                while True:
                    idx = buf.find(sig.header, search_start)
                    if idx == -1:
                        break
                    abs_offset = global_offset + idx
                    carved = self._extract_one(
                        stream, buf, idx, global_offset,
                        abs_offset, sig, evidence_id, output_dir,
                    )
                    if carved is not None:
                        results.append(carved)
                        hits += 1
                    search_start = idx + 1
                    if hits >= max_hits:
                        break

            # Keep tail for cross-boundary headers
            keep = max(self._max_header - 1, 0)
            if len(buf) > keep:
                global_offset += len(buf) - keep
                buf = buf[-keep:]

        logger.info("Carving complete: %d artifacts extracted", len(results))
        return results

    # ------------------------------------------------------------------
    def _extract_one(
        self,
        stream: BinaryIO,
        buf: bytes,
        buf_idx: int,
        buf_global_offset: int,
        abs_offset: int,
        sig: SignatureRule,
        evidence_id: str,
        output_dir: str,
    ) -> Optional[CarvedArtifact]:
        """Try to extract one carved artifact starting at *abs_offset*."""
        # Read up to max_size from the stream
        stream.seek(abs_offset)
        data = stream.read(sig.max_size)
        if len(data) < sig.min_size:
            return None

        # Find footer if specified
        if sig.footer:
            end_idx = data.find(sig.footer, len(sig.header))
            if end_idx != -1:
                data = data[: end_idx + len(sig.footer)]
            else:
                # No footer found — take max_size but mark partial
                pass

        if len(data) < max(sig.min_size, len(sig.header) + 1):
            return None

        # Validate internally if requested
        validation = CarvingValidation.NOT_VALIDATED
        if sig.validate_internal:
            validation = self._validate_internal(data, sig)
            if validation == CarvingValidation.INVALID:
                return None

        # Determine AI platform hint
        platform = AIPlatform.UNKNOWN
        sample = data[:8192].lower()
        for marker, plat in AI_CONTENT_MARKERS:
            if marker in sample:
                platform = plat
                break

        # Confidence hint based on validation and footer match
        confidence = ConfidenceLevel.LOW
        if sig.footer and sig.footer in data:
            confidence = ConfidenceLevel.MODERATE
            if validation == CarvingValidation.VALID:
                confidence = ConfidenceLevel.MODERATE  # still caps at moderate for carved

        # Write carved data
        carved_name = f"carved_{abs_offset:#010x}.{sig.extension}"
        carved_path = os.path.join(output_dir, carved_name)
        try:
            with open(carved_path, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            logger.warning("Cannot write carved file %s: %s", carved_path, exc)
            return None

        status = RecoveryStatus.COMPLETE if sig.footer and sig.footer in data else RecoveryStatus.PARTIAL

        return CarvedArtifact(
            source_evidence_id=evidence_id,
            source_image_path="",
            offset=abs_offset,
            recovered_size=len(data),
            signature_rule_used=sig.name,
            carved_filename=carved_name,
            temp_path=carved_path,
            validation=validation,
            recovery_mode=RecoveryMode.SIGNATURE_CARVING,
            recovery_status=status,
            confidence_hint=confidence,
            extraction_timestamp=datetime.now(tz=timezone.utc),
            chain_of_custody_note=f"Carved from offset {abs_offset:#x} using rule '{sig.name}'",
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _validate_internal(data: bytes, sig: SignatureRule) -> CarvingValidation:
        """Basic internal structure validation."""
        if sig.name in ("DOCX", "ZIP", "ChatGPT_Export"):
            # ZIP local file header: PK\x03\x04
            if data[:4] == b"PK\x03\x04" and len(data) > 30:
                # Check for end-of-central-directory
                if b"PK\x05\x06" in data[-256:]:
                    return CarvingValidation.VALID
                return CarvingValidation.PARTIAL_STRUCTURE
        if sig.name == "SQLite":
            if data[:16] == b"SQLite format 3\x00" and len(data) >= 100:
                return CarvingValidation.VALID
        if sig.name == "PDF":
            if data[:5] == b"%PDF-" and b"%%EOF" in data[-128:]:
                return CarvingValidation.VALID
            if data[:5] == b"%PDF-":
                return CarvingValidation.PARTIAL_STRUCTURE
        # Default: header matched
        return CarvingValidation.HEADER_ONLY


def load_signature_pack(path: str) -> List[SignatureRule]:
    """
    Load custom signature rules from a JSON file.

    Format: list of objects with keys: name, extension, header_hex,
    footer_hex, max_size, min_size, validate_internal, description.
    """
    import json
    rules: List[SignatureRule] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pack = json.load(fh)
        for entry in pack:
            rules.append(SignatureRule(
                name=entry.get("name", ""),
                extension=entry.get("extension", ""),
                header=bytes.fromhex(entry.get("header_hex", "")),
                footer=bytes.fromhex(entry.get("footer_hex", "")),
                max_size=entry.get("max_size", 50 * 1024 * 1024),
                min_size=entry.get("min_size", 0),
                validate_internal=entry.get("validate_internal", False),
                description=entry.get("description", ""),
            ))
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        logger.error("Failed to load signature pack %s: %s", path, exc)
    return rules
