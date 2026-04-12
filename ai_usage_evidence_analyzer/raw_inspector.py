"""
Raw byte-level forensic inspector.

Provides sector/offset dump, ASCII/hex preview, keyword scanning,
and structured domain/model-string search across raw evidence
streams.  Returns typed RawHit records that downstream modules
can correlate with carved or filesystem-level artifacts.
"""

from __future__ import annotations

import io
import logging
import re
from datetime import datetime, timezone
from typing import BinaryIO, Dict, List, Optional, Tuple

from .models import (
    AIPlatform,
    ConfidenceLevel,
    RawHit,
    RawHitType,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default keyword / pattern banks
# ---------------------------------------------------------------------------

AI_DOMAIN_PATTERNS: List[Tuple[str, AIPlatform]] = [
    (r"chat\.openai\.com", AIPlatform.CHATGPT),
    (r"chatgpt\.com", AIPlatform.CHATGPT),
    (r"api\.openai\.com", AIPlatform.CHATGPT),
    (r"platform\.openai\.com", AIPlatform.CHATGPT),
    (r"claude\.ai", AIPlatform.CLAUDE),
    (r"api\.anthropic\.com", AIPlatform.CLAUDE),
    (r"console\.anthropic\.com", AIPlatform.CLAUDE),
    (r"gemini\.google\.com", AIPlatform.GEMINI),
    (r"bard\.google\.com", AIPlatform.GEMINI),
    (r"generativelanguage\.googleapis\.com", AIPlatform.GEMINI),
    (r"copilot\.microsoft\.com", AIPlatform.COPILOT),
    (r"github\.copilot", AIPlatform.COPILOT),
    (r"copilot\.github\.com", AIPlatform.COPILOT),
    (r"app\.grammarly\.com", AIPlatform.GRAMMARLY),
    (r"perplexity\.ai", AIPlatform.PERPLEXITY),
    (r"deepseek\.com", AIPlatform.DEEPSEEK),
    (r"you\.com/search\?.*chatMode", AIPlatform.YOUCOM),
]

AI_MODEL_PATTERNS: List[Tuple[str, str]] = [
    (r"gpt-4o?(-mini|-turbo)?", "GPT-4 family"),
    (r"gpt-3\.5-turbo", "GPT-3.5-Turbo"),
    (r"claude-3[-.]\d?-?(opus|sonnet|haiku)?", "Claude 3 family"),
    (r"claude-2(\.\d)?", "Claude 2"),
    (r"gemini-(\d\.?\d?)-?(pro|ultra|flash|nano)?", "Gemini family"),
    (r"dall-?e-?[23]", "DALL-E"),
    (r"whisper-\d", "Whisper"),
    (r"codex", "Codex"),
]

EXPORT_MARKER_PATTERNS: List[str] = [
    r'"model"\s*:\s*"gpt-',
    r'"model"\s*:\s*"claude-',
    r'"conversation_id"\s*:',
    r'"message_id"\s*:',
    r'"author"\s*:\s*\{\s*"role"\s*:\s*"(assistant|user)"',
    r'"parts"\s*:\s*\[',
]

PLATFORM_TOKEN_PATTERNS: List[Tuple[str, AIPlatform]] = [
    (r"sk-[A-Za-z0-9]{20,}", AIPlatform.CHATGPT),  # OpenAI API key
    (r"sk-ant-[A-Za-z0-9\-]{20,}", AIPlatform.CLAUDE),  # Anthropic key
    (r"sess-[A-Za-z0-9]{20,}", AIPlatform.CHATGPT),  # session token
]


# ---------------------------------------------------------------------------
# Raw Inspector
# ---------------------------------------------------------------------------

class RawInspector:
    """
    Scan a raw byte stream for AI-related keywords, domains, model
    strings, platform tokens, and export markers.
    """

    def __init__(
        self,
        extra_keywords: Optional[List[str]] = None,
        scan_chunk_size: int = 1024 * 1024,  # 1 MB
        overlap: int = 4096,
    ):
        self._extra_keywords = extra_keywords or []
        self._scan_chunk = scan_chunk_size
        self._overlap = overlap

        # Pre-compile domain patterns
        self._domain_res = [
            (re.compile(pat.encode(), re.IGNORECASE), plat)
            for pat, plat in AI_DOMAIN_PATTERNS
        ]
        self._model_res = [
            (re.compile(pat.encode(), re.IGNORECASE), label)
            for pat, label in AI_MODEL_PATTERNS
        ]
        self._export_res = [
            re.compile(pat.encode(), re.IGNORECASE)
            for pat in EXPORT_MARKER_PATTERNS
        ]
        self._token_res = [
            (re.compile(pat.encode()), plat)
            for pat, plat in PLATFORM_TOKEN_PATTERNS
        ]
        self._extra_keyword_res = [
            re.compile(re.escape(kw.encode()), re.IGNORECASE)
            for kw in self._extra_keywords
        ]

    # ------------------------------------------------------------------
    def scan(
        self,
        stream: BinaryIO,
        evidence_id: str = "",
        max_hits: int = 5000,
    ) -> List[RawHit]:
        """
        Scan the full stream and return RawHit records.

        Raw hits alone stay at LOW confidence unless corroborated
        by filesystem or carved evidence.
        """
        results: List[RawHit] = []
        stream.seek(0, 2)
        stream_size = stream.tell()
        stream.seek(0)

        offset = 0
        carry = b""

        while offset < stream_size and len(results) < max_hits:
            stream.seek(max(0, offset - len(carry)))
            chunk = carry + stream.read(self._scan_chunk)
            if not chunk:
                break

            self._scan_chunk_domains(chunk, offset - len(carry), evidence_id, results, max_hits)
            self._scan_chunk_models(chunk, offset - len(carry), evidence_id, results, max_hits)
            self._scan_chunk_exports(chunk, offset - len(carry), evidence_id, results, max_hits)
            self._scan_chunk_tokens(chunk, offset - len(carry), evidence_id, results, max_hits)
            self._scan_chunk_keywords(chunk, offset - len(carry), evidence_id, results, max_hits)

            carry = chunk[-self._overlap:] if len(chunk) > self._overlap else b""
            offset += self._scan_chunk

        logger.info("Raw scan complete: %d hit(s) in %s", len(results), evidence_id)
        return results

    # ------------------------------------------------------------------
    def dump_offset(
        self,
        stream: BinaryIO,
        offset: int,
        length: int = 512,
    ) -> str:
        """Return hex + ASCII dump of *length* bytes at *offset*."""
        stream.seek(offset)
        data = stream.read(length)
        lines: List[str] = []
        for i in range(0, len(data), 16):
            row = data[i : i + 16]
            hex_part = " ".join(f"{b:02X}" for b in row)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"{offset + i:08X}  {hex_part:<48s}  |{ascii_part}|")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal scanning helpers
    # ------------------------------------------------------------------

    def _scan_chunk_domains(
        self, chunk: bytes, base_offset: int,
        evidence_id: str, results: List[RawHit], max_hits: int,
    ):
        for rx, platform in self._domain_res:
            if len(results) >= max_hits:
                return
            for m in rx.finditer(chunk):
                if len(results) >= max_hits:
                    return
                results.append(RawHit(
                    evidence_id=evidence_id,
                    offset=base_offset + m.start(),
                    length=m.end() - m.start(),
                    matched_pattern=m.group().decode(errors="replace"),
                    hit_type=RawHitType.DOMAIN_HIT,
                    suspected_platform=platform,
                    confidence_hint=ConfidenceLevel.LOW,
                    context_preview=self._context(chunk, m.start(), 64),
                    scan_timestamp=datetime.now(tz=timezone.utc),
                ))

    def _scan_chunk_models(
        self, chunk: bytes, base_offset: int,
        evidence_id: str, results: List[RawHit], max_hits: int,
    ):
        for rx, label in self._model_res:
            if len(results) >= max_hits:
                return
            for m in rx.finditer(chunk):
                if len(results) >= max_hits:
                    return
                results.append(RawHit(
                    evidence_id=evidence_id,
                    offset=base_offset + m.start(),
                    length=m.end() - m.start(),
                    matched_pattern=m.group().decode(errors="replace"),
                    hit_type=RawHitType.MODEL_NAME_HIT,
                    suspected_platform=AIPlatform.UNKNOWN,
                    confidence_hint=ConfidenceLevel.LOW,
                    context_preview=self._context(chunk, m.start(), 64),
                    scan_timestamp=datetime.now(tz=timezone.utc),
                    notes=f"Model family: {label}",
                ))

    def _scan_chunk_exports(
        self, chunk: bytes, base_offset: int,
        evidence_id: str, results: List[RawHit], max_hits: int,
    ):
        for rx in self._export_res:
            if len(results) >= max_hits:
                return
            for m in rx.finditer(chunk):
                if len(results) >= max_hits:
                    return
                results.append(RawHit(
                    evidence_id=evidence_id,
                    offset=base_offset + m.start(),
                    length=m.end() - m.start(),
                    matched_pattern=m.group().decode(errors="replace"),
                    hit_type=RawHitType.EXPORT_MARKER,
                    suspected_platform=AIPlatform.UNKNOWN,
                    confidence_hint=ConfidenceLevel.LOW,
                    context_preview=self._context(chunk, m.start(), 128),
                    scan_timestamp=datetime.now(tz=timezone.utc),
                ))

    def _scan_chunk_tokens(
        self, chunk: bytes, base_offset: int,
        evidence_id: str, results: List[RawHit], max_hits: int,
    ):
        for rx, platform in self._token_res:
            if len(results) >= max_hits:
                return
            for m in rx.finditer(chunk):
                if len(results) >= max_hits:
                    return
                results.append(RawHit(
                    evidence_id=evidence_id,
                    offset=base_offset + m.start(),
                    length=m.end() - m.start(),
                    matched_pattern="[REDACTED_TOKEN]",  # never store secrets
                    hit_type=RawHitType.PLATFORM_TOKEN,
                    suspected_platform=platform,
                    confidence_hint=ConfidenceLevel.LOW,
                    context_preview="[Token context redacted for security]",
                    scan_timestamp=datetime.now(tz=timezone.utc),
                    notes="API key / session token detected — redacted",
                ))

    def _scan_chunk_keywords(
        self, chunk: bytes, base_offset: int,
        evidence_id: str, results: List[RawHit], max_hits: int,
    ):
        for rx in self._extra_keyword_res:
            if len(results) >= max_hits:
                return
            for m in rx.finditer(chunk):
                if len(results) >= max_hits:
                    return
                results.append(RawHit(
                    evidence_id=evidence_id,
                    offset=base_offset + m.start(),
                    length=m.end() - m.start(),
                    matched_pattern=m.group().decode(errors="replace"),
                    hit_type=RawHitType.GENERIC_STRING,
                    suspected_platform=AIPlatform.UNKNOWN,
                    confidence_hint=ConfidenceLevel.LOW,
                    context_preview=self._context(chunk, m.start(), 64),
                    scan_timestamp=datetime.now(tz=timezone.utc),
                ))

    # ------------------------------------------------------------------
    @staticmethod
    def _context(chunk: bytes, pos: int, window: int) -> str:
        """Extract a printable context window around *pos*."""
        start = max(0, pos - window)
        end = min(len(chunk), pos + window)
        raw = chunk[start:end]
        return raw.decode("utf-8", errors="replace").replace("\x00", "")[:256]
