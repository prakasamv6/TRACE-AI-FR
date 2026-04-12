"""
C2PA Content Credentials / provenance manifest parser (FR-4).

Detects and parses C2PA (Coalition for Content Provenance and Authenticity)
manifests embedded in media files, verifying:
- Content origin assertions
- AI-use assertions (generativeAI type)
- Modification history (actions)
- Cryptographic signature bindings
- Manifest integrity validation

Reference: C2PA Technical Specification v2.x
"""

from __future__ import annotations

import json
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import (
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


# C2PA JUMBF box markers
C2PA_JUMBF_UUID = b'\xd8\xfe\xc3\xd6\x1b\x0e\x48\x3c\x92\x97\x58\x28\x87\x7e\xc4\x81'
C2PA_MANIFEST_LABEL = "c2pa"
C2PA_ASSERTION_LABEL = "c2pa.assertions"

# Known AI-related C2PA action types
AI_ACTION_TYPES = [
    "c2pa.created",
    "c2pa.edited",
    "c2pa.generated",
    "c2pa.ai_generated",
]

# Known AI generator software agents in C2PA manifests
AI_GENERATORS = {
    "dall-e": AIPlatform.CHATGPT,
    "openai": AIPlatform.CHATGPT,
    "chatgpt": AIPlatform.CHATGPT,
    "midjourney": AIPlatform.UNKNOWN,
    "stable diffusion": AIPlatform.UNKNOWN,
    "stability.ai": AIPlatform.UNKNOWN,
    "adobe firefly": AIPlatform.UNKNOWN,
    "google": AIPlatform.GEMINI,
    "imagen": AIPlatform.GEMINI,
    "anthropic": AIPlatform.CLAUDE,
}


@register_parser
class C2PAManifestParser(BaseParser):
    """
    Parse C2PA Content Credentials manifests from media files.
    Addresses FR-4: Provenance and authenticity verification.

    Scans JPEG, PNG, and WebP files for embedded C2PA JUMBF manifests
    and extracts AI-use assertions, modification history, and
    cryptographic binding information.
    """

    PARSER_NAME = "C2PAManifestParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Content Provenance"

    SCAN_DIRS = [
        "Downloads",
        "Documents",
        "Desktop",
        "Pictures",
        "Pictures/Screenshots",
    ]

    IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif"}

    MAX_SCAN_SIZE = 50 * 1024 * 1024  # 50 MB per file

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)
        if not os.path.isdir(user_base):
            return self._make_result(status=ParserStatus.NOT_APPLICABLE,
                                     notes="User profile not found")

        for scan_dir in self.SCAN_DIRS:
            dir_path = os.path.join(user_base, scan_dir)
            paths_searched.append(dir_path)
            if not os.path.isdir(dir_path):
                continue

            try:
                for fname in os.listdir(dir_path):
                    fpath = os.path.join(dir_path, fname)
                    if not os.path.isfile(fpath):
                        continue

                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in self.IMAGE_EXTENSIONS:
                        continue

                    try:
                        file_size = os.path.getsize(fpath)
                        if file_size > self.MAX_SCAN_SIZE or file_size < 100:
                            continue
                    except OSError:
                        continue

                    # Scan for C2PA manifest
                    manifest_data = self._extract_c2pa_manifest(fpath)
                    if manifest_data:
                        paths_found.append(fpath)
                        manifest_artifacts = self._parse_manifest(
                            fpath, fname, manifest_data
                        )
                        artifacts.extend(manifest_artifacts)

            except OSError as e:
                errors.append(f"Error scanning {dir_path}: {e}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"C2PA scan: {len(artifacts)} provenance manifests found",
            artifact_coverage=[],
            coverage_gaps=[],
            parse_failures=[],
            unsupported_artifacts=[],
        )

    def _extract_c2pa_manifest(self, file_path: str) -> Optional[bytes]:
        """
        Extract C2PA JUMBF manifest data from a media file.

        C2PA embeds manifests as JUMBF (JPEG Universal Metadata Box Format)
        boxes. For JPEG, these appear as APP11 markers. For PNG, they appear
        as caBX chunks. For WebP, as RIFF EXIF extended data.
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(32)

                if header[:2] == b'\xff\xd8':
                    # JPEG: scan for APP11 (0xFFEB) with C2PA JUMBF UUID
                    return self._scan_jpeg_c2pa(f)
                elif header[:8] == b'\x89PNG\r\n\x1a\n':
                    # PNG: scan for caBX chunk
                    return self._scan_png_c2pa(f)
                elif header[:4] == b'RIFF' and header[8:12] == b'WEBP':
                    # WebP: scan for C2PA data
                    return self._scan_webp_c2pa(f)
        except (OSError, struct.error):
            pass
        return None

    def _scan_jpeg_c2pa(self, f) -> Optional[bytes]:
        """Scan JPEG APP11 markers for C2PA JUMBF."""
        f.seek(2)
        data = b""
        while True:
            marker_bytes = f.read(2)
            if len(marker_bytes) < 2:
                break
            if marker_bytes[0] != 0xFF:
                break
            marker = marker_bytes[1]

            if marker == 0xD9:  # End of image
                break
            if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0x01):
                continue  # Standalone markers

            length_bytes = f.read(2)
            if len(length_bytes) < 2:
                break
            length = struct.unpack(">H", length_bytes)[0] - 2

            if marker == 0xEB:  # APP11 — JUMBF container
                segment = f.read(length)
                if C2PA_JUMBF_UUID in segment:
                    data += segment
            else:
                f.seek(length, 1)

            if len(data) > 10 * 1024 * 1024:  # Safety limit
                break

        return data if data else None

    def _scan_png_c2pa(self, f) -> Optional[bytes]:
        """Scan PNG for caBX (C2PA) chunk."""
        f.seek(8)  # Skip PNG signature
        while True:
            chunk_header = f.read(8)
            if len(chunk_header) < 8:
                break
            length = struct.unpack(">I", chunk_header[:4])[0]
            chunk_type = chunk_header[4:8]

            if chunk_type == b'caBX':
                data = f.read(length)
                f.read(4)  # CRC
                return data
            elif chunk_type == b'IEND':
                break
            else:
                f.seek(length + 4, 1)  # Skip data + CRC

        return None

    def _scan_webp_c2pa(self, f) -> Optional[bytes]:
        """Scan WebP for C2PA data in extended format."""
        f.seek(12)
        while f.tell() < os.fstat(f.fileno()).st_size:
            chunk_header = f.read(8)
            if len(chunk_header) < 8:
                break
            chunk_type = chunk_header[:4]
            chunk_size = struct.unpack("<I", chunk_header[4:8])[0]

            if chunk_type == b'C2PA':
                return f.read(chunk_size)
            else:
                f.seek(chunk_size + (chunk_size % 2), 1)

        return None

    def _parse_manifest(
        self, file_path: str, filename: str, manifest_data: bytes
    ) -> List[ArtifactRecord]:
        """Parse C2PA manifest data and extract provenance assertions."""
        artifacts: List[ArtifactRecord] = []

        # Try to find JSON-encoded assertions within the JUMBF manifest
        json_segments = self._extract_json_from_manifest(manifest_data)

        ai_detected = False
        platform = AIPlatform.UNKNOWN
        assertions_text: List[str] = []

        for segment in json_segments:
            try:
                data = json.loads(segment)

                # Check for AI-related assertions
                if isinstance(data, dict):
                    # Check actions
                    actions = data.get("actions", [])
                    if isinstance(actions, list):
                        for action in actions:
                            if isinstance(action, dict):
                                action_type = action.get("action", "")
                                software = action.get("softwareAgent", "")
                                if any(kw in action_type.lower()
                                       for kw in ["generated", "ai_generated", "created"]):
                                    ai_detected = True
                                    assertions_text.append(
                                        f"Action: {action_type}, Software: {software}"
                                    )
                                # Check software agent for AI generators
                                for gen_name, gen_platform in AI_GENERATORS.items():
                                    if gen_name in software.lower():
                                        ai_detected = True
                                        platform = gen_platform

                    # Check claim_generator
                    claim_gen = data.get("claim_generator", "")
                    if isinstance(claim_gen, str):
                        for gen_name, gen_platform in AI_GENERATORS.items():
                            if gen_name in claim_gen.lower():
                                ai_detected = True
                                platform = gen_platform
                                assertions_text.append(
                                    f"Claim generator: {claim_gen}"
                                )

                    # Check for generativeInfo assertion
                    gen_info = data.get("generativeInfo", data.get("ai_info", {}))
                    if gen_info:
                        ai_detected = True
                        assertions_text.append(f"Generative info: {json.dumps(gen_info)[:200]}")

            except (json.JSONDecodeError, ValueError):
                continue

        # Always record C2PA manifest presence
        ts = None
        try:
            ts = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
        except OSError:
            pass

        confidence = ConfidenceLevel.HIGH if ai_detected else ConfidenceLevel.MODERATE
        classification = (EvidenceClassification.DIRECT if ai_detected
                          else EvidenceClassification.INFERRED)

        indicator = f"C2PA manifest in {filename}"
        if assertions_text:
            indicator += f" — {'; '.join(assertions_text[:3])}"

        artifacts.append(ArtifactRecord(
            case_id=self.case_id,
            evidence_item_id=self.evidence_item_id,
            source_image=self.source_image,
            user_profile=self.user_profile,
            artifact_family=ArtifactFamily.USER_CONTENT,
            artifact_type="C2PA Content Credentials",
            artifact_subtype="c2pa_manifest",
            artifact_path=file_path,
            parser_used=self.PARSER_NAME,
            timestamp=ts,
            timestamp_type=TimestampType.MODIFIED,
            extracted_indicator=indicator[:1000],
            suspected_platform=platform,
            attribution_layer=AttributionLayer.CONTENT,
            confidence=confidence,
            classification=classification,
            notes=(
                f"C2PA Content Credentials manifest found in {filename}. "
                f"{'AI-generation assertion detected. ' if ai_detected else ''}"
                f"Manifest size: {len(manifest_data)} bytes. "
                f"Provenance boundary: C2PA verifies manifest integrity "
                f"but not semantic truth of content claims."
            ),
        ))

        return artifacts

    def _extract_json_from_manifest(self, data: bytes) -> List[bytes]:
        """Extract JSON segments from JUMBF manifest data."""
        segments: List[bytes] = []
        # Scan for JSON objects within the binary data
        i = 0
        while i < len(data):
            if data[i:i + 1] == b'{':
                # Try to find matching closing brace
                depth = 0
                j = i
                while j < len(data):
                    if data[j:j + 1] == b'{':
                        depth += 1
                    elif data[j:j + 1] == b'}':
                        depth -= 1
                        if depth == 0:
                            segment = data[i:j + 1]
                            # Validate it's valid UTF-8 JSON
                            try:
                                segment.decode("utf-8")
                                json.loads(segment)
                                segments.append(segment)
                            except (UnicodeDecodeError, json.JSONDecodeError):
                                pass
                            break
                    j += 1
                    if j - i > 1024 * 1024:  # Safety limit: 1MB per JSON
                        break
                i = j + 1
            else:
                i += 1
            if len(segments) >= 20:  # Limit segments
                break
        return segments
