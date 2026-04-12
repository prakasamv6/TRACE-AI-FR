"""
Generated Asset Parser (v4.0).

Detects AI-generated assets (images, documents, code files) with
provenance metadata:
- DALL-E / ChatGPT generated images
- Midjourney / Stable Diffusion outputs
- AI-generated code files with metadata headers
- C2PA / Content Credentials manifests
- AI watermark detection metadata

Produces GeneratedAssetRecord instances.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from ..models import (
    AIPlatform,
    ArtifactFamily,
    ArtifactRecord,
    AcquisitionSource,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceSourceClass,
    GeneratedAssetRecord,
    PlatformSurface,
)

logger = logging.getLogger(__name__)

# Known AI-generated file name patterns
_AI_GENERATED_PATTERNS = [
    "dall-e", "dalle", "chatgpt-image", "generated_image",
    "midjourney", "stable-diffusion", "sd_output",
    "ai_generated", "ai-generated",
]

# Image extensions that may contain AI-generated content
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff"}

# C2PA manifest indicators
_C2PA_MARKERS = [b"c2pa", b"C2PA", b"contentcredentials", b"Content Credentials"]


class GeneratedAssetParser:
    """
    Detect and catalog AI-generated assets in evidence.
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
        self.assets: List[GeneratedAssetRecord] = []
        self.artifacts: List[ArtifactRecord] = []

    def scan(self) -> List[GeneratedAssetRecord]:
        """Scan evidence for AI-generated assets."""
        if not os.path.isdir(self.evidence_root):
            return []

        for root, dirs, files in os.walk(self.evidence_root):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                # Check filename patterns
                if self._matches_ai_pattern(fname):
                    self._catalog_asset(fpath, fname, "filename_match")
                    continue

                # Check for C2PA content credentials in images
                if ext in _IMAGE_EXTENSIONS:
                    if self._has_c2pa_marker(fpath):
                        self._catalog_asset(fpath, fname, "c2pa_manifest")
                        continue

                # Check for AI metadata JSON sidecars
                if ext == ".json" and self._is_ai_metadata_sidecar(fpath):
                    self._catalog_asset(fpath, fname, "metadata_sidecar")

        logger.info("Found %d generated asset(s)", len(self.assets))
        return self.assets

    def _matches_ai_pattern(self, fname: str) -> bool:
        """Check if filename matches known AI-generated patterns."""
        fn_lower = fname.lower()
        return any(pat in fn_lower for pat in _AI_GENERATED_PATTERNS)

    def _has_c2pa_marker(self, fpath: str) -> bool:
        """Check file header for C2PA content credentials markers."""
        try:
            with open(fpath, "rb") as f:
                header = f.read(4096)
            return any(marker in header for marker in _C2PA_MARKERS)
        except OSError:
            return False

    def _is_ai_metadata_sidecar(self, fpath: str) -> bool:
        """Check if a JSON file is an AI asset metadata sidecar."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(10000)
            data = json.loads(content)
            if isinstance(data, dict):
                keys = set(data.keys())
                ai_keys = {"model", "prompt", "generator", "ai_model",
                          "generation_id", "c2pa", "content_credentials"}
                return bool(keys & ai_keys)
        except (json.JSONDecodeError, OSError):
            pass
        return False

    def _catalog_asset(self, fpath: str, fname: str, detection_method: str):
        """Create a GeneratedAssetRecord and corresponding ArtifactRecord."""
        try:
            stat = os.stat(fpath)
            file_hash = self._compute_hash(fpath)
        except OSError:
            return

        ext = os.path.splitext(fname)[1].lower()
        asset_type = "image" if ext in _IMAGE_EXTENSIONS else "document"
        platform = self._detect_platform(fname, fpath)

        # Check for C2PA metadata
        c2pa_meta = {}
        if detection_method == "c2pa_manifest":
            c2pa_meta = {"detected": True, "note": "C2PA manifest markers found in file header"}

        record = GeneratedAssetRecord(
            platform=platform,
            asset_type=asset_type,
            file_path=fpath,
            file_hash=file_hash,
            file_size=stat.st_size,
            c2pa_metadata=c2pa_meta,
        )
        self.assets.append(record)

        art = ArtifactRecord(
            case_id=self.case_id,
            evidence_item_id=self.evidence_item_id,
            source_image=self.source_image,
            artifact_family=ArtifactFamily.USER_CONTENT,
            artifact_type="Generated Asset",
            artifact_subtype=f"{asset_type}:{detection_method}",
            artifact_path=fpath,
            parser_used="GeneratedAssetParser",
            timestamp=datetime.fromtimestamp(stat.st_mtime),
            extracted_indicator=f"AI-generated {asset_type}: {fname}",
            suspected_platform=platform,
            classification=EvidenceClassification.INFERRED,
            confidence=ConfidenceLevel.MODERATE,
            evidence_source_class=EvidenceSourceClass.CONTENT_REMNANT_DERIVED,
            acquisition_source=AcquisitionSource.GENERATED_FILE_CAPTURE,
            platform_surface=PlatformSurface.UNKNOWN,
            related_generated_asset_id=record.asset_id,
            notes=(
                f"[GeneratedAsset] Detection: {detection_method}. "
                f"Hash: {file_hash[:16]}... "
                f"C2PA: {'present' if c2pa_meta else 'absent'}."
            ),
        )
        self.artifacts.append(art)

    def _detect_platform(self, fname: str, fpath: str) -> AIPlatform:
        """Detect AI platform from filename or metadata."""
        fn_lower = fname.lower()
        if "dall-e" in fn_lower or "dalle" in fn_lower or "chatgpt" in fn_lower:
            return AIPlatform.CHATGPT
        if "midjourney" in fn_lower:
            return AIPlatform.UNKNOWN  # No dedicated platform enum for Midjourney
        if "gemini" in fn_lower:
            return AIPlatform.GEMINI
        if "copilot" in fn_lower:
            return AIPlatform.COPILOT
        return AIPlatform.UNKNOWN

    @staticmethod
    def _compute_hash(fpath: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        try:
            with open(fpath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""
