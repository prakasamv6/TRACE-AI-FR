"""
Voice / Audio Evidence Module (v4.0).

Provides first-class forensic handling for voice and audio artifacts
from AI platform interactions. Supports:
- Transcript text files (imported)
- JSON voice/session logs
- Audio metadata extraction (no cloud API required)
- Hash generation for evidence integrity
- Provider/platform association
- Timestamp extraction
- Transcript-to-chat correlation
- Voice-session-to-generated-asset correlation

Hard rules:
- Do NOT claim speaker identity unless explicitly supported by separate evidence
- Do NOT require online speech-to-text services
- Absence of raw audio must NOT erase transcript-based evidence
- Transcript-only evidence must be labeled appropriately
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import (
    AIPlatform,
    ArtifactFamily,
    ArtifactRecord,
    AcquisitionSource,
    ConfidenceLevel,
    EvidenceClassification,
    EvidenceSourceClass,
    PlatformSurface,
    VoiceArtifactType,
    VoiceEvidenceRecord,
)
from .signatures import DOMAIN_TO_PLATFORM

logger = logging.getLogger(__name__)

# Supported transcript file extensions
_TRANSCRIPT_EXTENSIONS = {".txt", ".srt", ".vtt", ".json", ".csv"}

# Supported audio metadata extensions (metadata-only parsing)
_AUDIO_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg", ".flac", ".webm", ".aac", ".opus"}


class VoiceEvidenceEngine:
    """
    Parse and correlate voice/audio evidence from AI platform interactions.

    This engine operates in metadata-only mode by default. It does NOT
    perform speech-to-text transcription. It can import pre-existing
    transcripts and correlate them with other artifacts.
    """

    def __init__(
        self,
        case_id: str = "",
        evidence_item_id: str = "",
        source_image: str = "",
    ):
        self.case_id = case_id
        self.evidence_item_id = evidence_item_id
        self.source_image = source_image
        self.voice_records: List[VoiceEvidenceRecord] = []
        self.voice_artifacts: List[ArtifactRecord] = []

    def import_transcripts(self, transcript_dir: str) -> List[VoiceEvidenceRecord]:
        """
        Import transcript files from a directory.

        Supports .txt, .srt, .vtt, .json, .csv transcript formats.
        Each file generates a VoiceEvidenceRecord.
        """
        if not os.path.isdir(transcript_dir):
            logger.warning("Transcript directory not found: %s", transcript_dir)
            return []

        records = []
        for fname in sorted(os.listdir(transcript_dir)):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _TRANSCRIPT_EXTENSIONS:
                continue

            fpath = os.path.join(transcript_dir, fname)
            if not os.path.isfile(fpath):
                continue

            record = self._parse_transcript_file(fpath, fname)
            if record:
                records.append(record)
                self.voice_records.append(record)
                # Also create an ArtifactRecord for pipeline integration
                art = self._voice_to_artifact(record)
                self.voice_artifacts.append(art)

        logger.info("Imported %d transcript(s) from %s", len(records), transcript_dir)
        return records

    def scan_evidence_for_voice(
        self, evidence_root: str, user_profile: str = ""
    ) -> List[VoiceEvidenceRecord]:
        """
        Scan an evidence directory for voice/audio artifacts.

        Only extracts metadata (file size, timestamps, hash). Does NOT
        transcribe audio content.
        """
        if not os.path.isdir(evidence_root):
            return []

        records = []
        for root, dirs, files in os.walk(evidence_root):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                fpath = os.path.join(root, fname)

                if ext in _AUDIO_EXTENSIONS:
                    record = self._parse_audio_metadata(fpath, fname)
                    if record:
                        records.append(record)
                        self.voice_records.append(record)
                        art = self._voice_to_artifact(record)
                        self.voice_artifacts.append(art)

                # Look for voice session JSON logs
                if ext == ".json" and any(
                    kw in fname.lower()
                    for kw in ("voice", "audio", "speech", "whisper", "transcript")
                ):
                    record = self._parse_voice_session_log(fpath, fname)
                    if record:
                        records.append(record)
                        self.voice_records.append(record)
                        art = self._voice_to_artifact(record)
                        self.voice_artifacts.append(art)

        logger.info("Found %d voice/audio artifact(s) in evidence", len(records))
        return records

    def _parse_transcript_file(
        self, fpath: str, fname: str
    ) -> Optional[VoiceEvidenceRecord]:
        """Parse a transcript file into a VoiceEvidenceRecord."""
        try:
            file_hash = self._compute_hash(fpath)
            stat = os.stat(fpath)

            ext = os.path.splitext(fname)[1].lower()

            if ext == ".json":
                return self._parse_json_transcript(fpath, fname, file_hash, stat)

            # Plain text / SRT / VTT
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(100_000)  # Cap at 100KB

            platform = self._detect_platform_from_content(content, fname)

            return VoiceEvidenceRecord(
                platform=platform,
                artifact_type=VoiceArtifactType.TRANSCRIPT_TEXT,
                source_path=fpath,
                transcript_text=content,
                transcript_source="imported",
                timestamp=datetime.fromtimestamp(stat.st_mtime),
                file_hash=file_hash,
                caveats=[
                    "This transcript was imported from a file. Its provenance "
                    "and accuracy have not been independently verified.",
                    "Speaker identity cannot be determined from transcript alone.",
                ],
            )
        except Exception as e:
            logger.warning("Failed to parse transcript %s: %s", fpath, e)
            return None

    def _parse_json_transcript(
        self, fpath: str, fname: str, file_hash: str, stat: os.stat_result
    ) -> Optional[VoiceEvidenceRecord]:
        """Parse a JSON transcript or voice session log."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        # Extract text from common JSON transcript formats
        text = ""
        if isinstance(data, list):
            # Array of entries (e.g., Whisper output)
            parts = []
            for item in data[:500]:
                if isinstance(item, dict):
                    parts.append(item.get("text", item.get("transcript", "")))
                elif isinstance(item, str):
                    parts.append(item)
            text = "\n".join(parts)
        elif isinstance(data, dict):
            text = data.get("text", data.get("transcript", data.get("content", "")))
            if isinstance(text, list):
                text = "\n".join(str(t) for t in text)

        platform = self._detect_platform_from_content(
            text + " " + json.dumps(data)[:5000], fname
        )

        # Extract session metadata
        session_id = ""
        duration = 0.0
        if isinstance(data, dict):
            session_id = str(data.get("session_id", data.get("id", "")))
            duration = float(data.get("duration", data.get("duration_seconds", 0)))

        return VoiceEvidenceRecord(
            platform=platform,
            artifact_type=VoiceArtifactType.VOICE_SESSION_LOG,
            source_path=fpath,
            transcript_text=text[:100_000],
            transcript_source="imported",
            session_id=session_id,
            timestamp=datetime.fromtimestamp(stat.st_mtime),
            duration_seconds=duration,
            file_hash=file_hash,
            caveats=[
                "This voice session log was imported from a JSON file. "
                "Its provenance has not been independently verified.",
            ],
        )

    def _parse_audio_metadata(
        self, fpath: str, fname: str
    ) -> Optional[VoiceEvidenceRecord]:
        """Extract metadata from an audio file (no transcription)."""
        try:
            stat = os.stat(fpath)
            file_hash = self._compute_hash(fpath)

            platform = self._detect_platform_from_content("", fname)

            return VoiceEvidenceRecord(
                platform=platform,
                artifact_type=VoiceArtifactType.AUDIO_METADATA,
                source_path=fpath,
                transcript_text="",
                transcript_source="metadata-only",
                timestamp=datetime.fromtimestamp(stat.st_mtime),
                file_hash=file_hash,
                caveats=[
                    "Audio file metadata was extracted but content was NOT "
                    "transcribed. No speech-to-text service was invoked.",
                    "Speaker identity cannot be determined.",
                    "Audio content could not be verified without transcription.",
                ],
            )
        except Exception as e:
            logger.warning("Failed to parse audio metadata %s: %s", fpath, e)
            return None

    def _parse_voice_session_log(
        self, fpath: str, fname: str
    ) -> Optional[VoiceEvidenceRecord]:
        """Parse a voice session log JSON file."""
        return self._parse_transcript_file(fpath, fname)

    def _detect_platform_from_content(
        self, content: str, filename: str
    ) -> AIPlatform:
        """Detect AI platform from transcript content or filename."""
        combined = (content + " " + filename).lower()

        platform_keywords = {
            AIPlatform.CHATGPT: ["chatgpt", "openai", "gpt-4", "gpt4o"],
            AIPlatform.CLAUDE: ["claude", "anthropic"],
            AIPlatform.GEMINI: ["gemini", "bard", "google ai"],
            AIPlatform.PERPLEXITY: ["perplexity", "pplx"],
            AIPlatform.COPILOT: ["copilot", "bing chat"],
            AIPlatform.META_AI: ["meta ai", "llama", "meta.ai"],
            AIPlatform.GROK: ["grok", "x.ai"],
            AIPlatform.POE: ["poe.com", "quora poe"],
        }
        for platform, keywords in platform_keywords.items():
            if any(kw in combined for kw in keywords):
                return platform

        return AIPlatform.UNKNOWN

    def _voice_to_artifact(self, record: VoiceEvidenceRecord) -> ArtifactRecord:
        """Convert a VoiceEvidenceRecord to an ArtifactRecord for the pipeline."""
        return ArtifactRecord(
            case_id=self.case_id,
            evidence_item_id=self.evidence_item_id,
            source_image=self.source_image,
            artifact_family=ArtifactFamily.USER_CONTENT,
            artifact_type="Voice/Audio Evidence",
            artifact_subtype=record.artifact_type.value,
            artifact_path=record.source_path,
            parser_used="VoiceEvidenceEngine",
            timestamp=record.timestamp,
            extracted_indicator=(
                record.transcript_text[:200] if record.transcript_text
                else f"Audio file: {os.path.basename(record.source_path)}"
            ),
            suspected_platform=record.platform,
            classification=(
                EvidenceClassification.DIRECT if record.transcript_text
                else EvidenceClassification.INFERRED
            ),
            confidence=(
                ConfidenceLevel.MODERATE if record.transcript_text
                else ConfidenceLevel.LOW
            ),
            evidence_source_class=EvidenceSourceClass.VOICE_DERIVED,
            acquisition_source=AcquisitionSource.TRANSCRIPT_CAPTURE,
            platform_surface=PlatformSurface.VOICE_SESSION,
            related_voice_event_id=record.voice_id,
            notes=(
                f"[Voice] transcript_source={record.transcript_source}; "
                f"hash={record.file_hash[:16]}..."
                if record.file_hash else "[Voice] metadata-only"
            ),
        )

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
