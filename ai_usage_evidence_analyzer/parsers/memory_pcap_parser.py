"""
Memory dump and PCAP network capture parsers (FR-1).

Extends unified acquisition to include:
- Memory/RAM dump scanning for AI platform strings and URLs
- PCAP/network capture scanning for AI domain traffic
- Process memory remnants of AI application sessions
"""

from __future__ import annotations

import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

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
from ..signatures import ALL_SIGNATURES, match_domain, match_model_string


@register_parser
class MemoryDumpScanner(BaseParser):
    """
    Scan memory dumps (RAM captures) for AI platform evidence.
    Addresses FR-1: Unified acquisition from memory sources.

    Searches raw memory dumps for:
    - AI platform URLs and domains
    - API key fragments
    - Model identifier strings
    - Session tokens and authentication data
    - Prompt/response text remnants
    """

    PARSER_NAME = "MemoryDumpScanner"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Memory"

    # Memory dump file extensions
    MEMORY_EXTENSIONS = {
        ".dmp", ".raw", ".mem", ".vmem", ".lime",
        ".crash", ".core", ".bin",
    }

    # Directories where memory dumps may be placed
    MEMORY_LOCATIONS = [
        "",  # Evidence root
        "Memory",
        "RAM",
        "memory_captures",
        "volatility",
    ]

    MAX_DUMP_SIZE = 16 * 1024 * 1024 * 1024  # 16 GB safety limit
    CHUNK_SIZE = 4 * 1024 * 1024  # Read 4 MB at a time

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        # Build search patterns from signatures
        domain_patterns = []
        for sig in ALL_SIGNATURES:
            for domain in sig.domains:
                domain_patterns.append((domain.encode("ascii", errors="ignore"), sig.platform))

        api_key_pattern = re.compile(
            rb"(sk-[A-Za-z0-9]{20,}|"       # OpenAI API key
            rb"sk-ant-[A-Za-z0-9]{20,}|"     # Anthropic API key
            rb"AIza[A-Za-z0-9_-]{35})",        # Google API key
            re.ASCII,
        )

        model_strings = []
        for sig in ALL_SIGNATURES:
            for model, strings in sig.model_strings.items():
                for s in strings:
                    model_strings.append((s.encode("ascii", errors="ignore"), sig.platform, model))

        # Search memory dump files
        for mem_dir in self.MEMORY_LOCATIONS:
            search_dir = os.path.join(self.evidence_root, mem_dir) if mem_dir else self.evidence_root
            paths_searched.append(search_dir)
            if not os.path.isdir(search_dir):
                continue

            try:
                for fname in os.listdir(search_dir):
                    fpath = os.path.join(search_dir, fname)
                    if not os.path.isfile(fpath):
                        continue

                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in self.MEMORY_EXTENSIONS:
                        continue

                    try:
                        file_size = os.path.getsize(fpath)
                        if file_size > self.MAX_DUMP_SIZE:
                            errors.append(f"Skipping oversized dump: {fpath}")
                            continue
                    except OSError:
                        continue

                    paths_found.append(fpath)
                    dump_artifacts = self._scan_memory_dump(
                        fpath, file_size, domain_patterns, api_key_pattern,
                        model_strings, errors,
                    )
                    artifacts.extend(dump_artifacts)

            except OSError as e:
                errors.append(f"Error scanning {search_dir}: {e}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"Memory scan: {len(artifacts)} AI indicators from memory dumps",
        )

    def _scan_memory_dump(
        self,
        dump_path: str,
        file_size: int,
        domain_patterns: List,
        api_key_pattern: re.Pattern,
        model_strings: List,
        errors: List[str],
    ) -> List[ArtifactRecord]:
        """Scan a memory dump file for AI platform indicators."""
        artifacts: List[ArtifactRecord] = []
        found_domains: Set[str] = set()
        found_models: Set[str] = set()
        found_keys: List[str] = []

        try:
            ts = datetime.fromtimestamp(os.path.getmtime(dump_path), tz=timezone.utc)
        except OSError:
            ts = None

        try:
            with open(dump_path, "rb") as f:
                offset = 0
                while offset < file_size:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break

                    # Search for AI domains
                    for domain_bytes, platform in domain_patterns:
                        if domain_bytes in chunk:
                            domain_key = f"{platform.value}:{domain_bytes.decode('ascii', errors='replace')}"
                            if domain_key not in found_domains:
                                found_domains.add(domain_key)
                                artifacts.append(ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.NATIVE_APP,
                                    artifact_type="Memory AI Domain Reference",
                                    artifact_subtype="memory_domain",
                                    artifact_path=dump_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=ts,
                                    timestamp_type=TimestampType.MODIFIED,
                                    extracted_indicator=(
                                        f"AI domain in memory at ~offset {offset}: "
                                        f"{domain_bytes.decode('ascii', errors='replace')}"
                                    ),
                                    suspected_platform=platform,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.MODERATE,
                                    classification=EvidenceClassification.INFERRED,
                                    notes=(
                                        f"AI platform domain found in memory dump. "
                                        f"Memory residue indicates the platform was "
                                        f"accessed during this session."
                                    ),
                                ))

                    # Search for model strings
                    for model_bytes, platform, model in model_strings:
                        if model_bytes in chunk:
                            model_key = f"{model.value}"
                            if model_key not in found_models:
                                found_models.add(model_key)
                                artifacts.append(ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.NATIVE_APP,
                                    artifact_type="Memory AI Model Reference",
                                    artifact_subtype="memory_model",
                                    artifact_path=dump_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=ts,
                                    timestamp_type=TimestampType.MODIFIED,
                                    extracted_indicator=(
                                        f"AI model string in memory: "
                                        f"{model_bytes.decode('ascii', errors='replace')}"
                                    ),
                                    suspected_platform=platform,
                                    suspected_model=model,
                                    attribution_layer=AttributionLayer.MODEL,
                                    confidence=ConfidenceLevel.MODERATE,
                                    classification=EvidenceClassification.INFERRED,
                                    notes=(
                                        f"Model identifier {model.value} found in memory — "
                                        f"indicates specific model was used."
                                    ),
                                ))

                    # Search for API keys (redacted)
                    if len(found_keys) < 10:
                        for match in api_key_pattern.finditer(chunk):
                            key = match.group(0).decode("ascii", errors="replace")
                            redacted = key[:8] + "..." + key[-4:]
                            if redacted not in found_keys:
                                found_keys.append(redacted)
                                platform = AIPlatform.UNKNOWN
                                if key.startswith("sk-ant"):
                                    platform = AIPlatform.CLAUDE
                                elif key.startswith("sk-"):
                                    platform = AIPlatform.CHATGPT
                                elif key.startswith("AIza"):
                                    platform = AIPlatform.GEMINI

                                artifacts.append(ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.NATIVE_APP,
                                    artifact_type="Memory API Key Fragment",
                                    artifact_subtype="memory_api_key",
                                    artifact_path=dump_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=ts,
                                    timestamp_type=TimestampType.MODIFIED,
                                    extracted_indicator=f"API key in memory: {redacted}",
                                    suspected_platform=platform,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.HIGH,
                                    classification=EvidenceClassification.DIRECT,
                                    notes=(
                                        f"API key fragment found in memory dump. "
                                        f"Key redacted for security. Indicates "
                                        f"programmatic API access to AI platform."
                                    ),
                                ))

                    offset += len(chunk)

        except OSError as e:
            errors.append(f"Error reading memory dump {dump_path}: {e}")

        return artifacts


@register_parser
class PCAPScanner(BaseParser):
    """
    Scan PCAP/PCAPNG network captures for AI platform traffic.
    Addresses FR-1: Unified acquisition from network sources.

    Searches packet captures for:
    - DNS queries to AI platform domains
    - TLS SNI (Server Name Indication) for AI domains
    - HTTP Host headers referencing AI platforms
    - API request patterns to AI services
    """

    PARSER_NAME = "PCAPScanner"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Network Capture"

    PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

    PCAP_LOCATIONS = [
        "",
        "PCAP",
        "Network",
        "captures",
        "wireshark",
    ]

    # PCAP global header magic
    PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
    PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'
    PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

    MAX_PCAP_SIZE = 4 * 1024 * 1024 * 1024  # 4 GB
    CHUNK_SIZE = 4 * 1024 * 1024

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        # Build domain search patterns
        domain_patterns = []
        for sig in ALL_SIGNATURES:
            for domain in sig.domains:
                domain_patterns.append(
                    (domain.encode("ascii", errors="ignore"), sig.platform)
                )

        for pcap_dir in self.PCAP_LOCATIONS:
            search_dir = (
                os.path.join(self.evidence_root, pcap_dir)
                if pcap_dir else self.evidence_root
            )
            paths_searched.append(search_dir)
            if not os.path.isdir(search_dir):
                continue

            try:
                for fname in os.listdir(search_dir):
                    fpath = os.path.join(search_dir, fname)
                    if not os.path.isfile(fpath):
                        continue

                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in self.PCAP_EXTENSIONS:
                        continue

                    try:
                        file_size = os.path.getsize(fpath)
                        if file_size > self.MAX_PCAP_SIZE or file_size < 24:
                            continue
                    except OSError:
                        continue

                    # Verify PCAP header
                    try:
                        with open(fpath, "rb") as f:
                            magic = f.read(4)
                        if magic not in (self.PCAP_MAGIC, self.PCAP_MAGIC_BE, self.PCAPNG_MAGIC):
                            continue
                    except OSError:
                        continue

                    paths_found.append(fpath)
                    pcap_artifacts = self._scan_pcap(
                        fpath, file_size, domain_patterns, errors
                    )
                    artifacts.extend(pcap_artifacts)

            except OSError as e:
                errors.append(f"Error scanning {search_dir}: {e}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"PCAP scan: {len(artifacts)} AI network traffic indicators",
        )

    def _scan_pcap(
        self,
        pcap_path: str,
        file_size: int,
        domain_patterns: List,
        errors: List[str],
    ) -> List[ArtifactRecord]:
        """Scan a PCAP file for AI domain references."""
        artifacts: List[ArtifactRecord] = []
        found_domains: Set[str] = set()

        try:
            ts = datetime.fromtimestamp(os.path.getmtime(pcap_path), tz=timezone.utc)
        except OSError:
            ts = None

        try:
            with open(pcap_path, "rb") as f:
                offset = 0
                while offset < file_size:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break

                    for domain_bytes, platform in domain_patterns:
                        if domain_bytes in chunk:
                            domain_str = domain_bytes.decode("ascii", errors="replace")
                            domain_key = f"{platform.value}:{domain_str}"
                            if domain_key not in found_domains:
                                found_domains.add(domain_key)

                                # Try to determine if DNS, TLS SNI, or HTTP
                                context = "network traffic"
                                # Check for DNS query format (domain preceded by length bytes)
                                idx = chunk.find(domain_bytes)
                                if idx > 0 and chunk[idx - 1:idx] == bytes([len(domain_str.split(".")[0])]):
                                    context = "DNS query"
                                # Check for TLS SNI (preceded by 0x00 type byte)
                                elif idx > 2 and chunk[idx - 2:idx] == b'\x00\x00':
                                    context = "TLS SNI"

                                artifacts.append(ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.NATIVE_APP,
                                    artifact_type="Network AI Traffic",
                                    artifact_subtype="pcap_domain",
                                    artifact_path=pcap_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=ts,
                                    timestamp_type=TimestampType.MODIFIED,
                                    extracted_indicator=(
                                        f"AI domain in {context}: {domain_str}"
                                    ),
                                    suspected_platform=platform,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.HIGH,
                                    classification=EvidenceClassification.DIRECT,
                                    notes=(
                                        f"Network traffic to {domain_str} "
                                        f"({platform.value}) detected in PCAP. "
                                        f"Context: {context}."
                                    ),
                                ))

                    offset += len(chunk)

        except OSError as e:
            errors.append(f"Error reading PCAP {pcap_path}: {e}")

        return artifacts
