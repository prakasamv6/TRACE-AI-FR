"""
E01 forensic image handling module.

Provides read-only access to E01 (Expert Witness Format) forensic images,
extracts metadata, detects partitions, and provides a file-access layer
for downstream parsers.

Uses pytsk3 for filesystem access and pyewf (libewf) for EWF container handling.
Falls back gracefully when libraries are unavailable — including a binary string
scanner that extracts AI-platform evidence directly from raw E01 bytes.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sqlite3
import struct
import tempfile
import time
import zlib
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Dict, Generator, List, Optional, Tuple

from .models import (
    AIPlatform,
    AIModel,
    AccessMode,
    ArtifactFamily,
    ArtifactRecord,
    EvidenceClassification,
    EvidenceImageInfo,
    EvidenceSourceClass,
    ImageType,
    OSPlatform,
    PartitionInfo,
    ProcessingLog,
    TimestampType,
)

logger = logging.getLogger(__name__)

# Attempt to import forensic libraries; degrade gracefully if absent
try:
    import pyewf  # type: ignore[import-not-found]
    HAS_PYEWF = True
except ImportError:
    HAS_PYEWF = False
    logger.debug("pyewf not available. E01 native parsing will be limited.")

try:
    import pytsk3  # type: ignore[import-not-found]
    HAS_PYTSK3 = True
except ImportError:
    HAS_PYTSK3 = False
    logger.debug("pytsk3 not available. Filesystem parsing will be limited.")


# ---------------------------------------------------------------------------
# EWF Handle Wrapper (for pytsk3 compatibility)
# ---------------------------------------------------------------------------

if HAS_PYEWF and HAS_PYTSK3:
    class EWFImgInfo(pytsk3.Img_Info):
        """pytsk3-compatible image handle wrapping a pyewf EWF file."""

        def __init__(self, ewf_handle: "pyewf.handle"):
            self._ewf_handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset: int, size: int) -> bytes:
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self) -> int:
            return self._ewf_handle.get_media_size()


# ---------------------------------------------------------------------------
# E01 Handler
# ---------------------------------------------------------------------------

class E01Handler:
    """
    Read-only handler for E01 forensic images.

    Workflow:
        1. Open the E01 file(s)
        2. Extract image-level metadata
        3. Detect partitions
        4. Provide file-listing and file-reading capabilities per partition
    """

    def __init__(self, e01_path: str):
        self.e01_path = os.path.abspath(e01_path)
        self.logs: List[ProcessingLog] = []
        self._ewf_handle = None
        self._img_info = None
        self._volume_system = None
        self._partitions: List[PartitionInfo] = []
        self._evidence_info = EvidenceImageInfo(image_path=self.e01_path)
        self._evidence_info.processing_start = datetime.utcnow()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def open(self) -> EvidenceImageInfo:
        """Open the E01 image in read-only mode and extract metadata."""
        self._log("INFO", "e01_handler", f"Opening E01 image: {self.e01_path}")

        if not os.path.isfile(self.e01_path):
            self._log("ERROR", "e01_handler", f"E01 file not found: {self.e01_path}")
            self._evidence_info.errors.append(f"File not found: {self.e01_path}")
            return self._evidence_info

        # Gather segment files (E01, E02, ... )
        segment_files = self._find_segment_files()
        self._log("INFO", "e01_handler", f"Found {len(segment_files)} segment file(s)")

        # File size
        self._evidence_info.image_size_bytes = sum(
            os.path.getsize(f) for f in segment_files
        )

        if HAS_PYEWF:
            self._open_pyewf(segment_files)
        else:
            self._log(
                "INFO", "e01_handler",
                "pyewf not installed — falling back to mounted-directory mode."
            )

        self._evidence_info.processing_end = datetime.utcnow()
        self._evidence_info.read_only = True
        return self._evidence_info

    def detect_partitions(self) -> List[PartitionInfo]:
        """Detect partitions within the image."""
        if not HAS_PYTSK3 or self._img_info is None:
            self._log(
                "DEBUG", "e01_handler",
                "pytsk3 not available — partition detection skipped."
            )
            return []

        try:
            self._volume_system = pytsk3.Volume_Info(self._img_info)
            idx = 0
            for part in self._volume_system:
                pi = PartitionInfo(
                    index=idx,
                    description=part.desc.decode("utf-8", errors="replace") if part.desc else "",
                    type_desc=str(part.type),
                    offset=part.start * 512,
                    length=part.len * 512,
                    accessible=bool(part.len > 0 and part.type not in (
                        pytsk3.TSK_VS_PART_FLAG_META,
                        pytsk3.TSK_VS_PART_FLAG_UNALLOC,
                    )),
                )
                self._partitions.append(pi)
                idx += 1

            self._evidence_info.partitions = self._partitions
            self._log(
                "INFO", "e01_handler",
                f"Detected {len(self._partitions)} partition(s)"
            )
        except Exception as exc:
            # May be a logical image without a volume system
            self._log(
                "WARNING", "e01_handler",
                f"Volume system detection failed (may be a logical image): {exc}"
            )
            # Try treating the whole image as a single filesystem
            try:
                fs = pytsk3.FS_Info(self._img_info, offset=0)
                pi = PartitionInfo(
                    index=0,
                    description="Logical Image / Single Filesystem",
                    offset=0,
                    length=self._img_info.get_size() if hasattr(self._img_info, 'get_size') else 0,
                    accessible=True,
                    filesystem=str(fs.info.ftype) if hasattr(fs, 'info') else "Unknown",
                )
                self._partitions.append(pi)
                self._evidence_info.partitions = self._partitions
                self._evidence_info.image_type = ImageType.LOGICAL
                self._log("INFO", "e01_handler", "Treated as logical image with single filesystem")
            except Exception as exc2:
                self._log("ERROR", "e01_handler", f"Filesystem detection also failed: {exc2}")
                self._evidence_info.errors.append(f"Partition/filesystem detection failed: {exc2}")

        return self._partitions

    def open_filesystem(self, partition_offset: int = 0) -> Optional["pytsk3.FS_Info"]:
        """Open a filesystem at the given byte offset."""
        if not HAS_PYTSK3 or self._img_info is None:
            return None
        try:
            fs = pytsk3.FS_Info(self._img_info, offset=partition_offset)
            return fs
        except Exception as exc:
            self._log("ERROR", "e01_handler", f"Cannot open filesystem at offset {partition_offset}: {exc}")
            return None

    def list_directory(self, fs: "pytsk3.FS_Info", path: str = "/") -> List[Dict]:
        """List directory contents in a filesystem."""
        entries = []
        try:
            directory = fs.open_dir(path=path)
            for entry in directory:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                entry_info = {
                    "name": name,
                    "path": f"{path.rstrip('/')}/{name}",
                    "type": "dir" if entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR else "file",
                    "size": entry.info.meta.size if entry.info.meta else 0,
                }
                if entry.info.meta:
                    entry_info["created"] = entry.info.meta.crtime
                    entry_info["modified"] = entry.info.meta.mtime
                    entry_info["accessed"] = entry.info.meta.atime
                entries.append(entry_info)
        except Exception as exc:
            self._log("WARNING", "e01_handler", f"Cannot list directory '{path}': {exc}")
        return entries

    def read_file(self, fs: "pytsk3.FS_Info", path: str) -> Optional[bytes]:
        """Read a file from the filesystem (read-only)."""
        try:
            f = fs.open(path)
            size = f.info.meta.size
            data = f.read_random(0, size)
            return data
        except Exception as exc:
            self._log("WARNING", "e01_handler", f"Cannot read file '{path}': {exc}")
            return None

    def walk_directory(
        self, fs: "pytsk3.FS_Info", path: str = "/", max_depth: int = 10
    ) -> Generator[Dict, None, None]:
        """Recursively walk a directory tree in the filesystem."""
        if max_depth <= 0:
            return
        try:
            directory = fs.open_dir(path=path)
            for entry in directory:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                full_path = f"{path.rstrip('/')}/{name}"
                is_dir = entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR
                yield {
                    "name": name,
                    "path": full_path,
                    "type": "dir" if is_dir else "file",
                    "size": entry.info.meta.size if entry.info.meta else 0,
                }
                if is_dir:
                    yield from self.walk_directory(fs, full_path, max_depth - 1)
        except Exception:
            pass  # silently skip unreadable dirs in walk

    def compute_hash(self, algorithm: str = "md5") -> Optional[str]:
        """Compute hash of the E01 container file itself."""
        try:
            h = hashlib.new(algorithm)
            with open(self.e01_path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as exc:
            self._log("WARNING", "e01_handler", f"Hash computation failed: {exc}")
            return None

    def close(self):
        """Close all handles."""
        if self._ewf_handle and HAS_PYEWF:
            try:
                self._ewf_handle.close()
            except Exception:
                pass
        self._ewf_handle = None
        self._img_info = None

    def get_logs(self) -> List[ProcessingLog]:
        return list(self.logs)

    @property
    def evidence_info(self) -> EvidenceImageInfo:
        return self._evidence_info

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _find_segment_files(self) -> List[str]:
        """Find all EWF segment files (E01, E02, ..., EAA, etc.)."""
        base = Path(self.e01_path)
        parent = base.parent
        stem = base.stem
        segments = sorted(
            str(p)
            for p in parent.glob(f"{stem}.*")
            if p.suffix.lower().startswith(".e")
        )
        if not segments:
            segments = [self.e01_path]
        return segments

    def _open_pyewf(self, segment_files: List[str]):
        """Open with pyewf library."""
        try:
            filenames = pyewf.glob(self.e01_path) if hasattr(pyewf, 'glob') else segment_files
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(filenames)

            # Extract EWF metadata
            meta = {}
            for attr_name in [
                "media_size", "bytes_per_sector", "number_of_sectors",
                "format_version", "compression_method",
            ]:
                try:
                    val = getattr(self._ewf_handle, f"get_{attr_name}", lambda: None)()
                    if val is not None:
                        meta[attr_name] = str(val)
                except Exception:
                    pass

            # Try to get header values
            for hv in [
                "case_number", "description", "examiner_name",
                "evidence_number", "notes", "acquiry_date",
                "system_date", "acquiry_operating_system",
                "acquiry_software", "acquiry_software_version",
                "model", "serial_number",
            ]:
                try:
                    val = self._ewf_handle.get_header_value(hv)
                    if val:
                        meta[hv] = val
                except Exception:
                    pass

            self._evidence_info.ewf_metadata = meta
            self._log("INFO", "e01_handler", f"EWF metadata extracted: {len(meta)} fields")

            # Build pytsk3-compatible handle
            if HAS_PYTSK3:
                self._img_info = EWFImgInfo(self._ewf_handle)
                self._log("INFO", "e01_handler", "pytsk3 image handle created successfully")

        except Exception as exc:
            self._log("ERROR", "e01_handler", f"Failed to open E01 with pyewf: {exc}")
            self._evidence_info.errors.append(f"pyewf open failed: {exc}")

    def _log(self, level: str, module: str, message: str):
        entry = ProcessingLog(
            timestamp=datetime.utcnow(),
            level=level,
            module=module,
            message=message,
        )
        self.logs.append(entry)
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{module}] {message}")


# ---------------------------------------------------------------------------
# Mounted Directory Handler (alternative input mode)
# ---------------------------------------------------------------------------

class MountedEvidenceHandler:
    """
    Handler for pre-mounted or pre-extracted evidence directories.

    Used when:
    - The E01 has already been mounted externally
    - KAPE output folders are supplied
    - Exported artifact directories are provided for re-analysis
    """

    def __init__(self, evidence_dir: str, source_label: str = "Mounted Evidence"):
        self.evidence_dir = os.path.abspath(evidence_dir)
        self.source_label = source_label
        self.logs: List[ProcessingLog] = []

    def validate(self) -> bool:
        """Check that the directory exists and is accessible."""
        if not os.path.isdir(self.evidence_dir):
            self._log("ERROR", "mounted_handler", f"Directory not found: {self.evidence_dir}")
            return False
        self._log("INFO", "mounted_handler", f"Evidence directory validated: {self.evidence_dir}")
        return True

    def detect_os_platform(self) -> OSPlatform:
        """Heuristically detect the OS from directory structure."""
        # Windows indicators
        win_indicators = [
            "Windows", "Users", "ProgramData", "Program Files",
            "System32", "AppData",
        ]
        # macOS indicators
        mac_indicators = [
            "Library", "Applications", "System", "private/var",
            ".DS_Store",
        ]
        # iPhone logical indicators
        iphone_indicators = [
            "HomeDomain", "AppDomain", "MediaDomain",
            "CameraRollDomain",
        ]

        top_level = set()
        try:
            for item in os.listdir(self.evidence_dir):
                top_level.add(item)
        except OSError:
            return OSPlatform.UNKNOWN

        win_score = sum(1 for i in win_indicators if i in top_level)
        mac_score = sum(1 for i in mac_indicators if i in top_level)
        iphone_score = sum(1 for i in iphone_indicators if i in top_level)

        if iphone_score > 0 and iphone_score >= mac_score:
            return OSPlatform.IPHONE
        if mac_score > win_score:
            return OSPlatform.MACOS
        if win_score > 0:
            return OSPlatform.WINDOWS
        return OSPlatform.UNKNOWN

    def find_user_profiles(self) -> List[str]:
        """Find user profile directories."""
        profiles = []
        # Windows: Users/*
        users_dir = os.path.join(self.evidence_dir, "Users")
        if os.path.isdir(users_dir):
            for item in os.listdir(users_dir):
                if item.lower() not in (
                    "default", "default user", "public", "all users",
                    ".net v4.5", ".net v4.5 classic",
                ):
                    full = os.path.join(users_dir, item)
                    if os.path.isdir(full):
                        profiles.append(item)

        # macOS: Users/*
        if not profiles:
            for item in os.listdir(self.evidence_dir):
                if item == "Users" and os.path.isdir(os.path.join(self.evidence_dir, item)):
                    for user in os.listdir(os.path.join(self.evidence_dir, item)):
                        if user.lower() not in ("shared", ".localized", "guest"):
                            full = os.path.join(self.evidence_dir, "Users", user)
                            if os.path.isdir(full):
                                profiles.append(user)

        return profiles

    def find_file(self, relative_path: str) -> Optional[str]:
        """Find a file relative to the evidence root."""
        full = os.path.join(self.evidence_dir, relative_path)
        if os.path.isfile(full):
            return full
        return None

    def walk(self, subdir: str = "") -> Generator[Tuple[str, List[str], List[str]], None, None]:
        """Walk the evidence directory tree."""
        root = os.path.join(self.evidence_dir, subdir) if subdir else self.evidence_dir
        if os.path.isdir(root):
            yield from os.walk(root)

    def get_logs(self) -> List[ProcessingLog]:
        return list(self.logs)

    def _log(self, level: str, module: str, message: str):
        entry = ProcessingLog(
            timestamp=datetime.utcnow(),
            level=level,
            module=module,
            message=message,
        )
        self.logs.append(entry)


# ---------------------------------------------------------------------------
# E01 Binary Scanner — fallback when pyewf/pytsk3 are unavailable
# ---------------------------------------------------------------------------

class E01BinaryScanner:
    """
    Scan raw E01 file bytes for AI-platform evidence strings.

    EWF stores data in zlib-compressed chunks. This scanner:
      1. Reads the raw file in large blocks
      2. Attempts zlib decompression on each EWF data chunk
      3. Falls back to scanning raw bytes (some strings survive compression)
      4. Extracts URLs, cookie domains, filenames, and model strings
      5. Carves embedded SQLite databases when headers are found
      6. Returns ArtifactRecord objects for every AI-platform match

    This is a best-effort approach that works on most commercial E01 images.
    """

    # EWF section signatures
    _EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
    _EWF2_SIGNATURE = b"EVF2\r\n\x81\x00"
    _SQLITE_HEADER = b"SQLite format 3\x00"

    # Chunk size for reading (4 MB)
    CHUNK_SIZE = 4 * 1024 * 1024

    def __init__(self, e01_path: str, source_image: str = "",
                 case_id: str = "", evidence_item_id: str = ""):
        self.e01_path = os.path.abspath(e01_path)
        self.source_image = source_image or f"E01:{os.path.basename(e01_path)}"
        self.case_id = case_id
        self.evidence_item_id = evidence_item_id
        self.logs: List[ProcessingLog] = []
        self._seen_indicators: set = set()  # deduplication

        # Import signatures lazily to avoid circular imports at module level
        from .signatures import ALL_SIGNATURES
        self._signatures = ALL_SIGNATURES

    def scan(self) -> List[ArtifactRecord]:
        """Scan the E01 file and return found artifacts."""
        import time
        self._log("INFO", "e01_scanner",
                  f"Starting binary scan of E01: {self.e01_path} "
                  f"({os.path.getsize(self.e01_path) / (1024*1024):.1f} MB)")

        artifacts: List[ArtifactRecord] = []
        decompressed_pool = bytearray()
        scan_start = time.monotonic()
        MAX_SCAN_TIME = 60.0  # 60-second overall cap

        try:
            file_size = os.path.getsize(self.e01_path)
            bytes_read = 0

            with open(self.e01_path, "rb") as f:
                while True:
                    if time.monotonic() - scan_start > MAX_SCAN_TIME:
                        self._log("WARNING", "e01_scanner",
                                  "Scan time limit reached; finishing early")
                        break

                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    bytes_read += len(chunk)

                    # 1. Try to find and decompress zlib streams in the chunk
                    decompressed = self._decompress_zlib_streams(chunk)
                    if decompressed:
                        decompressed_pool.extend(decompressed)
                        # Scan decompressed data for AI indicators
                        arts = self._scan_bytes_for_indicators(
                            decompressed, "decompressed_ewf_data")
                        artifacts.extend(arts)

                        # Look for embedded SQLite DBs in decompressed data
                        arts = self._carve_sqlite_databases(decompressed)
                        artifacts.extend(arts)

                    # 2. Also scan raw chunk (some strings survive or are in
                    #    EWF headers/metadata regions)
                    arts = self._scan_bytes_for_indicators(chunk, "raw_ewf_data")
                    artifacts.extend(arts)

                    progress_pct = (bytes_read / file_size * 100) if file_size else 0
                    if bytes_read % (20 * 1024 * 1024) == 0 or bytes_read >= file_size:
                        self._log("INFO", "e01_scanner",
                                  f"Scan progress: {progress_pct:.0f}% "
                                  f"({bytes_read/(1024*1024):.0f} MB / "
                                  f"{file_size/(1024*1024):.0f} MB) — "
                                  f"{len(artifacts)} artifacts found so far")

        except Exception as exc:
            self._log("ERROR", "e01_scanner", f"Binary scan error: {exc}")

        self._log("INFO", "e01_scanner",
                  f"Binary scan complete: {len(artifacts)} artifacts extracted")
        return artifacts

    # Limits to prevent hangs on large E01 files
    _MAX_ZLIB_ATTEMPTS = 50  # max decompression tries per chunk
    _MAX_DECOMPRESSED_SIZE = 8 * 1024 * 1024  # 8 MB cap per chunk
    _ZLIB_CHUNK_TIMEOUT = 5.0  # seconds per chunk

    def _decompress_zlib_streams(self, data: bytes) -> bytes:
        """Find and decompress zlib-compressed streams in the data."""
        import time
        result = bytearray()

        # zlib streams typically start with 0x78 (deflate)
        # Common zlib headers: 78 01, 78 5E, 78 9C, 78 DA
        valid_second_bytes = frozenset((0x01, 0x5E, 0x9C, 0xDA))
        offset = 0
        attempts = 0
        t_start = time.monotonic()

        while offset < len(data) - 2:
            # Enforce limits to avoid hangs
            if attempts >= self._MAX_ZLIB_ATTEMPTS:
                break
            if len(result) >= self._MAX_DECOMPRESSED_SIZE:
                break
            if time.monotonic() - t_start > self._ZLIB_CHUNK_TIMEOUT:
                break

            idx = data.find(b"\x78", offset)
            if idx == -1 or idx + 1 >= len(data):
                break
            # Check for valid zlib header
            if data[idx + 1] in valid_second_bytes:
                attempts += 1
                try:
                    decompressed = zlib.decompress(data[idx:idx + 65536])
                    result.extend(decompressed)
                except (zlib.error, Exception):
                    pass
            offset = idx + 1

        return bytes(result)

    def _scan_bytes_for_indicators(self, data: bytes,
                                    source_label: str) -> List[ArtifactRecord]:
        """Scan a byte buffer for AI platform indicators."""
        artifacts: List[ArtifactRecord] = []

        # Decode to string for regex matching (latin-1 preserves all bytes)
        try:
            text = data.decode("latin-1")
        except Exception:
            return artifacts

        for sig in self._signatures:
            # Scan for domain matches (most reliable indicator)
            for domain in sig.domains:
                # Look for the domain in URLs or as standalone reference
                pattern = re.escape(domain)
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    indicator = domain
                    dedup_key = (sig.platform.value, "domain", domain)
                    if dedup_key in self._seen_indicators:
                        continue
                    self._seen_indicators.add(dedup_key)

                    # Try to extract the full URL around the match
                    url_start = max(0, m.start() - 200)
                    url_end = min(len(text), m.end() + 500)
                    context = text[url_start:url_end]
                    url_match = re.search(
                        r"https?://[^\s\"'<>\x00-\x1f]{5,500}", context)
                    if url_match:
                        indicator = url_match.group(0)

                    art = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        artifact_family=ArtifactFamily.BROWSER_HISTORY,
                        artifact_type="URL Reference",
                        artifact_subtype="E01 Binary Scan",
                        artifact_path=f"{self.source_image}:{source_label}",
                        parser_used="E01BinaryScanner",
                        extracted_indicator=indicator,
                        suspected_platform=sig.platform,
                        classification=EvidenceClassification.DIRECT,
                        notes=f"Domain '{domain}' found in E01 binary scan",
                    )
                    artifacts.append(art)

            # Scan for cookie domain patterns
            for cookie_domain in sig.cookie_domains:
                pattern = re.escape(cookie_domain)
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    dedup_key = (sig.platform.value, "cookie", cookie_domain)
                    if dedup_key in self._seen_indicators:
                        continue
                    self._seen_indicators.add(dedup_key)

                    art = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        artifact_family=ArtifactFamily.BROWSER_COOKIES,
                        artifact_type="Cookie Domain Reference",
                        artifact_subtype="E01 Binary Scan",
                        artifact_path=f"{self.source_image}:{source_label}",
                        parser_used="E01BinaryScanner",
                        extracted_indicator=cookie_domain,
                        suspected_platform=sig.platform,
                        classification=EvidenceClassification.INFERRED,
                        notes=f"Cookie domain '{cookie_domain}' in E01 scan",
                    )
                    artifacts.append(art)

            # Scan for model strings (strong evidence)
            for model_enum, model_strs in sig.model_strings.items():
                for model_str in model_strs:
                    if len(model_str) < 4:
                        continue
                    pattern = re.escape(model_str)
                    for m in re.finditer(pattern, text, re.IGNORECASE):
                        dedup_key = (sig.platform.value, "model", model_str)
                        if dedup_key in self._seen_indicators:
                            continue
                        self._seen_indicators.add(dedup_key)

                        art = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            artifact_family=ArtifactFamily.BROWSER_LOCAL_STORAGE,
                            artifact_type="AI Model Reference",
                            artifact_subtype="E01 Binary Scan",
                            artifact_path=f"{self.source_image}:{source_label}",
                            parser_used="E01BinaryScanner",
                            extracted_indicator=model_str,
                            suspected_platform=sig.platform,
                            suspected_model=model_enum,
                            classification=EvidenceClassification.DIRECT,
                            notes=f"Model string '{model_str}' found in E01",
                        )
                        artifacts.append(art)

            # Scan for local storage keys / app identifiers
            for key in sig.local_storage_keys:
                if len(key) < 4:
                    continue
                pattern = re.escape(key)
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    dedup_key = (sig.platform.value, "ls_key", key)
                    if dedup_key in self._seen_indicators:
                        continue
                    self._seen_indicators.add(dedup_key)

                    art = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        artifact_family=ArtifactFamily.BROWSER_LOCAL_STORAGE,
                        artifact_type="Local Storage Key",
                        artifact_subtype="E01 Binary Scan",
                        artifact_path=f"{self.source_image}:{source_label}",
                        parser_used="E01BinaryScanner",
                        extracted_indicator=key,
                        suspected_platform=sig.platform,
                        classification=EvidenceClassification.INFERRED,
                        notes=f"LocalStorage key '{key}' found in E01 scan",
                    )
                    artifacts.append(art)

            # Scan for app process / executable names
            for proc in sig.process_names:
                if len(proc) < 5:
                    continue
                pattern = re.escape(proc)
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    dedup_key = (sig.platform.value, "process", proc)
                    if dedup_key in self._seen_indicators:
                        continue
                    self._seen_indicators.add(dedup_key)

                    art = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        artifact_family=ArtifactFamily.OS_EXECUTION,
                        artifact_type="Process/App Reference",
                        artifact_subtype="E01 Binary Scan",
                        artifact_path=f"{self.source_image}:{source_label}",
                        parser_used="E01BinaryScanner",
                        extracted_indicator=proc,
                        suspected_platform=sig.platform,
                        classification=EvidenceClassification.INFERRED,
                        notes=f"Process name '{proc}' found in E01 scan",
                    )
                    artifacts.append(art)

        return artifacts

    def _carve_sqlite_databases(self, data: bytes) -> List[ArtifactRecord]:
        """Attempt to carve SQLite databases from decompressed data."""
        artifacts: List[ArtifactRecord] = []
        offset = 0

        while offset < len(data):
            idx = data.find(self._SQLITE_HEADER, offset)
            if idx == -1:
                break

            # Try to extract a reasonable chunk as SQLite DB
            # SQLite page size is at offset 16: 2 bytes big-endian
            try:
                if idx + 100 < len(data):
                    page_size_raw = data[idx + 16:idx + 18]
                    page_size = int.from_bytes(page_size_raw, "big")
                    if page_size == 1:
                        page_size = 65536
                    if 512 <= page_size <= 65536:
                        # Extract up to 2MB or end of data
                        db_end = min(idx + 2 * 1024 * 1024, len(data))
                        db_data = data[idx:db_end]

                        arts = self._analyze_sqlite_bytes(db_data)
                        artifacts.extend(arts)
            except Exception:
                pass

            offset = idx + 100  # skip past this header

        return artifacts

    def _analyze_sqlite_bytes(self, db_data: bytes) -> List[ArtifactRecord]:
        """Write SQLite bytes to temp file and query for AI indicators."""
        artifacts: List[ArtifactRecord] = []
        tmp_path = None

        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".sqlite", prefix="e01_carved_")
            os.close(fd)
            with open(tmp_path, "wb") as f:
                f.write(db_data)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            conn.execute("PRAGMA journal_mode=OFF")

            # Get table names
            tables = [row[0] for row in
                      conn.execute(
                          "SELECT name FROM sqlite_master "
                          "WHERE type='table'").fetchall()]

            # Known Chrome/browser tables
            if "urls" in tables:
                arts = self._scan_chrome_history(conn)
                artifacts.extend(arts)
            if "cookies" in tables:
                arts = self._scan_chrome_cookies(conn)
                artifacts.extend(arts)
            if "downloads" in tables:
                arts = self._scan_chrome_downloads(conn)
                artifacts.extend(arts)

            # Generic: scan all text columns for AI platform references
            if not artifacts:
                arts = self._scan_generic_tables(conn, tables)
                artifacts.extend(arts)

            conn.close()
        except Exception:
            pass
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return artifacts

    def _scan_chrome_history(self, conn: sqlite3.Connection) -> List[ArtifactRecord]:
        """Query carved Chrome History database for AI URLs."""
        artifacts: List[ArtifactRecord] = []
        from .signatures import ALL_SIGNATURES, DOMAIN_TO_PLATFORM

        try:
            rows = conn.execute(
                "SELECT url, title, visit_count, last_visit_time "
                "FROM urls ORDER BY last_visit_time DESC LIMIT 5000"
            ).fetchall()
        except Exception:
            return artifacts

        for url, title, visit_count, last_visit_time in rows:
            if not url:
                continue
            for domain, platform in DOMAIN_TO_PLATFORM.items():
                if domain in url.lower():
                    dedup_key = ("carved_history", url)
                    if dedup_key in self._seen_indicators:
                        continue
                    self._seen_indicators.add(dedup_key)

                    ts = None
                    if last_visit_time and last_visit_time > 11644473600000000:
                        try:
                            epoch = (last_visit_time - 11644473600000000) / 1_000_000
                            ts = datetime.utcfromtimestamp(epoch)
                        except (ValueError, OSError):
                            pass

                    art = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        artifact_family=ArtifactFamily.BROWSER_HISTORY,
                        artifact_type="Browser History",
                        artifact_subtype="Carved SQLite from E01",
                        artifact_path=f"{self.source_image}:carved_history_db",
                        parser_used="E01BinaryScanner.carved_history",
                        timestamp=ts,
                        timestamp_type=TimestampType.LAST_VISITED,
                        extracted_indicator=url,
                        suspected_platform=platform,
                        classification=EvidenceClassification.DIRECT,
                        notes=f"URL '{url}' (title: {title or 'N/A'}) "
                              f"found in carved Chrome History DB from E01",
                    )
                    artifacts.append(art)
                    break

        return artifacts

    def _scan_chrome_cookies(self, conn: sqlite3.Connection) -> List[ArtifactRecord]:
        """Query carved Chrome Cookies database for AI cookie domains."""
        artifacts: List[ArtifactRecord] = []
        from .signatures import ALL_SIGNATURES

        try:
            rows = conn.execute(
                "SELECT host_key, name, creation_utc, last_access_utc "
                "FROM cookies LIMIT 5000"
            ).fetchall()
        except Exception:
            return artifacts

        for host_key, name, creation_utc, last_access_utc in rows:
            if not host_key:
                continue
            for sig in ALL_SIGNATURES:
                for cookie_domain in sig.cookie_domains:
                    if cookie_domain in host_key.lower():
                        dedup_key = ("carved_cookie", host_key, name)
                        if dedup_key in self._seen_indicators:
                            continue
                        self._seen_indicators.add(dedup_key)

                        ts = None
                        ts_val = last_access_utc or creation_utc
                        if ts_val and ts_val > 11644473600000000:
                            try:
                                epoch = (ts_val - 11644473600000000) / 1_000_000
                                ts = datetime.utcfromtimestamp(epoch)
                            except (ValueError, OSError):
                                pass

                        art = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            artifact_family=ArtifactFamily.BROWSER_COOKIES,
                            artifact_type="Browser Cookie",
                            artifact_subtype="Carved SQLite from E01",
                            artifact_path=f"{self.source_image}:carved_cookies_db",
                            parser_used="E01BinaryScanner.carved_cookies",
                            timestamp=ts,
                            extracted_indicator=f"{host_key} ({name})",
                            suspected_platform=sig.platform,
                            classification=EvidenceClassification.DIRECT,
                            notes=f"Cookie for '{host_key}' carved from E01",
                        )
                        artifacts.append(art)
                        break

        return artifacts

    def _scan_chrome_downloads(self, conn: sqlite3.Connection) -> List[ArtifactRecord]:
        """Query carved Chrome Downloads database for AI downloads."""
        artifacts: List[ArtifactRecord] = []
        from .signatures import ALL_SIGNATURES

        try:
            rows = conn.execute(
                "SELECT target_path, tab_url, start_time "
                "FROM downloads LIMIT 5000"
            ).fetchall()
        except Exception:
            return artifacts

        for target_path, tab_url, start_time in rows:
            combined = f"{target_path or ''} {tab_url or ''}"
            for sig in ALL_SIGNATURES:
                for domain in sig.domains:
                    if domain in combined.lower():
                        dedup_key = ("carved_download", target_path, tab_url)
                        if dedup_key in self._seen_indicators:
                            continue
                        self._seen_indicators.add(dedup_key)

                        art = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            artifact_family=ArtifactFamily.BROWSER_DOWNLOADS,
                            artifact_type="Browser Download",
                            artifact_subtype="Carved SQLite from E01",
                            artifact_path=f"{self.source_image}:carved_downloads_db",
                            parser_used="E01BinaryScanner.carved_downloads",
                            extracted_indicator=f"{target_path or tab_url}",
                            suspected_platform=sig.platform,
                            classification=EvidenceClassification.DIRECT,
                            notes=f"Download from '{domain}' carved from E01",
                        )
                        artifacts.append(art)
                        break

        return artifacts

    def _scan_generic_tables(self, conn: sqlite3.Connection,
                              tables: List[str]) -> List[ArtifactRecord]:
        """Scan all text columns in unknown tables for AI references."""
        artifacts: List[ArtifactRecord] = []
        from .signatures import ALL_SIGNATURES

        for table in tables[:20]:
            try:
                rows = conn.execute(
                    f'SELECT * FROM "{table}" LIMIT 200').fetchall()
                for row in rows:
                    for cell in row:
                        if not isinstance(cell, str) or len(cell) < 6:
                            continue
                        cell_lower = cell.lower()
                        for sig in ALL_SIGNATURES:
                            for domain in sig.domains:
                                if domain in cell_lower:
                                    dedup_key = ("carved_generic", table, cell[:100])
                                    if dedup_key in self._seen_indicators:
                                        continue
                                    self._seen_indicators.add(dedup_key)

                                    art = ArtifactRecord(
                                        case_id=self.case_id,
                                        evidence_item_id=self.evidence_item_id,
                                        source_image=self.source_image,
                                        artifact_family=ArtifactFamily.UNKNOWN,
                                        artifact_type="Database Reference",
                                        artifact_subtype=f"Carved table: {table}",
                                        artifact_path=f"{self.source_image}:carved_{table}",
                                        parser_used="E01BinaryScanner.generic",
                                        extracted_indicator=cell[:500],
                                        suspected_platform=sig.platform,
                                        classification=EvidenceClassification.INFERRED,
                                        notes=f"AI reference in carved DB table '{table}'",
                                    )
                                    artifacts.append(art)
                                    break
            except Exception:
                continue

        return artifacts

    def get_logs(self) -> List[ProcessingLog]:
        return list(self.logs)

    def _log(self, level: str, module: str, message: str):
        entry = ProcessingLog(
            timestamp=datetime.utcnow(),
            level=level,
            module=module,
            message=message,
        )
        self.logs.append(entry)
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{module}] {message}")