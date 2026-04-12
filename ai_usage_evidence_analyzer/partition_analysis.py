"""
Partition and filesystem health analysis.

Inspects raw evidence for partition table structures (MBR/GPT),
assesses filesystem health, and determines what access tiers
the evidence supports.  Results influence confidence ceilings
and caveat generation downstream.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import field
from datetime import datetime, timezone
from typing import BinaryIO, Dict, List, Optional, Tuple

from .models import (
    ConfidenceLevel,
    EvidenceAccessCapabilities,
    EvidenceAccessTier,
    FilesystemHealth,
    PartitionFinding,
    PartitionScheme,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MBR_SIGNATURE = b"\x55\xAA"
GPT_SIGNATURE = b"EFI PART"
GPT_HEADER_OFFSET = 512  # LBA 1
MBR_PARTITION_TABLE_OFFSET = 446
MBR_ENTRY_SIZE = 16
MBR_MAX_ENTRIES = 4

NTFS_MAGIC = b"NTFS    "
FAT32_MAGIC = b"FAT32   "
EXT_MAGIC = b"\x53\xef"  # ext2/3/4 at offset 0x438
HFS_MAGIC = b"H+\x00\x04"
APFS_MAGIC = b"NXSB"

KNOWN_FS_TYPES: Dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32MB",
    0x06: "FAT16",
    0x07: "NTFS/exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32",
    0x27: "WinRE",
    0x42: "Dynamic Disk",
    0x82: "Linux swap",
    0x83: "Linux",
    0x85: "Linux extended",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xAF: "HFS/HFS+",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System",
    0xFD: "Linux RAID",
}


# ---------------------------------------------------------------------------
# Partition Scanner
# ---------------------------------------------------------------------------

class PartitionScanner:
    """
    Detect partition scheme (MBR/GPT/hybrid) and enumerate partitions
    from a raw evidence stream.
    """

    def scan(self, stream: BinaryIO, evidence_id: str = "") -> List[PartitionFinding]:
        """Read partition structures and return findings."""
        findings: List[PartitionFinding] = []
        scheme = self._detect_scheme(stream)

        if scheme == PartitionScheme.GPT:
            findings = self._scan_gpt(stream, evidence_id)
        elif scheme in (PartitionScheme.MBR, PartitionScheme.HYBRID):
            findings = self._scan_mbr(stream, evidence_id)
        else:
            findings.append(PartitionFinding(
                evidence_id=evidence_id,
                partition_index=-1,
                scheme=PartitionScheme.NONE_DETECTED,
                offset=0,
                size_bytes=0,
                fs_type_label="unknown",
                health=FilesystemHealth.UNKNOWN,
                notes="No recognisable partition table found",
            ))

        logger.info(
            "Partition scan for %s: scheme=%s, %d finding(s)",
            evidence_id, scheme.value, len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    def _detect_scheme(self, stream: BinaryIO) -> PartitionScheme:
        stream.seek(510)
        sig = stream.read(2)
        has_mbr = sig == MBR_SIGNATURE

        stream.seek(GPT_HEADER_OFFSET)
        gpt_hdr = stream.read(8)
        has_gpt = gpt_hdr == GPT_SIGNATURE

        if has_gpt and has_mbr:
            return PartitionScheme.HYBRID
        if has_gpt:
            return PartitionScheme.GPT
        if has_mbr:
            return PartitionScheme.MBR
        return PartitionScheme.NONE_DETECTED

    # ------------------------------------------------------------------
    def _scan_mbr(self, stream: BinaryIO, evidence_id: str) -> List[PartitionFinding]:
        findings: List[PartitionFinding] = []
        stream.seek(MBR_PARTITION_TABLE_OFFSET)
        for i in range(MBR_MAX_ENTRIES):
            entry = stream.read(MBR_ENTRY_SIZE)
            if len(entry) < MBR_ENTRY_SIZE:
                break
            status = entry[0]
            ptype = entry[4]
            if ptype == 0x00:
                continue
            lba_start = struct.unpack_from("<I", entry, 8)[0]
            sector_count = struct.unpack_from("<I", entry, 12)[0]
            offset = lba_start * 512
            size = sector_count * 512
            fs_label = KNOWN_FS_TYPES.get(ptype, f"0x{ptype:02X}")
            health = self._quick_fs_check(stream, offset)

            findings.append(PartitionFinding(
                evidence_id=evidence_id,
                partition_index=i,
                scheme=PartitionScheme.MBR,
                offset=offset,
                size_bytes=size,
                fs_type_label=fs_label,
                health=health,
                notes=f"Status=0x{status:02X}, Type=0x{ptype:02X}",
            ))
        return findings

    # ------------------------------------------------------------------
    def _scan_gpt(self, stream: BinaryIO, evidence_id: str) -> List[PartitionFinding]:
        findings: List[PartitionFinding] = []
        stream.seek(GPT_HEADER_OFFSET)
        hdr = stream.read(92)
        if len(hdr) < 92:
            return findings
        try:
            entry_lba = struct.unpack_from("<Q", hdr, 72)[0]
            num_entries = struct.unpack_from("<I", hdr, 80)[0]
            entry_size = struct.unpack_from("<I", hdr, 84)[0]
        except struct.error:
            return findings

        stream.seek(entry_lba * 512)
        for i in range(min(num_entries, 128)):
            entry = stream.read(entry_size)
            if len(entry) < 128:
                break
            type_guid = entry[0:16]
            if type_guid == b"\x00" * 16:
                continue
            first_lba = struct.unpack_from("<Q", entry, 32)[0]
            last_lba = struct.unpack_from("<Q", entry, 40)[0]
            offset = first_lba * 512
            size = (last_lba - first_lba + 1) * 512
            name_raw = entry[56:128]
            name = name_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            health = self._quick_fs_check(stream, offset)

            findings.append(PartitionFinding(
                evidence_id=evidence_id,
                partition_index=i,
                scheme=PartitionScheme.GPT,
                offset=offset,
                size_bytes=size,
                fs_type_label=name or "GPT partition",
                health=health,
                notes="",
            ))
        return findings

    # ------------------------------------------------------------------
    def _quick_fs_check(self, stream: BinaryIO, offset: int) -> FilesystemHealth:
        """Peek at the first sector of a partition for known FS signatures."""
        try:
            stream.seek(offset)
            sector = stream.read(4096)
        except OSError:
            return FilesystemHealth.UNKNOWN

        if len(sector) < 512:
            return FilesystemHealth.UNKNOWN

        # NTFS: OEM ID at offset 3
        if sector[3:11] == NTFS_MAGIC:
            return FilesystemHealth.INTACT
        # FAT32: at offset 82
        if len(sector) > 90 and sector[82:90] == FAT32_MAGIC:
            return FilesystemHealth.INTACT
        # ext2/3/4: superblock at 0x438 relative to partition start (need 2 sectors)
        if len(sector) >= 0x43A:
            if sector[0x438:0x43A] == EXT_MAGIC:
                return FilesystemHealth.INTACT
        # HFS+
        if len(sector) >= 1028 and sector[1024:1028] == HFS_MAGIC:
            return FilesystemHealth.INTACT
        # APFS
        if sector[32:36] == APFS_MAGIC:
            return FilesystemHealth.INTACT

        # If we have MBR/GPT record but no recognisable FS magic
        return FilesystemHealth.DEGRADED


# ---------------------------------------------------------------------------
# Filesystem Health Assessor
# ---------------------------------------------------------------------------

class FilesystemHealthAssessor:
    """
    Aggregate partition findings into an overall filesystem health verdict
    and determine the evidence access tier.
    """

    def assess(
        self, findings: List[PartitionFinding]
    ) -> Tuple[FilesystemHealth, EvidenceAccessTier]:
        if not findings:
            return FilesystemHealth.UNKNOWN, EvidenceAccessTier.RAW_STREAM_ONLY

        healths = [f.health for f in findings]

        if all(h == FilesystemHealth.INTACT for h in healths):
            overall = FilesystemHealth.INTACT
            tier = EvidenceAccessTier.FULL_FORENSIC_ACCESS
        elif any(h == FilesystemHealth.INTACT for h in healths):
            overall = FilesystemHealth.DEGRADED
            tier = EvidenceAccessTier.PARTIAL_FILESYSTEM_ACCESS
        elif any(h == FilesystemHealth.DEGRADED for h in healths):
            overall = FilesystemHealth.PARTIALLY_READABLE
            tier = EvidenceAccessTier.PARTIAL_FILESYSTEM_ACCESS
        elif any(h == FilesystemHealth.CORRUPT for h in healths):
            overall = FilesystemHealth.CORRUPT
            tier = EvidenceAccessTier.RAW_STREAM_ONLY
        else:
            overall = FilesystemHealth.UNKNOWN
            tier = EvidenceAccessTier.RAW_STREAM_ONLY

        # Promote to CARVING_ONLY when no usable FS detected
        if tier == EvidenceAccessTier.RAW_STREAM_ONLY:
            has_scheme = any(
                f.scheme not in (PartitionScheme.NONE_DETECTED, PartitionScheme.UNKNOWN)
                for f in findings
            )
            if not has_scheme:
                overall = FilesystemHealth.CARVING_ONLY

        return overall, tier

    def build_capabilities(
        self,
        findings: List[PartitionFinding],
        health: FilesystemHealth,
        tier: EvidenceAccessTier,
    ) -> EvidenceAccessCapabilities:
        from .models import EvidenceAccessCapabilities
        limitations = self._health_caveats(health, tier)
        return EvidenceAccessCapabilities(
            access_tier=tier,
            has_raw_stream=tier in (
                EvidenceAccessTier.FULL_FORENSIC_ACCESS,
                EvidenceAccessTier.PARTIAL_FILESYSTEM_ACCESS,
                EvidenceAccessTier.RAW_STREAM_ONLY,
            ),
            limitations=limitations,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _health_caveats(health: FilesystemHealth, tier: EvidenceAccessTier) -> List[str]:
        caveats: List[str] = []
        if health == FilesystemHealth.DEGRADED:
            caveats.append("Filesystem shows signs of degradation; some metadata may be unreliable.")
        elif health == FilesystemHealth.PARTIALLY_READABLE:
            caveats.append("Only portions of the filesystem are readable; coverage is limited.")
        elif health == FilesystemHealth.CORRUPT:
            caveats.append("Filesystem is corrupt; only raw-stream carving is available.")
        elif health == FilesystemHealth.CARVING_ONLY:
            caveats.append("No recognisable filesystem detected; only signature carving is possible.")

        if tier == EvidenceAccessTier.RAW_STREAM_ONLY:
            caveats.append(
                "Evidence accessible only as a raw byte stream. "
                "Absence of artifacts cannot rule out AI usage."
            )
        return caveats
