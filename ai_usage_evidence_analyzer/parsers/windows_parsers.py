"""
Windows artifact parsers.

Parses Windows-specific forensic artifacts including:
- Prefetch
- AmCache
- UserAssist
- Jump Lists
- LNK files
- RecentDocs / OpenSaveMRU / LastVisitedMRU
- Registry hives
- Recycle Bin metadata
"""

from __future__ import annotations

import os
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..models import (
    AccessMode,
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
from ..signatures import ALL_SIGNATURES, match_domain, match_model_string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if not ft or ft <= 0:
        return None
    try:
        return WINDOWS_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def scan_binary_for_ai_strings(data: bytes) -> List[Dict]:
    """
    Scan binary data for AI-related strings.
    Returns list of {platform, matched_string, offset}.
    """
    results = []
    # Decode as UTF-8 and UTF-16LE
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = data.decode(encoding, errors="replace")
        except Exception:
            continue

        for sig in ALL_SIGNATURES:
            for domain in sig.domains:
                idx = text.lower().find(domain.lower())
                if idx >= 0:
                    context_start = max(0, idx - 50)
                    context_end = min(len(text), idx + len(domain) + 100)
                    context = text[context_start:context_end].strip()
                    results.append({
                        "platform": sig.platform,
                        "matched_string": domain,
                        "context": context[:200],
                    })

            for app_name in sig.app_names_windows:
                if app_name.lower() in text.lower():
                    results.append({
                        "platform": sig.platform,
                        "matched_string": app_name,
                        "context": f"App name match: {app_name}",
                    })

            for proc in sig.process_names:
                if proc.lower() in text.lower():
                    results.append({
                        "platform": sig.platform,
                        "matched_string": proc,
                        "context": f"Process name match: {proc}",
                    })

    return results


# ---------------------------------------------------------------------------
# Prefetch Parser
# ---------------------------------------------------------------------------

@register_parser
class PrefetchParser(BaseParser):
    """Parse Windows Prefetch files for AI application execution evidence."""

    PARSER_NAME = "WindowsPrefetchParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "OS Execution Trace"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        prefetch_dir = os.path.join(self.evidence_root, "Windows", "Prefetch")
        paths_searched.append(prefetch_dir)

        if not os.path.isdir(prefetch_dir):
            paths_missing.append(prefetch_dir)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Prefetch directory not found.",
            )

        paths_found.append(prefetch_dir)

        # Known prefetch names for AI apps
        ai_prefetch_names = []
        for sig in ALL_SIGNATURES:
            for pf in sig.prefetch_names:
                ai_prefetch_names.append((pf.upper(), sig.platform))

        # Also check for browsers (used to access AI tools)
        browser_prefetch = [
            ("CHROME.EXE", "Chrome"),
            ("MSEDGE.EXE", "Edge"),
            ("FIREFOX.EXE", "Firefox"),
            ("BRAVE.EXE", "Brave"),
        ]

        for fname in os.listdir(prefetch_dir):
            if not fname.upper().endswith(".PF"):
                continue

            fpath = os.path.join(prefetch_dir, fname)
            fname_upper = fname.upper()

            # Check for AI app prefetch
            for pf_name, platform in ai_prefetch_names:
                if pf_name in fname_upper:
                    ts = self._get_file_timestamp(fpath)
                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.OS_EXECUTION,
                        artifact_type="Prefetch",
                        artifact_subtype="Application Execution",
                        artifact_path=fpath,
                        parser_used=self.PARSER_NAME,
                        timestamp=ts,
                        timestamp_type=TimestampType.EXECUTION,
                        timezone_normalized=True if ts else False,
                        extracted_indicator=f"Prefetch: {fname}",
                        suspected_platform=platform,
                        suspected_access_mode=AccessMode.NATIVE_APP,
                        classification=EvidenceClassification.DIRECT,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.MODERATE,
                        notes="Prefetch file indicates program execution. "
                              "Does not confirm interactive AI use.",
                    )
                    artifacts.append(record)

            # Scan prefetch internals for AI-related strings
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                matches = scan_binary_for_ai_strings(data)
                for m in matches:
                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.OS_EXECUTION,
                        artifact_type="Prefetch Reference",
                        artifact_subtype="Embedded String",
                        artifact_path=fpath,
                        parser_used=self.PARSER_NAME,
                        extracted_indicator=f"{m['matched_string']} in {fname}",
                        suspected_platform=m["platform"],
                        suspected_access_mode=AccessMode.UNKNOWN,
                        classification=EvidenceClassification.INFERRED,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.LOW,
                        notes=f"String found in prefetch. Context: {m.get('context', '')[:100]}",
                    )
                    artifacts.append(record)
            except Exception as exc:
                errors.append(f"Error reading {fname}: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )

    def _get_file_timestamp(self, path: str) -> Optional[datetime]:
        try:
            stat = os.stat(path)
            return datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Recent Files / LNK Parser
# ---------------------------------------------------------------------------

@register_parser
class RecentFilesParser(BaseParser):
    """Parse Windows Recent files (LNK shortcuts) for AI-related file access."""

    PARSER_NAME = "WindowsRecentFilesParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "OS Recent Files"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        recent_dir = os.path.join(
            self.evidence_root, "Users", self.user_profile,
            "AppData", "Roaming", "Microsoft", "Windows", "Recent"
        )
        paths_searched.append(recent_dir)

        if not os.path.isdir(recent_dir):
            paths_missing.append(recent_dir)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Recent files directory not found.",
            )

        paths_found.append(recent_dir)

        for fname in os.listdir(recent_dir):
            fpath = os.path.join(recent_dir, fname)
            if not os.path.isfile(fpath):
                continue

            # Check filename for AI-related patterns
            fname_lower = fname.lower()
            for sig in ALL_SIGNATURES:
                matched = False
                for pattern in sig.download_patterns + sig.export_patterns:
                    if re.search(pattern, fname_lower, re.IGNORECASE):
                        matched = True
                        break

                # Also check for domain names in LNK targets
                if not matched:
                    for domain in sig.domains:
                        if domain.replace(".", "_") in fname_lower or domain.replace(".", "-") in fname_lower:
                            matched = True
                            break

                if not matched:
                    # Scan the LNK binary for AI strings
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read(4096)
                        matches = scan_binary_for_ai_strings(data)
                        if matches:
                            matched = True
                            sig_platform = matches[0]["platform"]
                            # Find the right sig
                            for s in ALL_SIGNATURES:
                                if s.platform == sig_platform:
                                    sig = s
                                    break
                    except Exception:
                        continue

                if matched:
                    ts = self._get_file_timestamp(fpath)
                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.OS_RECENT_FILES,
                        artifact_type="Recent File / LNK",
                        artifact_subtype="Windows Recent",
                        artifact_path=fpath,
                        parser_used=self.PARSER_NAME,
                        timestamp=ts,
                        timestamp_type=TimestampType.ACCESSED,
                        timezone_normalized=True if ts else False,
                        extracted_indicator=f"Recent file: {fname}",
                        suspected_platform=sig.platform,
                        suspected_access_mode=AccessMode.UNKNOWN,
                        classification=EvidenceClassification.INFERRED,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.LOW,
                        notes="Filename match in Recent files. "
                              "A suggestive filename alone is a weak indicator.",
                    )
                    artifacts.append(record)
                    break  # only one match per file

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )

    def _get_file_timestamp(self, path: str) -> Optional[datetime]:
        try:
            stat = os.stat(path)
            return datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# UserAssist Parser (Stub with basic binary scan)
# ---------------------------------------------------------------------------

@register_parser
class UserAssistParser(BaseParser):
    """
    Parse Windows UserAssist registry entries for AI application execution.

    NOTE: Full registry hive parsing requires python-registry or similar.
    This MVP provides binary scanning of NTUSER.DAT for AI-related strings.
    """

    PARSER_NAME = "WindowsUserAssistParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "OS Registry"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        ntuser_dat = os.path.join(
            self.evidence_root, "Users", self.user_profile, "NTUSER.DAT"
        )
        paths_searched.append(ntuser_dat)

        if not os.path.isfile(ntuser_dat):
            paths_missing.append(ntuser_dat)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="NTUSER.DAT not found. Registry analysis unavailable.",
            )

        paths_found.append(ntuser_dat)

        # Try python-registry if available
        try:
            from Registry import Registry as RegistryModule  # type: ignore[import-not-found]
            return self._parse_with_registry_lib(ntuser_dat, artifacts, errors,
                                                  paths_searched, paths_found, paths_missing)
        except ImportError:
            pass

        # Fallback: binary scan of NTUSER.DAT
        self._log("INFO", "python-registry not available. Falling back to binary scan.")
        try:
            with open(ntuser_dat, "rb") as f:
                data = f.read()

            matches = scan_binary_for_ai_strings(data)
            seen = set()
            for m in matches:
                key = (m["platform"].value, m["matched_string"])
                if key in seen:
                    continue
                seen.add(key)

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile,
                    artifact_family=ArtifactFamily.OS_REGISTRY,
                    artifact_type="Registry String Match",
                    artifact_subtype="NTUSER.DAT Binary Scan",
                    artifact_path=ntuser_dat,
                    parser_used=self.PARSER_NAME,
                    extracted_indicator=f"{m['matched_string']}",
                    suspected_platform=m["platform"],
                    suspected_access_mode=AccessMode.UNKNOWN,
                    classification=EvidenceClassification.INFERRED,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.LOW,
                    notes=f"String found via binary scan. Full registry parsing requires "
                          f"python-registry. Context: {m.get('context', '')[:80]}",
                )
                artifacts.append(record)

        except Exception as exc:
            errors.append(f"NTUSER.DAT binary scan error: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes="Registry analysis performed via binary scan. "
                  "For full UserAssist/RecentDocs/OpenSaveMRU parsing, "
                  "install python-registry.",
        )

    def _parse_with_registry_lib(self, ntuser_path, artifacts, errors,
                                  paths_searched, paths_found, paths_missing):
        """Parse using python-registry library if available."""
        from Registry import Registry as RegistryModule  # type: ignore[import-not-found]

        try:
            reg = RegistryModule.Registry(ntuser_path)

            # UserAssist
            ua_paths = [
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
            ]
            for ua_path in ua_paths:
                try:
                    key = reg.open(ua_path)
                    for subkey in key.subkeys():
                        for count_key in subkey.subkeys():
                            if count_key.name() == "Count":
                                for val in count_key.values():
                                    # UserAssist values are ROT13 encoded
                                    decoded_name = val.name().encode().decode("rot13") if hasattr(str, 'decode') else \
                                        val.name().translate(str.maketrans(
                                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
                                        ))
                                    platform = match_domain(decoded_name)
                                    if not platform:
                                        for sig in ALL_SIGNATURES:
                                            for app in sig.app_names_windows + sig.process_names:
                                                if app.lower() in decoded_name.lower():
                                                    platform = sig.platform
                                                    break
                                            if platform:
                                                break

                                    if platform:
                                        record = ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.OS_REGISTRY,
                                            artifact_type="UserAssist",
                                            artifact_subtype="Execution Count",
                                            artifact_path=ntuser_path,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=decoded_name[:200],
                                            suspected_platform=platform,
                                            suspected_access_mode=AccessMode.UNKNOWN,
                                            classification=EvidenceClassification.DIRECT,
                                            attribution_layer=AttributionLayer.PLATFORM,
                                            confidence=ConfidenceLevel.MODERATE,
                                            notes="UserAssist entry indicates program execution.",
                                        )
                                        artifacts.append(record)
                except Exception:
                    pass

            # RecentDocs
            try:
                rd_key = reg.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
                for val in rd_key.values():
                    try:
                        data = val.value()
                        if isinstance(data, bytes):
                            text = data.decode("utf-16-le", errors="replace").split("\x00")[0]
                            for sig in ALL_SIGNATURES:
                                for pattern in sig.download_patterns + sig.export_patterns:
                                    if re.search(pattern, text, re.IGNORECASE):
                                        record = ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.OS_REGISTRY,
                                            artifact_type="RecentDocs",
                                            artifact_subtype="Registry",
                                            artifact_path=ntuser_path,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=text[:200],
                                            suspected_platform=sig.platform,
                                            classification=EvidenceClassification.INFERRED,
                                            attribution_layer=AttributionLayer.PLATFORM,
                                            confidence=ConfidenceLevel.LOW,
                                            notes="Filename pattern match in RecentDocs.",
                                        )
                                        artifacts.append(record)
                                        break
                    except Exception:
                        pass
            except Exception:
                pass

        except Exception as exc:
            errors.append(f"python-registry parse error: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )


# ---------------------------------------------------------------------------
# Event Log Parser
# ---------------------------------------------------------------------------

@register_parser
class WindowsEventLogParser(BaseParser):
    """
    Parse Windows Event Logs for AI-related activity.

    Attempts to parse EVTX files using python-evtx if available.
    Falls back to binary string scanning if not installed.
    
    Extracts:
    - Application events related to AI apps
    - System events showing process launches
    - PowerShell event logs with AI-related commands
    - Security events (process creation, network connections)
    """

    PARSER_NAME = "WindowsEventLogParser"
    PARSER_VERSION = "2.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "OS Event Log"
    IS_STUB = False

    # Event log files of interest
    TARGET_LOGS = [
        "Application.evtx",
        "System.evtx",
        "Security.evtx",
        "Microsoft-Windows-PowerShell%4Operational.evtx",
        "Windows PowerShell.evtx",
        "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched = []
        paths_found = []
        paths_missing = []

        evtx_dir = os.path.join(
            self.evidence_root, "Windows", "System32", "winevt", "Logs"
        )
        paths_searched.append(evtx_dir)

        if not os.path.isdir(evtx_dir):
            paths_missing.append(evtx_dir)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Windows Event Log directory not found.",
            )

        paths_found.append(evtx_dir)

        # Check for python-evtx library
        has_evtx_lib = False
        try:
            import Evtx.Evtx as evtx_module  # type: ignore[import-not-found]  # noqa: F401
            has_evtx_lib = True
        except ImportError:
            self._log("INFO", "python-evtx not installed. Using binary scan fallback.")

        # Process each target log file
        for log_name in self.TARGET_LOGS:
            log_path = os.path.join(evtx_dir, log_name)
            paths_searched.append(log_path)

            if not os.path.isfile(log_path):
                paths_missing.append(log_path)
                continue

            paths_found.append(log_path)

            if has_evtx_lib:
                self._parse_evtx_structured(log_path, log_name, artifacts, errors)
            else:
                self._parse_evtx_binary(log_path, log_name, artifacts, errors)

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        notes = ("Event logs parsed using python-evtx." if has_evtx_lib 
                 else "Event logs scanned using binary pattern matching. "
                      "Install python-evtx for full XML parsing.")
        
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes=notes,
        )

    def _parse_evtx_structured(self, log_path: str, log_name: str, 
                               artifacts: List, errors: List) -> None:
        """Parse EVTX file using python-evtx library."""
        try:
            import Evtx.Evtx as evtx_module
            import xml.etree.ElementTree as ET

            with evtx_module.Evtx(log_path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        
                        # Extract event data
                        event_id_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
                        event_id = int(event_id_elem.text) if event_id_elem is not None else 0
                        
                        time_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
                        timestamp_str = time_elem.get("SystemTime") if time_elem is not None else None
                        timestamp = None
                        if timestamp_str:
                            try:
                                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            except Exception:
                                pass

                        # Check for AI-related content in event data
                        xml_lower = xml_str.lower()
                        
                        for sig in ALL_SIGNATURES:
                            matched = False
                            matched_indicator = ""
                            
                            # Check domains
                            for domain in sig.domains:
                                if domain.lower() in xml_lower:
                                    matched = True
                                    matched_indicator = f"Domain: {domain}"
                                    break
                            
                            # Check process names
                            if not matched:
                                for proc in sig.process_names:
                                    if proc.lower() in xml_lower:
                                        matched = True
                                        matched_indicator = f"Process: {proc}"
                                        break
                            
                            # Check app names
                            if not matched:
                                for app in sig.app_names_windows:
                                    if app.lower() in xml_lower:
                                        matched = True
                                        matched_indicator = f"App: {app}"
                                        break
                            
                            if matched:
                                # Extract event message if available
                                event_data = []
                                for data_elem in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                                    if data_elem.text:
                                        event_data.append(data_elem.text[:100])
                                
                                record_obj = ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.OS_EVENT_LOG,
                                    artifact_type="Windows Event Log",
                                    artifact_subtype=f"{log_name} Event ID {event_id}",
                                    artifact_path=log_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=timestamp,
                                    timestamp_type=TimestampType.CREATED,
                                    timezone_normalized=True if timestamp else False,
                                    extracted_indicator=matched_indicator,
                                    suspected_platform=sig.platform,
                                    suspected_access_mode=AccessMode.UNKNOWN,
                                    classification=EvidenceClassification.CIRCUMSTANTIAL,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.LOW,
                                    notes=f"Event log entry. Data: {' | '.join(event_data[:3])}",
                                )
                                artifacts.append(record_obj)
                                
                    except Exception as exc:
                        errors.append(f"Error parsing event record in {log_name}: {exc}")
                        
        except Exception as exc:
            errors.append(f"Error opening {log_name}: {exc}")

    def _parse_evtx_binary(self, log_path: str, log_name: str,
                           artifacts: List, errors: List) -> None:
        """Parse EVTX file using binary string scanning."""
        try:
            with open(log_path, "rb") as f:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    
                    matches = scan_binary_for_ai_strings(data)
                    for m in matches:
                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.OS_EVENT_LOG,
                            artifact_type="Windows Event Log",
                            artifact_subtype=f"{log_name} String Match",
                            artifact_path=log_path,
                            parser_used=self.PARSER_NAME,
                            extracted_indicator=f"String: {m['matched_string']}",
                            suspected_platform=m["platform"],
                            suspected_access_mode=AccessMode.UNKNOWN,
                            classification=EvidenceClassification.INFERRED,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.LOW,
                            notes=f"Binary scan match. {m.get('context', '')[:100]}",
                        )
                        artifacts.append(record)
                        
        except Exception as exc:
            errors.append(f"Error scanning {log_name}: {exc}")


# ---------------------------------------------------------------------------
# Recycle Bin Parser
# ---------------------------------------------------------------------------

@register_parser
class RecycleBinParser(BaseParser):
    """Parse Windows Recycle Bin for deleted AI-related files."""

    PARSER_NAME = "WindowsRecycleBinParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "File System"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        recycle_bin = os.path.join(self.evidence_root, "$Recycle.Bin")
        paths_searched.append(recycle_bin)

        if not os.path.isdir(recycle_bin):
            # Try alternate casing
            recycle_bin = os.path.join(self.evidence_root, "$RECYCLE.BIN")
            paths_searched.append(recycle_bin)

        if not os.path.isdir(recycle_bin):
            paths_missing.append(recycle_bin)
            return self._make_result(
                status=ParserStatus.NOT_APPLICABLE,
                paths_searched=paths_searched,
                paths_missing=paths_missing,
                notes="Recycle Bin not found.",
            )

        paths_found.append(recycle_bin)

        # Walk through $I files (metadata) and $R files (content)
        for dirpath, dirnames, filenames in os.walk(recycle_bin):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                # Check $I metadata files for AI-related original filenames
                if fname.startswith("$I"):
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read()
                        # $I file contains original filename in UTF-16LE after header
                        if len(data) > 28:
                            original_name = data[28:].decode("utf-16-le", errors="replace").rstrip("\x00")
                            for sig in ALL_SIGNATURES:
                                for pattern in sig.download_patterns + sig.export_patterns:
                                    if re.search(pattern, original_name, re.IGNORECASE):
                                        record = ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.FILE_SYSTEM,
                                            artifact_type="Recycle Bin Entry",
                                            artifact_subtype="Deleted File",
                                            artifact_path=fpath,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=f"Deleted: {original_name}",
                                            suspected_platform=sig.platform,
                                            classification=EvidenceClassification.INFERRED,
                                            attribution_layer=AttributionLayer.PLATFORM,
                                            confidence=ConfidenceLevel.LOW,
                                            notes="Deleted file with AI-suggestive filename. "
                                                  "Filename alone is a weak indicator.",
                                        )
                                        artifacts.append(record)
                                        break
                    except Exception as exc:
                        errors.append(f"Error reading {fname}: {exc}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )


# ---------------------------------------------------------------------------
# Windows App Data Parser (checks for AI app installations)
# ---------------------------------------------------------------------------

@register_parser
class WindowsAppDataParser(BaseParser):
    """Check Windows AppData directories for AI native application artifacts."""

    PARSER_NAME = "WindowsAppDataParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "Native Application"
    IS_STUB = False

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)

        for sig in ALL_SIGNATURES:
            for app_folder in sig.app_data_folders_windows:
                full_path = os.path.join(user_base, app_folder)
                paths_searched.append(full_path)

                if os.path.isdir(full_path):
                    paths_found.append(full_path)

                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.NATIVE_APP,
                        artifact_type="App Data Directory",
                        artifact_subtype="Windows AppData",
                        artifact_path=full_path,
                        parser_used=self.PARSER_NAME,
                        extracted_indicator=f"App directory found: {app_folder}",
                        suspected_platform=sig.platform,
                        suspected_access_mode=AccessMode.NATIVE_APP,
                        classification=EvidenceClassification.DIRECT,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.MODERATE,
                        notes="Application data directory present. Indicates installation "
                              "but not necessarily active investigative use.",
                    )
                    artifacts.append(record)

                    # Scan contents for additional indicators
                    try:
                        for item in os.listdir(full_path):
                            item_path = os.path.join(full_path, item)
                            if os.path.isfile(item_path) and item.endswith(
                                (".json", ".log", ".db", ".sqlite", ".sqlite3")
                            ):
                                try:
                                    with open(item_path, "rb") as f:
                                        data = f.read(1024 * 512)  # 512KB
                                    text = data.decode("utf-8", errors="replace")
                                    model = match_model_string(text)
                                    if model:
                                        record = ArtifactRecord(
                                            case_id=self.case_id,
                                            evidence_item_id=self.evidence_item_id,
                                            source_image=self.source_image,
                                            user_profile=self.user_profile,
                                            artifact_family=ArtifactFamily.NATIVE_APP,
                                            artifact_type="App Data File",
                                            artifact_subtype="Model String",
                                            artifact_path=item_path,
                                            parser_used=self.PARSER_NAME,
                                            extracted_indicator=f"Model ref: {model.value} in {item}",
                                            suspected_platform=sig.platform,
                                            suspected_model=model,
                                            suspected_access_mode=AccessMode.NATIVE_APP,
                                            classification=EvidenceClassification.DIRECT,
                                            attribution_layer=AttributionLayer.MODEL,
                                            confidence=ConfidenceLevel.MODERATE,
                                            notes="Model identifier found in app data file.",
                                        )
                                        artifacts.append(record)
                                except Exception:
                                    pass
                    except Exception as exc:
                        errors.append(f"Error scanning {full_path}: {exc}")
                else:
                    paths_missing.append(full_path)

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
        )


# ---------------------------------------------------------------------------
# Full Registry Hive Parser
# ---------------------------------------------------------------------------

@register_parser
class RegistryHiveParser(BaseParser):
    r"""
    Comprehensive Windows Registry hive parser for AI platform forensics.

    Parses multiple registry hives for AI-related artifacts:
      - NTUSER.DAT: TypedURLs, RunMRU, RecentDocs, OpenSaveMRU,
                     LastVisitedMRU, BagMRU/Bags, Shell\Associations
      - SOFTWARE:   Installed programs, App Paths, Uninstall entries
      - SYSTEM:     USB history, network references (AppCompatCache)
      - UsrClass.dat: Shell Bags, file associations, COM objects

    Supports two backends:
      1. python-registry (full structured parsing when installed)
      2. Binary string scanning (fallback when python-registry absent)
    """

    PARSER_NAME = "WindowsRegistryHiveParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS]
    ARTIFACT_FAMILY = "OS Registry"
    IS_STUB = False

    # Registry hives to search and their typical locations
    HIVE_LOCATIONS = {
        "NTUSER.DAT": [
            "Users/{profile}/NTUSER.DAT",
            "Users/{profile}/ntuser.dat",
        ],
        "UsrClass.dat": [
            "Users/{profile}/AppData/Local/Microsoft/Windows/UsrClass.dat",
            "Users/{profile}/AppData/Local/Microsoft/Windows/usrclass.dat",
        ],
        "SOFTWARE": [
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/software",
        ],
        "SYSTEM": [
            "Windows/System32/config/SYSTEM",
            "Windows/System32/config/system",
        ],
        "SAM": [
            "Windows/System32/config/SAM",
            "Windows/System32/config/sam",
        ],
    }

    # Key paths to examine inside NTUSER.DAT
    NTUSER_KEY_PATHS = {
        "TypedURLs": (
            r"Software\Microsoft\Internet Explorer\TypedURLs",
            "TypedURL",
            "Typed URL from Internet Explorer / Edge Legacy",
        ),
        "RunMRU": (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "RunMRU",
            "Run dialog command history",
        ),
        "RecentDocs": (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "RecentDocs",
            "Recently accessed documents",
        ),
        "OpenSaveMRU": (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            "OpenSaveMRU",
            "Open/Save dialog history",
        ),
        "LastVisitedMRU": (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            "LastVisitedMRU",
            "Last visited folder MRU in Open/Save dialogs",
        ),
        "WordWheelQuery": (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
            "WordWheelQuery",
            "Windows Search / Explorer search bar queries",
        ),
        "TypedPaths": (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            "TypedPath",
            "Paths typed into Windows Explorer address bar",
        ),
    }

    # Key paths to examine inside SOFTWARE hive
    SOFTWARE_KEY_PATHS = {
        "Uninstall_x64": (
            r"Microsoft\Windows\CurrentVersion\Uninstall",
            "Uninstall",
            "Installed programs (64-bit)",
        ),
        "Uninstall_x86": (
            r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "Uninstall",
            "Installed programs (32-bit/WOW64)",
        ),
        "AppPaths": (
            r"Microsoft\Windows\CurrentVersion\App Paths",
            "AppPaths",
            "Application executable paths",
        ),
        "RegisteredApps": (
            r"RegisteredApplications",
            "RegisteredApps",
            "Registered application capabilities",
        ),
    }

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []
        paths_missing: List[str] = []

        # Collect AI-related registry key patterns from signatures
        ai_key_patterns = []
        for sig in ALL_SIGNATURES:
            for rk in sig.registry_keys:
                ai_key_patterns.append((rk, sig.platform))

        # Check for python-registry
        has_registry_lib = False
        try:
            from Registry import Registry as RegistryModule  # type: ignore[import-not-found]  # noqa: F401
            has_registry_lib = True
        except ImportError:
            self._log("INFO", "python-registry not installed. "
                       "Using binary scan fallback for hive parsing.")

        # Parse user-scoped hives (NTUSER.DAT, UsrClass.dat)
        for hive_name in ("NTUSER.DAT", "UsrClass.dat"):
            hive_path = self._find_hive(hive_name, paths_searched, paths_found, paths_missing)
            if hive_path:
                if has_registry_lib:
                    self._parse_hive_structured(
                        hive_path, hive_name, artifacts, errors, ai_key_patterns
                    )
                else:
                    self._parse_hive_binary(
                        hive_path, hive_name, artifacts, errors
                    )

        # Parse system-scoped hives (SOFTWARE, SYSTEM, SAM)
        for hive_name in ("SOFTWARE", "SYSTEM", "SAM"):
            hive_path = self._find_hive(hive_name, paths_searched, paths_found, paths_missing)
            if hive_path:
                if has_registry_lib:
                    self._parse_hive_structured(
                        hive_path, hive_name, artifacts, errors, ai_key_patterns
                    )
                else:
                    self._parse_hive_binary(
                        hive_path, hive_name, artifacts, errors
                    )

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        notes = ("Full registry hive analysis via python-registry."
                 if has_registry_lib
                 else "Registry hive analysis via binary string scanning. "
                      "Install python-registry for structured key parsing.")
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            paths_missing=paths_missing,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Hive locator
    # ------------------------------------------------------------------

    def _find_hive(self, hive_name: str, paths_searched, paths_found, paths_missing):
        """Locate a registry hive file on disk."""
        candidates = self.HIVE_LOCATIONS.get(hive_name, [])
        for tmpl in candidates:
            path = os.path.join(
                self.evidence_root,
                tmpl.format(profile=self.user_profile),
            )
            paths_searched.append(path)
            if os.path.isfile(path):
                paths_found.append(path)
                return path
        # Not found
        for tmpl in candidates:
            paths_missing.append(os.path.join(
                self.evidence_root,
                tmpl.format(profile=self.user_profile),
            ))
        return None

    # ------------------------------------------------------------------
    # Structured parsing (python-registry)
    # ------------------------------------------------------------------

    def _parse_hive_structured(self, hive_path: str, hive_name: str,
                                artifacts: list, errors: list,
                                ai_key_patterns: list):
        """Parse a registry hive using python-registry for structured access."""
        from Registry import Registry as RegistryModule  # type: ignore[import-not-found]

        try:
            reg = RegistryModule.Registry(hive_path)
        except Exception as exc:
            errors.append(f"Failed to open {hive_name} at {hive_path}: {exc}")
            return

        if hive_name in ("NTUSER.DAT", "ntuser.dat"):
            self._parse_ntuser_keys(reg, hive_path, artifacts, errors)
            self._check_ai_registry_keys(reg, hive_path, hive_name,
                                          artifacts, ai_key_patterns)
        elif hive_name in ("SOFTWARE", "software"):
            self._parse_software_keys(reg, hive_path, artifacts, errors)
            self._check_ai_registry_keys(reg, hive_path, hive_name,
                                          artifacts, ai_key_patterns)
        elif hive_name in ("UsrClass.dat", "usrclass.dat"):
            self._parse_usrclass_keys(reg, hive_path, artifacts, errors)
        elif hive_name in ("SYSTEM", "system"):
            self._parse_system_appcompat(reg, hive_path, artifacts, errors)

    def _parse_ntuser_keys(self, reg, hive_path: str, artifacts: list, errors: list):
        """Parse NTUSER.DAT key paths for AI indicators."""
        for key_label, (key_path, artifact_subtype, description) in self.NTUSER_KEY_PATHS.items():
            try:
                key = reg.open(key_path)
            except Exception:
                continue

            for val in key.values():
                try:
                    val_name = val.name()
                    val_data = val.value()

                    if isinstance(val_data, bytes):
                        text = val_data.decode("utf-16-le", errors="replace").split("\x00")[0]
                    elif isinstance(val_data, str):
                        text = val_data
                    else:
                        text = str(val_data)

                    platform = match_domain(text)
                    if not platform:
                        for sig in ALL_SIGNATURES:
                            for pat in (sig.domains + sig.app_names_windows +
                                        sig.process_names + sig.search_keywords):
                                if pat.lower() in text.lower():
                                    platform = sig.platform
                                    break
                            if platform:
                                break

                    if platform:
                        classification = EvidenceClassification.DIRECT
                        confidence = ConfidenceLevel.MODERATE
                        if key_label == "TypedURLs":
                            confidence = ConfidenceLevel.HIGH
                        elif key_label in ("RunMRU", "WordWheelQuery"):
                            classification = EvidenceClassification.INFERRED
                            confidence = ConfidenceLevel.LOW

                        ts = None
                        try:
                            ts = key.timestamp()
                        except Exception:
                            pass

                        record = ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.OS_REGISTRY,
                            artifact_type=f"Registry — {key_label}",
                            artifact_subtype=artifact_subtype,
                            artifact_path=hive_path,
                            parser_used=self.PARSER_NAME,
                            timestamp=ts,
                            timestamp_type=TimestampType.MODIFIED if ts else None,
                            timezone_normalized=True if ts else False,
                            extracted_indicator=f"{val_name}: {text[:200]}",
                            suspected_platform=platform,
                            suspected_access_mode=AccessMode.BROWSER
                                if key_label == "TypedURLs" else AccessMode.UNKNOWN,
                            classification=classification,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=confidence,
                            notes=f"{description}. Key: {key_path}\\{val_name}",
                        )
                        artifacts.append(record)
                except Exception:
                    continue

            # Recurse one level into subkeys (e.g., RecentDocs\.pdf)
            try:
                for subkey in key.subkeys():
                    for val in subkey.values():
                        try:
                            val_data = val.value()
                            if isinstance(val_data, bytes):
                                text = val_data.decode("utf-16-le", errors="replace").split("\x00")[0]
                            elif isinstance(val_data, str):
                                text = val_data
                            else:
                                continue

                            platform = match_domain(text)
                            if not platform:
                                for sig in ALL_SIGNATURES:
                                    for dpat in sig.download_patterns + sig.export_patterns:
                                        if re.search(dpat, text, re.IGNORECASE):
                                            platform = sig.platform
                                            break
                                    if platform:
                                        break
                            if platform:
                                record = ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.OS_REGISTRY,
                                    artifact_type=f"Registry — {key_label}/{subkey.name()}",
                                    artifact_subtype=artifact_subtype,
                                    artifact_path=hive_path,
                                    parser_used=self.PARSER_NAME,
                                    extracted_indicator=text[:200],
                                    suspected_platform=platform,
                                    classification=EvidenceClassification.INFERRED,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.LOW,
                                    notes=f"Subkey match in {key_path}\\{subkey.name()}",
                                )
                                artifacts.append(record)
                        except Exception:
                            continue
            except Exception:
                pass

    def _parse_software_keys(self, reg, hive_path: str, artifacts: list, errors: list):
        """Parse SOFTWARE hive for installed AI applications."""
        for key_label, (key_path, artifact_subtype, description) in self.SOFTWARE_KEY_PATHS.items():
            try:
                key = reg.open(key_path)
            except Exception:
                continue

            if "Uninstall" in key_label or "AppPaths" in key_label:
                try:
                    for subkey in key.subkeys():
                        subkey_name = subkey.name()
                        display_name = subkey_name
                        install_location = ""
                        for val in subkey.values():
                            try:
                                if val.name() == "DisplayName":
                                    display_name = str(val.value())
                                elif val.name() == "InstallLocation":
                                    install_location = str(val.value())
                            except Exception:
                                pass

                        combined = f"{display_name} {install_location} {subkey_name}".lower()

                        for sig in ALL_SIGNATURES:
                            matched = False
                            for name in (sig.app_names_windows + sig.process_names +
                                         [d for d in sig.domains]):
                                if name.lower() in combined:
                                    matched = True
                                    break
                            if matched:
                                ts = None
                                try:
                                    ts = subkey.timestamp()
                                except Exception:
                                    pass

                                record = ArtifactRecord(
                                    case_id=self.case_id,
                                    evidence_item_id=self.evidence_item_id,
                                    source_image=self.source_image,
                                    user_profile=self.user_profile,
                                    artifact_family=ArtifactFamily.OS_REGISTRY,
                                    artifact_type=f"Registry — {key_label}",
                                    artifact_subtype=artifact_subtype,
                                    artifact_path=hive_path,
                                    parser_used=self.PARSER_NAME,
                                    timestamp=ts,
                                    timestamp_type=TimestampType.MODIFIED if ts else None,
                                    timezone_normalized=True if ts else False,
                                    extracted_indicator=f"Installed: {display_name}",
                                    suspected_platform=sig.platform,
                                    suspected_access_mode=AccessMode.NATIVE_APP,
                                    classification=EvidenceClassification.DIRECT,
                                    attribution_layer=AttributionLayer.PLATFORM,
                                    confidence=ConfidenceLevel.MODERATE,
                                    notes=f"{description}. Registry key: {key_path}\\{subkey_name}",
                                )
                                artifacts.append(record)
                                break
                except Exception as exc:
                    errors.append(f"Error parsing {key_label}: {exc}")
            else:
                for val in key.values():
                    try:
                        val_text = f"{val.name()} {val.value()}".lower()
                        for sig in ALL_SIGNATURES:
                            for name in sig.app_names_windows:
                                if name.lower() in val_text:
                                    record = ArtifactRecord(
                                        case_id=self.case_id,
                                        evidence_item_id=self.evidence_item_id,
                                        source_image=self.source_image,
                                        user_profile=self.user_profile,
                                        artifact_family=ArtifactFamily.OS_REGISTRY,
                                        artifact_type=f"Registry — {key_label}",
                                        artifact_subtype=artifact_subtype,
                                        artifact_path=hive_path,
                                        parser_used=self.PARSER_NAME,
                                        extracted_indicator=f"Registered: {val.name()}",
                                        suspected_platform=sig.platform,
                                        suspected_access_mode=AccessMode.NATIVE_APP,
                                        classification=EvidenceClassification.INFERRED,
                                        attribution_layer=AttributionLayer.PLATFORM,
                                        confidence=ConfidenceLevel.LOW,
                                        notes=f"Application registered in {key_path}.",
                                    )
                                    artifacts.append(record)
                                    break
                    except Exception:
                        continue

    def _parse_usrclass_keys(self, reg, hive_path: str, artifacts: list, errors: list):
        """Parse UsrClass.dat for Shell Bags with AI-related folder paths."""
        bag_paths = [
            r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            r"Local Settings\Software\Microsoft\Windows\Shell\Bags",
        ]
        for bag_path in bag_paths:
            try:
                key = reg.open(bag_path)
                self._walk_key_for_ai(key, hive_path, bag_path, "ShellBag",
                                       "Folder navigation (Shell Bags)",
                                       artifacts)
            except Exception:
                continue

    def _parse_system_appcompat(self, reg, hive_path: str, artifacts: list, errors: list):
        """Parse SYSTEM hive for AppCompatCache / ShimCache entries."""
        try:
            select_key = reg.open("Select")
            current_val = None
            for val in select_key.values():
                if val.name() == "Current":
                    current_val = val.value()
                    break
            if current_val:
                cs = f"ControlSet{current_val:03d}"
                shimcache_path = f"{cs}\\Control\\Session Manager\\AppCompatCache"
                try:
                    key = reg.open(shimcache_path)
                    for val in key.values():
                        try:
                            data = val.value()
                            if isinstance(data, bytes):
                                matches = scan_binary_for_ai_strings(data)
                                seen = set()
                                for m in matches:
                                    mk = (m["platform"].value, m["matched_string"])
                                    if mk in seen:
                                        continue
                                    seen.add(mk)
                                    record = ArtifactRecord(
                                        case_id=self.case_id,
                                        evidence_item_id=self.evidence_item_id,
                                        source_image=self.source_image,
                                        user_profile=self.user_profile,
                                        artifact_family=ArtifactFamily.OS_REGISTRY,
                                        artifact_type="Registry — AppCompatCache",
                                        artifact_subtype="ShimCache",
                                        artifact_path=hive_path,
                                        parser_used=self.PARSER_NAME,
                                        extracted_indicator=(
                                            f"ShimCache: {m['matched_string']}"
                                        ),
                                        suspected_platform=m["platform"],
                                        suspected_access_mode=AccessMode.UNKNOWN,
                                        classification=EvidenceClassification.INFERRED,
                                        attribution_layer=AttributionLayer.PLATFORM,
                                        confidence=ConfidenceLevel.LOW,
                                        notes=f"AI string in AppCompatCache. "
                                              f"Context: {m.get('context', '')[:80]}",
                                    )
                                    artifacts.append(record)
                        except Exception:
                            continue
                except Exception:
                    pass
        except Exception as exc:
            errors.append(f"SYSTEM AppCompatCache parse error: {exc}")

    def _check_ai_registry_keys(self, reg, hive_path: str, hive_name: str,
                                  artifacts: list, ai_key_patterns: list):
        """Check for AI-platform-specific registry keys defined in signatures."""
        for key_path, platform in ai_key_patterns:
            try:
                key = reg.open(key_path)
                ts = None
                try:
                    ts = key.timestamp()
                except Exception:
                    pass

                record = ArtifactRecord(
                    case_id=self.case_id,
                    evidence_item_id=self.evidence_item_id,
                    source_image=self.source_image,
                    user_profile=self.user_profile,
                    artifact_family=ArtifactFamily.OS_REGISTRY,
                    artifact_type="Registry — AI Platform Key",
                    artifact_subtype="Known AI Key",
                    artifact_path=hive_path,
                    parser_used=self.PARSER_NAME,
                    timestamp=ts,
                    timestamp_type=TimestampType.MODIFIED if ts else None,
                    timezone_normalized=True if ts else False,
                    extracted_indicator=f"Registry key exists: {key_path}",
                    suspected_platform=platform,
                    suspected_access_mode=AccessMode.NATIVE_APP,
                    classification=EvidenceClassification.DIRECT,
                    attribution_layer=AttributionLayer.PLATFORM,
                    confidence=ConfidenceLevel.HIGH,
                    notes=f"AI platform registry key found in {hive_name}: {key_path}",
                )
                artifacts.append(record)

                for val in key.values():
                    try:
                        val_text = str(val.value())[:200] if val.value() else ""
                        if val_text:
                            record = ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.OS_REGISTRY,
                                artifact_type="Registry — AI Platform Value",
                                artifact_subtype="Known AI Key Value",
                                artifact_path=hive_path,
                                parser_used=self.PARSER_NAME,
                                extracted_indicator=(
                                    f"{key_path}\\{val.name()} = {val_text[:150]}"
                                ),
                                suspected_platform=platform,
                                suspected_access_mode=AccessMode.NATIVE_APP,
                                classification=EvidenceClassification.DIRECT,
                                attribution_layer=AttributionLayer.PLATFORM,
                                confidence=ConfidenceLevel.MODERATE,
                                notes=f"Value under AI platform registry key.",
                            )
                            artifacts.append(record)
                    except Exception:
                        continue
            except Exception:
                continue

    def _walk_key_for_ai(self, key, hive_path: str, key_path: str,
                          artifact_subtype: str, description: str,
                          artifacts: list, depth: int = 0):
        """Recursively walk registry key looking for AI-related string values."""
        if depth > 5:
            return

        for val in key.values():
            try:
                val_data = val.value()
                if isinstance(val_data, bytes):
                    text = val_data.decode("utf-16-le", errors="replace").split("\x00")[0]
                elif isinstance(val_data, str):
                    text = val_data
                else:
                    continue

                if len(text) < 4:
                    continue

                platform = match_domain(text)
                if not platform:
                    for sig in ALL_SIGNATURES:
                        for pat in sig.domains + sig.app_names_windows:
                            if pat.lower() in text.lower():
                                platform = sig.platform
                                break
                        if platform:
                            break

                if platform:
                    record = ArtifactRecord(
                        case_id=self.case_id,
                        evidence_item_id=self.evidence_item_id,
                        source_image=self.source_image,
                        user_profile=self.user_profile,
                        artifact_family=ArtifactFamily.OS_REGISTRY,
                        artifact_type=f"Registry — {artifact_subtype}",
                        artifact_subtype=artifact_subtype,
                        artifact_path=hive_path,
                        parser_used=self.PARSER_NAME,
                        extracted_indicator=text[:200],
                        suspected_platform=platform,
                        classification=EvidenceClassification.INFERRED,
                        attribution_layer=AttributionLayer.PLATFORM,
                        confidence=ConfidenceLevel.LOW,
                        notes=f"{description}. Key: {key_path}",
                    )
                    artifacts.append(record)
            except Exception:
                continue

        try:
            for subkey in key.subkeys():
                self._walk_key_for_ai(
                    subkey, hive_path,
                    f"{key_path}\\{subkey.name()}",
                    artifact_subtype, description,
                    artifacts, depth + 1,
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Binary fallback (no python-registry)
    # ------------------------------------------------------------------

    def _parse_hive_binary(self, hive_path: str, hive_name: str,
                            artifacts: list, errors: list):
        """Binary scan fallback when python-registry is not installed."""
        try:
            with open(hive_path, "rb") as f:
                data = f.read()
        except Exception as exc:
            errors.append(f"Failed to read {hive_name} at {hive_path}: {exc}")
            return

        matches = scan_binary_for_ai_strings(data)
        seen = set()
        for m in matches:
            mkey = (m["platform"].value, m["matched_string"], hive_name)
            if mkey in seen:
                continue
            seen.add(mkey)

            record = ArtifactRecord(
                case_id=self.case_id,
                evidence_item_id=self.evidence_item_id,
                source_image=self.source_image,
                user_profile=self.user_profile,
                artifact_family=ArtifactFamily.OS_REGISTRY,
                artifact_type=f"Registry — {hive_name} Binary Scan",
                artifact_subtype="Binary String Match",
                artifact_path=hive_path,
                parser_used=self.PARSER_NAME,
                extracted_indicator=f"{m['matched_string']}",
                suspected_platform=m["platform"],
                suspected_access_mode=AccessMode.UNKNOWN,
                classification=EvidenceClassification.INFERRED,
                attribution_layer=AttributionLayer.PLATFORM,
                confidence=ConfidenceLevel.LOW,
                notes=f"String found via binary scan of {hive_name}. "
                      f"Install python-registry for structured parsing. "
                      f"Context: {m.get('context', '')[:80]}",
            )
            artifacts.append(record)
