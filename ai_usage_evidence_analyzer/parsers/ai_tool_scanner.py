"""
AI Tool Scanner Parser
======================
Scans evidence roots for AI tools registered in the tool inventory YAML.
Produces ForensicChecklistEntries and ArtifactRecords for each tool found.

For each tool, candidate artifact paths (per OS) are checked against the
evidence directory tree.  The scanner translates Windows %envvar% path
templates to real on-disk paths relative to the evidence root.
"""

from __future__ import annotations

import fnmatch
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import (
    AccessMode,
    AIPlatform,
    AIModel,
    ArtifactCoverageRecord,
    ArtifactFamily,
    ArtifactRecord,
    AttributionLayer,
    ConfidenceLevel,
    CoverageGapRecord,
    EvidenceClassification,
    OSPlatform,
    ParserResult,
    ParserStatus,
    TimestampType,
)
from ..parser_registry import BaseParser, register_parser
from ..tool_registry import (
    CaveatFlag,
    CorroborationLevel,
    EvidenceStatus,
    SurfaceClass,
    ToolRecord,
    ToolRegistry,
    classify_surface,
)
from ..forensic_checklist import ForensicChecklistEntry

# ---------------------------------------------------------------------------
# Path template expansion helpers
# ---------------------------------------------------------------------------

#: Windows environment-variable prefix patterns we recognise in artifact paths.
_WIN_ENVVAR = re.compile(r"%([A-Za-z][A-Za-z0-9_ ]*)%")

# Map of Windows env-var names → typical on-disk sub-paths within a user
# profile root.  We only expand vars that have a well-known location relative
# to the evidence root.
_WIN_ENVVAR_SUBPATHS: Dict[str, List[str]] = {
    "LOCALAPPDATA":  ["Users", "{user}", "AppData", "Local"],
    "APPDATA":       ["Users", "{user}", "AppData", "Roaming"],
    "USERPROFILE":   ["Users", "{user}"],
    "TEMP":          ["Users", "{user}", "AppData", "Local", "Temp"],
    "PROGRAMFILES":  ["Program Files"],
    "PROGRAMFILES(X86)": ["Program Files (x86)"],
    "PROGRAMDATA":   ["ProgramData"],
    "SYSTEMROOT":    ["Windows"],
    "WINDIR":        ["Windows"],
    # macOS/Linux – expressed as ~ in YAML
    "HOME":          ["{user}"],
}


def _expand_template(template: str, username: str = "*") -> List[str]:
    """
    Expand a Windows %var% template to a list of concrete candidate paths.

    ``~`` prefixed paths are left unchanged (handled as macOS/Linux).
    Returns multiple expansions when a wildcard is used.
    """
    if template.startswith("~"):
        # POSIX home-directory shorthand – keep as-is
        return [template]

    candidates: List[str] = [template]

    def _replace(m: re.Match) -> str:
        var = m.group(1).upper()
        parts = _WIN_ENVVAR_SUBPATHS.get(var)
        if parts is None:
            return m.group(0)  # leave unknown vars unexpanded
        expanded = os.path.join(*[p.replace("{user}", username) for p in parts])
        return expanded

    expanded = _WIN_ENVVAR.sub(_replace, template)
    # Normalise forward slashes
    candidates = [expanded.replace("/", os.sep)]
    return candidates


def _resolve_all_templates(
    raw_paths: List[str],
    os_name: str,
    users: List[str],
) -> List[str]:
    """
    Given a list of raw path templates and a list of known user-profile names,
    return a flat list of on-disk candidate relative paths.
    """
    resolved: List[str] = []
    for raw in raw_paths:
        if os_name in ("Windows",):
            for user in (users or ["*"]):
                for exp in _expand_template(raw, username=user):
                    resolved.append(exp)
        else:
            # macOS / Linux — just strip leading ~/
            p = raw.lstrip("~/")
            for user in (users or ["*"]):
                resolved.append(os.path.join("Users", user, p) if raw.startswith("~") else raw.lstrip("/"))
    # De-duplicate while preserving order
    seen: set = set()
    out: List[str] = []
    for p in resolved:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _evidence_path_exists(evidence_root: str, candidate: str) -> Tuple[bool, Optional[str]]:
    """
    Check whether a candidate path (possibly containing * globs) exists under
    the evidence root.  Returns (found, matched_path).
    """
    if not evidence_root:
        return False, None

    # Normalise separators
    candidate = candidate.replace("/", os.sep).lstrip(os.sep)

    # Fast path: exact match
    full = os.path.join(evidence_root, candidate)
    if os.path.exists(full):
        return True, full

    # Glob match – only if the candidate contains wildcards
    if "*" in candidate or "?" in candidate:
        parts = Path(candidate).parts
        # Walk evidence_root trying to match each segment
        try:
            matches = list(Path(evidence_root).glob(candidate))
            if matches:
                return True, str(matches[0])
        except Exception:
            pass

    return False, None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register_parser
class AIToolScannerParser(BaseParser):
    """
    Scans the evidence tree against the AI tool inventory to produce a
    forensic checklist that documents the presence, absence, or partial
    presence of every registered AI tool.
    """

    PARSER_NAME = "AIToolScannerParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS, OSPlatform.LINUX, OSPlatform.UNKNOWN]
    ARTIFACT_FAMILY = "AI Tool Inventory Scan"
    IS_STUB = False

    # Path to the YAML config relative to this file's package root
    _CONFIG_RELATIVE = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "config", "ai_tool_inventory.yaml"
    )

    def __init__(
        self,
        evidence_root: str,
        user_profile: str = "",
        case_id: str = "",
        evidence_item_id: str = "",
        source_image: str = "",
        os_platform: OSPlatform = OSPlatform.UNKNOWN,
        user_profiles: Optional[List[str]] = None,
        config_path: Optional[str] = None,
    ):
        super().__init__(
            evidence_root=evidence_root,
            user_profile=user_profile,
            case_id=case_id,
            evidence_item_id=evidence_item_id,
            source_image=source_image,
        )
        self.os_platform = os_platform
        self.user_profiles: List[str] = user_profiles or (
            [os.path.basename(user_profile)] if user_profile else []
        )
        self.config_path = config_path or self._CONFIG_RELATIVE
        self.checklist_entries: List[ForensicChecklistEntry] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self) -> ParserResult:
        t0 = time.perf_counter()
        artifacts: List[ArtifactRecord] = []

        if not os.path.isfile(self.config_path):
            return self._make_result(
                status=ParserStatus.ERROR,
                errors=[f"AI tool inventory config not found: {self.config_path}"],
                elapsed_ms=0.0,
            )

        try:
            registry = ToolRegistry(self.config_path)
        except Exception as exc:
            return self._make_result(
                status=ParserStatus.ERROR,
                errors=[f"Failed to load tool registry: {exc}"],
                elapsed_ms=0.0,
            )

        os_name = self._os_label()
        all_tools = registry.all_tools()

        for tool in all_tools:
            if os_name not in tool.platform_supported and os_name != "Unknown":
                # Still produce a NOT_VERIFIED entry for unsupported platforms
                self.checklist_entries.append(self._make_entry(
                    tool=tool,
                    status=EvidenceStatus.NOT_VERIFIED,
                    found_paths=[],
                    notes=f"Tool not supported on detected OS ({os_name}).",
                    caveat_flags=[CaveatFlag.OS_OR_HARDWARE_LIMITATION, CaveatFlag.NEGATIVE_FINDING_SCOPED],
                ))
                continue

            raw_candidates: List[str] = tool.artifact_path_candidates.get(os_name, [])
            if not raw_candidates:
                # Try generic key
                for candidate_os_key in ("Unknown", "all"):
                    raw_candidates = tool.artifact_path_candidates.get(candidate_os_key, [])
                    if raw_candidates:
                        break

            if not raw_candidates:
                self.checklist_entries.append(self._make_entry(
                    tool=tool,
                    status=EvidenceStatus.NOT_VERIFIED,
                    found_paths=[],
                    notes="No artifact path candidates defined for this OS.",
                    caveat_flags=[CaveatFlag.PARSER_LIMITATION, CaveatFlag.NEGATIVE_FINDING_SCOPED],
                ))
                continue

            resolved = _resolve_all_templates(raw_candidates, os_name, self.user_profiles)
            found_paths: List[str] = []
            for candidate in resolved:
                ok, matched = _evidence_path_exists(self.evidence_root, candidate)
                if ok and matched:
                    found_paths.append(matched)

            # Deduplicate
            found_paths = list(dict.fromkeys(found_paths))

            if found_paths:
                status = EvidenceStatus.FOUND
                caveats = self._compute_caveats(tool, status)
                caveats.append(CaveatFlag.PRESENCE_ONLY)
                # Assess evidence-class diversity
                ev_classes = set()
                for p in found_paths:
                    ev_classes.add(self._classify_evidence_path(p, tool))
                if len(ev_classes) <= 1:
                    caveats.append(CaveatFlag.CORROBORATION_LEVEL_LIMITED)
                entry = self._make_entry(
                    tool=tool,
                    status=status,
                    found_paths=found_paths,
                    notes=f"{len(found_paths)} artifact path(s) matched.",
                    caveat_flags=caveats,
                    artifact_count=len(found_paths),
                )
                artifacts.extend(
                    self._paths_to_artifact_records(tool, found_paths)
                )
            else:
                not_found_caveats = self._compute_caveats(tool, EvidenceStatus.NOT_FOUND)
                entry = self._make_entry(
                    tool=tool,
                    status=EvidenceStatus.NOT_FOUND,
                    found_paths=[],
                    notes="No artifact paths located in evidence.",
                    caveat_flags=not_found_caveats,
                )

            self.checklist_entries.append(entry)

        elapsed = (time.perf_counter() - t0) * 1000
        n_found = sum(1 for e in self.checklist_entries if e.evidence_status == EvidenceStatus.FOUND)
        n_total = len(self.checklist_entries)

        # Build structured coverage + gap records
        coverage_records = []
        gap_records = []
        for entry in self.checklist_entries:
            if entry.evidence_status == EvidenceStatus.FOUND:
                coverage_records.append(ArtifactCoverageRecord(
                    platform=AIPlatform.UNKNOWN,
                    os=self.os_platform,
                    artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                    expected_path=", ".join(entry.artifact_paths[:3]),
                    actual_path=", ".join(entry.artifact_paths[:3]),
                    parser_used=self.PARSER_NAME,
                    parser_result_status="FOUND",
                    evidence_count=entry.artifact_count,
                    explanation=f"{entry.tool_name}: {entry.notes}",
                    caveat_text="; ".join(
                        str(f).replace("CaveatFlag.", "")
                        for f in (entry.caveat_flags or [])[:3]
                    ),
                ))
            elif entry.evidence_status == EvidenceStatus.NOT_FOUND:
                gap_records.append(CoverageGapRecord(
                    platform=AIPlatform.UNKNOWN,
                    os=self.os_platform,
                    artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                    gap_reason=f"NOT_FOUND: {entry.tool_name}",
                    explanation=entry.notes,
                    caveat_text="; ".join(
                        str(f).replace("CaveatFlag.", "")
                        for f in (entry.caveat_flags or [])[:3]
                    ),
                ))

        return self._make_result(
            status=ParserStatus.SUCCESS,
            artifacts=artifacts,
            elapsed_ms=elapsed,
            notes=(
                f"AI Tool Scanner: {n_found}/{n_total} tools detected in evidence. "
                f"Checklist has {n_total} entries."
            ),
            artifact_coverage=coverage_records,
            coverage_gaps=gap_records,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _os_label(self) -> str:
        """Map OSPlatform enum to the YAML os_name key."""
        mapping = {
            OSPlatform.WINDOWS: "Windows",
            OSPlatform.MACOS: "macOS",
            OSPlatform.LINUX: "Linux",
            OSPlatform.UNKNOWN: "Unknown",
        }
        return mapping.get(self.os_platform, "Unknown")

    def _compute_caveats(self, tool: ToolRecord, status: EvidenceStatus) -> List[CaveatFlag]:
        """Derive caveats via the tool's surface-class enforcement path."""
        sc = classify_surface(tool)
        if sc == SurfaceClass.BROWSER_FIRST:
            return self._caveats_browser_first(tool, status)
        if sc == SurfaceClass.LOCAL_WEBUI:
            return self._caveats_local_webui(tool, status)
        if sc == SurfaceClass.IDE_CLI:
            return self._caveats_ide_cli(tool, status)
        return self._caveats_native_desktop(tool, status)

    # ------------------------------------------------------------------
    # Surface-class enforcement paths
    # ------------------------------------------------------------------

    def _caveats_browser_first(
        self, tool: ToolRecord, status: EvidenceStatus,
    ) -> List[CaveatFlag]:
        """Browser-first tools: artifacts live in browser history/cookies/localStorage.
        FOUND  → browser access observed, but does not confirm substantive use.
        NOT_FOUND → browser history may have been cleared or private browsing used.
        """
        flags: List[CaveatFlag] = [CaveatFlag.BROWSER_ACCESS_ONLY]
        if status == EvidenceStatus.FOUND:
            flags.append(CaveatFlag.USE_NOT_ESTABLISHED)
            flags.append(CaveatFlag.REMOTE_INFERENCE_POSSIBLE)
        else:
            flags.append(CaveatFlag.BROWSER_HISTORY_CLEARED)
            flags.append(CaveatFlag.PRIVACY_OR_CLEANUP_POSSIBLE)
            flags.append(CaveatFlag.NEGATIVE_FINDING_SCOPED)
        if len(tool.execution_surface) > 1:
            flags.append(CaveatFlag.MULTI_SURFACE_PRODUCT)
        return list(dict.fromkeys(flags))

    def _caveats_local_webui(
        self, tool: ToolRecord, status: EvidenceStatus,
    ) -> List[CaveatFlag]:
        """Local-webui tools: self-hosted servers accessed via localhost.
        FOUND  → install/config artifacts found; localhost browser hits not checked.
        NOT_FOUND → may run in Docker, WSL, or via SSH tunnel.
        """
        flags: List[CaveatFlag] = [CaveatFlag.LOCAL_WEBUI_LOCALHOST_ONLY]
        surfaces = {s.value for s in tool.execution_surface}
        if "DOCKER_CONTAINER" in surfaces or "WSL" in surfaces:
            flags.append(CaveatFlag.LOCAL_WEBUI_CONTAINER_POSSIBLE)
        if status == EvidenceStatus.FOUND:
            flags.append(CaveatFlag.USE_NOT_ESTABLISHED)
            if "SELF_HOSTED_REMOTE" in surfaces:
                flags.append(CaveatFlag.REMOTE_INFERENCE_POSSIBLE)
        else:
            flags.append(CaveatFlag.PORTABLE_INSTALL_POSSIBLE)
            flags.append(CaveatFlag.CUSTOM_PATH_POSSIBLE)
            flags.append(CaveatFlag.NEGATIVE_FINDING_SCOPED)
        if len(tool.execution_surface) > 1:
            flags.append(CaveatFlag.MULTI_SURFACE_PRODUCT)
        return list(dict.fromkeys(flags))

    def _caveats_ide_cli(
        self, tool: ToolRecord, status: EvidenceStatus,
    ) -> List[CaveatFlag]:
        """IDE extensions / terminal CLIs: config dirs, extension manifests, cred files.
        FOUND  → config or extension present; does not establish code-generation use.
        NOT_FOUND → may be installed via dotfiles, SSH remote, or portable IDE.
        """
        flags: List[CaveatFlag] = [CaveatFlag.IDE_CONFIG_NOT_USAGE]
        if "API KEY" in tool.notes.upper() or "TOKEN" in tool.notes.upper() or "CREDENTIAL" in tool.notes.upper():
            flags.append(CaveatFlag.CREDENTIAL_FILE_ONLY)
            flags.append(CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED)
        if status == EvidenceStatus.FOUND:
            flags.append(CaveatFlag.USE_NOT_ESTABLISHED)
        else:
            flags.append(CaveatFlag.PORTABLE_INSTALL_POSSIBLE)
            flags.append(CaveatFlag.CUSTOM_PATH_POSSIBLE)
            flags.append(CaveatFlag.NEGATIVE_FINDING_SCOPED)
        if len(tool.execution_surface) > 1:
            flags.append(CaveatFlag.MULTI_SURFACE_PRODUCT)
        return list(dict.fromkeys(flags))

    def _caveats_native_desktop(
        self, tool: ToolRecord, status: EvidenceStatus,
    ) -> List[CaveatFlag]:
        """Native desktop apps: install dirs, app data, binary signatures.
        FOUND  → installation detected; usage not established.
        NOT_FOUND → may be portable, custom-path, or uninstalled.
        """
        flags: List[CaveatFlag] = []
        surf_labels = [s.value for s in tool.execution_surface]
        if "BROWSER" in surf_labels:
            flags.append(CaveatFlag.BROWSER_ACCESS_ONLY)
        if "REMOTE" in tool.notes.upper() or "API" in tool.category.upper():
            flags.append(CaveatFlag.REMOTE_INFERENCE_POSSIBLE)
        if "PORTABLE" in tool.notes.upper():
            flags.append(CaveatFlag.PORTABLE_INSTALL_POSSIBLE)
        if "CLOUD_SYNC" in tool.notes.upper() or "SYNC" in tool.notes.upper():
            flags.append(CaveatFlag.CLOUD_SYNC_POSSIBLE)
        if "API KEY" in tool.notes.upper() or "CREDENTIAL" in tool.category.upper():
            flags.append(CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED)
        if len(tool.execution_surface) > 1:
            flags.append(CaveatFlag.MULTI_SURFACE_PRODUCT)
        if status == EvidenceStatus.FOUND:
            flags.append(CaveatFlag.USE_NOT_ESTABLISHED)
        else:
            flags.append(CaveatFlag.NEGATIVE_FINDING_SCOPED)
            flags.append(CaveatFlag.PORTABLE_INSTALL_POSSIBLE)
            flags.append(CaveatFlag.CUSTOM_PATH_POSSIBLE)
        return list(dict.fromkeys(flags))

    def _make_entry(
        self,
        tool: ToolRecord,
        status: EvidenceStatus,
        found_paths: List[str],
        notes: str,
        caveat_flags: Optional[List[CaveatFlag]] = None,
        artifact_count: int = 0,
    ) -> ForensicChecklistEntry:
        """Build a ForensicChecklistEntry from scan results."""
        # Map status → corroboration level
        if status == EvidenceStatus.FOUND and artifact_count >= 2:
            # Check evidence-class diversity for higher corroboration
            ev_classes = set()
            for p in found_paths:
                ev_classes.add(self._classify_evidence_path(p, tool))
            if len(ev_classes) >= 2:
                corr = CorroborationLevel.LEVEL_2_CONFIGURATION_OR_WORKSPACE_INDICATORS
            else:
                corr = CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY
        else:
            corr = CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY

        from ..tool_registry import AttributionScope
        # Default attribution: if browser-only, device-level; otherwise user-profile
        surf_labels = [s.value for s in tool.execution_surface]
        if "BROWSER" in surf_labels and len(surf_labels) == 1:
            attr_scope = AttributionScope.DEVICE_LEVEL_ONLY
        elif status == EvidenceStatus.FOUND:
            attr_scope = AttributionScope.USER_PROFILE_LINKED
        else:
            attr_scope = AttributionScope.PERSON_ATTRIBUTION_NOT_ESTABLISHED

        return ForensicChecklistEntry(
            tool_id=tool.tool_id,
            tool_name=tool.tool_name,
            category=tool.category,
            artifact_paths=found_paths,
            evidence_status=status,
            notes=notes,
            detection_method=tool.detection_method,
            execution_surface=", ".join(surf_labels),
            inference_location=(
                "LOCAL" if any(
                    kw in tool.category for kw in ("Local LLM", "Image Generator")
                ) else "REMOTE" if "Browser" in tool.category or "Web" in tool.category
                else "UNKNOWN"
            ),
            confidence=(
                "HIGH" if status == EvidenceStatus.FOUND and artifact_count >= 2
                else "MEDIUM" if status == EvidenceStatus.FOUND
                else "N/A"
            ),
            caveat_flags=caveat_flags or [],
            acquisition_source="FORENSIC_IMAGE" if self.source_image else "FILE_COLLECTION",
            artifact_count=artifact_count,
            corroboration_level=corr,
            attribution_scope=attr_scope,
            parser_coverage_status=(
                "COVERED" if status in (EvidenceStatus.FOUND, EvidenceStatus.NOT_FOUND)
                else "NOT_COVERED"
            ),
        )

    def _paths_to_artifact_records(
        self,
        tool: ToolRecord,
        found_paths: List[str],
    ) -> List[ArtifactRecord]:
        """
        Convert matched filesystem paths into lightweight ArtifactRecords so
        they appear in the main artifact table of the report.

        Each artifact is tagged with an evidence_class (A–F) based on path
        heuristics so that downstream claim-ladder and corroboration gates
        can distinguish presence from usage.
        """
        records: List[ArtifactRecord] = []
        for path in found_paths:
            try:
                stat = os.stat(path)
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            except OSError:
                mtime = None

            ev_class = self._classify_evidence_path(path, tool)

            rec = ArtifactRecord(
                evidence_item_id=self.evidence_item_id,
                case_id=self.case_id,
                artifact_family=ArtifactFamily.INSTALL_ARTIFACTS,
                suspected_platform=AIPlatform.UNKNOWN,
                artifact_type=tool.tool_name,
                confidence=ConfidenceLevel.MEDIUM,
                classification=EvidenceClassification.CIRCUMSTANTIAL,
                suspected_access_mode=AccessMode.READ_ONLY,
                artifact_path=path,
                source_image=self.source_image or "",
                attribution_layer=AttributionLayer.DEVICE,
                notes=(
                    f"AI Tool Scanner detected: {tool.tool_name} "
                    f"({tool.category}). Evidence class: {ev_class}. {tool.notes}"
                ),
                timestamp=mtime,
                timestamp_type=TimestampType.FILESYSTEM_MODIFIED,
            )
            records.append(rec)
        return records

    # ------------------------------------------------------------------
    # Evidence-path classification (A–F)
    # ------------------------------------------------------------------

    #: Heuristic keyword sets for classifying artifact paths into evidence
    #: classes.  Order matters: first match wins.
    _EVIDENCE_CLASS_RULES: List[Tuple[str, List[str]]] = [
        # F – Attribution (account tokens, login state)
        ("F-Attribution", ["auth", "token", "credential", "login", "session",
                           "cookie", "oauth", "api_key", "apikey", ".env"]),
        # E – Output (generated content, exports)
        ("E-Output", ["output", "export", "generated", "download", "result",
                       "completion", "response"]),
        # D – Usage/Interaction (history, logs, cache of interactions)
        ("D-Usage", ["history", "chat", "conversation", "prompt", "log",
                      "usage", "recent", "cache", "local_storage",
                      "localstorage", "indexeddb"]),
        # C – Execution (prefetch, event logs, process evidence)
        ("C-Execution", ["prefetch", "event", "amcache", "shimcache",
                          "userassist", "bam", ".exe", "run", "mru"]),
        # B – Configuration (settings, prefs, workspace config)
        ("B-Configuration", ["config", "setting", "preference", "pref",
                              "workspace", "extension", "manifest",
                              "globalStorage", "plugin"]),
        # A – Presence/Install (install dirs, binaries, packages)
        ("A-Presence", ["program", "install", "app", "bin", "package",
                         ".ollama", ".claude", ".cursor", "copilot"]),
    ]

    def _classify_evidence_path(self, path: str, tool: ToolRecord) -> str:
        """
        Classify a matched artifact path into an evidence class (A–F).

        Returns one of:
          A-Presence, B-Configuration, C-Execution, D-Usage,
          E-Output, F-Attribution
        """
        path_lower = path.lower().replace("\\", "/")
        for ev_class, keywords in self._EVIDENCE_CLASS_RULES:
            if any(kw in path_lower for kw in keywords):
                return ev_class
        return "A-Presence"  # Default: treat unclassified as presence
