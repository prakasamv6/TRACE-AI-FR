# ai_usage_evidence_analyzer/tool_registry.py
"""
AI Tool Registry: Extensible registry for AI desktop tools, IDE extensions, local LLMs, and related products.
Supports per-tool, per-OS artifact path templates, detection rules, and metadata for forensic analysis.
"""

import yaml
from enum import Enum, auto
from typing import List, Dict, Optional, Any

class EvidenceStatus(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    NOT_VERIFIED = "NOT_VERIFIED"
    PARTIAL = "PARTIAL"

class ExecutionSurface(str, Enum):
    DESKTOP_APP = "DESKTOP_APP"
    BROWSER = "BROWSER"
    IDE_EXTENSION = "IDE_EXTENSION"
    TERMINAL = "TERMINAL"
    DOCKER_CONTAINER = "DOCKER_CONTAINER"
    WSL = "WSL"
    SELF_HOSTED_REMOTE = "SELF_HOSTED_REMOTE"
    UNKNOWN = "UNKNOWN"

class InferenceLocation(str, Enum):
    LOCAL = "LOCAL"
    REMOTE = "REMOTE"
    UNKNOWN = "UNKNOWN"

class AcquisitionSource(str, Enum):
    LIVE_HOST = "LIVE_HOST"
    FORENSIC_IMAGE = "FORENSIC_IMAGE"
    LOGICAL_EXPORT = "LOGICAL_EXPORT"
    FILE_COLLECTION = "FILE_COLLECTION"
    UNKNOWN = "UNKNOWN"

class AttributionScope(str, Enum):
    DEVICE_LEVEL_ONLY = "DEVICE_LEVEL_ONLY"
    USER_PROFILE_LINKED = "USER_PROFILE_LINKED"
    ACCOUNT_LINKED = "ACCOUNT_LINKED"
    PERSON_ATTRIBUTION_NOT_ESTABLISHED = "PERSON_ATTRIBUTION_NOT_ESTABLISHED"
    UNKNOWN = "UNKNOWN"

class CorroborationLevel(str, Enum):
    LEVEL_1_PRESENCE_OR_ACCESS_ONLY = "LEVEL_1_PRESENCE_OR_ACCESS_ONLY"
    LEVEL_2_CONFIGURATION_OR_WORKSPACE_INDICATORS = "LEVEL_2_CONFIGURATION_OR_WORKSPACE_INDICATORS"
    LEVEL_3_INTERACTION_OR_WORKFLOW_INDICATORS = "LEVEL_3_INTERACTION_OR_WORKFLOW_INDICATORS"
    LEVEL_4_OUTPUT_LINKED_OR_TASK_LINKED_CORROBORATION = "LEVEL_4_OUTPUT_LINKED_OR_TASK_LINKED_CORROBORATION"

class CaveatFlag(str, Enum):
    PRESENCE_ONLY = "PRESENCE_ONLY"
    PARTIAL = "PARTIAL"
    USE_NOT_ESTABLISHED = "USE_NOT_ESTABLISHED"
    ATTRIBUTION_NOT_ESTABLISHED = "ATTRIBUTION_NOT_ESTABLISHED"
    BROWSER_ACCESS_ONLY = "BROWSER_ACCESS_ONLY"
    REMOTE_INFERENCE_POSSIBLE = "REMOTE_INFERENCE_POSSIBLE"
    SECONDARY_ARTIFACTS_ONLY = "SECONDARY_ARTIFACTS_ONLY"
    MULTI_SURFACE_PRODUCT = "MULTI_SURFACE_PRODUCT"
    PORTABLE_INSTALL_POSSIBLE = "PORTABLE_INSTALL_POSSIBLE"
    CUSTOM_PATH_POSSIBLE = "CUSTOM_PATH_POSSIBLE"
    OS_OR_HARDWARE_LIMITATION = "OS_OR_HARDWARE_LIMITATION"
    TIMESTAMP_INTERPRETATION_LIMITED = "TIMESTAMP_INTERPRETATION_LIMITED"
    NEGATIVE_FINDING_SCOPED = "NEGATIVE_FINDING_SCOPED"
    PRIVACY_OR_CLEANUP_POSSIBLE = "PRIVACY_OR_CLEANUP_POSSIBLE"
    PARSER_LIMITATION = "PARSER_LIMITATION"
    ENCRYPTED_OR_INACCESSIBLE = "ENCRYPTED_OR_INACCESSIBLE"
    MULTI_USER_CONTEXT = "MULTI_USER_CONTEXT"
    CLOUD_SYNC_POSSIBLE = "CLOUD_SYNC_POSSIBLE"
    OUTPUT_GENERATOR_NOT_CONFIRMED = "OUTPUT_GENERATOR_NOT_CONFIRMED"
    INSUFFICIENT_BASIS_FOR_CONCLUSION = "INSUFFICIENT_BASIS_FOR_CONCLUSION"
    CHAIN_OF_CUSTODY_METADATA_RECORDED = "CHAIN_OF_CUSTODY_METADATA_RECORDED"
    # Surface-class-specific caveats
    LOCAL_WEBUI_LOCALHOST_ONLY = "LOCAL_WEBUI_LOCALHOST_ONLY"
    LOCAL_WEBUI_CONTAINER_POSSIBLE = "LOCAL_WEBUI_CONTAINER_POSSIBLE"
    IDE_CONFIG_NOT_USAGE = "IDE_CONFIG_NOT_USAGE"
    CREDENTIAL_FILE_ONLY = "CREDENTIAL_FILE_ONLY"
    BROWSER_HISTORY_CLEARED = "BROWSER_HISTORY_CLEARED"
    # Evidence-path and enforcement caveats
    PERSON_LEVEL_ATTRIBUTION_NOT_ESTABLISHED = "PERSON_LEVEL_ATTRIBUTION_NOT_ESTABLISHED"
    LOCAL_INFERENCE_NOT_ESTABLISHED = "LOCAL_INFERENCE_NOT_ESTABLISHED"
    STANDALONE_BINARY_POSSIBLE = "STANDALONE_BINARY_POSSIBLE"
    BROWSER_FIRST_TOOL = "BROWSER_FIRST_TOOL"
    SELF_HOSTED_OR_LOCAL_WEBUI_POSSIBLE = "SELF_HOSTED_OR_LOCAL_WEBUI_POSSIBLE"
    IDE_SURFACE_ONLY = "IDE_SURFACE_ONLY"
    CLI_SURFACE_ONLY = "CLI_SURFACE_ONLY"
    REMOTE_SESSION_POSSIBLE = "REMOTE_SESSION_POSSIBLE"
    ACQUISITION_SCOPE_LIMITED = "ACQUISITION_SCOPE_LIMITED"
    CORROBORATION_LEVEL_LIMITED = "CORROBORATION_LEVEL_LIMITED"


class SurfaceClass(str, Enum):
    """
    High-level enforcement class for AI tools.  Each class defines how the
    tool primarily leaves artifacts and therefore how FOUND / NOT_FOUND /
    PARTIAL findings should be interpreted.
    """
    BROWSER_FIRST = "BROWSER_FIRST"
    LOCAL_WEBUI = "LOCAL_WEBUI"
    IDE_CLI = "IDE_CLI"
    NATIVE_DESKTOP = "NATIVE_DESKTOP"


# Categories that map to each surface class
_BROWSER_FIRST_CATEGORIES = {"Web Assistant", "Enterprise AI"}
_LOCAL_WEBUI_CATEGORIES = {"Image Generator"}
_IDE_CLI_CATEGORIES = {"IDE Extension", "Terminal CLI", "API Credential"}


def classify_surface(tool: "ToolRecord") -> SurfaceClass:
    """
    Classify a tool into its enforcement surface class based on its
    execution surfaces and category.
    """
    surfaces = {s.value for s in tool.execution_surface}

    # Category-based overrides (most reliable signal)
    if tool.category in _IDE_CLI_CATEGORIES:
        return SurfaceClass.IDE_CLI
    if tool.category in _BROWSER_FIRST_CATEGORIES:
        return SurfaceClass.BROWSER_FIRST
    if tool.category in _LOCAL_WEBUI_CATEGORIES:
        return SurfaceClass.LOCAL_WEBUI

    # Surface-based classification
    has_browser = "BROWSER" in surfaces
    has_desktop = "DESKTOP_APP" in surfaces
    has_ide = "IDE_EXTENSION" in surfaces
    has_terminal = "TERMINAL" in surfaces
    has_container = "DOCKER_CONTAINER" in surfaces
    has_self_hosted = "SELF_HOSTED_REMOTE" in surfaces

    if has_container or has_self_hosted:
        return SurfaceClass.LOCAL_WEBUI
    if has_ide or has_terminal:
        return SurfaceClass.IDE_CLI
    if has_browser and not has_desktop:
        return SurfaceClass.BROWSER_FIRST
    if has_desktop:
        # Local LLM desktop apps that also serve a web UI
        if tool.category == "Local LLM" and (has_self_hosted or has_browser):
            return SurfaceClass.LOCAL_WEBUI
        return SurfaceClass.NATIVE_DESKTOP

    return SurfaceClass.NATIVE_DESKTOP

class ToolRecord:
    def __init__(self, tool_id: str, tool_name: str, vendor: str, category: str,
                 platform_supported: List[str], execution_surface: List[ExecutionSurface],
                 artifact_path_candidates: Dict[str, List[str]], detection_method: str,
                 notes: str = "", rule_version: str = "1.0.0"):
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.vendor = vendor
        self.category = category
        self.platform_supported = platform_supported
        self.execution_surface = execution_surface
        self.artifact_path_candidates = artifact_path_candidates
        self.detection_method = detection_method
        self.notes = notes
        self.rule_version = rule_version

class ToolRegistry:
    def __init__(self, config_path: str):
        self.tools: Dict[str, ToolRecord] = {}
        self.load_from_config(config_path)

    def load_from_config(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        for tool in data.get("tools", []):
            record = ToolRecord(
                tool_id=tool["tool_id"],
                tool_name=tool["tool_name"],
                vendor=tool["vendor"],
                category=tool["category"],
                platform_supported=tool["platform_supported"],
                execution_surface=[ExecutionSurface(s) for s in tool["execution_surface"]],
                artifact_path_candidates=tool["artifact_path_candidates"],
                detection_method=tool["detection_method"],
                notes=tool.get("notes", ""),
                rule_version=tool.get("rule_version", "1.0.0")
            )
            self.tools[record.tool_id] = record

    def get_tool(self, tool_id: str) -> Optional[ToolRecord]:
        return self.tools.get(tool_id)

    def all_tools(self) -> List[ToolRecord]:
        return list(self.tools.values())

    def find_by_surface(self, surface: ExecutionSurface) -> List[ToolRecord]:
        return [t for t in self.tools.values() if surface in t.execution_surface]

    def find_by_category(self, category: str) -> List[ToolRecord]:
        return [t for t in self.tools.values() if t.category == category]

    def candidate_paths(self, tool_id: str, os_name: str) -> List[str]:
        tool = self.get_tool(tool_id)
        if not tool:
            return []
        return tool.artifact_path_candidates.get(os_name, [])
