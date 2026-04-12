# ai_usage_evidence_analyzer/forensic_checklist.py
"""
Forensic Checklist Generator: Produces structured checklist output for AI tool detection, artifact analysis, and evidence status.
Integrates with ToolRegistry and parser results. Supports export to CSV, JSON, and report-ready tables.
"""

import csv
import json
from typing import List, Dict, Any
from .tool_registry import ToolRegistry, EvidenceStatus, CaveatFlag, CorroborationLevel, AttributionScope

class ForensicChecklistEntry:
    def __init__(self, tool_id: str, tool_name: str, category: str, artifact_paths: List[str],
                 evidence_status: EvidenceStatus, notes: str = "",
                 detection_method: str = "", execution_surface: str = "", inference_location: str = "UNKNOWN",
                 confidence: str = "", caveat_flags: List[CaveatFlag] = None, acquisition_source: str = "UNKNOWN",
                 artifact_count: int = 0, corroboration_level: CorroborationLevel = CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY,
                 attribution_scope: AttributionScope = AttributionScope.UNKNOWN, parser_coverage_status: str = ""):
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.category = category
        self.artifact_paths = artifact_paths
        self.evidence_status = evidence_status
        self.notes = notes
        self.detection_method = detection_method
        self.execution_surface = execution_surface
        self.inference_location = inference_location
        self.confidence = confidence
        self.caveat_flags = caveat_flags or []
        self.acquisition_source = acquisition_source
        self.artifact_count = artifact_count
        self.corroboration_level = corroboration_level
        self.attribution_scope = attribution_scope
        self.parser_coverage_status = parser_coverage_status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Tool Name": self.tool_name,
            "Category": self.category,
            "Likely Artifact Paths": ", ".join(self.artifact_paths),
            "Evidence Status": self.evidence_status,
            "Notes": self.notes,
            "Detection Method": self.detection_method,
            "Execution Surface": self.execution_surface,
            "Inference Location": self.inference_location,
            "Confidence": self.confidence,
            "Caveat Flags": ", ".join([str(f) for f in self.caveat_flags]),
            "Acquisition Source": self.acquisition_source,
            "Artifact Count": self.artifact_count,
            "Corroboration Level": self.corroboration_level,
            "Attribution Scope": self.attribution_scope,
            "Parser Coverage Status": self.parser_coverage_status,
        }

class ForensicChecklistGenerator:
    def __init__(self, tool_registry: ToolRegistry):
        self.tool_registry = tool_registry
        self.entries: List[ForensicChecklistEntry] = []

    def add_entry(self, entry: ForensicChecklistEntry):
        self.entries.append(entry)

    def generate_from_scan(self, scan_results: List[Dict[str, Any]]):
        # scan_results: [{tool_id, evidence_status, artifact_paths, ...}]
        for result in scan_results:
            tool = self.tool_registry.get_tool(result["tool_id"])
            if not tool:
                continue
            entry = ForensicChecklistEntry(
                tool_id=tool.tool_id,
                tool_name=tool.tool_name,
                category=tool.category,
                artifact_paths=result.get("artifact_paths", []),
                evidence_status=result.get("evidence_status", EvidenceStatus.NOT_VERIFIED),
                notes=result.get("notes", ""),
                detection_method=tool.detection_method,
                execution_surface=", ".join([str(s) for s in tool.execution_surface]),
                inference_location=result.get("inference_location", "UNKNOWN"),
                confidence=result.get("confidence", ""),
                caveat_flags=result.get("caveat_flags", []),
                acquisition_source=result.get("acquisition_source", "UNKNOWN"),
                artifact_count=result.get("artifact_count", 0),
                corroboration_level=result.get("corroboration_level", CorroborationLevel.LEVEL_1_PRESENCE_OR_ACCESS_ONLY),
                attribution_scope=result.get("attribution_scope", AttributionScope.UNKNOWN),
                parser_coverage_status=result.get("parser_coverage_status", "")
            )
            self.add_entry(entry)

    def to_csv(self, path: str):
        if not self.entries:
            return
        with open(path, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(self.entries[0].to_dict().keys()))
            writer.writeheader()
            for entry in self.entries:
                writer.writerow(entry.to_dict())

    def to_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self.entries], f, indent=2)

    def as_table(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries]
