"""
Evidence Exhibit Manager.

Manages forensic evidence exhibits (screenshots, file references, database
excerpts) with proper E01 source paths. Every exhibit is tracked with:
  - Sequential exhibit number (Exhibit 1, Exhibit 2, …)
  - Description of what the exhibit shows
  - Full evidence path FROM THE E01 / evidence source
  - Artifact family and platform association
  - Optional screenshot path (if extracted/captured)

Per SANS / NIST forensic report standards:
  - Every finding must reference its source evidence by exhibit
  - Exhibits must include the full path within the evidence image
  - Screenshots should be captured at time of analysis
  - No finding should be presented without a supporting exhibit
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EvidenceExhibit:
    """A single piece of evidence referenced in the report."""
    exhibit_number: int = 0
    title: str = ""
    description: str = ""
    evidence_path: str = ""          # Path INSIDE the E01 / evidence root
    evidence_source: str = ""        # E01 filename or evidence root directory
    artifact_family: str = ""
    platform: str = ""
    confidence: str = ""
    timestamp: Optional[str] = None
    screenshot_path: Optional[str] = None  # Path to screenshot in output dir
    extracted_indicator: str = ""
    file_hash: Optional[str] = None  # Hash of the source artifact file
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exhibit_number": self.exhibit_number,
            "title": self.title,
            "description": self.description,
            "evidence_path": self.evidence_path,
            "evidence_source": self.evidence_source,
            "artifact_family": self.artifact_family,
            "platform": self.platform,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "screenshot_path": self.screenshot_path,
            "extracted_indicator": self.extracted_indicator,
            "file_hash": self.file_hash,
            "notes": self.notes,
        }

    @property
    def full_evidence_reference(self) -> str:
        """Full reference string: evidence_source / evidence_path."""
        if self.evidence_source and self.evidence_path:
            return f"{os.path.basename(self.evidence_source)}:/{self.evidence_path}"
        return self.evidence_path or "(path unavailable)"

    @property
    def figure_caption(self) -> str:
        """Generate figure caption for the exhibit."""
        return f"Figure {self.exhibit_number}: {self.title}"


class ExhibitManager:
    """
    Manages the collection of evidence exhibits for a forensic report.

    Usage:
        mgr = ExhibitManager(output_dir="./output", evidence_source="case.E01")
        ex = mgr.add_exhibit(
            title="Chrome History — ChatGPT Access",
            description="Browser history record showing access to chat.openai.com",
            evidence_path="Users/JDoe/AppData/Local/Google/Chrome/User Data/Default/History",
            artifact_family="Browser History",
            platform="ChatGPT",
            confidence="Moderate",
        )
        # ex.exhibit_number == 1
    """

    def __init__(self, output_dir: str, evidence_source: str = ""):
        self.output_dir = output_dir
        self.evidence_source = evidence_source
        self.exhibits: List[EvidenceExhibit] = []
        self._counter = 0

        # Create exhibits sub-directory for screenshots
        self.exhibits_dir = os.path.join(output_dir, "exhibits")
        os.makedirs(self.exhibits_dir, exist_ok=True)

    def add_exhibit(
        self,
        title: str,
        description: str,
        evidence_path: str,
        artifact_family: str = "",
        platform: str = "",
        confidence: str = "",
        timestamp: Optional[str] = None,
        extracted_indicator: str = "",
        notes: str = "",
        source_file_path: Optional[str] = None,
    ) -> EvidenceExhibit:
        """
        Register a new evidence exhibit.

        Args:
            title: Short title for the exhibit (e.g., "Chrome History — ChatGPT")
            description: What the exhibit shows
            evidence_path: Path WITHIN the E01/evidence image
            artifact_family: Artifact family name
            platform: AI platform name
            confidence: Confidence level string
            timestamp: Timestamp of the artifact
            extracted_indicator: The actual indicator value
            notes: Additional notes
            source_file_path: Absolute path on examiner workstation (for screenshot/hash)

        Returns:
            The created EvidenceExhibit with assigned exhibit number.
        """
        self._counter += 1

        exhibit = EvidenceExhibit(
            exhibit_number=self._counter,
            title=title,
            description=description,
            evidence_path=evidence_path,
            evidence_source=self.evidence_source,
            artifact_family=artifact_family,
            platform=platform,
            confidence=confidence,
            timestamp=timestamp,
            extracted_indicator=extracted_indicator,
            notes=notes,
        )

        # If source file exists, compute hash and optionally copy
        if source_file_path and os.path.isfile(source_file_path):
            exhibit.file_hash = self._compute_file_hash(source_file_path)
            # Copy the artifact as a screenshot / reference copy
            self._capture_screenshot(exhibit, source_file_path)

        self.exhibits.append(exhibit)
        logger.info(f"Exhibit {self._counter}: {title} — {evidence_path}")
        return exhibit

    def add_exhibit_from_artifact(self, artifact, evidence_root: str = "") -> EvidenceExhibit:
        """
        Create an exhibit directly from an ArtifactRecord.

        Args:
            artifact: An ArtifactRecord dataclass instance.
            evidence_root: The evidence root directory on disk.

        Returns:
            The created EvidenceExhibit.
        """
        ts_str = None
        if artifact.timestamp:
            ts_str = artifact.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        source_file = None
        if evidence_root and artifact.artifact_path:
            candidate = os.path.join(evidence_root, artifact.artifact_path)
            if os.path.isfile(candidate):
                source_file = candidate

        return self.add_exhibit(
            title=f"{artifact.artifact_family.value} — {artifact.suspected_platform.value}",
            description=(
                f"{artifact.artifact_type or artifact.artifact_family.value} artifact "
                f"indicating {artifact.suspected_platform.value} access"
            ),
            evidence_path=artifact.artifact_path or "(embedded/parsed)",
            artifact_family=artifact.artifact_family.value,
            platform=artifact.suspected_platform.value,
            confidence=artifact.confidence.value,
            timestamp=ts_str,
            extracted_indicator=artifact.extracted_indicator[:200] if artifact.extracted_indicator else "",
            notes=artifact.notes[:200] if artifact.notes else "",
            source_file_path=source_file,
        )

    def get_exhibit(self, number: int) -> Optional[EvidenceExhibit]:
        """Get exhibit by number."""
        for ex in self.exhibits:
            if ex.exhibit_number == number:
                return ex
        return None

    def get_exhibits_for_platform(self, platform: str) -> List[EvidenceExhibit]:
        """Get all exhibits for a given AI platform."""
        return [ex for ex in self.exhibits if ex.platform == platform]

    def get_all(self) -> List[EvidenceExhibit]:
        """Return all exhibits in order."""
        return list(self.exhibits)

    def to_dicts(self) -> List[Dict[str, Any]]:
        """Serialize all exhibits for JSON export."""
        return [ex.to_dict() for ex in self.exhibits]

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _compute_file_hash(self, filepath: str) -> str:
        """Compute MD5 hash of a file for exhibit integrity."""
        md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
            return md5.hexdigest()
        except OSError as e:
            logger.warning(f"Could not hash exhibit file {filepath}: {e}")
            return ""

    def _capture_screenshot(self, exhibit: EvidenceExhibit, source_path: str):
        """
        Copy/reference the source artifact into the exhibits folder.

        For binary database files (SQLite, etc.), we copy the file.
        For text files, we copy as-is.
        The path is recorded as the screenshot_path on the exhibit.
        """
        try:
            ext = os.path.splitext(source_path)[1] or ".bin"
            safe_name = f"exhibit_{exhibit.exhibit_number:03d}{ext}"
            dest = os.path.join(self.exhibits_dir, safe_name)
            shutil.copy2(source_path, dest)
            exhibit.screenshot_path = os.path.join("exhibits", safe_name)
            logger.debug(f"Exhibit {exhibit.exhibit_number}: captured to {dest}")
        except OSError as e:
            logger.warning(f"Could not capture exhibit file: {e}")


def generate_exhibit_reference_md(exhibit: EvidenceExhibit) -> str:
    """
    Generate a Markdown exhibit reference block suitable for embedding
    in a forensic report.
    """
    lines = []
    lines.append(f"> **Exhibit {exhibit.exhibit_number}: {exhibit.title}**")
    lines.append(f">")
    lines.append(f"> {exhibit.description}")
    lines.append(f">")
    lines.append(f"> - **E01 Source Path:** `{exhibit.full_evidence_reference}`")
    if exhibit.timestamp:
        lines.append(f"> - **Timestamp:** {exhibit.timestamp}")
    if exhibit.extracted_indicator:
        lines.append(f"> - **Indicator:** {exhibit.extracted_indicator[:150]}")
    lines.append(f"> - **Confidence:** {exhibit.confidence}")
    if exhibit.file_hash:
        lines.append(f"> - **Artifact Hash (MD5):** `{exhibit.file_hash}`")
    if exhibit.screenshot_path:
        lines.append(f">")
        lines.append(f"> *See attached: [{exhibit.screenshot_path}]({exhibit.screenshot_path})*")
    lines.append("")
    return "\n".join(lines)


def generate_exhibit_reference_html(exhibit: EvidenceExhibit) -> str:
    """
    Generate an HTML exhibit reference block.
    """
    html = f"""<div class="exhibit-block" id="exhibit-{exhibit.exhibit_number}">
    <h4>Exhibit {exhibit.exhibit_number}: {exhibit.title}</h4>
    <p>{exhibit.description}</p>
    <table class="exhibit-meta">
        <tr><td><strong>E01 Source Path:</strong></td><td><code>{exhibit.full_evidence_reference}</code></td></tr>"""

    if exhibit.timestamp:
        html += f"""
        <tr><td><strong>Timestamp:</strong></td><td>{exhibit.timestamp}</td></tr>"""
    if exhibit.extracted_indicator:
        html += f"""
        <tr><td><strong>Indicator:</strong></td><td>{exhibit.extracted_indicator[:150]}</td></tr>"""

    html += f"""
        <tr><td><strong>Confidence:</strong></td><td>{exhibit.confidence}</td></tr>"""

    if exhibit.file_hash:
        html += f"""
        <tr><td><strong>Artifact Hash (MD5):</strong></td><td><code>{exhibit.file_hash}</code></td></tr>"""

    html += """
    </table>"""

    if exhibit.screenshot_path:
        html += f"""
    <p class="exhibit-attachment"><em>See attached: <a href="{exhibit.screenshot_path}">{exhibit.screenshot_path}</a></em></p>"""

    html += """
</div>"""
    return html
