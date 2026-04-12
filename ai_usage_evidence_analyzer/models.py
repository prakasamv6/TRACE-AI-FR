"""
Core data models for TRACE-AI-FR
(Trace Reconstruction and Adjudication for Corroborated Endpoint
AI Evidence with Forensic Rigor).

All forensic findings, artifacts, evidence records, FRAUEs,
governance records, and validation states are represented using
these strongly-typed data models based on Python dataclasses.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AIPlatform(str, Enum):
    CHATGPT = "ChatGPT"
    CLAUDE = "Claude"
    GEMINI = "Gemini"
    COPILOT = "Copilot"
    GRAMMARLY = "Grammarly"
    PERPLEXITY = "Perplexity"
    DEEPSEEK = "DeepSeek"
    YOUCOM = "You.com"
    META_AI = "Meta AI"
    GROK = "Grok"
    POE = "Poe"
    UNKNOWN = "Unknown"


class AIModel(str, Enum):
    GPT4 = "GPT-4"
    GPT4_TURBO = "GPT-4 Turbo"
    GPT4O = "GPT-4o"
    CLAUDE_3_OPUS = "Claude 3 Opus"
    CLAUDE_3_SONNET = "Claude 3 Sonnet"
    CLAUDE_3_HAIKU = "Claude 3 Haiku"
    CLAUDE_35_SONNET = "Claude 3.5 Sonnet"
    GEMINI_PRO = "Gemini Pro"
    GEMINI_ULTRA = "Gemini Ultra"
    GEMINI_15_PRO = "Gemini 1.5 Pro"
    COPILOT_GPT4 = "Copilot GPT-4"
    PERPLEXITY_ONLINE = "Perplexity Online"
    LLAMA_3 = "Llama 3"
    GROK_2 = "Grok-2"
    UNKNOWN = "Unknown"


class AccessMode(str, Enum):
    BROWSER = "Browser"
    NATIVE_APP = "Native App"
    READ_ONLY = "Read Only"
    UNKNOWN = "Unknown"


class ConfidenceLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    MODERATE = "Moderate"
    LOW = "Low"
    UNSUPPORTED = "Unsupported"


class EvidenceClassification(str, Enum):
    DIRECT = "Direct"
    CIRCUMSTANTIAL = "Circumstantial"
    INFERRED = "Inferred"


class AttributionLayer(str, Enum):
    PLATFORM = "Platform"
    MODEL = "Model"
    CONTENT = "Content"
    DEVICE = "Device"


class ArtifactFamily(str, Enum):
    BROWSER_HISTORY = "Browser History"
    BROWSER_DOWNLOADS = "Browser Downloads"
    BROWSER_COOKIES = "Browser Cookies"
    BROWSER_LOCAL_STORAGE = "Browser Local Storage"
    BROWSER_SESSION = "Browser Session"
    BROWSER_CACHE = "Browser Cache"
    NATIVE_APP = "Native Application"
    OS_EXECUTION = "OS Execution Trace"
    OS_RECENT_FILES = "OS Recent Files"
    OS_REGISTRY = "OS Registry"
    OS_EVENT_LOG = "OS Event Log"
    OS_PLIST = "OS Plist"
    OS_UNIFIED_LOG = "OS Unified Log"
    FILE_SYSTEM = "File System"
    USER_CONTENT = "User Content"
    CLIPBOARD = "Clipboard"
    SCREENSHOT = "Screenshot"
    NOTIFICATION = "Notification"
    INSTALL_ARTIFACTS = "Install Artifacts"
    UNKNOWN = "Unknown"


class OSPlatform(str, Enum):
    WINDOWS = "Windows"
    MACOS = "macOS"
    LINUX = "Linux"
    IPHONE = "iPhone"
    UNKNOWN = "Unknown"


class ImageType(str, Enum):
    FULL_DISK = "Full Disk Image"
    LOGICAL = "Logical Image"
    TRIAGE = "Triage Collection"
    PARTIAL = "Partial Evidence Container"
    UNKNOWN = "Unknown"


class TimestampType(str, Enum):
    CREATED = "Created"
    MODIFIED = "Modified"
    ACCESSED = "Accessed"
    FILESYSTEM_MODIFIED = "Filesystem Modified"
    ENTRY_CREATED = "Entry Created"
    LAST_VISITED = "Last Visited"
    EXPIRY = "Expiry"
    SESSION_START = "Session Start"
    SESSION_END = "Session End"
    EXECUTION = "Execution"
    UNKNOWN = "Unknown"


class ParserStatus(str, Enum):
    SUCCESS = "Success"
    PARTIAL = "Partial"
    FAILED = "Failed"
    ERROR = "Error"
    NOT_APPLICABLE = "Not Applicable"
    STUB = "Stub (Not Implemented)"
    SKIPPED = "Skipped"


# ---------------------------------------------------------------------------
# TRACE-AI-FR framework enumerations
# ---------------------------------------------------------------------------

class ClaimLevel(str, Enum):
    """Four-level claim ladder (Section: Claim Ladder)."""
    ARTIFACT_OBSERVATION = "Level 1 — Artifact Observation"
    PLATFORM_PRESENCE = "Level 2 — Platform Presence"
    FRAUE_RECONSTRUCTION = "Level 3 — FRAUE Reconstruction"
    GOVERNED_CONCLUSION = "Level 4 — Governed Forensic Conclusion"


class PersistenceState(str, Enum):
    """Artifact/event persistence classification (Rule 7)."""
    INTACT = "Intact"
    PARTIALLY_RETAINED = "Partially Retained"
    WEAKLY_RETAINED = "Weakly Retained"
    FRAGMENT_ONLY = "Fragment Only"
    NOT_OBSERVED = "Not Observed Within Scope"


class EvidenceSourceClass(str, Enum):
    """Evidence-source classes that must not be treated as interchangeable (Rule 8)."""
    BROWSER_DERIVED = "Browser-Derived"
    NATIVE_APP_DERIVED = "Native-App-Derived"
    OS_DERIVED = "OS-Derived"
    MOBILE_LOGICAL_DERIVED = "Mobile-Logical-Derived"
    CONTENT_REMNANT_DERIVED = "Content-Remnant-Derived"
    PROVIDER_EXPORT_DERIVED = "Provider-Export-Derived"
    VOICE_DERIVED = "Voice-Derived"
    UNKNOWN = "Unknown"


# ---------------------------------------------------------------------------
# v4.0: Multi-source acquisition, platform surface, evidence confidence
# ---------------------------------------------------------------------------

class AcquisitionSource(str, Enum):
    """How the artifact was acquired / which evidence channel it came from."""
    E01_IMAGE = "E01 Image"
    MOUNTED_DIRECTORY = "Mounted Directory"
    ZIP_ARCHIVE = "ZIP Archive"
    BROWSER_ARTIFACT = "Browser Artifact"
    MOBILE_LOGICAL_EXTRACTION = "Mobile Logical Extraction"
    PROVIDER_EXPORT = "Provider Export"
    SHARED_LINK_CAPTURE = "Shared Link Capture"
    GENERATED_FILE_CAPTURE = "Generated File Capture"
    SCREENSHOT_CAPTURE = "Screenshot Capture"
    TRANSCRIPT_CAPTURE = "Transcript Capture"
    MEMORY_CAPTURE = "Memory Capture"
    PCAP_CAPTURE = "PCAP Capture"
    MANUAL_IMPORT = "Manual Import"
    UNKNOWN = "Unknown"


class PlatformSurface(str, Enum):
    """The surface / access modality through which AI interaction occurred."""
    BROWSER_WEB = "Browser Web"
    NATIVE_DESKTOP_APP = "Native Desktop App"
    MOBILE_APP = "Mobile App"
    PROVIDER_EXPORT = "Provider Export"
    SHARED_PUBLIC_LINK = "Shared Public Link"
    GENERATED_ASSET = "Generated Asset"
    PROJECT_WORKSPACE = "Project/Workspace"
    MEMORY_PROFILE = "Memory/Profile"
    VOICE_SESSION = "Voice Session"
    UNKNOWN = "Unknown"


class EvidenceConfidenceClass(str, Enum):
    """Usage-level evidence confidence (Caveat 4)."""
    OBSERVED_AI_USE = "Observed AI Use"
    CORROBORATED_AI_USE = "Corroborated AI Use"
    SUSPECTED_AI_USE = "Suspected AI Use"
    INSUFFICIENT_SUPPORT = "Insufficient Support"


class VoiceArtifactType(str, Enum):
    """Types of voice/audio evidence artifacts."""
    TRANSCRIPT_TEXT = "Transcript Text"
    VOICE_SESSION_LOG = "Voice Session Log"
    AUDIO_METADATA = "Audio Metadata"
    ASR_OUTPUT = "ASR Output"
    VOICE_MEMO = "Voice Memo"
    UNKNOWN = "Unknown"


class ImageReviewEvidenceState(str, Enum):
    """Graded image-review evidence states (Rule 5)."""
    DIRECTLY_SUPPORTED = "Directly Supported"
    CONSISTENT_WITH = "Consistent With"
    SUGGESTIVE_OF = "Suggestive Of"
    NONE_IDENTIFIED = "None Identified"


class EventConfidenceLevel(str, Enum):
    """Event-level (FRAUE) confidence — distinct from artifact confidence (Rule 9)."""
    HIGH = "High"
    MODERATE = "Moderate"
    LOW = "Low"
    INSUFFICIENT = "Insufficient"


class ValidationLevel(str, Enum):
    """Validation status for parsers and the overall framework."""
    VALIDATED = "Validated"
    PARTIALLY_VALIDATED = "Partially Validated"
    NOT_VALIDATED = "Not Validated"
    DRIFT_DETECTED = "Drift Detected"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------

@dataclass
class CaseInfo:
    """Case-level metadata."""
    case_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    case_name: str = ""
    examiner: str = ""
    organization: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ArtifactProvenance:
    """Provenance chain for an individual artifact (v4.0)."""
    acquisition_source: AcquisitionSource = AcquisitionSource.UNKNOWN
    parser_name: str = ""
    extraction_method: str = ""
    original_source_path: str = ""
    temp_copy_path: str = ""
    hash_status: str = ""  # "verified", "computed", "unavailable"
    source_hashes: Dict[str, str] = field(default_factory=dict)  # e.g. {"md5": "abc..."}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "acquisition_source": self.acquisition_source.value,
            "parser_name": self.parser_name,
            "extraction_method": self.extraction_method,
            "original_source_path": self.original_source_path,
            "temp_copy_path": self.temp_copy_path,
            "hash_status": self.hash_status,
            "source_hashes": self.source_hashes,
        }


@dataclass
class EvidenceImageInfo:
    """Metadata about the source E01 image."""
    evidence_item_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    image_path: str = ""
    image_type: ImageType = ImageType.UNKNOWN
    image_format: str = "E01"
    image_size_bytes: int = 0
    md5_hash: Optional[str] = None
    sha1_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    acquired_date: Optional[str] = None
    examiner_notes: Optional[str] = None
    ewf_metadata: Dict[str, str] = field(default_factory=dict)
    partitions: List[PartitionInfo] = field(default_factory=list)
    detected_os: OSPlatform = OSPlatform.UNKNOWN
    user_profiles: List[str] = field(default_factory=list)
    processing_start: Optional[datetime] = None
    processing_end: Optional[datetime] = None
    read_only: bool = True
    errors: List[str] = field(default_factory=list)


@dataclass
class PartitionInfo:
    """Information about a detected partition."""
    index: int = 0
    description: str = ""
    type_desc: str = ""
    offset: int = 0
    length: int = 0
    filesystem: str = ""
    accessible: bool = False
    mount_point: Optional[str] = None
    errors: List[str] = field(default_factory=list)


@dataclass
class ArtifactRecord:
    """
    A single forensic artifact finding.
    Every detection record must capture all required fields.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    evidence_item_id: str = ""
    source_image: str = ""
    partition_or_container: str = ""
    user_profile: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    artifact_type: str = ""
    artifact_subtype: str = ""
    artifact_path: str = ""
    parser_used: str = ""
    timestamp: Optional[datetime] = None
    timestamp_type: TimestampType = TimestampType.UNKNOWN
    timezone_normalized: bool = False
    timezone_info: str = ""
    extracted_indicator: str = ""
    suspected_platform: AIPlatform = AIPlatform.UNKNOWN
    suspected_model: AIModel = AIModel.UNKNOWN
    suspected_access_mode: AccessMode = AccessMode.UNKNOWN
    classification: EvidenceClassification = EvidenceClassification.INFERRED
    attribution_layer: AttributionLayer = AttributionLayer.PLATFORM
    confidence: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    corroborating_artifacts: List[str] = field(default_factory=list)
    notes: str = ""
    raw_data: Optional[Dict[str, Any]] = None
    # TRACE-AI-FR provenance and governance fields
    evidence_source_class: EvidenceSourceClass = EvidenceSourceClass.UNKNOWN
    persistence_state: PersistenceState = PersistenceState.NOT_OBSERVED
    timestamp_provenance: str = ""  # E.g. "SQLite last_visit_time column"
    preservation_context: str = ""  # E.g. "Recovered from active database"
    parser_validation_status: ValidationLevel = ValidationLevel.NOT_VALIDATED
    claim_level: ClaimLevel = ClaimLevel.ARTIFACT_OBSERVATION
    # v4.0: Multi-source acquisition, platform surface, provenance
    acquisition_source: AcquisitionSource = AcquisitionSource.UNKNOWN
    platform_surface: PlatformSurface = PlatformSurface.UNKNOWN
    provenance: Optional[ArtifactProvenance] = None
    related_shared_link_id: str = ""
    related_generated_asset_id: str = ""
    related_voice_event_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = {
            "record_id": self.record_id,
            "case_id": self.case_id,
            "evidence_item_id": self.evidence_item_id,
            "source_image": self.source_image,
            "partition_or_container": self.partition_or_container,
            "user_profile": self.user_profile,
            "artifact_family": self.artifact_family.value,
            "artifact_type": self.artifact_type,
            "artifact_subtype": self.artifact_subtype,
            "artifact_path": self.artifact_path,
            "parser_used": self.parser_used,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_type": self.timestamp_type.value,
            "timezone_normalized": self.timezone_normalized,
            "timezone_info": self.timezone_info,
            "extracted_indicator": self.extracted_indicator,
            "suspected_platform": self.suspected_platform.value if self.suspected_platform else None,
            "suspected_model": self.suspected_model.value if self.suspected_model else None,
            "suspected_access_mode": self.suspected_access_mode.value if self.suspected_access_mode else None,
            "classification": self.classification.value,
            "attribution_layer": self.attribution_layer.value,
            "confidence": self.confidence.value,
            "corroborating_artifacts": self.corroborating_artifacts,
            "notes": self.notes,
            "evidence_source_class": self.evidence_source_class.value,
            "persistence_state": self.persistence_state.value,
            "timestamp_provenance": self.timestamp_provenance,
            "preservation_context": self.preservation_context,
            "parser_validation_status": self.parser_validation_status.value,
            "claim_level": self.claim_level.value,
            # v4.0 fields
            "acquisition_source": self.acquisition_source.value,
            "platform_surface": self.platform_surface.value,
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "related_shared_link_id": self.related_shared_link_id,
            "related_generated_asset_id": self.related_generated_asset_id,
            "related_voice_event_id": self.related_voice_event_id,
        }
        return d


@dataclass
class ProcessingLog:
    """Log entry for processing events."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    level: str = "INFO"
    module: str = ""
    message: str = ""
    details: Optional[str] = None


@dataclass
class ParserResult:
    """Result from running an artifact parser, including forensic coverage records (v5.0)."""
    parser_name: str = ""
    parser_version: str = "1.0.0"
    status: ParserStatus = ParserStatus.SUCCESS
    artifacts_found: List[ArtifactRecord] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    artifact_paths_searched: List[str] = field(default_factory=list)
    artifact_paths_found: List[str] = field(default_factory=list)
    artifact_paths_missing: List[str] = field(default_factory=list)
    notes: str = ""
    # v5.0 forensic coverage records
    artifact_coverage: List[ArtifactCoverageRecord] = field(default_factory=list)
    coverage_gaps: List[CoverageGapRecord] = field(default_factory=list)
    parse_failures: List[ParseFailureRecord] = field(default_factory=list)
    unsupported_artifacts: List[UnsupportedArtifactRecord] = field(default_factory=list)


@dataclass
class EvidenceCoverage:
    """Assessment of what the evidence source actually contains."""
    image_type: ImageType = ImageType.UNKNOWN
    full_disk_available: bool = False
    partitions_accessible: int = 0
    partitions_total: int = 0
    encrypted_areas_detected: bool = False
    carving_enabled: bool = False
    os_detected: OSPlatform = OSPlatform.UNKNOWN
    user_profiles_found: List[str] = field(default_factory=list)
    browsers_detected: List[str] = field(default_factory=list)
    native_apps_detected: List[str] = field(default_factory=list)
    artifact_families_available: List[str] = field(default_factory=list)
    artifact_families_missing: List[str] = field(default_factory=list)
    parsers_succeeded: List[str] = field(default_factory=list)
    parsers_failed: List[str] = field(default_factory=list)
    parsers_not_applicable: List[str] = field(default_factory=list)
    parsers_stub: List[str] = field(default_factory=list)
    coverage_notes: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class TimelineEvent:
    """A single event on the reconstructed timeline."""
    timestamp: datetime
    event_type: str = ""
    description: str = ""
    platform: AIPlatform = AIPlatform.UNKNOWN
    access_mode: AccessMode = AccessMode.UNKNOWN
    artifact_record_id: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    classification: EvidenceClassification = EvidenceClassification.INFERRED


@dataclass
class ComparativeMatrixRow:
    """A single row of the comparative artifact matrix."""
    platform: AIPlatform = AIPlatform.UNKNOWN
    user_profile: str = ""
    ai_tool_or_model: str = ""
    browser_vs_app: AccessMode = AccessMode.UNKNOWN
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    artifact_type: str = ""
    artifact_location: str = ""
    evidentiary_value: str = ""
    timestamp_quality: str = ""
    persistence_after_deletion: str = ""
    relevance_to_crime_scene: str = ""
    classification: EvidenceClassification = EvidenceClassification.INFERRED
    confidence: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    evidence_coverage_caveat: str = ""
    comments: str = ""


@dataclass
class AIUsageFootprint:
    """Observable artifact-based measure of AI-system use."""
    platform: AIPlatform = AIPlatform.UNKNOWN
    model: AIModel = AIModel.UNKNOWN
    access_mode: AccessMode = AccessMode.UNKNOWN
    total_artifacts: int = 0
    direct_artifacts: int = 0
    inferred_artifacts: int = 0
    earliest_activity: Optional[datetime] = None
    latest_activity: Optional[datetime] = None
    estimated_session_count: int = 0
    image_upload_indicators: int = 0
    content_export_indicators: int = 0
    prompt_remnants_found: int = 0
    response_remnants_found: int = 0
    overall_confidence: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    caveats: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# TRACE-AI-FR: Forensically Reconstructed AI-Use Event (FRAUE)
# ---------------------------------------------------------------------------

@dataclass
class FRAUE:
    """
    Forensically Reconstructed AI-Use Event.

    A time-bounded, platform-attributed episode of probable AI-system
    interaction reconstructed from corroborated endpoint artifacts and
    reported with explicit confidence, provenance, uncertainty, evidence
    coverage, and alternative explanations.
    """
    fraue_id: str = field(default_factory=lambda: f"FRAUE-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    model: AIModel = AIModel.UNKNOWN
    access_mode: AccessMode = AccessMode.UNKNOWN
    user_profile: str = ""

    # Time window
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    time_provenance: str = ""  # How the window was derived

    # Activity classification
    likely_activity_class: str = ""  # e.g. "chat session", "image upload"
    image_review_state: ImageReviewEvidenceState = ImageReviewEvidenceState.NONE_IDENTIFIED
    persistence_state: PersistenceState = PersistenceState.NOT_OBSERVED

    # Supporting evidence
    artifact_ids: List[str] = field(default_factory=list)
    artifact_family_count: int = 0  # Distinct families contributing
    source_diversity: int = 0  # Distinct evidence source classes
    direct_artifact_count: int = 0
    inferred_artifact_count: int = 0

    # Confidence and adjudication
    event_confidence: EventConfidenceLevel = EventConfidenceLevel.INSUFFICIENT
    claim_level: ClaimLevel = ClaimLevel.ARTIFACT_OBSERVATION
    corroboration_met: bool = False  # Rule 9 threshold met
    time_coherence: bool = False
    coverage_sufficient: bool = False

    # Mandatory qualifications
    alternative_explanations: List[str] = field(default_factory=list)
    inference_boundaries: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)
    # v4.0: Multi-source, platform surface, evidence confidence
    acquisition_sources: List[str] = field(default_factory=list)
    platform_surfaces: List[str] = field(default_factory=list)
    confidence_class: EvidenceConfidenceClass = EvidenceConfidenceClass.INSUFFICIENT_SUPPORT
    direct_evidence_artifact_ids: List[str] = field(default_factory=list)
    corroborating_artifact_ids: List[str] = field(default_factory=list)
    missing_expected_artifact_families: List[str] = field(default_factory=list)
    voice_related: bool = False
    shared_link_related: bool = False
    generated_asset_related: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fraue_id": self.fraue_id,
            "platform": self.platform.value,
            "model": self.model.value if self.model else None,
            "access_mode": self.access_mode.value if self.access_mode else None,
            "user_profile": self.user_profile,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "time_provenance": self.time_provenance,
            "likely_activity_class": self.likely_activity_class,
            "image_review_state": self.image_review_state.value,
            "persistence_state": self.persistence_state.value,
            "artifact_ids": self.artifact_ids,
            "artifact_family_count": self.artifact_family_count,
            "source_diversity": self.source_diversity,
            "direct_artifact_count": self.direct_artifact_count,
            "inferred_artifact_count": self.inferred_artifact_count,
            "event_confidence": self.event_confidence.value,
            "claim_level": self.claim_level.value,
            "corroboration_met": self.corroboration_met,
            "time_coherence": self.time_coherence,
            "coverage_sufficient": self.coverage_sufficient,
            "alternative_explanations": self.alternative_explanations,
            "inference_boundaries": self.inference_boundaries,
            "caveats": self.caveats,
            # v4.0 fields
            "acquisition_sources": self.acquisition_sources,
            "platform_surfaces": self.platform_surfaces,
            "confidence_class": self.confidence_class.value,
            "direct_evidence_artifact_ids": self.direct_evidence_artifact_ids,
            "corroborating_artifact_ids": self.corroborating_artifact_ids,
            "missing_expected_artifact_families": self.missing_expected_artifact_families,
            "voice_related": self.voice_related,
            "shared_link_related": self.shared_link_related,
            "generated_asset_related": self.generated_asset_related,
        }


@dataclass
class VersionDriftEntry:
    """Tracks parser/signature version for drift validation (Rule 12)."""
    component: str = ""  # e.g. "ChromiumHistoryParser"
    component_version: str = ""
    signature_version: str = ""
    last_validated_date: str = ""
    target_browser_version: str = ""
    target_os_version: str = ""
    validation_status: ValidationLevel = ValidationLevel.NOT_VALIDATED
    notes: str = ""


@dataclass
class GovernanceRecord:
    """
    AI Use Evidence Governance Record (Layer 8).

    Case-level record documenting collection scope, legal basis,
    evidence classes examined, parser versions, validation state,
    known blind spots, inference boundaries, and required disclosures.
    """
    case_id: str = ""
    generated_at: datetime = field(default_factory=datetime.utcnow)
    framework_name: str = "TRACE-AI-FR"
    framework_version: str = "4.0.0"

    # Collection scope
    collection_scope: str = ""
    legal_basis: str = ""
    evidence_source_classes_examined: List[str] = field(default_factory=list)

    # Tool state
    parser_versions: Dict[str, str] = field(default_factory=dict)
    signature_version: str = ""
    validation_state: ValidationLevel = ValidationLevel.NOT_VALIDATED
    version_drift_register: List[VersionDriftEntry] = field(default_factory=list)

    # Inference boundaries
    known_blind_spots: List[str] = field(default_factory=list)
    inference_boundaries: List[str] = field(default_factory=list)
    required_disclosures: List[str] = field(default_factory=list)

    # Framework rules applied
    rules_applied: List[str] = field(default_factory=list)

    # v4.0: Extended governance fields
    provider_capability_blind_spots: List[str] = field(default_factory=list)
    acquisition_blind_spots: List[str] = field(default_factory=list)
    surface_coverage_summary: List[str] = field(default_factory=list)
    export_vs_endpoint_limitations: List[str] = field(default_factory=list)
    voice_limitations: List[str] = field(default_factory=list)
    direct_evidence_summary: List[str] = field(default_factory=list)
    corroborating_evidence_summary: List[str] = field(default_factory=list)
    missing_evidence_summary: List[str] = field(default_factory=list)
    alternative_explanations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "generated_at": self.generated_at.isoformat(),
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "collection_scope": self.collection_scope,
            "legal_basis": self.legal_basis,
            "evidence_source_classes_examined": self.evidence_source_classes_examined,
            "parser_versions": self.parser_versions,
            "signature_version": self.signature_version,
            "validation_state": self.validation_state.value,
            "version_drift_register": [
                {
                    "component": v.component,
                    "component_version": v.component_version,
                    "signature_version": v.signature_version,
                    "last_validated_date": v.last_validated_date,
                    "validation_status": v.validation_status.value,
                    "notes": v.notes,
                }
                for v in self.version_drift_register
            ],
            "known_blind_spots": self.known_blind_spots,
            "inference_boundaries": self.inference_boundaries,
            "required_disclosures": self.required_disclosures,
            "rules_applied": self.rules_applied,
            # v4.0 fields
            "provider_capability_blind_spots": self.provider_capability_blind_spots,
            "acquisition_blind_spots": self.acquisition_blind_spots,
            "surface_coverage_summary": self.surface_coverage_summary,
            "export_vs_endpoint_limitations": self.export_vs_endpoint_limitations,
            "voice_limitations": self.voice_limitations,
            "direct_evidence_summary": self.direct_evidence_summary,
            "corroborating_evidence_summary": self.corroborating_evidence_summary,
            "missing_evidence_summary": self.missing_evidence_summary,
            "alternative_explanations": self.alternative_explanations,
        }


@dataclass
class ExaminationQuestion:
    """A forensic examination question loaded from a Word document."""
    number: int = 0
    text: str = ""
    answer: str = ""
    evidence_references: List[str] = field(default_factory=list)


class FRStatus(str, Enum):
    """Assessment status for a Functional Requirement."""
    FULLY_ADDRESSED = "Fully Addressed"
    PARTIALLY_ADDRESSED = "Partially Addressed"
    GAP_IDENTIFIED = "Gap Identified"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class FRAssessment:
    """Assessment of one Functional Requirement (FR-1 through FR-9)."""
    fr_id: str = ""
    title: str = ""
    description: str = ""
    status: FRStatus = FRStatus.GAP_IDENTIFIED
    capability_summary: str = ""
    evidence_from_analysis: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "fr_id": self.fr_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "capability_summary": self.capability_summary,
            "evidence_from_analysis": self.evidence_from_analysis,
            "gaps": self.gaps,
            "caveats": self.caveats,
        }


# ---------------------------------------------------------------------------
# Recovery & Carving Enumerations (v3.0)
# ---------------------------------------------------------------------------

class RecoveryMode(str, Enum):
    """How an artifact was recovered."""
    NONE = "None"
    FILESYSTEM_METADATA = "Filesystem Metadata Recovery"
    DELETED_FILE = "Deleted File Recovery"
    SIGNATURE_CARVING = "Signature Carving"
    PARTITION_RECONSTRUCTION = "Partition Reconstruction Assisted"
    RAW_SCAN = "Raw Scan Only"


class RecoveryStatus(str, Enum):
    """Result status of a recovery operation."""
    COMPLETE = "Complete"
    PARTIAL = "Partial"
    FRAGMENT = "Fragment"
    FAILED = "Failed"
    NOT_ATTEMPTED = "Not Attempted"


class FilesystemHealth(str, Enum):
    """Overall health of the source filesystem."""
    INTACT = "Intact"
    DEGRADED = "Degraded"
    PARTIALLY_READABLE = "Partially Readable"
    CORRUPT = "Corrupt"
    CARVING_ONLY = "Carving Only"
    UNKNOWN = "Unknown"


class PartitionScheme(str, Enum):
    """Partition table type."""
    MBR = "MBR"
    GPT = "GPT"
    HYBRID = "Hybrid"
    NONE_DETECTED = "None Detected"
    UNKNOWN = "Unknown"


class CarvingValidation(str, Enum):
    """Validation result for a carved artifact."""
    VALID = "Valid"
    HEADER_ONLY = "Header Only"
    PARTIAL_STRUCTURE = "Partial Structure"
    INVALID = "Invalid"
    NOT_VALIDATED = "Not Validated"


class AcquisitionQuality(str, Enum):
    """Quality of the forensic acquisition process."""
    NORMAL = "Normal"
    DEGRADED = "Degraded"
    UNKNOWN = "Unknown"


class EvidenceAccessTier(str, Enum):
    """Level of evidence access available."""
    FULL_FORENSIC_ACCESS = "Full Forensic Access"
    PARTIAL_FILESYSTEM_ACCESS = "Partial Filesystem Access"
    RAW_STREAM_ONLY = "Raw Stream Only"
    DIRECTORY_ONLY = "Directory Only"


class RawHitType(str, Enum):
    """Classification of a raw byte-level hit."""
    GENERIC_STRING = "Generic String"
    PLATFORM_TOKEN = "Platform Token"
    DOMAIN_HIT = "Domain Hit"
    MODEL_NAME_HIT = "Model Name Hit"
    EXPORT_MARKER = "Export Marker"
    HIGH_VALUE_STRUCTURED = "High Value Structured Hit"


# ---------------------------------------------------------------------------
# Recovery & Carving Dataclasses (v3.0)
# ---------------------------------------------------------------------------

@dataclass
class AcquisitionMetadata:
    """Metadata about the forensic acquisition process (ddrescue-like)."""
    source_image_path: str = ""
    acquisition_tool: str = ""
    acquisition_quality: AcquisitionQuality = AcquisitionQuality.UNKNOWN
    bad_sector_count: int = 0
    retry_count: int = 0
    partial_read_map_path: str = ""
    acquisition_notes: str = ""
    total_sectors: int = 0
    successful_sectors: int = 0
    acquisition_date: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_image_path": self.source_image_path,
            "acquisition_tool": self.acquisition_tool,
            "acquisition_quality": self.acquisition_quality.value,
            "bad_sector_count": self.bad_sector_count,
            "retry_count": self.retry_count,
            "partial_read_map_path": self.partial_read_map_path,
            "acquisition_notes": self.acquisition_notes,
            "total_sectors": self.total_sectors,
            "successful_sectors": self.successful_sectors,
            "acquisition_date": self.acquisition_date.isoformat() if self.acquisition_date else None,
        }


@dataclass
class SignatureRule:
    """A single file-signature carving rule."""
    name: str = ""
    extension: str = ""
    header: bytes = b""
    footer: bytes = b""
    max_size: int = 50 * 1024 * 1024  # 50 MB default
    min_size: int = 0
    validate_internal: bool = False
    description: str = ""


@dataclass
class CarvedArtifact:
    """An artifact recovered via signature-based carving."""
    carved_id: str = field(default_factory=lambda: f"CARVED-{str(uuid.uuid4())[:8].upper()}")
    source_evidence_id: str = ""
    source_image_path: str = ""
    offset: int = 0
    recovered_size: int = 0
    signature_rule_used: str = ""
    carved_filename: str = ""  # Synthetic name: carved_{offset}_{ext}
    temp_path: str = ""
    validation: CarvingValidation = CarvingValidation.NOT_VALIDATED
    recovery_mode: RecoveryMode = RecoveryMode.SIGNATURE_CARVING
    recovery_status: RecoveryStatus = RecoveryStatus.NOT_ATTEMPTED
    confidence_hint: ConfidenceLevel = ConfidenceLevel.LOW
    extraction_timestamp: Optional[datetime] = None
    chain_of_custody_note: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "carved_id": self.carved_id,
            "source_evidence_id": self.source_evidence_id,
            "source_image_path": self.source_image_path,
            "offset": self.offset,
            "recovered_size": self.recovered_size,
            "signature_rule_used": self.signature_rule_used,
            "carved_filename": self.carved_filename,
            "validation": self.validation.value,
            "recovery_mode": self.recovery_mode.value,
            "recovery_status": self.recovery_status.value,
            "confidence_hint": self.confidence_hint.value,
            "extraction_timestamp": self.extraction_timestamp.isoformat() if self.extraction_timestamp else None,
            "chain_of_custody_note": self.chain_of_custody_note,
            "notes": self.notes,
        }


@dataclass
class RawHit:
    """A raw byte-level search hit (analyst-supporting evidence)."""
    hit_id: str = field(default_factory=lambda: f"RAW-{str(uuid.uuid4())[:8].upper()}")
    evidence_id: str = ""
    offset: int = 0
    length: int = 0
    hit_type: RawHitType = RawHitType.GENERIC_STRING
    matched_pattern: str = ""
    context_preview: str = ""
    suspected_platform: AIPlatform = AIPlatform.UNKNOWN
    confidence_hint: ConfidenceLevel = ConfidenceLevel.LOW
    scan_timestamp: Optional[datetime] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit_id": self.hit_id,
            "evidence_id": self.evidence_id,
            "offset": self.offset,
            "length": self.length,
            "hit_type": self.hit_type.value,
            "matched_pattern": self.matched_pattern,
            "context_preview": self.context_preview,
            "suspected_platform": self.suspected_platform.value,
            "confidence_hint": self.confidence_hint.value,
            "scan_timestamp": self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            "notes": self.notes,
        }


@dataclass
class PartitionFinding:
    """Finding from partition/filesystem health analysis."""
    evidence_id: str = ""
    partition_index: int = 0
    scheme: PartitionScheme = PartitionScheme.UNKNOWN
    offset: int = 0
    size_bytes: int = 0
    fs_type_label: str = ""
    health: FilesystemHealth = FilesystemHealth.UNKNOWN
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "partition_index": self.partition_index,
            "scheme": self.scheme.value,
            "offset": self.offset,
            "size_bytes": self.size_bytes,
            "fs_type_label": self.fs_type_label,
            "health": self.health.value,
            "notes": self.notes,
        }


@dataclass
class RecoveryAuditRecord:
    """Audit trail for a single recovery operation."""
    audit_id: str = field(default_factory=lambda: f"RAUDIT-{str(uuid.uuid4())[:8].upper()}")
    recovery_mode: RecoveryMode = RecoveryMode.NONE
    source_evidence_id: str = ""
    evidence_id: str = ""
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    modes_applied: List[str] = field(default_factory=list)
    total_carved: int = 0
    total_raw_hits: int = 0
    partitions_found: int = 0
    filesystem_health: FilesystemHealth = FilesystemHealth.UNKNOWN
    evidence_access_tier: EvidenceAccessTier = EvidenceAccessTier.DIRECTORY_ONLY
    caveats: List[str] = field(default_factory=list)
    provenance_note: str = ""
    recovery_status: RecoveryStatus = RecoveryStatus.NOT_ATTEMPTED
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "recovery_mode": self.recovery_mode.value,
            "source_evidence_id": self.source_evidence_id,
            "evidence_id": self.evidence_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "modes_applied": self.modes_applied,
            "total_carved": self.total_carved,
            "total_raw_hits": self.total_raw_hits,
            "partitions_found": self.partitions_found,
            "filesystem_health": self.filesystem_health.value,
            "evidence_access_tier": self.evidence_access_tier.value,
            "caveats": self.caveats,
            "provenance_note": self.provenance_note,
            "recovery_status": self.recovery_status.value,
            "notes": self.notes,
        }


@dataclass
class EvidenceAccessCapabilities:
    """Detected evidence-access capabilities for this analysis run."""
    has_pyewf: bool = False
    has_pytsk3: bool = False
    has_python_registry: bool = False
    has_raw_stream: bool = False
    access_tier: EvidenceAccessTier = EvidenceAccessTier.DIRECTORY_ONLY
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_pyewf": self.has_pyewf,
            "has_pytsk3": self.has_pytsk3,
            "has_python_registry": self.has_python_registry,
            "has_raw_stream": self.has_raw_stream,
            "access_tier": self.access_tier.value,
            "limitations": self.limitations,
        }


@dataclass
class ForensicReport:
    """Top-level container for the complete forensic report."""
    case_info: CaseInfo = field(default_factory=CaseInfo)
    evidence_info: EvidenceImageInfo = field(default_factory=EvidenceImageInfo)
    evidence_coverage: EvidenceCoverage = field(default_factory=EvidenceCoverage)
    all_artifacts: List[ArtifactRecord] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    ai_footprints: List[AIUsageFootprint] = field(default_factory=list)
    fraues: List[FRAUE] = field(default_factory=list)
    matrix_rows: List[ComparativeMatrixRow] = field(default_factory=list)
    parser_results: List[ParserResult] = field(default_factory=list)
    processing_logs: List[ProcessingLog] = field(default_factory=list)
    governance_record: Optional[GovernanceRecord] = None
    generated_at: datetime = field(default_factory=datetime.utcnow)
    tool_version: str = "4.0.0"
    framework_name: str = "TRACE-AI-FR"
    carving_enabled: bool = False
    analysis_notes: List[str] = field(default_factory=list)
    scope_of_conclusion: str = ""
    inference_boundaries: List[str] = field(default_factory=list)
    examination_questions: List[ExaminationQuestion] = field(default_factory=list)
    fr_assessments: List[FRAssessment] = field(default_factory=list)
    # v3.0: Recovery-aware fields
    recovered_artifacts: List[ArtifactRecord] = field(default_factory=list)
    carved_artifacts: List[CarvedArtifact] = field(default_factory=list)
    raw_hits: List[RawHit] = field(default_factory=list)
    partition_findings: List[PartitionFinding] = field(default_factory=list)
    recovery_audit: List[RecoveryAuditRecord] = field(default_factory=list)
    acquisition_metadata: Optional[AcquisitionMetadata] = None
    filesystem_health: FilesystemHealth = FilesystemHealth.UNKNOWN
    evidence_access_tier: EvidenceAccessTier = EvidenceAccessTier.DIRECTORY_ONLY
    recovery_mode_used: RecoveryMode = RecoveryMode.NONE
    # v4.0: Voice evidence, shared links, generated assets, schema version
    schema_version: str = "4.0.0"
    voice_evidence: List[Any] = field(default_factory=list)
    shared_links: List[Any] = field(default_factory=list)
    generated_assets: List[Any] = field(default_factory=list)
    docx_generated: bool = False
    docx_path: str = ""
    report_template_name: str = "UNCC-DFL-TRACE-AI-FR"
    report_template_version: str = "4.0.0"
    report_fallback_used: bool = False
    report_fallback_reason: str = ""
    # v5.0: AI tool inventory checklist
    forensic_checklist: List[Any] = field(default_factory=list)
    # v5.0: Artifact coverage ledgers
    artifact_coverage_ledger: List[Any] = field(default_factory=list)
    coverage_gap_ledger: List[Any] = field(default_factory=list)
    parse_failure_ledger: List[Any] = field(default_factory=list)
    unsupported_artifact_ledger: List[Any] = field(default_factory=list)


# ---------------------------------------------------------------------------
# v4.0: Voice, Shared Link, Generated Asset, Provider Capability
# ---------------------------------------------------------------------------

@dataclass
class VoiceEvidenceRecord:
    """A voice/audio evidence artifact (v4.0)."""
    voice_id: str = field(default_factory=lambda: f"VOICE-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    artifact_type: VoiceArtifactType = VoiceArtifactType.UNKNOWN
    source_path: str = ""
    transcript_text: str = ""
    transcript_source: str = ""  # "imported", "extracted", "metadata-only"
    session_id: str = ""
    timestamp: Optional[datetime] = None
    duration_seconds: float = 0.0
    speaker_label: str = ""  # label only, not identity
    file_hash: str = ""
    linked_artifact_ids: List[str] = field(default_factory=list)
    linked_fraue_id: str = ""
    notes: str = ""
    caveats: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "voice_id": self.voice_id,
            "platform": self.platform.value,
            "artifact_type": self.artifact_type.value,
            "source_path": self.source_path,
            "transcript_text": self.transcript_text[:500] if self.transcript_text else "",
            "transcript_source": self.transcript_source,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "duration_seconds": self.duration_seconds,
            "speaker_label": self.speaker_label,
            "file_hash": self.file_hash,
            "linked_artifact_ids": self.linked_artifact_ids,
            "linked_fraue_id": self.linked_fraue_id,
            "notes": self.notes,
            "caveats": self.caveats,
        }


@dataclass
class SharedLinkRecord:
    """A shared/public link to an AI conversation or asset (v4.0)."""
    link_id: str = field(default_factory=lambda: f"SLINK-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    url: str = ""
    captured_from: str = ""  # e.g. "browser_history", "clipboard", "export"
    creation_timestamp: Optional[datetime] = None
    access_timestamp: Optional[datetime] = None
    linked_artifact_ids: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "link_id": self.link_id,
            "platform": self.platform.value,
            "url": self.url,
            "captured_from": self.captured_from,
            "creation_timestamp": self.creation_timestamp.isoformat() if self.creation_timestamp else None,
            "access_timestamp": self.access_timestamp.isoformat() if self.access_timestamp else None,
            "linked_artifact_ids": self.linked_artifact_ids,
            "notes": self.notes,
        }


@dataclass
class GeneratedAssetRecord:
    """A file generated by an AI platform (v4.0)."""
    asset_id: str = field(default_factory=lambda: f"GASSET-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    asset_type: str = ""  # "image", "code", "document", "audio"
    file_path: str = ""
    file_hash: str = ""
    file_size: int = 0
    creation_timestamp: Optional[datetime] = None
    c2pa_metadata: Dict[str, Any] = field(default_factory=dict)
    linked_artifact_ids: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "platform": self.platform.value,
            "asset_type": self.asset_type,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "creation_timestamp": self.creation_timestamp.isoformat() if self.creation_timestamp else None,
            "c2pa_metadata": self.c2pa_metadata,
            "linked_artifact_ids": self.linked_artifact_ids,
            "notes": self.notes,
        }


@dataclass
class ProviderCapabilityProfile:
    """Capability profile for an AI platform provider (v4.0)."""
    platform: AIPlatform = AIPlatform.UNKNOWN
    profile_version: str = "1.0"
    supports_export: bool = False
    supports_share_links: bool = False
    supports_projects_or_workspaces: bool = False
    supports_memory_profile: bool = False
    supports_generated_assets: bool = False
    supports_voice: bool = False
    supports_native_desktop: bool = False
    supports_mobile_app: bool = False
    supports_browser_access: bool = True
    supports_api_artifacts: bool = False
    expected_artifact_families: List[str] = field(default_factory=list)
    expected_platform_surfaces: List[str] = field(default_factory=list)
    known_blind_spots: List[str] = field(default_factory=list)
    retention_notes: str = ""
    capability_confidence: str = "medium"  # "high", "medium", "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform.value,
            "profile_version": self.profile_version,
            "supports_export": self.supports_export,
            "supports_share_links": self.supports_share_links,
            "supports_projects_or_workspaces": self.supports_projects_or_workspaces,
            "supports_memory_profile": self.supports_memory_profile,
            "supports_generated_assets": self.supports_generated_assets,
            "supports_voice": self.supports_voice,
            "supports_native_desktop": self.supports_native_desktop,
            "supports_mobile_app": self.supports_mobile_app,
            "supports_browser_access": self.supports_browser_access,
            "supports_api_artifacts": self.supports_api_artifacts,
            "expected_artifact_families": self.expected_artifact_families,
            "expected_platform_surfaces": self.expected_platform_surfaces,
            "known_blind_spots": self.known_blind_spots,
            "retention_notes": self.retention_notes,
            "capability_confidence": self.capability_confidence,
        }


@dataclass
class ProjectWorkspaceRecord:
    """Record of an AI platform project or workspace (v4.0, optional)."""
    workspace_id: str = field(default_factory=lambda: f"WS-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    workspace_name: str = ""
    workspace_type: str = ""  # "project", "workspace", "collection"
    discovery_path: str = ""
    creation_timestamp: Optional[datetime] = None
    last_modified_timestamp: Optional[datetime] = None
    linked_artifact_ids: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "platform": self.platform.value,
            "workspace_name": self.workspace_name,
            "workspace_type": self.workspace_type,
            "discovery_path": self.discovery_path,
            "creation_timestamp": self.creation_timestamp.isoformat() if self.creation_timestamp else None,
            "last_modified_timestamp": self.last_modified_timestamp.isoformat() if self.last_modified_timestamp else None,
            "linked_artifact_ids": self.linked_artifact_ids,
            "notes": self.notes,
        }


@dataclass
class MemoryItemRecord:
    """Record of an AI platform memory/personalization item (v4.0, optional)."""
    memory_id: str = field(default_factory=lambda: f"MEM-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    memory_key: str = ""
    memory_value: str = ""
    discovery_path: str = ""
    creation_timestamp: Optional[datetime] = None
    linked_artifact_ids: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "platform": self.platform.value,
            "memory_key": self.memory_key,
            "memory_value": self.memory_value,
            "discovery_path": self.discovery_path,
            "creation_timestamp": self.creation_timestamp.isoformat() if self.creation_timestamp else None,
            "linked_artifact_ids": self.linked_artifact_ids,
            "notes": self.notes,
        }

# ---------------------------------------------------------------------------
# v5.0: Additional Data Models for Full Forensic Coverage
# ---------------------------------------------------------------------------

@dataclass
class ArtifactCoverageRecord:
    """Ledger entry for artifact coverage per platform, OS, user/profile, parser."""
    record_id: str = field(default_factory=lambda: f"COV-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    os: OSPlatform = OSPlatform.UNKNOWN
    user_profile: str = ""
    browser_profile: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    expected_path: str = ""
    actual_path: str = ""
    parser_used: str = ""
    parser_result_status: str = ""
    evidence_count: int = 0
    artifact_ids: Set[str] = field(default_factory=set)
    reason_code: str = ""
    explanation: str = ""
    confidence_impact: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    caveat_text: str = ""

@dataclass
class ExpectedArtifactLocation:
    """Expected artifact location for a given platform, OS, user/profile, artifact family."""
    platform: AIPlatform = AIPlatform.UNKNOWN
    os: OSPlatform = OSPlatform.UNKNOWN
    user_profile: str = ""
    browser_profile: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    expected_path: str = ""
    notes: str = ""

@dataclass
class CoverageGapRecord:
    """Record of a gap in artifact coverage (expected but not found/assessed)."""
    gap_id: str = field(default_factory=lambda: f"GAP-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    os: OSPlatform = OSPlatform.UNKNOWN
    user_profile: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    expected_path: str = ""
    gap_reason: str = ""
    explanation: str = ""
    confidence_impact: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    caveat_text: str = ""

@dataclass
class ParseFailureRecord:
    """Record of a parser failure for a given artifact location."""
    failure_id: str = field(default_factory=lambda: f"FAIL-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    os: OSPlatform = OSPlatform.UNKNOWN
    user_profile: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    path: str = ""
    parser_used: str = ""
    error_message: str = ""
    dependency_limited: bool = False
    encrypted_or_locked: bool = False
    corrupted: bool = False
    partial_recovery: bool = False
    unsupported: bool = False
    timestamp: Optional[datetime] = None
    caveat_text: str = ""

@dataclass
class UnsupportedArtifactRecord:
    """Record of an artifact location that is present but unsupported by current parsers."""
    record_id: str = field(default_factory=lambda: f"UNSUP-{str(uuid.uuid4())[:8].upper()}")
    platform: AIPlatform = AIPlatform.UNKNOWN
    os: OSPlatform = OSPlatform.UNKNOWN
    user_profile: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    path: str = ""
    parser_needed: str = ""
    notes: str = ""

@dataclass
class UserAttributionStatus:
    """User attribution status for a finding or artifact."""
    status: str = "AMBIGUOUS"  # ATTRIBUTED, PROBABLE_USER_SCOPE, SYSTEM_SCOPE_ONLY, AMBIGUOUS_MULTI_USER, PROFILE_SCOPE_UNRESOLVED
    explanation: str = ""

@dataclass
class OSProfileExtended:
    """Extended OS profile info for multi-user, multi-profile, multi-container attribution."""
    os: OSPlatform = OSPlatform.UNKNOWN
    user_profile: str = ""
    browser_profiles: List[str] = field(default_factory=list)
    app_containers: List[str] = field(default_factory=list)
    system_scope: bool = False
    ambiguous: bool = False
    notes: str = ""

@dataclass
class LinuxPackageEvidence:
    """Evidence of Linux package install/remove for an AI tool."""
    package_manager: str = ""
    package_name: str = ""
    version: str = ""
    install_timestamp: Optional[datetime] = None
    remove_timestamp: Optional[datetime] = None
    user_scope: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class BrowserExtensionInstallRecord:
    """Evidence of browser extension install for an AI tool."""
    browser: str = ""
    extension_id: str = ""
    extension_name: str = ""
    version: str = ""
    install_timestamp: Optional[datetime] = None
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class NativeAppInstallRecord:
    """Evidence of native app install for an AI tool."""
    app_name: str = ""
    bundle_id: str = ""
    version: str = ""
    install_path: str = ""
    install_timestamp: Optional[datetime] = None
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class PWAShortcutRecord:
    """Evidence of PWA/shortcut install for an AI tool."""
    browser: str = ""
    shortcut_name: str = ""
    install_path: str = ""
    install_timestamp: Optional[datetime] = None
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class PortableAppRecord:
    """Evidence of portable app presence for an AI tool."""
    app_name: str = ""
    executable_path: str = ""
    detected_timestamp: Optional[datetime] = None
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class ThemePreference:
    """User or session theme preference for accessibility-first UI."""
    theme: str = "default"
    density: str = "standard"
    reduced_motion: bool = False
    text_size: str = "medium"
    high_contrast: bool = False
    forensic_lab_mode: bool = False
    courtroom_print_mode: bool = False

@dataclass
class AccessibilityPreference:
    """User or session accessibility preference for UI/UX."""
    screen_reader: bool = False
    keyboard_navigation: bool = True
    focus_visible: bool = True
    color_blind_mode: bool = False
    custom_settings: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TimestampNormalizationRecord:
    """Record of timestamp normalization and provenance."""
    original_value: str = ""
    normalized_value: str = ""
    timezone_assumption: str = ""
    normalization_method: str = ""
    ambiguity_flag: bool = False
    confidence_impact: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED

@dataclass
class ParserHealthRecord:
    """Health/coverage status for a parser in a given run."""
    parser_name: str = ""
    status: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    dependency_limitations: List[str] = field(default_factory=list)
    coverage_notes: List[str] = field(default_factory=list)

@dataclass
class DependencyLimitationRecord:
    """Record of a missing/limited dependency affecting parser coverage."""
    dependency_name: str = ""
    affected_parsers: List[str] = field(default_factory=list)
    limitation_type: str = ""
    impact: str = ""
    caveat_text: str = ""

@dataclass
class AlternativeExplanationRecord:
    """Alternative explanation for a finding or evidence gap."""
    explanation: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    caveat_text: str = ""

@dataclass
class RegistryArtifactRecord:
    """Windows Registry artifact record for install, execution, config, MRU, etc."""
    hive: str = ""
    key_path: str = ""
    value_name: str = ""
    value_data: Any = None
    timestamp: Optional[datetime] = None
    artifact_type: str = ""
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class EventLogArtifactRecord:
    """Windows Event Log artifact record for install, execution, service, etc."""
    log_name: str = ""
    event_id: int = 0
    record_number: int = 0
    timestamp: Optional[datetime] = None
    event_data: Dict[str, Any] = field(default_factory=dict)
    artifact_type: str = ""
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""

@dataclass
class PlistArtifactRecord:
    """macOS Plist artifact record for install, config, app-state, etc."""
    plist_path: str = ""
    key: str = ""
    value: Any = None
    timestamp: Optional[datetime] = None
    artifact_type: str = ""
    user_profile: str = ""
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    notes: str = ""
# ---------------------------------------------------------------------------
# v5.0: Installed Tool and Usage Evidence Models
# ---------------------------------------------------------------------------


@dataclass
class InstalledToolRecord:
    """Evidence of AI tool installation or presence (cross-platform, multi-OS, multi-user)."""
    record_id: str = field(default_factory=lambda: f"INST-{str(uuid.uuid4())[:8].upper()}")
    platform_name: str = ""
    tool_variant: str = ""
    os: OSPlatform = OSPlatform.UNKNOWN
    user_scope: str = ""  # user profile, system, ambiguous
    browser_profile_scope: str = ""
    install_type: str = ""  # package, bundle, extension, portable, PWA, etc.
    install_path: str = ""
    package_name_or_bundle_id: str = ""
    executable_name: str = ""
    version_string: str = ""
    publisher: str = ""
    install_timestamp: Optional[datetime] = None
    removal_timestamp: Optional[datetime] = None
    installation_state: str = "UNKNOWN"  # INSTALLED_CONFIRMED, INSTALLED_PROBABLE, EXTENSION_INSTALLED, etc.
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    source_paths: Set[str] = field(default_factory=set)
    parser_name: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    notes: str = ""

@dataclass
class UsageEvidenceRecord:
    """Evidence of AI tool usage, browser/native access, exports, remnants, etc."""
    record_id: str = field(default_factory=lambda: f"USE-{str(uuid.uuid4())[:8].upper()}")
    platform_name: str = ""
    tool_variant: str = ""
    os: OSPlatform = OSPlatform.UNKNOWN
    user_scope: str = ""
    browser_profile_scope: str = ""
    usage_type: str = ""  # browser, native, extension, export, remnant, etc.
    usage_path: str = ""
    artifact_family: ArtifactFamily = ArtifactFamily.UNKNOWN
    artifact_type: str = ""
    timestamp: Optional[datetime] = None
    timestamp_type: TimestampType = TimestampType.UNKNOWN
    evidence_class: str = ""  # A-N, as per strict evidentiary class separation
    supporting_artifact_ids: Set[str] = field(default_factory=set)
    source_paths: Set[str] = field(default_factory=set)
    parser_name: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNSUPPORTED
    notes: str = ""
