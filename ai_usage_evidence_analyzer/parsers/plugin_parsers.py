"""
Third-party tool-chain and plugin visibility parsers (FR-7).

Detects:
- Browser extensions / add-ons that interact with AI platforms
- ChatGPT plugins and custom GPTs
- RAG (Retrieval-Augmented Generation) source indicators
- Third-party API tool-chain traces (Zapier, IFTTT, AutoGPT, LangChain)
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

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
from ..signatures import ALL_SIGNATURES


# Known AI-related browser extensions (Chrome/Edge/Brave)
AI_EXTENSIONS = {
    # Extension ID -> (name, associated_platform)
    "mhnlakgilnojmhinhkckjpncpbhabphi": ("ChatGPT for Google", AIPlatform.CHATGPT),
    "jgjaeacdkonaoafenlfkkkmbaopkbilf": ("ChatGPT Writer", AIPlatform.CHATGPT),
    "oboonakemofpalcgghocfoadofidjkkk": ("ChatGPT Sidebar", AIPlatform.CHATGPT),
    "iaakpnchhognanibcahlpcplchdfmgma": ("WebChatGPT", AIPlatform.CHATGPT),
    "liecbddmkiiihnedobmlmillhodjkdmb": ("AIPRM for ChatGPT", AIPlatform.CHATGPT),
    "gfbhmfnnalfkfophnaeeaolgbikhbdkh": ("Claude for Chrome", AIPlatform.CLAUDE),
    "pkidhknolbjpfchahfnpfjjepjcbbnam": ("Google Gemini Extension", AIPlatform.GEMINI),
    "bfhkfdnddlhfippjbflipboognpdpoeh": ("Copilot Sidebar", AIPlatform.UNKNOWN),
    "ndjbjjjbhhechalimfihmlnfhepfmhgp": ("Perplexity AI", AIPlatform.UNKNOWN),
}

# Known AI tool-chain / automation indicators
TOOLCHAIN_INDICATORS = [
    # (regex_pattern, tool_name, description)
    (r"zapier\.com.*openai|zapier\.com.*chatgpt", "Zapier+OpenAI", "Zapier AI automation workflow"),
    (r"ifttt\.com.*(ai|chatgpt|gemini|claude)", "IFTTT+AI", "IFTTT AI integration"),
    (r"auto-gpt|autogpt", "AutoGPT", "Autonomous GPT agent framework"),
    (r"langchain|lang[-_]?chain", "LangChain", "LangChain framework traces"),
    (r"llamaindex|llama[-_]?index", "LlamaIndex", "LlamaIndex RAG framework"),
    (r"semantic[-_]?kernel", "SemanticKernel", "Microsoft Semantic Kernel"),
    (r"crew[-_]?ai|crewai", "CrewAI", "CrewAI multi-agent framework"),
    (r"huggingface|hugging[-_]?face", "HuggingFace", "HuggingFace model hub"),
    (r"replicate\.com", "Replicate", "Replicate model API"),
    (r"together\.ai|togetherai", "Together.ai", "Together.ai inference API"),
]

# ChatGPT Custom GPT / Plugin indicators
CHATGPT_PLUGIN_PATTERNS = [
    r"chat\.openai\.com/g/g-[A-Za-z0-9]+",  # Custom GPT URLs
    r"chatgpt\.com/g/g-[A-Za-z0-9]+",
    r'"gizmo_id"\s*:\s*"g-[A-Za-z0-9]+"',   # Plugin ID in JSON
    r'"namespace"\s*:\s*"[^"]+_plugin"',       # Plugin namespace
    r"gpts\.openai\.com",                      # GPT Store
]

# RAG / retrieval indicators
RAG_INDICATORS = [
    r"pinecone\.io|pinecone-client",
    r"weaviate\.(io|cloud)",
    r"chromadb|chroma[-_]?db",
    r"qdrant\.tech|qdrant",
    r"milvus\.io|pymilvus",
    r"faiss[-_]index",
]


@register_parser
class BrowserExtensionParser(BaseParser):
    """
    Detect AI-related browser extensions in Chrome/Edge/Brave/Firefox profiles.
    Addresses FR-7: Third-party tool-chain and plugin visibility.
    """

    PARSER_NAME = "BrowserExtensionParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Browser Extensions"

    # Browser extension directories (relative to user profile)
    CHROME_EXTENSIONS = [
        "AppData/Local/Google/Chrome/User Data/Default/Extensions",
        "Library/Application Support/Google/Chrome/Default/Extensions",
    ]
    EDGE_EXTENSIONS = [
        "AppData/Local/Microsoft/Edge/User Data/Default/Extensions",
        "Library/Application Support/Microsoft Edge/Default/Extensions",
    ]
    BRAVE_EXTENSIONS = [
        "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Extensions",
        "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
    ]
    FIREFOX_EXTENSIONS = [
        "AppData/Roaming/Mozilla/Firefox/Profiles",
        "Library/Application Support/Firefox/Profiles",
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)
        if not os.path.isdir(user_base):
            return self._make_result(status=ParserStatus.NOT_APPLICABLE,
                                     notes="User profile not found")

        # Check Chromium-based extension directories
        for ext_dirs in [self.CHROME_EXTENSIONS, self.EDGE_EXTENSIONS, self.BRAVE_EXTENSIONS]:
            for ext_rel in ext_dirs:
                ext_path = os.path.join(user_base, ext_rel)
                paths_searched.append(ext_path)
                if not os.path.isdir(ext_path):
                    continue
                paths_found.append(ext_path)

                try:
                    for ext_id in os.listdir(ext_path):
                        ext_dir = os.path.join(ext_path, ext_id)
                        if not os.path.isdir(ext_dir):
                            continue

                        # Check known AI extensions
                        if ext_id in AI_EXTENSIONS:
                            name, platform = AI_EXTENSIONS[ext_id]
                            artifacts.append(self._make_extension_artifact(
                                ext_id, name, platform, ext_dir,
                                ConfidenceLevel.HIGH,
                                EvidenceClassification.DIRECT,
                            ))
                        else:
                            # Check manifest.json for AI-related keywords
                            manifest = self._read_manifest(ext_dir)
                            if manifest:
                                ai_match = self._check_manifest_ai(manifest)
                                if ai_match:
                                    artifacts.append(self._make_extension_artifact(
                                        ext_id,
                                        manifest.get("name", ext_id),
                                        ai_match,
                                        ext_dir,
                                        ConfidenceLevel.MODERATE,
                                        EvidenceClassification.INFERRED,
                                    ))
                except OSError as e:
                    errors.append(f"Error scanning {ext_path}: {e}")

        # Check Firefox extensions (addons.json)
        for ff_rel in self.FIREFOX_EXTENSIONS:
            ff_path = os.path.join(user_base, ff_rel)
            paths_searched.append(ff_path)
            if not os.path.isdir(ff_path):
                continue
            for profile_dir in os.listdir(ff_path):
                addons_json = os.path.join(ff_path, profile_dir, "addons.json")
                if os.path.isfile(addons_json):
                    paths_found.append(addons_json)
                    try:
                        with open(addons_json, "r", encoding="utf-8", errors="replace") as f:
                            data = json.load(f)
                        for addon in data.get("addons", []):
                            name = addon.get("name", "")
                            desc = addon.get("description", "")
                            combined = f"{name} {desc}".lower()
                            for kw in ["chatgpt", "claude", "gemini", "openai", "anthropic",
                                       "perplexity", "copilot", "meta ai", "grok", "poe",
                                       "ai assistant"]:
                                if kw in combined:
                                    platform = AIPlatform.UNKNOWN
                                    if "chatgpt" in combined or "openai" in combined:
                                        platform = AIPlatform.CHATGPT
                                    elif "claude" in combined or "anthropic" in combined:
                                        platform = AIPlatform.CLAUDE
                                    elif "gemini" in combined:
                                        platform = AIPlatform.GEMINI
                                    elif "perplexity" in combined:
                                        platform = AIPlatform.PERPLEXITY
                                    elif "copilot" in combined:
                                        platform = AIPlatform.COPILOT
                                    elif "meta ai" in combined:
                                        platform = AIPlatform.META_AI
                                    elif "grok" in combined:
                                        platform = AIPlatform.GROK
                                    elif "poe" in combined:
                                        platform = AIPlatform.POE
                                    artifacts.append(ArtifactRecord(
                                        case_id=self.case_id,
                                        evidence_item_id=self.evidence_item_id,
                                        source_image=self.source_image,
                                        user_profile=self.user_profile,
                                        artifact_family=ArtifactFamily.BROWSER_SESSION,
                                        artifact_type="Firefox AI Extension",
                                        artifact_subtype="addon",
                                        artifact_path=addons_json,
                                        parser_used=self.PARSER_NAME,
                                        extracted_indicator=f"Firefox addon: {name}",
                                        suspected_platform=platform,
                                        attribution_layer=AttributionLayer.PLATFORM,
                                        confidence=ConfidenceLevel.MODERATE,
                                        classification=EvidenceClassification.INFERRED,
                                    ))
                                    break
                    except (json.JSONDecodeError, OSError) as e:
                        errors.append(f"Error reading {addons_json}: {e}")

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"Found {len(artifacts)} AI-related browser extensions",
        )

    def _read_manifest(self, ext_dir: str) -> Optional[Dict]:
        """Read the most recent manifest.json from an extension directory."""
        for version_dir in sorted(os.listdir(ext_dir), reverse=True):
            manifest_path = os.path.join(ext_dir, version_dir, "manifest.json")
            if os.path.isfile(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass
        # Try root-level manifest
        root_manifest = os.path.join(ext_dir, "manifest.json")
        if os.path.isfile(root_manifest):
            try:
                with open(root_manifest, "r", encoding="utf-8", errors="replace") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return None

    def _check_manifest_ai(self, manifest: Dict) -> Optional[AIPlatform]:
        """Check if an extension manifest references AI platforms."""
        text = json.dumps(manifest).lower()
        if any(k in text for k in ["chatgpt", "openai", "gpt-4"]):
            return AIPlatform.CHATGPT
        if any(k in text for k in ["claude", "anthropic"]):
            return AIPlatform.CLAUDE
        if any(k in text for k in ["gemini", "bard", "google ai"]):
            return AIPlatform.GEMINI
        if any(k in text for k in ["ai assistant", "ai copilot", "ai writer", "ai chat"]):
            return AIPlatform.UNKNOWN
        return None

    def _make_extension_artifact(
        self, ext_id: str, name: str, platform: AIPlatform,
        path: str, confidence: ConfidenceLevel,
        classification: EvidenceClassification,
    ) -> ArtifactRecord:
        # Try to get install time from directory mtime
        ts = None
        try:
            ts = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        except OSError:
            pass
        return ArtifactRecord(
            case_id=self.case_id,
            evidence_item_id=self.evidence_item_id,
            source_image=self.source_image,
            user_profile=self.user_profile,
            artifact_family=ArtifactFamily.BROWSER_SESSION,
            artifact_type="AI Browser Extension",
            artifact_subtype="chromium-extension",
            artifact_path=path,
            parser_used=self.PARSER_NAME,
            timestamp=ts,
            timestamp_type=TimestampType.MODIFIED,
            extracted_indicator=f"Extension: {name} (ID: {ext_id})",
            suspected_platform=platform,
            attribution_layer=AttributionLayer.PLATFORM,
            confidence=confidence,
            classification=classification,
            notes=f"Browser extension '{name}' associated with {platform.value}",
        )


@register_parser
class ToolChainParser(BaseParser):
    """
    Detect third-party AI tool-chain and automation traces.
    Scans browser history, downloads, and local files for:
    - AutoGPT, LangChain, LlamaIndex usage
    - Zapier/IFTTT AI automation workflows
    - ChatGPT Custom GPT and Plugin usage
    - RAG vector-database indicators
    """

    PARSER_NAME = "ToolChainParser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_OS = [OSPlatform.WINDOWS, OSPlatform.MACOS]
    ARTIFACT_FAMILY = "Tool Chain"

    HISTORY_DBS = [
        ("Chrome", "AppData/Local/Google/Chrome/User Data/Default/History"),
        ("Chrome", "Library/Application Support/Google/Chrome/Default/History"),
        ("Edge", "AppData/Local/Microsoft/Edge/User Data/Default/History"),
        ("Edge", "Library/Application Support/Microsoft Edge/Default/History"),
    ]

    def parse(self) -> ParserResult:
        artifacts: List[ArtifactRecord] = []
        errors: List[str] = []
        paths_searched: List[str] = []
        paths_found: List[str] = []

        user_base = os.path.join(self.evidence_root, "Users", self.user_profile)
        if not os.path.isdir(user_base):
            return self._make_result(status=ParserStatus.NOT_APPLICABLE,
                                     notes="User profile not found")

        # Scan browser history for tool-chain indicators
        for browser_name, hist_rel in self.HISTORY_DBS:
            hist_path = os.path.join(user_base, hist_rel)
            paths_searched.append(hist_path)
            if not os.path.isfile(hist_path):
                continue
            paths_found.append(hist_path)

            try:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
                tmp.close()
                shutil.copy2(hist_path, tmp.name)
                conn = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT url, title FROM urls").fetchall()
                conn.close()

                for row in rows:
                    url = row["url"] or ""
                    title = row["title"] or ""
                    combined = f"{url} {title}".lower()

                    # Check ChatGPT plugins / Custom GPTs
                    for pattern in CHATGPT_PLUGIN_PATTERNS:
                        if re.search(pattern, combined, re.IGNORECASE):
                            artifacts.append(ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                                artifact_type="ChatGPT Plugin/Custom GPT",
                                artifact_subtype="plugin_url",
                                artifact_path=hist_path,
                                parser_used=self.PARSER_NAME,
                                extracted_indicator=url[:500],
                                suspected_platform=AIPlatform.CHATGPT,
                                attribution_layer=AttributionLayer.PLATFORM,
                                confidence=ConfidenceLevel.HIGH,
                                classification=EvidenceClassification.DIRECT,
                                notes=f"Custom GPT or plugin URL found in {browser_name} history",
                            ))
                            break

                    # Check tool-chain indicators
                    for pattern, tool_name, desc in TOOLCHAIN_INDICATORS:
                        if re.search(pattern, combined, re.IGNORECASE):
                            artifacts.append(ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                                artifact_type="AI Tool-Chain Trace",
                                artifact_subtype="toolchain_url",
                                artifact_path=hist_path,
                                parser_used=self.PARSER_NAME,
                                extracted_indicator=f"{tool_name}: {url[:300]}",
                                suspected_platform=AIPlatform.UNKNOWN,
                                attribution_layer=AttributionLayer.CONTENT,
                                confidence=ConfidenceLevel.MODERATE,
                                classification=EvidenceClassification.INFERRED,
                                notes=f"{desc} — detected in {browser_name} history",
                            ))
                            break

                    # Check RAG indicators
                    for pattern in RAG_INDICATORS:
                        if re.search(pattern, combined, re.IGNORECASE):
                            artifacts.append(ArtifactRecord(
                                case_id=self.case_id,
                                evidence_item_id=self.evidence_item_id,
                                source_image=self.source_image,
                                user_profile=self.user_profile,
                                artifact_family=ArtifactFamily.BROWSER_HISTORY,
                                artifact_type="RAG Infrastructure Trace",
                                artifact_subtype="rag_url",
                                artifact_path=hist_path,
                                parser_used=self.PARSER_NAME,
                                extracted_indicator=url[:500],
                                suspected_platform=AIPlatform.UNKNOWN,
                                attribution_layer=AttributionLayer.CONTENT,
                                confidence=ConfidenceLevel.LOW,
                                classification=EvidenceClassification.INFERRED,
                                notes="RAG vector-database service detected in browser history",
                            ))
                            break

                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
            except (sqlite3.Error, OSError) as e:
                errors.append(f"Error querying {hist_path}: {e}")

        # Scan local files for tool-chain config/artifacts
        toolchain_files = [
            (".autogpt", "AutoGPT", "AutoGPT agent configuration"),
            (".langchain", "LangChain", "LangChain configuration"),
            (".env", "Environment", "API key environment file"),
        ]
        for fname, tool, desc in toolchain_files:
            fpath = os.path.join(user_base, fname)
            if os.path.isfile(fpath):
                paths_found.append(fpath)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read(4096)
                    ai_keys = re.findall(
                        r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_AI_KEY|"
                        r"HUGGINGFACE_TOKEN|REPLICATE_API_TOKEN)",
                        content, re.IGNORECASE,
                    )
                    if ai_keys:
                        artifacts.append(ArtifactRecord(
                            case_id=self.case_id,
                            evidence_item_id=self.evidence_item_id,
                            source_image=self.source_image,
                            user_profile=self.user_profile,
                            artifact_family=ArtifactFamily.FILE_SYSTEM,
                            artifact_type="AI API Configuration",
                            artifact_subtype="config_file",
                            artifact_path=fpath,
                            parser_used=self.PARSER_NAME,
                            extracted_indicator=f"API keys found: {', '.join(set(ai_keys))}",
                            suspected_platform=AIPlatform.UNKNOWN,
                            attribution_layer=AttributionLayer.PLATFORM,
                            confidence=ConfidenceLevel.MODERATE,
                            classification=EvidenceClassification.INFERRED,
                            notes=f"{desc} — contains AI service API key references",
                        ))
                except OSError:
                    pass

        status = ParserStatus.SUCCESS if artifacts else ParserStatus.NOT_APPLICABLE
        return self._make_result(
            status=status,
            artifacts=artifacts,
            errors=errors,
            paths_searched=paths_searched,
            paths_found=paths_found,
            notes=f"Found {len(artifacts)} tool-chain/plugin artifacts",
        )
