"""
AI detection signatures and rules for ChatGPT, Claude, Gemini,
Perplexity, Microsoft Copilot, Meta AI, Grok, Poe, Adobe Firefly,
Checkr, Tidio, Lindy, Synthesia, Lattice AI, DataRobot, Leena AI,
and Nexos AI.

This module contains all known forensic indicators, domains, URLs, app names,
bundle IDs, filename patterns, and other detection signatures for the
target AI platforms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import AIPlatform, AIModel


# ---------------------------------------------------------------------------
# Detection Signature Definitions
# ---------------------------------------------------------------------------

@dataclass
class PlatformSignature:
    """A collection of forensic indicators for one AI platform."""
    platform: AIPlatform
    domains: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    cookie_domains: List[str] = field(default_factory=list)
    app_names_windows: List[str] = field(default_factory=list)
    app_names_macos: List[str] = field(default_factory=list)
    bundle_ids: List[str] = field(default_factory=list)
    package_ids_mobile: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)
    local_storage_keys: List[str] = field(default_factory=list)
    cache_db_names: List[str] = field(default_factory=list)
    download_patterns: List[str] = field(default_factory=list)
    export_patterns: List[str] = field(default_factory=list)
    screenshot_patterns: List[str] = field(default_factory=list)
    prompt_indicators: List[str] = field(default_factory=list)
    response_indicators: List[str] = field(default_factory=list)
    model_strings: Dict[AIModel, List[str]] = field(default_factory=dict)
    search_keywords: List[str] = field(default_factory=list)
    app_support_folders_macos: List[str] = field(default_factory=list)
    app_data_folders_windows: List[str] = field(default_factory=list)
    prefetch_names: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ChatGPT / OpenAI Signatures
# ---------------------------------------------------------------------------

CHATGPT_SIGNATURES = PlatformSignature(
    platform=AIPlatform.CHATGPT,
    domains=[
        "chat.openai.com",
        "chatgpt.com",
        "openai.com",
        "cdn.oaistatic.com",
        "auth0.openai.com",
        "ab.chatgpt.com",
        "api.openai.com",
    ],
    url_patterns=[
        r"https?://chat\.openai\.com",
        r"https?://chatgpt\.com",
        r"https?://openai\.com/chat",
        r"https?://cdn\.oaistatic\.com",
        r"chatgpt\.com/c/",
        r"chat\.openai\.com/c/",
        r"chat\.openai\.com/g/",
    ],
    cookie_domains=[
        ".openai.com",
        ".chatgpt.com",
        "chat.openai.com",
        "chatgpt.com",
    ],
    app_names_windows=[
        "ChatGPT",
        "ChatGPT.exe",
    ],
    app_names_macos=[
        "ChatGPT",
        "com.openai.chat",
    ],
    bundle_ids=[
        "com.openai.chat",
        "com.openai.chatgpt",
    ],
    package_ids_mobile=[
        "com.openai.chatgpt",
    ],
    process_names=[
        "ChatGPT",
        "ChatGPT.exe",
        "chatgpt",
    ],
    local_storage_keys=[
        "chatgpt",
        "openai",
        "__Secure-next-auth.session-token",
        "oai-did",
        "_puid",
    ],
    cache_db_names=[
        "chat.openai.com",
        "chatgpt.com",
    ],
    download_patterns=[
        r"chat[-_]?gpt.*\.(?:txt|json|md|pdf|html|csv)",
        r"conversations?.*\.json",
        r"openai.*export",
        r"chatgpt[-_]export",
        r"chatgpt.*\.zip",
    ],
    export_patterns=[
        r"chat[-_]?gpt.*export",
        r"conversations\.json",
        r"message_feed",
        r"chat_export",
    ],
    screenshot_patterns=[
        r"chatgpt",
        r"chat\.openai",
        r"openai.*screenshot",
    ],
    prompt_indicators=[
        "send a message",
        "Message ChatGPT",
        "You said:",
        "ChatGPT said:",
    ],
    response_indicators=[
        "ChatGPT",
        "as an AI language model",
        "as a large language model",
        "I'm ChatGPT",
    ],
    model_strings={
        AIModel.GPT4: ["gpt-4", "GPT-4"],
        AIModel.GPT4_TURBO: ["gpt-4-turbo", "GPT-4 Turbo"],
        AIModel.GPT4O: ["gpt-4o", "GPT-4o"],
    },
    search_keywords=[
        "chatgpt",
        "chat gpt",
        "openai",
        "gpt-4",
        "gpt4",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/com.openai.chat",
        "~/Library/Containers/com.openai.chat",
        "~/Library/Group Containers/group.com.openai.chat",
    ],
    app_data_folders_windows=[
        "AppData/Local/Programs/ChatGPT",
        "AppData/Local/ChatGPT",
        "AppData/Roaming/ChatGPT",
    ],
    prefetch_names=[
        "CHATGPT.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\OpenAI",
        r"SOFTWARE\ChatGPT",
    ],
)


# ---------------------------------------------------------------------------
# Claude / Anthropic Signatures
# ---------------------------------------------------------------------------

CLAUDE_SIGNATURES = PlatformSignature(
    platform=AIPlatform.CLAUDE,
    domains=[
        "claude.ai",
        "anthropic.com",
        "api.anthropic.com",
        "cdn.anthropic.com",
        "console.anthropic.com",
    ],
    url_patterns=[
        r"https?://claude\.ai",
        r"https?://anthropic\.com",
        r"claude\.ai/chat",
        r"claude\.ai/new",
    ],
    cookie_domains=[
        ".claude.ai",
        "claude.ai",
        ".anthropic.com",
    ],
    app_names_windows=[
        "Claude",
        "Claude.exe",
    ],
    app_names_macos=[
        "Claude",
        "com.anthropic.claude",
    ],
    bundle_ids=[
        "com.anthropic.claude",
        "com.anthropic.claudeapp",
    ],
    package_ids_mobile=[
        "com.anthropic.claude",
    ],
    process_names=[
        "Claude",
        "Claude.exe",
        "claude",
    ],
    local_storage_keys=[
        "claude",
        "anthropic",
    ],
    cache_db_names=[
        "claude.ai",
    ],
    download_patterns=[
        r"claude.*\.(?:txt|json|md|pdf|html|csv)",
        r"anthropic.*\.(?:txt|json|md|pdf)",
        r"claude[-_]?export",
        r"artifact.*\.(?:txt|py|js|html|json|md)",
    ],
    export_patterns=[
        r"claude.*export",
        r"claude.*artifact",
        r"anthropic.*export",
    ],
    screenshot_patterns=[
        r"claude",
        r"anthropic",
    ],
    prompt_indicators=[
        "Reply to Claude",
        "Message Claude",
    ],
    response_indicators=[
        "Claude",
        "I'm Claude",
        "as Claude",
        "Anthropic",
    ],
    model_strings={
        AIModel.CLAUDE_3_OPUS: ["claude-3-opus", "Claude 3 Opus"],
        AIModel.CLAUDE_3_SONNET: ["claude-3-sonnet", "Claude 3 Sonnet"],
        AIModel.CLAUDE_3_HAIKU: ["claude-3-haiku", "Claude 3 Haiku"],
        AIModel.CLAUDE_35_SONNET: ["claude-3-5-sonnet", "Claude 3.5 Sonnet", "claude-3.5-sonnet"],
    },
    search_keywords=[
        "claude ai",
        "claude",
        "anthropic",
        "claude 3",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/com.anthropic.claude",
        "~/Library/Containers/com.anthropic.claude",
    ],
    app_data_folders_windows=[
        "AppData/Local/Programs/Claude",
        "AppData/Local/Claude",
        "AppData/Roaming/Claude",
    ],
    prefetch_names=[
        "CLAUDE.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Anthropic",
        r"SOFTWARE\Claude",
    ],
)


# ---------------------------------------------------------------------------
# Gemini / Google Signatures
# ---------------------------------------------------------------------------

GEMINI_SIGNATURES = PlatformSignature(
    platform=AIPlatform.GEMINI,
    domains=[
        "gemini.google.com",
        "bard.google.com",
        "aistudio.google.com",
        "generativelanguage.googleapis.com",
        "makersuite.google.com",
        "deepmind.google",
    ],
    url_patterns=[
        r"https?://gemini\.google\.com",
        r"https?://bard\.google\.com",
        r"https?://aistudio\.google\.com",
        r"gemini\.google\.com/app",
        r"gemini\.google\.com/chat",
    ],
    cookie_domains=[
        ".google.com",
        "gemini.google.com",
        "bard.google.com",
    ],
    app_names_windows=[
        "Google Gemini",
    ],
    app_names_macos=[
        "Google Gemini",
    ],
    bundle_ids=[
        "com.google.Gemini",
        "com.google.bard",
    ],
    package_ids_mobile=[
        "com.google.android.apps.bard",
        "com.google.gemini",
    ],
    process_names=[
        "Gemini",
    ],
    local_storage_keys=[
        "gemini",
        "bard",
    ],
    cache_db_names=[
        "gemini.google.com",
        "bard.google.com",
    ],
    download_patterns=[
        r"gemini.*\.(?:txt|json|md|pdf|html|csv)",
        r"bard.*\.(?:txt|json|md|pdf)",
        r"gemini[-_]?export",
    ],
    export_patterns=[
        r"gemini.*export",
        r"bard.*export",
    ],
    screenshot_patterns=[
        r"gemini",
        r"bard",
    ],
    prompt_indicators=[
        "Enter a prompt here",
        "Ask Gemini",
    ],
    response_indicators=[
        "Gemini",
        "Google Gemini",
    ],
    model_strings={
        AIModel.GEMINI_PRO: ["gemini-pro", "Gemini Pro"],
        AIModel.GEMINI_ULTRA: ["gemini-ultra", "Gemini Ultra"],
        AIModel.GEMINI_15_PRO: ["gemini-1.5-pro", "Gemini 1.5 Pro"],
    },
    search_keywords=[
        "gemini",
        "google gemini",
        "bard",
        "google bard",
        "gemini pro",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Google/Gemini",
    ],
    app_data_folders_windows=[
        "AppData/Local/Google/Gemini",
    ],
    prefetch_names=[],
    registry_keys=[],
)


# ---------------------------------------------------------------------------
# Perplexity Signatures
# ---------------------------------------------------------------------------

PERPLEXITY_SIGNATURES = PlatformSignature(
    platform=AIPlatform.PERPLEXITY,
    domains=[
        "perplexity.ai",
        "www.perplexity.ai",
        "api.perplexity.ai",
        "labs.perplexity.ai",
    ],
    url_patterns=[
        r"https?://(?:www\.)?perplexity\.ai",
        r"perplexity\.ai/search",
        r"perplexity\.ai/collections",
    ],
    cookie_domains=[
        ".perplexity.ai",
        "perplexity.ai",
    ],
    app_names_windows=[
        "Perplexity",
        "Perplexity.exe",
    ],
    app_names_macos=[
        "Perplexity",
        "ai.perplexity.app",
    ],
    bundle_ids=[
        "ai.perplexity.app",
        "ai.perplexity.app.mac",
    ],
    package_ids_mobile=[
        "ai.perplexity.app.android",
        "ai.perplexity.app.ios",
    ],
    process_names=[
        "Perplexity",
        "Perplexity.exe",
    ],
    local_storage_keys=[
        "perplexity",
    ],
    cache_db_names=[
        "perplexity.ai",
    ],
    download_patterns=[
        r"perplexity.*\.(?:txt|json|md|pdf|html|csv)",
    ],
    export_patterns=[
        r"perplexity.*export",
    ],
    screenshot_patterns=[
        r"perplexity",
    ],
    prompt_indicators=[
        "Ask anything",
        "Ask follow-up",
    ],
    response_indicators=[
        "Perplexity",
        "Sources",
    ],
    model_strings={
        AIModel.PERPLEXITY_ONLINE: ["perplexity-online", "pplx-online", "sonar"],
    },
    search_keywords=[
        "perplexity",
        "perplexity ai",
        "pplx",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/ai.perplexity.app",
        "~/Library/Containers/ai.perplexity.app",
    ],
    app_data_folders_windows=[
        "AppData/Local/Perplexity",
        "AppData/Roaming/Perplexity",
    ],
    prefetch_names=[
        "PERPLEXITY.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Perplexity",
    ],
)


# ---------------------------------------------------------------------------
# Microsoft Copilot Signatures
# ---------------------------------------------------------------------------

COPILOT_SIGNATURES = PlatformSignature(
    platform=AIPlatform.COPILOT,
    domains=[
        "copilot.microsoft.com",
        "www.bing.com/chat",
        "sydney.bing.com",
        "edgeservices.bing.com",
        "copilot.cloud.microsoft",
        "copilot.microsoft365.com",
        "github.copilot.com",
        "m365.cloud.microsoft/chat",
    ],
    url_patterns=[
        r"https?://copilot\.microsoft\.com",
        r"https?://www\.bing\.com/chat",
        r"https?://www\.bing\.com/search\?.*showconv=1",
        r"copilot\.microsoft365\.com",
        r"copilot\.cloud\.microsoft",
    ],
    cookie_domains=[
        ".microsoft.com",
        ".bing.com",
        "copilot.microsoft.com",
    ],
    app_names_windows=[
        "Microsoft Copilot",
        "Copilot",
        "Microsoft.Copilot",
    ],
    app_names_macos=[
        "Microsoft Copilot",
    ],
    bundle_ids=[
        "com.microsoft.copilot",
    ],
    package_ids_mobile=[
        "com.microsoft.copilot",
        "com.microsoft.bing",
    ],
    process_names=[
        "Copilot",
        "Copilot.exe",
        "Microsoft.Copilot.exe",
    ],
    local_storage_keys=[
        "copilot",
        "bing_chat",
        "sydney",
    ],
    cache_db_names=[
        "copilot.microsoft.com",
        "www.bing.com",
    ],
    download_patterns=[
        r"copilot.*\.(?:txt|json|md|pdf|html|csv)",
        r"bing[-_]?chat.*\.(?:txt|json)",
    ],
    export_patterns=[
        r"copilot.*export",
        r"bing.*chat.*export",
    ],
    screenshot_patterns=[
        r"copilot",
        r"bing.*chat",
    ],
    prompt_indicators=[
        "Ask me anything",
        "Message Copilot",
        "Ask Copilot",
    ],
    response_indicators=[
        "Copilot",
        "Microsoft Copilot",
        "Bing Chat",
    ],
    model_strings={
        AIModel.COPILOT_GPT4: ["copilot-gpt4", "Copilot GPT-4"],
    },
    search_keywords=[
        "copilot",
        "microsoft copilot",
        "bing chat",
        "bing copilot",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/com.microsoft.copilot",
    ],
    app_data_folders_windows=[
        "AppData/Local/Microsoft/Copilot",
        "AppData/Local/Packages/Microsoft.Copilot_8wekyb3d8bbwe",
        "AppData/Local/Microsoft/Edge/User Data",
    ],
    prefetch_names=[
        "COPILOT.EXE",
        "MICROSOFT.COPILOT.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Microsoft\Copilot",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Copilot",
    ],
)


# ---------------------------------------------------------------------------
# Meta AI Signatures
# ---------------------------------------------------------------------------

META_AI_SIGNATURES = PlatformSignature(
    platform=AIPlatform.META_AI,
    domains=[
        "meta.ai",
        "www.meta.ai",
        "ai.meta.com",
        "llama.meta.com",
        "imagine.meta.com",
    ],
    url_patterns=[
        r"https?://(?:www\.)?meta\.ai",
        r"https?://ai\.meta\.com",
        r"meta\.ai/\?utm",
    ],
    cookie_domains=[
        ".meta.ai",
        "meta.ai",
        ".meta.com",
    ],
    app_names_windows=[
        "Meta AI",
    ],
    app_names_macos=[
        "Meta AI",
    ],
    bundle_ids=[
        "com.meta.ai",
        "com.facebook.orca",
    ],
    package_ids_mobile=[
        "com.meta.ai",
        "com.facebook.orca",
        "com.instagram.android",
        "com.whatsapp",
    ],
    process_names=[
        "MetaAI",
    ],
    local_storage_keys=[
        "meta_ai",
        "metaai",
    ],
    cache_db_names=[
        "meta.ai",
    ],
    download_patterns=[
        r"meta[-_]?ai.*\.(?:txt|json|md|pdf|html|csv)",
    ],
    export_patterns=[
        r"meta[-_]?ai.*export",
    ],
    screenshot_patterns=[
        r"meta[\s_-]?ai",
    ],
    prompt_indicators=[
        "Ask Meta AI anything",
        "Message Meta AI",
    ],
    response_indicators=[
        "Meta AI",
    ],
    model_strings={
        AIModel.LLAMA_3: ["llama-3", "Llama 3", "llama3"],
    },
    search_keywords=[
        "meta ai",
        "meta llama",
        "llama ai",
        "meta.ai",
    ],
    app_support_folders_macos=[],
    app_data_folders_windows=[],
    prefetch_names=[],
    registry_keys=[],
)


# ---------------------------------------------------------------------------
# Grok / xAI Signatures
# ---------------------------------------------------------------------------

GROK_SIGNATURES = PlatformSignature(
    platform=AIPlatform.GROK,
    domains=[
        "grok.com",
        "x.ai",
        "api.x.ai",
        "console.x.ai",
    ],
    url_patterns=[
        r"https?://grok\.com",
        r"https?://x\.ai",
        r"grok\.com/chat",
    ],
    cookie_domains=[
        ".grok.com",
        "grok.com",
        ".x.ai",
    ],
    app_names_windows=[
        "Grok",
        "Grok.exe",
    ],
    app_names_macos=[
        "Grok",
    ],
    bundle_ids=[
        "ai.x.grok",
    ],
    package_ids_mobile=[
        "ai.x.grok",
    ],
    process_names=[
        "Grok",
        "Grok.exe",
    ],
    local_storage_keys=[
        "grok",
        "xai",
    ],
    cache_db_names=[
        "grok.com",
        "x.ai",
    ],
    download_patterns=[
        r"grok.*\.(?:txt|json|md|pdf|html|csv)",
    ],
    export_patterns=[
        r"grok.*export",
    ],
    screenshot_patterns=[
        r"grok",
    ],
    prompt_indicators=[
        "Ask Grok",
        "Talk to Grok",
    ],
    response_indicators=[
        "Grok",
        "xAI",
    ],
    model_strings={
        AIModel.GROK_2: ["grok-2", "Grok-2", "grok-beta"],
    },
    search_keywords=[
        "grok",
        "grok ai",
        "xai grok",
        "grok.com",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/ai.x.grok",
    ],
    app_data_folders_windows=[
        "AppData/Local/Grok",
        "AppData/Roaming/Grok",
    ],
    prefetch_names=[
        "GROK.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\xAI",
        r"SOFTWARE\Grok",
    ],
)


# ---------------------------------------------------------------------------
# Poe (Quora) Signatures
# ---------------------------------------------------------------------------

POE_SIGNATURES = PlatformSignature(
    platform=AIPlatform.POE,
    domains=[
        "poe.com",
        "www.poe.com",
        "api.poe.com",
    ],
    url_patterns=[
        r"https?://(?:www\.)?poe\.com",
        r"poe\.com/chat",
        r"poe\.com/[A-Z]",
    ],
    cookie_domains=[
        ".poe.com",
        "poe.com",
    ],
    app_names_windows=[
        "Poe",
        "Poe.exe",
    ],
    app_names_macos=[
        "Poe",
        "ai.poe.app",
    ],
    bundle_ids=[
        "ai.poe.app",
        "com.quora.poe",
    ],
    package_ids_mobile=[
        "com.quora.poe",
        "ai.poe.app",
    ],
    process_names=[
        "Poe",
        "Poe.exe",
    ],
    local_storage_keys=[
        "poe",
        "quora_poe",
    ],
    cache_db_names=[
        "poe.com",
    ],
    download_patterns=[
        r"poe.*\.(?:txt|json|md|pdf|html|csv)",
    ],
    export_patterns=[
        r"poe.*export",
    ],
    screenshot_patterns=[
        r"poe",
    ],
    prompt_indicators=[
        "Talk to",
        "Start a new chat",
    ],
    response_indicators=[
        "Poe",
    ],
    model_strings={},
    search_keywords=[
        "poe",
        "poe ai",
        "poe.com",
        "quora poe",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/ai.poe.app",
        "~/Library/Containers/ai.poe.app",
    ],
    app_data_folders_windows=[
        "AppData/Local/Poe",
        "AppData/Roaming/Poe",
    ],
    prefetch_names=[
        "POE.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Poe",
    ],
)


# ---------------------------------------------------------------------------
# Adobe Firefly Signatures
# ---------------------------------------------------------------------------

ADOBE_FIREFLY_SIGNATURES = PlatformSignature(
    platform=AIPlatform.ADOBE_FIREFLY,
    domains=[
        "firefly.adobe.com",
        "adobe.com",
        "firefly-api.adobe.io",
        "cc-api-storage.adobe.io",
    ],
    url_patterns=[
        r"https?://firefly\.adobe\.com",
        r"https?://.*\.adobe\.com/firefly",
        r"firefly\.adobe\.com/generate",
        r"firefly\.adobe\.com/upload",
    ],
    cookie_domains=[
        ".adobe.com",
        "firefly.adobe.com",
    ],
    app_names_windows=[
        "Adobe Firefly",
        "AdobeFirefly.exe",
        "Adobe Creative Cloud",
    ],
    app_names_macos=[
        "Adobe Firefly",
        "Adobe Creative Cloud",
    ],
    bundle_ids=[
        "com.adobe.firefly",
        "com.adobe.cc.firefly",
    ],
    package_ids_mobile=[
        "com.adobe.firefly",
    ],
    process_names=[
        "AdobeFirefly",
        "Adobe Firefly",
    ],
    local_storage_keys=[
        "adobe_firefly",
        "firefly_session",
    ],
    cache_db_names=[
        "firefly.adobe.com",
    ],
    download_patterns=[
        r"firefly.*\.(?:png|jpg|jpeg|psd|ai)",
        r"adobe.*firefly.*\.(?:png|jpg)",
    ],
    export_patterns=[
        r"firefly.*export",
        r"firefly.*generated",
    ],
    screenshot_patterns=[
        r"firefly",
        r"adobe.*ai",
    ],
    prompt_indicators=[
        "Text to image",
        "Generate",
        "Describe what you want to create",
    ],
    response_indicators=[
        "Generated by Adobe Firefly",
        "Firefly",
    ],
    model_strings={
        AIModel.FIREFLY_2: ["Firefly 2", "firefly-2"],
        AIModel.FIREFLY_3: ["Firefly 3", "firefly-3"],
    },
    search_keywords=[
        "adobe firefly",
        "firefly ai",
        "adobe ai",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Adobe/Firefly",
        "~/Library/Caches/Adobe/Firefly",
    ],
    app_data_folders_windows=[
        "AppData/Local/Adobe/Firefly",
        "AppData/Roaming/Adobe/Firefly",
    ],
    prefetch_names=[
        "ADOBEFIREFLY.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Adobe\Firefly",
    ],
)


# ---------------------------------------------------------------------------
# Checkr Signatures
# ---------------------------------------------------------------------------

CHECKR_SIGNATURES = PlatformSignature(
    platform=AIPlatform.CHECKR,
    domains=[
        "checkr.com",
        "dashboard.checkr.com",
        "api.checkr.com",
        "app.checkr.com",
    ],
    url_patterns=[
        r"https?://.*\.checkr\.com",
        r"checkr\.com/dashboard",
        r"checkr\.com/candidates",
    ],
    cookie_domains=[
        ".checkr.com",
        "dashboard.checkr.com",
    ],
    app_names_windows=[
        "Checkr",
    ],
    app_names_macos=[
        "Checkr",
    ],
    bundle_ids=[
        "com.checkr.app",
    ],
    package_ids_mobile=[
        "com.checkr.candidate",
        "com.checkr.app",
    ],
    process_names=[
        "Checkr",
    ],
    local_storage_keys=[
        "checkr",
        "checkr_session",
    ],
    cache_db_names=[
        "checkr.com",
    ],
    download_patterns=[
        r"checkr.*\.(?:pdf|csv)",
        r"background.*check.*\.pdf",
    ],
    export_patterns=[
        r"checkr.*report",
        r"checkr.*export",
    ],
    screenshot_patterns=[
        r"checkr",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "checkr",
        "background check",
        "checkr ai",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Checkr",
    ],
    app_data_folders_windows=[
        "AppData/Local/Checkr",
        "AppData/Roaming/Checkr",
    ],
    prefetch_names=[
        "CHECKR.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Checkr",
    ],
)


# ---------------------------------------------------------------------------
# Tidio Signatures
# ---------------------------------------------------------------------------

TIDIO_SIGNATURES = PlatformSignature(
    platform=AIPlatform.TIDIO,
    domains=[
        "tidio.com",
        "www.tidio.com",
        "panel.tidio.com",
        "api.tidio.co",
    ],
    url_patterns=[
        r"https?://.*\.tidio\.com",
        r"tidio\.com/panel",
        r"tidio\.com/dashboard",
    ],
    cookie_domains=[
        ".tidio.com",
        "panel.tidio.com",
    ],
    app_names_windows=[
        "Tidio",
    ],
    app_names_macos=[
        "Tidio",
    ],
    bundle_ids=[
        "com.tidio.app",
    ],
    package_ids_mobile=[
        "com.tidio.chat",
    ],
    process_names=[
        "Tidio",
    ],
    local_storage_keys=[
        "tidio",
        "tidio_state",
    ],
    cache_db_names=[
        "tidio.com",
    ],
    download_patterns=[
        r"tidio.*\.(?:csv|json)",
        r"tidio.*chat.*\.(?:txt|csv)",
    ],
    export_patterns=[
        r"tidio.*export",
    ],
    screenshot_patterns=[
        r"tidio",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "tidio",
        "tidio chat",
        "tidio ai",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Tidio",
    ],
    app_data_folders_windows=[
        "AppData/Local/Tidio",
        "AppData/Roaming/Tidio",
    ],
    prefetch_names=[
        "TIDIO.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Tidio",
    ],
)


# ---------------------------------------------------------------------------
# Lindy Signatures
# ---------------------------------------------------------------------------

LINDY_SIGNATURES = PlatformSignature(
    platform=AIPlatform.LINDY,
    domains=[
        "lindy.ai",
        "app.lindy.ai",
        "api.lindy.ai",
    ],
    url_patterns=[
        r"https?://.*\.lindy\.ai",
        r"lindy\.ai/app",
        r"lindy\.ai/agents",
    ],
    cookie_domains=[
        ".lindy.ai",
        "app.lindy.ai",
    ],
    app_names_windows=[
        "Lindy",
    ],
    app_names_macos=[
        "Lindy",
    ],
    bundle_ids=[
        "ai.lindy.app",
    ],
    package_ids_mobile=[
        "ai.lindy.mobile",
    ],
    process_names=[
        "Lindy",
    ],
    local_storage_keys=[
        "lindy",
        "lindy_agents",
    ],
    cache_db_names=[
        "lindy.ai",
    ],
    download_patterns=[
        r"lindy.*\.(?:json|csv)",
    ],
    export_patterns=[
        r"lindy.*export",
    ],
    screenshot_patterns=[
        r"lindy",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "lindy",
        "lindy ai",
        "ai agents",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Lindy",
    ],
    app_data_folders_windows=[
        "AppData/Local/Lindy",
        "AppData/Roaming/Lindy",
    ],
    prefetch_names=[
        "LINDY.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Lindy",
    ],
)


# ---------------------------------------------------------------------------
# Synthesia Signatures
# ---------------------------------------------------------------------------

SYNTHESIA_SIGNATURES = PlatformSignature(
    platform=AIPlatform.SYNTHESIA,
    domains=[
        "synthesia.io",
        "app.synthesia.io",
        "api.synthesia.io",
    ],
    url_patterns=[
        r"https?://.*\.synthesia\.io",
        r"synthesia\.io/app",
        r"synthesia\.io/video",
    ],
    cookie_domains=[
        ".synthesia.io",
        "app.synthesia.io",
    ],
    app_names_windows=[
        "Synthesia",
    ],
    app_names_macos=[
        "Synthesia",
    ],
    bundle_ids=[
        "io.synthesia.app",
    ],
    package_ids_mobile=[
        "io.synthesia.mobile",
    ],
    process_names=[
        "Synthesia",
    ],
    local_storage_keys=[
        "synthesia",
        "synthesia_videos",
    ],
    cache_db_names=[
        "synthesia.io",
    ],
    download_patterns=[
        r"synthesia.*\.(?:mp4|mov|avi)",
        r"synthesia.*video.*\.mp4",
    ],
    export_patterns=[
        r"synthesia.*export",
    ],
    screenshot_patterns=[
        r"synthesia",
    ],
    prompt_indicators=[
        "Create video",
        "Generate video",
    ],
    response_indicators=[
        "Created with Synthesia",
    ],
    model_strings={
        AIModel.SYNTHESIA_AI: ["Synthesia AI", "synthesia-ai"],
    },
    search_keywords=[
        "synthesia",
        "synthesia ai",
        "ai video",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Synthesia",
    ],
    app_data_folders_windows=[
        "AppData/Local/Synthesia",
        "AppData/Roaming/Synthesia",
    ],
    prefetch_names=[
        "SYNTHESIA.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Synthesia",
    ],
)


# ---------------------------------------------------------------------------
# Lattice AI Signatures
# ---------------------------------------------------------------------------

LATTICE_AI_SIGNATURES = PlatformSignature(
    platform=AIPlatform.LATTICE_AI,
    domains=[
        "lattice.com",
        "app.lattice.com",
        "api.lattice.com",
    ],
    url_patterns=[
        r"https?://.*\.lattice\.com",
        r"lattice\.com/performance",
        r"lattice\.com/engagement",
    ],
    cookie_domains=[
        ".lattice.com",
        "app.lattice.com",
    ],
    app_names_windows=[
        "Lattice",
    ],
    app_names_macos=[
        "Lattice",
    ],
    bundle_ids=[
        "com.lattice.app",
    ],
    package_ids_mobile=[
        "com.lattice.mobile",
    ],
    process_names=[
        "Lattice",
    ],
    local_storage_keys=[
        "lattice",
        "lattice_hr",
    ],
    cache_db_names=[
        "lattice.com",
    ],
    download_patterns=[
        r"lattice.*\.(?:pdf|csv|xlsx)",
    ],
    export_patterns=[
        r"lattice.*report",
        r"lattice.*export",
    ],
    screenshot_patterns=[
        r"lattice",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "lattice",
        "lattice ai",
        "lattice hr",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/Lattice",
    ],
    app_data_folders_windows=[
        "AppData/Local/Lattice",
        "AppData/Roaming/Lattice",
    ],
    prefetch_names=[
        "LATTICE.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\Lattice",
    ],
)


# ---------------------------------------------------------------------------
# DataRobot Signatures
# ---------------------------------------------------------------------------

DATAROBOT_SIGNATURES = PlatformSignature(
    platform=AIPlatform.DATAROBOT,
    domains=[
        "datarobot.com",
        "app.datarobot.com",
        "api.datarobot.com",
    ],
    url_patterns=[
        r"https?://.*\.datarobot\.com",
        r"datarobot\.com/projects",
        r"datarobot\.com/models",
    ],
    cookie_domains=[
        ".datarobot.com",
        "app.datarobot.com",
    ],
    app_names_windows=[
        "DataRobot",
    ],
    app_names_macos=[
        "DataRobot",
    ],
    bundle_ids=[
        "com.datarobot.app",
    ],
    package_ids_mobile=[
        "com.datarobot.mobile",
    ],
    process_names=[
        "DataRobot",
    ],
    local_storage_keys=[
        "datarobot",
        "datarobot_projects",
    ],
    cache_db_names=[
        "datarobot.com",
    ],
    download_patterns=[
        r"datarobot.*\.(?:csv|json|pkl|h5)",
        r"datarobot.*model.*\.(?:pkl|pmml)",
    ],
    export_patterns=[
        r"datarobot.*export",
        r"datarobot.*model",
    ],
    screenshot_patterns=[
        r"datarobot",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "datarobot",
        "datarobot ai",
        "automl",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/DataRobot",
    ],
    app_data_folders_windows=[
        "AppData/Local/DataRobot",
        "AppData/Roaming/DataRobot",
    ],
    prefetch_names=[
        "DATAROBOT.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\DataRobot",
    ],
)


# ---------------------------------------------------------------------------
# Leena AI Signatures
# ---------------------------------------------------------------------------

LEENA_AI_SIGNATURES = PlatformSignature(
    platform=AIPlatform.LEENA_AI,
    domains=[
        "leena.ai",
        "app.leena.ai",
        "api.leena.ai",
    ],
    url_patterns=[
        r"https?://.*\.leena\.ai",
        r"leena\.ai/dashboard",
        r"leena\.ai/hr",
    ],
    cookie_domains=[
        ".leena.ai",
        "app.leena.ai",
    ],
    app_names_windows=[
        "Leena AI",
    ],
    app_names_macos=[
        "Leena AI",
    ],
    bundle_ids=[
        "ai.leena.app",
    ],
    package_ids_mobile=[
        "ai.leena.mobile",
    ],
    process_names=[
        "LeenaAI",
    ],
    local_storage_keys=[
        "leena",
        "leena_hr",
    ],
    cache_db_names=[
        "leena.ai",
    ],
    download_patterns=[
        r"leena.*\.(?:csv|pdf)",
    ],
    export_patterns=[
        r"leena.*export",
    ],
    screenshot_patterns=[
        r"leena",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "leena ai",
        "leena hr",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/LeenaAI",
    ],
    app_data_folders_windows=[
        "AppData/Local/LeenaAI",
        "AppData/Roaming/LeenaAI",
    ],
    prefetch_names=[
        "LEENAAI.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\LeenaAI",
    ],
)


# ---------------------------------------------------------------------------
# Nexos AI Signatures
# ---------------------------------------------------------------------------

NEXOS_AI_SIGNATURES = PlatformSignature(
    platform=AIPlatform.NEXOS_AI,
    domains=[
        "nexos.ai",
        "app.nexos.ai",
        "api.nexos.ai",
    ],
    url_patterns=[
        r"https?://.*\.nexos\.ai",
        r"nexos\.ai/supply-chain",
        r"nexos\.ai/logistics",
    ],
    cookie_domains=[
        ".nexos.ai",
        "app.nexos.ai",
    ],
    app_names_windows=[
        "Nexos AI",
    ],
    app_names_macos=[
        "Nexos AI",
    ],
    bundle_ids=[
        "ai.nexos.app",
    ],
    package_ids_mobile=[
        "ai.nexos.mobile",
    ],
    process_names=[
        "NexosAI",
    ],
    local_storage_keys=[
        "nexos",
        "nexos_supply_chain",
    ],
    cache_db_names=[
        "nexos.ai",
    ],
    download_patterns=[
        r"nexos.*\.(?:csv|xlsx|pdf)",
    ],
    export_patterns=[
        r"nexos.*export",
        r"nexos.*report",
    ],
    screenshot_patterns=[
        r"nexos",
    ],
    prompt_indicators=[],
    response_indicators=[],
    model_strings={},
    search_keywords=[
        "nexos ai",
        "supply chain ai",
    ],
    app_support_folders_macos=[
        "~/Library/Application Support/NexosAI",
    ],
    app_data_folders_windows=[
        "AppData/Local/NexosAI",
        "AppData/Roaming/NexosAI",
    ],
    prefetch_names=[
        "NEXOSAI.EXE",
    ],
    registry_keys=[
        r"SOFTWARE\NexosAI",
    ],
)


# ---------------------------------------------------------------------------
# Master Signature Registry
# ---------------------------------------------------------------------------

ALL_SIGNATURES: List[PlatformSignature] = [
    CHATGPT_SIGNATURES,
    CLAUDE_SIGNATURES,
    GEMINI_SIGNATURES,
    PERPLEXITY_SIGNATURES,
    COPILOT_SIGNATURES,
    META_AI_SIGNATURES,
    GROK_SIGNATURES,
    POE_SIGNATURES,
    ADOBE_FIREFLY_SIGNATURES,
    CHECKR_SIGNATURES,
    TIDIO_SIGNATURES,
    LINDY_SIGNATURES,
    SYNTHESIA_SIGNATURES,
    LATTICE_AI_SIGNATURES,
    DATAROBOT_SIGNATURES,
    LEENA_AI_SIGNATURES,
    NEXOS_AI_SIGNATURES,
]

ALL_AI_DOMAINS: List[str] = []
for sig in ALL_SIGNATURES:
    ALL_AI_DOMAINS.extend(sig.domains)

DOMAIN_TO_PLATFORM: Dict[str, AIPlatform] = {}
for sig in ALL_SIGNATURES:
    for domain in sig.domains:
        DOMAIN_TO_PLATFORM[domain] = sig.platform


def get_signature(platform: AIPlatform) -> Optional[PlatformSignature]:
    """Get the signature definition for a given platform."""
    for sig in ALL_SIGNATURES:
        if sig.platform == platform:
            return sig
    return None


def match_domain(url_or_domain: str) -> Optional[AIPlatform]:
    """Check if a URL or domain string matches any AI platform."""
    lowered = url_or_domain.lower()
    for sig in ALL_SIGNATURES:
        for domain in sig.domains:
            if domain.lower() in lowered:
                return sig.platform
    return None


def match_model_string(text: str) -> Optional[AIModel]:
    """Check if text contains any known model identifier strings."""
    lowered = text.lower()
    for sig in ALL_SIGNATURES:
        for model, strings in sig.model_strings.items():
            for s in strings:
                if s.lower() in lowered:
                    return model
    return None
