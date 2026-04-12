"""
Provider Capability Registry (v4.0).

Tracks known capabilities, limitations, and expected artifact families
for each supported AI platform. Used in parser gating, correlation,
governance, forensic readiness assessment, and report generation.

If a capability is unknown, conservative defaults are applied,
confidence is lowered, and the blind spot is disclosed.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from .models import (
    AIPlatform,
    ProviderCapabilityProfile,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Seeded capability profiles for the 8 supported AI platforms
# ---------------------------------------------------------------------------

_CHATGPT_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.CHATGPT,
    profile_version="2026-04",
    supports_export=True,
    supports_share_links=True,
    supports_projects_or_workspaces=True,
    supports_memory_profile=True,
    supports_generated_assets=True,
    supports_voice=True,
    supports_native_desktop=True,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=True,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Browser Downloads",
        "Native Application", "User Content", "OS Execution Trace",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Native Desktop App", "Mobile App",
        "Provider Export", "Shared Public Link", "Generated Asset",
        "Project/Workspace", "Memory/Profile", "Voice Session",
    ],
    known_blind_spots=[
        "ChatGPT conversation content is encrypted in transit; only metadata "
        "and local cache remnants survive on the endpoint.",
        "Memory feature content is not exported in standard data export.",
    ],
    retention_notes=(
        "ChatGPT data export includes conversations.json with full message "
        "history. Browser artifacts include session cookies and local storage. "
        "Desktop app stores data in AppData (Windows) or Application Support (macOS)."
    ),
    capability_confidence="high",
)

_CLAUDE_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.CLAUDE,
    profile_version="2026-04",
    supports_export=True,
    supports_share_links=False,
    supports_projects_or_workspaces=True,
    supports_memory_profile=False,
    supports_generated_assets=True,
    supports_voice=False,
    supports_native_desktop=True,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=True,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Browser Downloads",
        "Native Application", "User Content",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Native Desktop App", "Mobile App",
        "Provider Export", "Generated Asset", "Project/Workspace",
    ],
    known_blind_spots=[
        "Claude does not support public share links; conversation sharing "
        "requires explicit invitation.",
        "No voice/audio interaction support as of profile date.",
    ],
    retention_notes=(
        "Claude conversation export available via account settings. "
        "Projects feature stores artifacts within workspaces."
    ),
    capability_confidence="high",
)

_GEMINI_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.GEMINI,
    profile_version="2026-04",
    supports_export=True,
    supports_share_links=True,
    supports_projects_or_workspaces=False,
    supports_memory_profile=False,
    supports_generated_assets=True,
    supports_voice=True,
    supports_native_desktop=False,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=True,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Browser Downloads",
        "User Content",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Mobile App", "Provider Export",
        "Shared Public Link", "Generated Asset", "Voice Session",
    ],
    known_blind_spots=[
        "Gemini is deeply integrated into Google services; separating "
        "Gemini-specific artifacts from general Google activity is difficult.",
        "No standalone desktop app; relies on browser and mobile app.",
    ],
    retention_notes=(
        "Google Takeout includes Gemini conversation data. "
        "Gemini activity may appear in Google My Activity logs."
    ),
    capability_confidence="high",
)

_PERPLEXITY_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.PERPLEXITY,
    profile_version="2026-04",
    supports_export=False,
    supports_share_links=True,
    supports_projects_or_workspaces=False,
    supports_memory_profile=False,
    supports_generated_assets=False,
    supports_voice=False,
    supports_native_desktop=True,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=True,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Native Application",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Native Desktop App", "Mobile App",
        "Shared Public Link",
    ],
    known_blind_spots=[
        "Perplexity does not provide a full data export feature.",
        "Search results are ephemeral and may not persist locally.",
    ],
    retention_notes=(
        "Perplexity threads are accessible via account but not bulk-exportable. "
        "Desktop and mobile apps leave standard application traces."
    ),
    capability_confidence="medium",
)

_COPILOT_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.COPILOT,
    profile_version="2026-04",
    supports_export=False,
    supports_share_links=True,
    supports_projects_or_workspaces=False,
    supports_memory_profile=False,
    supports_generated_assets=True,
    supports_voice=True,
    supports_native_desktop=True,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=False,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Native Application",
        "OS Execution Trace", "OS Registry",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Native Desktop App", "Mobile App",
        "Shared Public Link", "Generated Asset", "Voice Session",
    ],
    known_blind_spots=[
        "Microsoft Copilot is integrated into Windows 11, Edge, and M365; "
        "distinguishing intentional Copilot use from background Copilot "
        "activity requires careful artifact analysis.",
        "No standalone data export feature.",
    ],
    retention_notes=(
        "Copilot activity may appear in Edge browser history, Windows "
        "activity history, and M365 audit logs. Registry traces in "
        "HKCU\\Software\\Microsoft\\Windows\\Shell."
    ),
    capability_confidence="medium",
)

_META_AI_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.META_AI,
    profile_version="2026-04",
    supports_export=False,
    supports_share_links=False,
    supports_projects_or_workspaces=False,
    supports_memory_profile=False,
    supports_generated_assets=True,
    supports_voice=False,
    supports_native_desktop=False,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=False,
    expected_artifact_families=[
        "Browser History", "Browser Cookies",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Mobile App", "Generated Asset",
    ],
    known_blind_spots=[
        "Meta AI is embedded in Messenger, WhatsApp, and Instagram; "
        "isolating Meta AI-specific interactions from general messaging "
        "requires message-level analysis.",
        "No standalone data export for Meta AI conversations.",
        "No share link or workspace features.",
    ],
    retention_notes=(
        "Meta AI interactions within Messenger/WhatsApp may appear in "
        "those apps' local databases. Browser-based meta.ai leaves "
        "standard browser artifacts."
    ),
    capability_confidence="low",
)

_GROK_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.GROK,
    profile_version="2026-04",
    supports_export=False,
    supports_share_links=False,
    supports_projects_or_workspaces=False,
    supports_memory_profile=False,
    supports_generated_assets=True,
    supports_voice=False,
    supports_native_desktop=True,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=True,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Native Application",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Native Desktop App", "Mobile App",
        "Generated Asset",
    ],
    known_blind_spots=[
        "Grok is integrated into the X (Twitter) platform; separating "
        "Grok-specific artifacts from general X activity is challenging.",
        "No conversation export feature.",
        "No share link feature.",
    ],
    retention_notes=(
        "Grok interactions via x.ai or grok.com leave browser artifacts. "
        "Desktop app (if installed) leaves standard application traces."
    ),
    capability_confidence="medium",
)

_POE_PROFILE = ProviderCapabilityProfile(
    platform=AIPlatform.POE,
    profile_version="2026-04",
    supports_export=False,
    supports_share_links=True,
    supports_projects_or_workspaces=False,
    supports_memory_profile=False,
    supports_generated_assets=False,
    supports_voice=False,
    supports_native_desktop=True,
    supports_mobile_app=True,
    supports_browser_access=True,
    supports_api_artifacts=False,
    expected_artifact_families=[
        "Browser History", "Browser Cookies", "Native Application",
    ],
    expected_platform_surfaces=[
        "Browser Web", "Native Desktop App", "Mobile App",
        "Shared Public Link",
    ],
    known_blind_spots=[
        "Poe is a multi-model aggregator; identifying which underlying "
        "model was used requires conversation-level analysis.",
        "No full data export feature.",
    ],
    retention_notes=(
        "Poe conversations are stored server-side. Local artifacts "
        "include browser history, cookies, and native app data."
    ),
    capability_confidence="medium",
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_DEFAULT_PROFILES: Dict[AIPlatform, ProviderCapabilityProfile] = {
    AIPlatform.CHATGPT: _CHATGPT_PROFILE,
    AIPlatform.CLAUDE: _CLAUDE_PROFILE,
    AIPlatform.GEMINI: _GEMINI_PROFILE,
    AIPlatform.PERPLEXITY: _PERPLEXITY_PROFILE,
    AIPlatform.COPILOT: _COPILOT_PROFILE,
    AIPlatform.META_AI: _META_AI_PROFILE,
    AIPlatform.GROK: _GROK_PROFILE,
    AIPlatform.POE: _POE_PROFILE,
}


class ProviderCapabilityRegistry:
    """
    Registry of provider capability profiles for the 8 supported AI platforms.

    Used in:
    - Parser gating (skip parsers for unsupported features)
    - Correlation (surface inference)
    - Governance (blind spot surfacing)
    - Forensic readiness assessment
    - Report generation (capability matrix)
    """

    def __init__(self):
        self._profiles: Dict[AIPlatform, ProviderCapabilityProfile] = dict(_DEFAULT_PROFILES)

    def get_profile(self, platform: AIPlatform) -> ProviderCapabilityProfile:
        """
        Get the capability profile for a platform.

        If the platform is unknown or not registered, returns a conservative
        default profile with all capabilities set to False and low confidence.
        """
        if platform in self._profiles:
            return self._profiles[platform]

        logger.warning(
            "No capability profile for platform '%s'; using conservative defaults.",
            platform.value,
        )
        return ProviderCapabilityProfile(
            platform=platform,
            capability_confidence="low",
            known_blind_spots=[
                f"No capability profile registered for {platform.value}. "
                "All capability assumptions are conservative defaults.",
            ],
        )

    def get_all_profiles(self) -> List[ProviderCapabilityProfile]:
        """Return all registered profiles."""
        return list(self._profiles.values())

    def get_blind_spots_for_platform(self, platform: AIPlatform) -> List[str]:
        """Return known blind spots for a platform."""
        profile = self.get_profile(platform)
        return list(profile.known_blind_spots)

    def get_all_blind_spots(self) -> List[str]:
        """Aggregate all blind spots across all registered platforms."""
        spots = []
        for profile in self._profiles.values():
            for spot in profile.known_blind_spots:
                spots.append(f"[{profile.platform.value}] {spot}")
        return spots

    def supports_feature(self, platform: AIPlatform, feature: str) -> bool:
        """Check if a platform supports a specific feature."""
        profile = self.get_profile(platform)
        attr = f"supports_{feature}"
        return getattr(profile, attr, False)

    def get_capability_matrix(self) -> List[Dict]:
        """Build a capability matrix suitable for report tables."""
        rows = []
        for profile in self._profiles.values():
            rows.append({
                "platform": profile.platform.value,
                "export": profile.supports_export,
                "share_links": profile.supports_share_links,
                "projects": profile.supports_projects_or_workspaces,
                "memory": profile.supports_memory_profile,
                "generated_assets": profile.supports_generated_assets,
                "voice": profile.supports_voice,
                "desktop_app": profile.supports_native_desktop,
                "mobile_app": profile.supports_mobile_app,
                "browser": profile.supports_browser_access,
                "api": profile.supports_api_artifacts,
                "confidence": profile.capability_confidence,
            })
        return rows

    def update_profile(self, profile: ProviderCapabilityProfile) -> None:
        """Update or add a capability profile."""
        self._profiles[profile.platform] = profile


# Singleton instance
capability_registry = ProviderCapabilityRegistry()
