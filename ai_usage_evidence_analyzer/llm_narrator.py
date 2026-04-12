"""
LLM-powered forensic narrative generator.

Supports two providers (in priority order):
  1. **OpenRouter** (openrouter.ai) — access to Claude, GPT-4o, Llama, etc.
     Set OPENROUTER_API_KEY or pass --openrouter-api-key.
  2. **OpenAI** (direct) — set OPENAI_API_KEY or pass --openai-api-key.

Generates professional, defensible forensic report narratives from
structured artifact data. The LLM enhances readability — it does NOT
interpret evidence or draw conclusions beyond what the data supports.

Forensic rules enforced at prompt-level:
  - Never overclaim: the LLM must not infer intent, motive, or guilt.
  - Every claim must reference an artifact path and exhibit number.
  - Absence of evidence must be stated explicitly.
  - Confidence levels must be carried through verbatim.

Falls back gracefully to template-based narrative when:
  - No API key is set (neither OpenRouter nor OpenAI)
  - openai package is not installed
  - API call fails for any reason
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenRouter / OpenAI configuration
# ---------------------------------------------------------------------------
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_DEFAULT_MODEL = "anthropic/claude-sonnet-4"
OPENAI_DEFAULT_MODEL = "gpt-4o"

# ---------------------------------------------------------------------------
# Check OpenAI SDK availability (used for both OpenRouter and OpenAI)
# ---------------------------------------------------------------------------
_OPENAI_AVAILABLE = False
_openai_client = None
_active_provider = None  # "openrouter" | "openai" | None

try:
    from openai import OpenAI  # type: ignore[import-not-found]
    _OPENAI_AVAILABLE = True
except ImportError:
    logger.debug("openai package not installed. LLM narrator will use fallback templates.")


def _get_client():
    """Lazy-init the LLM client. Prefers OpenRouter, falls back to OpenAI."""
    global _openai_client, _active_provider
    if _openai_client is not None:
        return _openai_client

    # Priority 1: OpenRouter
    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
    if openrouter_key:
        _openai_client = OpenAI(
            api_key=openrouter_key,
            base_url=OPENROUTER_BASE_URL,
        )
        _active_provider = "openrouter"
        logger.info("LLM narrator using OpenRouter (openrouter.ai)")
        return _openai_client

    # Priority 2: Direct OpenAI
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_key:
        _openai_client = OpenAI(api_key=openai_key)
        _active_provider = "openai"
        logger.info("LLM narrator using direct OpenAI API")
        return _openai_client

    return None


def reset_client():
    """Reset the cached client (useful when API keys change at runtime)."""
    global _openai_client, _active_provider
    _openai_client = None
    _active_provider = None


# ---------------------------------------------------------------------------
# System prompt — strict forensic guardrails
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior digital forensic report writer assisting a DFIR examiner.
Your role is to convert structured artifact data into clear, professional
forensic narrative paragraphs suitable for court presentation.

RULES — NEVER VIOLATE:
1. Never infer intent, motive, or guilt. You describe artifacts, not people.
2. Every factual claim MUST reference a specific exhibit number and evidence path.
3. Use passive, objective voice ("browser history records indicate…").
4. Preserve confidence levels verbatim: High, Moderate, Low, Unsupported.
5. If evidence is absent, state "No artifacts of this type were identified."
6. Do NOT speculate. Do NOT use the word "clearly" or "obviously".
7. Do NOT fabricate artifact paths, timestamps, or hash values.
8. Qualify all statements appropriately:
   - "The browser history records suggest…"
   - "This artifact is consistent with…"
   - "Based on the recovered artifact…"
9. Always mention limitations (e.g., "File carving was disabled").
10. Format output as clean Markdown paragraphs, no JSON.
"""


# ---------------------------------------------------------------------------
# Narrative generation functions
# ---------------------------------------------------------------------------

def generate_overview_narrative(
    case_name: str,
    examiner: str,
    organization: str,
    evidence_path: str,
    image_type: str,
    detected_os: str,
    date_str: str,
    description: str = "",
) -> str:
    """Generate the Overview section narrative."""
    data = {
        "section": "Overview / Case Summary",
        "case_name": case_name,
        "examiner": examiner,
        "organization": organization,
        "evidence_path": os.path.basename(evidence_path),
        "image_type": image_type,
        "detected_os": detected_os,
        "report_date": date_str,
        "description": description,
    }

    user_prompt = (
        f"Write the Overview section for a forensic report.\n"
        f"Data:\n{json.dumps(data, indent=2)}\n\n"
        f"Write 1-2 paragraphs in third-person passive voice. "
        f"State who provided the evidence, what was provided, and what "
        f"analysis was requested. Follow the SANS forensic report standard."
    )

    return _call_llm(user_prompt, fallback=_fallback_overview(data))


def generate_acquisition_narrative(
    tool_version: str,
    md5_hash: str,
    sha1_hash: str,
    image_path: str,
    image_type: str,
    image_size_bytes: int,
    detected_os: str,
    read_only: bool,
    parsers_used: List[str],
) -> str:
    """Generate the Forensic Acquisition & Exam Preparation narrative."""
    data = {
        "section": "Forensic Acquisition & Exam Preparation",
        "tool": f"AI Usage Evidence Analyzer v{tool_version}",
        "md5_hash": md5_hash or "Not computed",
        "sha1_hash": sha1_hash or "Not computed",
        "evidence_file": os.path.basename(image_path),
        "image_type": image_type,
        "image_size_bytes": image_size_bytes,
        "detected_os": detected_os,
        "read_only": read_only,
        "parsers_used": parsers_used,
    }

    user_prompt = (
        f"Write the Forensic Acquisition & Exam Preparation section.\n"
        f"Data:\n{json.dumps(data, indent=2)}\n\n"
        f"Include: workstation/tool info, hash verification statement, "
        f"evidence details, read-only processing confirmation, and list "
        f"of forensic tools/parsers used. Follow SANS and NIST standards."
    )

    return _call_llm(user_prompt, fallback=_fallback_acquisition(data))


def generate_finding_narrative(
    finding_number: int,
    platform_name: str,
    total_artifacts: int,
    direct_count: int,
    inferred_count: int,
    overall_confidence: str,
    access_mode: str,
    earliest_activity: str,
    latest_activity: str,
    estimated_sessions: int,
    model_name: str,
    exhibits: List[Dict[str, Any]],
    caveats: List[str],
) -> str:
    """Generate a per-platform finding narrative with exhibit references."""
    data = {
        "finding_number": finding_number,
        "platform": platform_name,
        "total_artifacts": total_artifacts,
        "direct": direct_count,
        "inferred": inferred_count,
        "confidence": overall_confidence,
        "access_mode": access_mode,
        "earliest_activity": earliest_activity,
        "latest_activity": latest_activity,
        "sessions": estimated_sessions,
        "model": model_name,
        "exhibits": exhibits[:10],  # Limit to avoid token overflow
        "caveats": caveats,
    }

    user_prompt = (
        f"Write Finding #{finding_number} for platform: {platform_name}.\n"
        f"Data:\n{json.dumps(data, indent=2)}\n\n"
        f"CRITICAL: Reference each exhibit by its exhibit number (e.g., Exhibit 1) "
        f"and include the E01 source path for every piece of evidence. "
        f"Use objective forensic language. State the confidence level. "
        f"Include any caveats. Do not speculate or overclaim."
    )

    return _call_llm(user_prompt, fallback=_fallback_finding(data))


def generate_conclusion_narrative(
    platforms_found: List[Dict[str, Any]],
    total_artifacts: int,
    carving_enabled: bool,
    full_disk: bool,
) -> str:
    """Generate the Conclusion section narrative."""
    data = {
        "platforms": platforms_found,
        "total_artifacts": total_artifacts,
        "carving_enabled": carving_enabled,
        "full_disk": full_disk,
    }

    user_prompt = (
        f"Write the Conclusion section for a forensic report.\n"
        f"Data:\n{json.dumps(data, indent=2)}\n\n"
        f"Summarize findings per platform with confidence levels. "
        f"Include mandatory evidentiary caveats. State limitations. "
        f"End with standard closing: evidence is being provided to "
        f"the requesting party. Do not overclaim."
    )

    return _call_llm(user_prompt, fallback=_fallback_conclusion(data))


# ---------------------------------------------------------------------------
# OpenAI API call with fallback
# ---------------------------------------------------------------------------

def _call_llm(user_prompt: str, fallback: str) -> str:
    """Call LLM via OpenRouter or OpenAI. Return fallback on any failure."""
    if not _OPENAI_AVAILABLE:
        logger.debug("openai package not available, using fallback template.")
        return fallback

    client = _get_client()
    if client is None:
        logger.debug("No API key set (OPENROUTER_API_KEY or OPENAI_API_KEY), using fallback template.")
        return fallback

    # Model resolution: env override → provider default
    env_model = os.environ.get("AIUEA_LLM_MODEL", "")
    if env_model:
        model = env_model
    elif _active_provider == "openrouter":
        model = OPENROUTER_DEFAULT_MODEL
    else:
        model = OPENAI_DEFAULT_MODEL

    # Extra headers for OpenRouter ranking/attribution
    extra_headers = {}
    if _active_provider == "openrouter":
        extra_headers = {
            "HTTP-Referer": "https://github.com/TRACE-AI-FR",
            "X-Title": "TRACE-AI-FR Forensic Report Generator",
        }

    try:
        kwargs: Dict[str, Any] = dict(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,  # Low creativity for forensic precision
            max_tokens=1500,
        )
        if extra_headers:
            kwargs["extra_headers"] = extra_headers

        response = client.chat.completions.create(**kwargs)
        text = response.choices[0].message.content.strip()
        logger.info(f"LLM narrative generated ({len(text)} chars, provider={_active_provider}, model={model})")
        return text
    except Exception as exc:
        logger.warning(f"LLM call failed: {exc}. Using fallback template.")
        return fallback


# ---------------------------------------------------------------------------
# Fallback template-based narratives
# ---------------------------------------------------------------------------

def _fallback_overview(data: Dict) -> str:
    evidence_file = data["evidence_path"]
    org = data.get("organization") or "the requesting agency"
    examiner = data.get("examiner") or "this examiner"
    date_str = data["report_date"]
    detected_os = data["detected_os"]
    image_type = data["image_type"]
    description = data.get("description", "")

    text = (
        f"On {date_str}, {org} provided "
        f"{'an Expert Witness Format (E01) image' if 'e01' in image_type.lower() or evidence_file.lower().endswith('.e01') else 'a forensic evidence directory'} "
        f"to the forensic laboratory for analysis. "
        f"The evidence was received by {examiner} and identified as "
        f"**{evidence_file}**.\n\n"
    )

    if description:
        text += description + "\n"
    else:
        text += (
            f"The examiner was instructed to perform a forensic analysis to determine "
            f"whether AI platforms — specifically ChatGPT, Claude, Google Gemini, "
            f"Perplexity, Microsoft Copilot, Meta AI, Grok, or Poe — "
            f"were used on the examined {detected_os} endpoint. This analysis includes "
            f"identification of browser history, cookies, downloads, application traces, "
            f"cached content, and any other artifacts that indicate AI platform access or usage.\n"
        )

    return text


def _fallback_acquisition(data: Dict) -> str:
    tool = data["tool"]
    md5 = data["md5_hash"]
    sha1 = data["sha1_hash"]
    evidence_file = data["evidence_file"]
    read_only = data["read_only"]
    detected_os = data["detected_os"]
    parsers = data.get("parsers_used", [])
    size = data.get("image_size_bytes", 0)

    text = (
        f"The forensic analysis was performed using **{tool}** on the "
        f"examiner's forensic workstation.\n\n"
    )

    if md5 != "Not computed" or sha1 != "Not computed":
        text += "The evidence was verified using cryptographic hash values:\n\n"
        text += "| Hash Algorithm | Value |\n|---|---|\n"
        if md5 != "Not computed":
            text += f"| MD5 | `{md5}` |\n"
        if sha1 != "Not computed":
            text += f"| SHA-1 | `{sha1}` |\n"
        text += "\n"
    else:
        text += (
            "*Note: No hash verification was performed on the evidence source. "
            "If the evidence was provided as a mounted directory, hash verification "
            "may not be applicable.*\n\n"
        )

    if size:
        size_mb = size / (1024 * 1024)
        text += (
            f"**Evidence Details:**\n\n"
            f"- Evidence Source: `{evidence_file}`\n"
            f"- Image Size: {size:,} bytes ({size_mb:.2f} MB)\n"
            f"- Detected Operating System: {detected_os}\n"
            f"- Read-Only Processing: {'Yes' if read_only else 'No'}\n\n"
        )

    if read_only:
        text += (
            "All evidence was processed in **read-only mode**. SQLite databases "
            "within the evidence were copied to temporary storage before querying "
            "to avoid WAL lock interference. No modifications were made to the "
            "original evidence.\n\n"
        )

    if parsers:
        text += "The following tools and parsers were used for forensic analysis:\n\n"
        for p in parsers:
            text += f"- *{p}*\n"
        text += "\n"

    return text


def _fallback_finding(data: Dict) -> str:
    num = data["finding_number"]
    platform = data["platform"]
    total = data["total_artifacts"]
    direct = data["direct"]
    inferred = data["inferred"]
    confidence = data["confidence"]
    access_mode = data.get("access_mode", "Unknown")
    earliest = data.get("earliest_activity", "N/A")
    latest = data.get("latest_activity", "N/A")
    sessions = data.get("sessions", 0)
    model = data.get("model", "Unknown")
    exhibits = data.get("exhibits", [])
    caveats = data.get("caveats", [])

    text = (
        f"Forensic analysis of the submitted evidence identified **{total}** "
        f"artifact(s) associated with **{platform}** "
        f"({direct} direct, {inferred} inferred). "
        f"The overall confidence for this finding is **{confidence}**.\n\n"
    )

    if access_mode and access_mode != "Unknown":
        text += f"The platform appears to have been accessed via **{access_mode}**.\n\n"

    if earliest != "N/A":
        text += f"- Earliest recorded activity: {earliest}\n"
    if latest != "N/A":
        text += f"- Latest recorded activity: {latest}\n"
    if sessions > 0:
        text += f"- Estimated session count: {sessions}\n"
    if model and model != "Unknown":
        text += f"- Model identified: {model}\n"
    text += "\n"

    if exhibits:
        text += "**Supporting Evidence:**\n\n"
        for ex in exhibits:
            ex_num = ex.get("exhibit_number", "?")
            ex_desc = ex.get("description", "")
            ex_path = ex.get("evidence_path", "")
            ex_conf = ex.get("confidence", "")
            text += (
                f"- **Exhibit {ex_num}:** {ex_desc}\n"
                f"  - Source: `{ex_path}`\n"
                f"  - Confidence: {ex_conf}\n"
            )
        text += "\n"

    if caveats:
        text += "**Caveats:**\n\n"
        for c in caveats:
            text += f"- {c}\n"
        text += "\n"

    return text


def _fallback_conclusion(data: Dict) -> str:
    platforms = data.get("platforms", [])
    total = data.get("total_artifacts", 0)
    carving = data.get("carving_enabled", False)
    full_disk = data.get("full_disk", False)

    if not platforms:
        text = (
            "Based on the forensic analysis performed, no artifacts indicating AI platform "
            "usage (ChatGPT, Claude, Gemini, Perplexity, Copilot, Meta AI, Grok, or Poe) were identified in the submitted evidence. "
            "This negative finding is qualified by the evidence coverage assessment above — "
            "absence of evidence is not evidence of absence.\n\n"
        )
    else:
        text = ""
        for p in platforms:
            name = p.get("name", "Unknown")
            conf = p.get("confidence", "Unsupported")
            total_a = p.get("total", 0)
            direct_a = p.get("direct", 0)

            if conf == "High":
                strength = "strongly supported"
            elif conf == "Moderate":
                strength = "supported at moderate confidence"
            else:
                strength = "indicated at low confidence"

            text += (
                f"The forensic analysis {strength} that **{name}** was accessed "
                f"from this endpoint. {total_a} artifact(s) were identified, of which "
                f"{direct_a} constitute direct evidence.\n\n"
            )

    text += "**Evidentiary Caveats:**\n\n"
    text += "- A domain visit alone is not enough to conclude substantive AI use.\n"
    text += "- A cached object alone is not enough to conclude prompt submission.\n"
    text += "- A login trace alone is not enough to conclude active investigative use.\n"
    text += "- An export file alone is not enough to prove which model generated it unless corroborated.\n"
    text += "- Platform attribution, model attribution, and content attribution are separate analytical layers.\n"
    text += "- Absence of evidence must not be reported as evidence of absence.\n\n"

    if not carving:
        text += (
            "File carving was disabled. Artifacts in unallocated space were not examined. "
            "Additional analysis may yield further findings.\n\n"
        )

    if not full_disk:
        text += (
            "The evidence source was not a full disk image. Artifacts outside the "
            "provided scope may exist on the original media.\n\n"
        )

    text += (
        "The forensic evidence and reports are being provided to the requesting "
        "party. No further analysis as of this report.\n"
    )

    return text
