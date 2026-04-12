# ai_usage_evidence_analyzer/caveats.py
"""
Centralized caveat flag logic, language, and enforcement for forensic reporting and UI.
"""
from .tool_registry import CaveatFlag

CAVEAT_LANGUAGE = {
    CaveatFlag.PRESENCE_ONLY: "Artifacts consistent with presence or installation; does not establish use.",
    CaveatFlag.PARTIAL: "Partial evidence found; some expected artifacts are missing or incomplete.",
    CaveatFlag.USE_NOT_ESTABLISHED: "Use not established from available artifacts.",
    CaveatFlag.ATTRIBUTION_NOT_ESTABLISHED: "Attribution to a specific individual not established.",
    CaveatFlag.BROWSER_ACCESS_ONLY: "Browser artifacts indicate access, not substantive use.",
    CaveatFlag.REMOTE_INFERENCE_POSSIBLE: "Remote inference possible; local execution not confirmed.",
    CaveatFlag.SECONDARY_ARTIFACTS_ONLY: "Only secondary workflow artifacts identified.",
    CaveatFlag.MULTI_SURFACE_PRODUCT: "Product may appear on multiple surfaces; context preserved.",
    CaveatFlag.PORTABLE_INSTALL_POSSIBLE: "Portable or custom install possible; negative findings scoped.",
    CaveatFlag.CUSTOM_PATH_POSSIBLE: "Custom or non-default path possible.",
    CaveatFlag.OS_OR_HARDWARE_LIMITATION: "OS/hardware limitations may affect findings.",
    CaveatFlag.TIMESTAMP_INTERPRETATION_LIMITED: "Timestamps may not reflect time of use.",
    CaveatFlag.NEGATIVE_FINDING_SCOPED: "Negative findings are limited to examined locations.",
    CaveatFlag.PRIVACY_OR_CLEANUP_POSSIBLE: "Evidence visibility may be reduced by cleanup or privacy features.",
    CaveatFlag.PARSER_LIMITATION: "Parser limitations may affect coverage.",
    CaveatFlag.ENCRYPTED_OR_INACCESSIBLE: "Some sources were encrypted or inaccessible.",
    CaveatFlag.MULTI_USER_CONTEXT: "Multi-user or shared context detected.",
    CaveatFlag.CLOUD_SYNC_POSSIBLE: "Cloud or account sync may affect artifact origin.",
    CaveatFlag.OUTPUT_GENERATOR_NOT_CONFIRMED: "Output artifacts not deterministically linked to a tool.",
    CaveatFlag.INSUFFICIENT_BASIS_FOR_CONCLUSION: "Insufficient basis for a definitive conclusion.",
    CaveatFlag.CHAIN_OF_CUSTODY_METADATA_RECORDED: "Chain-of-custody and parser metadata recorded.",
    # Surface-class-specific caveats
    CaveatFlag.LOCAL_WEBUI_LOCALHOST_ONLY: "Tool accessed via localhost; browser history may show only local addresses.",
    CaveatFlag.LOCAL_WEBUI_CONTAINER_POSSIBLE: "Tool may run inside Docker or WSL; host-level artifacts may be absent.",
    CaveatFlag.IDE_CONFIG_NOT_USAGE: "IDE extension or CLI config present; does not establish code-generation use.",
    CaveatFlag.CREDENTIAL_FILE_ONLY: "Only credential or API-key files found; actual tool invocation not confirmed.",
    CaveatFlag.BROWSER_HISTORY_CLEARED: "Browser history may have been cleared or private browsing session used.",
    # Evidence-path and enforcement caveats
    CaveatFlag.PERSON_LEVEL_ATTRIBUTION_NOT_ESTABLISHED: "Person-level attribution not established; evidence ties to device or profile only.",
    CaveatFlag.LOCAL_INFERENCE_NOT_ESTABLISHED: "Local inference not established; model weights or GPU activity not confirmed.",
    CaveatFlag.STANDALONE_BINARY_POSSIBLE: "Tool may run as a standalone or portable binary outside standard install paths.",
    CaveatFlag.BROWSER_FIRST_TOOL: "Primary interaction surface is a web browser; local artifacts are limited to browser history, cookies, and localStorage.",
    CaveatFlag.SELF_HOSTED_OR_LOCAL_WEBUI_POSSIBLE: "Tool may be self-hosted or accessed via a local web UI; remote vs. local distinction not confirmed.",
    CaveatFlag.IDE_SURFACE_ONLY: "Evidence limited to IDE extension configuration; code-generation output not linked.",
    CaveatFlag.CLI_SURFACE_ONLY: "Evidence limited to CLI configuration or binary presence; command-line invocation not confirmed.",
    CaveatFlag.REMOTE_SESSION_POSSIBLE: "Tool may have been accessed via SSH, RDP, or remote desktop session; artifacts may reside on remote host.",
    CaveatFlag.ACQUISITION_SCOPE_LIMITED: "Acquisition scope is limited (e.g., logical image, triage, or partial collection); unexamined areas may contain relevant evidence.",
    CaveatFlag.CORROBORATION_LEVEL_LIMITED: "Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.",
}

GLOBAL_REPORT_FOOTER = (
    "The presence of AI-related artifacts indicates possible access, installation, configuration, or environmental capability. "
    "Such artifacts do not independently establish actual use, authorship, intent, cognitive reliance, or person-level attribution. "
    "Conclusions should be interpreted in light of acquisition scope, corroboration level, parser coverage, and any documented limitations."
)

UI_WARNINGS = [
    "Presence does not equal use.",
    "Device evidence does not automatically establish person-level attribution.",
    "Browser access does not necessarily establish substantive interaction.",
    "NOT_FOUND applies only to examined locations.",
    "NOT_VERIFIED means no conclusion is stated.",
    "Remote inference may leave limited local model artifacts.",
    "Installation does not establish execution or output generation.",
    "Corroboration from a single artifact family limits claim level.",
]

def get_caveat_text(flags):
    return [CAVEAT_LANGUAGE.get(f, str(f)) for f in flags]
