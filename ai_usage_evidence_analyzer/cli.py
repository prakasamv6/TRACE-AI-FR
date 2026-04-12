"""
CLI entry point for TRACE-AI-FR forensic analysis framework.

Usage:
    python -m ai_usage_evidence_analyzer.cli analyze --evidence PATH --output DIR [OPTIONS]
    python -m ai_usage_evidence_analyzer.cli info
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime

from . import __version__, __product__, __full_name__

# ---------------------------------------------------------------------------
# Rich console helpers (graceful fallback if Rich unavailable)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console(stderr=True) if RICH_AVAILABLE else None


def _print(msg: str = ""):
    """Print to stdout (or rich console if available)."""
    if console:
        console.print(msg, highlight=False)
    else:
        print(msg)


def setup_logging(verbose: bool = False, log_file: str = None):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    if verbose:
        handlers.append(logging.StreamHandler(sys.stderr))

    if not handlers:
        handlers.append(logging.NullHandler())

    logging.basicConfig(level=level, format=fmt, handlers=handlers)


def _banner():
    """Print the TRACE-AI-FR banner."""
    if not RICH_AVAILABLE:
        print(f"\n  {__product__} v{__version__}")
        print(f"  {__full_name__}\n")
        return

    banner_text = Text()
    banner_text.append("TRACE", style="bold cyan")
    banner_text.append("-", style="dim white")
    banner_text.append("AI", style="bold yellow")
    banner_text.append("-", style="dim white")
    banner_text.append("FR", style="bold green")
    banner_text.append(f"  v{__version__}", style="dim white")

    subtitle = Text(__full_name__, style="italic dim")

    panel = Panel(
        Text.assemble(banner_text, "\n", subtitle),
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        padding=(1, 4),
    )
    console.print(panel)


def _config_table(args, llm_status: str):
    """Print a configuration summary table."""
    if not RICH_AVAILABLE:
        print(f"  Evidence:  {args.evidence}")
        print(f"  Output:    {args.output}")
        print(f"  Case:      {args.case_name or '(unnamed)'}")
        print(f"  Examiner:  {args.examiner or '(unspecified)'}")
        print(f"  Carving:   {'Enabled' if args.enable_carving else 'Disabled'}")
        print(f"  Mode:      {args.input_mode}")
        print(f"  LLM:       {llm_status}")
        return

    table = Table(
        title="[bold]Analysis Configuration[/bold]",
        box=box.ROUNDED,
        show_header=False,
        title_style="bold white",
        border_style="bright_blue",
        padding=(0, 2),
    )
    table.add_column("Parameter", style="bold cyan", no_wrap=True)
    table.add_column("Value", style="white")

    carving = "[green]Enabled[/green]" if args.enable_carving else "[dim]Disabled[/dim]"
    llm_rich = "[green]Enabled[/green]" if "Enabled" in llm_status else "[dim yellow]Disabled[/dim yellow]"

    table.add_row("Evidence", str(args.evidence))
    table.add_row("Output", str(args.output))
    table.add_row("Case", args.case_name or "[dim](unnamed)[/dim]")
    table.add_row("Examiner", args.examiner or "[dim](unspecified)[/dim]")
    table.add_row("Organization", args.organization or "[dim](unspecified)[/dim]")
    table.add_row("Mode", args.input_mode)
    table.add_row("Carving", carving)
    table.add_row("LLM Narratives", llm_rich)

    console.print(table)
    console.print()


def _results_panel(report, output_dir: str):
    """Print a rich results panel."""
    fraue_count = len(report.fraues) if hasattr(report, "fraues") else 0

    if not RICH_AVAILABLE:
        print(f"\n  Analysis Complete")
        print(f"  Artifacts: {len(report.all_artifacts)}")
        print(f"  Timeline Events: {len(report.timeline)}")
        print(f"  AI Footprints: {len(report.ai_footprints)}")
        print(f"  FRAUEs: {fraue_count}")
        print(f"  Output: {output_dir}\n")
        return

    # --- Summary stats grid ---
    stats = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 3))
    stats.add_column("Metric", style="bold")
    stats.add_column("Value", justify="right", style="bold cyan")

    stats.add_row("Artifacts Found", str(len(report.all_artifacts)))
    stats.add_row("Timeline Events", str(len(report.timeline)))
    stats.add_row("AI Footprints", str(len(report.ai_footprints)))
    stats.add_row("FRAUEs Reconstructed", str(fraue_count))
    stats.add_row("Matrix Rows", str(len(report.matrix_rows)))
    stats.add_row("Parsers Run", str(len(report.parser_results)))

    console.print(Panel(
        stats,
        title="[bold green]Analysis Complete[/bold green]",
        border_style="green",
        box=box.DOUBLE_EDGE,
        padding=(1, 2),
    ))

    # --- Platform findings table ---
    if report.ai_footprints:
        pt = Table(
            title="[bold]Detected AI Platforms[/bold]",
            box=box.ROUNDED,
            border_style="cyan",
        )
        pt.add_column("Platform", style="bold yellow")
        pt.add_column("Artifacts", justify="right")
        pt.add_column("Direct", justify="right", style="green")
        pt.add_column("Inferred", justify="right", style="dim")
        pt.add_column("Confidence", justify="center")
        pt.add_column("Earliest", style="dim")
        pt.add_column("Latest", style="dim")

        for fp in report.ai_footprints:
            conf = fp.overall_confidence.value
            conf_color = {"High": "green", "Moderate": "yellow", "Low": "red"}.get(conf, "dim")
            pt.add_row(
                fp.platform.value,
                str(fp.total_artifacts),
                str(fp.direct_artifacts),
                str(fp.inferred_artifacts),
                f"[{conf_color}]{conf}[/{conf_color}]",
                fp.earliest_activity.strftime("%Y-%m-%d %H:%M") if fp.earliest_activity else "N/A",
                fp.latest_activity.strftime("%Y-%m-%d %H:%M") if fp.latest_activity else "N/A",
            )
        console.print(pt)
    else:
        console.print(Panel(
            "[yellow]No AI platform usage detected.[/yellow]\n"
            "[dim]NOTE: Absence of evidence is not evidence of absence.\n"
            "Review the evidence coverage assessment in the report.[/dim]",
            border_style="yellow",
        ))

    # --- FRAUE summary ---
    if fraue_count > 0 and hasattr(report, "fraues"):
        ft = Table(
            title="[bold]Reconstructed Events (FRAUEs)[/bold]",
            box=box.ROUNDED,
            border_style="magenta",
        )
        ft.add_column("FRAUE ID", style="bold")
        ft.add_column("Platform", style="yellow")
        ft.add_column("Activity", style="cyan")
        ft.add_column("Time Window")
        ft.add_column("Event Confidence", justify="center")
        ft.add_column("Claim Level", justify="center")

        for fraue in report.fraues[:15]:
            ec = fraue.event_confidence.value
            ec_color = {"HIGH": "green", "MODERATE": "yellow", "LOW": "red"}.get(ec, "dim")
            cl = fraue.claim_level.value
            cl_color = "green" if "Governed" in cl else "yellow" if "FRAUE" in cl else "dim"
            window = ""
            if fraue.window_start and fraue.window_end:
                window = (f"{fraue.window_start.strftime('%m/%d %H:%M')}"
                          f" — {fraue.window_end.strftime('%m/%d %H:%M')}")
            elif fraue.window_start:
                window = fraue.window_start.strftime("%m/%d %H:%M")

            ft.add_row(
                fraue.fraue_id,
                fraue.platform.value,
                fraue.likely_activity_class or "—",
                window or "—",
                f"[{ec_color}]{ec}[/{ec_color}]",
                f"[{cl_color}]{cl}[/{cl_color}]",
            )
        if fraue_count > 15:
            ft.add_row("...", f"+{fraue_count - 15} more", "", "", "", "")
        console.print(ft)

    # --- Output files ---
    console.print(f"\n[bold]Output Directory:[/bold] [link=file://{output_dir}]{output_dir}[/link]")
    console.print()


def cmd_analyze(args):
    """Execute forensic analysis."""
    import os as _os
    from .engine import AnalysisEngine

    # Set LLM API keys from CLI flags if provided (OpenRouter preferred)
    if getattr(args, "openrouter_api_key", None):
        _os.environ["OPENROUTER_API_KEY"] = args.openrouter_api_key
    if getattr(args, "openai_api_key", None):
        _os.environ["OPENAI_API_KEY"] = args.openai_api_key
    if getattr(args, "llm_model", None):
        _os.environ["AIUEA_LLM_MODEL"] = args.llm_model

    if _os.environ.get("OPENROUTER_API_KEY"):
        llm_status = "Enabled (OpenRouter)"
    elif _os.environ.get("OPENAI_API_KEY"):
        llm_status = "Enabled (OpenAI)"
    else:
        llm_status = "Disabled (no API key)"

    engine = AnalysisEngine(
        evidence_path=args.evidence,
        output_dir=args.output,
        case_name=args.case_name or "",
        examiner=args.examiner or "",
        organization=args.organization or "",
        case_id=args.case_id or None,
        carving_enabled=args.enable_carving,
        input_mode=args.input_mode,
        # Recovery flags (v3.0)
        recovery_mode=getattr(args, "recovery_mode", "none"),
        signature_pack=getattr(args, "signature_pack", ""),
        scan_unallocated=getattr(args, "scan_unallocated", False),
        raw_search=getattr(args, "raw_search", False),
        partition_scan=getattr(args, "partition_scan", False),
        acquisition_quality=getattr(args, "acquisition_quality", "unknown"),
        acquisition_log=getattr(args, "acquisition_log", ""),
        # v4.0 flags
        enable_voice_analysis=getattr(args, "enable_voice_analysis", False),
        import_transcripts=getattr(args, "import_transcripts", ""),
        import_provider_exports=getattr(args, "import_provider_exports", False),
        import_shared_links=getattr(args, "import_shared_links", False),
        include_capability_matrix=getattr(args, "include_capability_matrix", False),
        strict_repo_check=getattr(args, "strict_repo_check", False),
        allow_report_fallback=getattr(args, "allow_report_fallback", True),
    )

    _banner()
    _config_table(args, llm_status)

    # Run analysis with progress indicator
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[dim]{task.fields[layer]}[/dim]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "Analyzing evidence...", total=None, layer="Layer 1: Evidence Scope"
            )
            report = engine.run()
            progress.update(task, completed=100, total=100,
                            layer="Complete")
    else:
        print("Analyzing evidence...")
        report = engine.run()

    _results_panel(report, args.output)


def cmd_info(args):
    """Show tool information."""
    if not RICH_AVAILABLE:
        _banner_plain_info()
        return

    _banner()

    # Framework info
    info_table = Table(box=box.ROUNDED, show_header=False, border_style="bright_blue")
    info_table.add_column("", style="bold cyan", no_wrap=True)
    info_table.add_column("", style="white")
    info_table.add_row("Framework", "TRACE-AI-FR v4.0.0")
    info_table.add_row("Architecture", "8-Layer Forensic Pipeline")
    info_table.add_row("Unit of Analysis", "FRAUE (Forensically Reconstructed AI-Use Event)")
    info_table.add_row("Rules Engine", "12 Enforceable Forensic Rules")
    info_table.add_row("AI Platforms", "ChatGPT, Claude, Gemini, Perplexity, Copilot, Meta AI, Grok, Poe")
    info_table.add_row("OS Support", "Windows, macOS, iPhone (logical)")
    info_table.add_row("Browsers", "Chrome, Edge, Firefox, Brave, Safari")
    console.print(info_table)
    console.print()

    # Input/Output formats
    io_table = Table(title="[bold]Input / Output Formats[/bold]",
                     box=box.ROUNDED, border_style="cyan")
    io_table.add_column("Direction", style="bold")
    io_table.add_column("Format")
    io_table.add_column("Notes", style="dim")
    io_table.add_row("Input", "E01 forensic images", "requires pyewf + pytsk3")
    io_table.add_row("Input", "ZIP archives", "auto-extracted")
    io_table.add_row("Input", "Mounted directories", "KAPE / manual export")
    io_table.add_row("Output", "SQLite database", "structured findings")
    io_table.add_row("Output", "JSON", "machine-readable + FRAUE data")
    io_table.add_row("Output", "Markdown report", "forensic-grade, LLM-enhanced")
    io_table.add_row("Output", "HTML report", "interactive, print-ready")
    io_table.add_row("Output", "Governance JSON", "audit trail + Rule 11")
    console.print(io_table)
    console.print()

    # 8-layer architecture
    layers_table = Table(title="[bold]8-Layer Architecture[/bold]",
                         box=box.ROUNDED, border_style="green")
    layers_table.add_column("#", style="bold", justify="center")
    layers_table.add_column("Layer", style="bold yellow")
    layers_table.add_column("Description")
    layers = [
        ("1", "Evidence Scope", "Define & document evidence boundaries"),
        ("2", "Acquisition / Provenance", "Hash verification, chain of custody"),
        ("3", "Parsing / Normalization", "Extract artifacts, assign evidence-source classes"),
        ("4", "Correlation / Sessionization", "Timeline reconstruction, corroboration"),
        ("5", "Scoring / Adjudication", "Artifact → event confidence, FRAUE assembly"),
        ("6", "Reporting", "Governed reports with exhibits & narratives"),
        ("7", "Validation", "5-phase validation (parse, scenario, FP, drift, repro)"),
        ("8", "Governance", "Inference boundaries, scope of conclusion, audit"),
    ]
    for num, name, desc in layers:
        layers_table.add_row(num, name, desc)
    console.print(layers_table)
    console.print()

    # Library status
    lib_table = Table(title="[bold]Library Status[/bold]",
                      box=box.ROUNDED, border_style="yellow")
    lib_table.add_column("Library", style="bold")
    lib_table.add_column("Status", justify="center")
    lib_table.add_column("Purpose", style="dim")

    for lib_name, purpose in [
        ("pyewf", "E01 native parsing"),
        ("pytsk3", "Filesystem parsing"),
        ("rich", "Terminal UX"),
        ("openai", "LLM report narratives"),
        ("pandas", "Advanced matrix export"),
    ]:
        try:
            __import__(lib_name)
            lib_table.add_row(lib_name, "[green]Available[/green]", purpose)
        except ImportError:
            lib_table.add_row(lib_name, "[red]Not Installed[/red]", purpose)
    console.print(lib_table)
    console.print()


def _banner_plain_info():
    """Plain-text info for when Rich is unavailable."""
    from .signatures import ALL_SIGNATURES
    
    # Get all platform names from signatures
    platform_names = [sig.platform.value for sig in ALL_SIGNATURES]
    platforms_str = ", ".join(platform_names[:8])
    if len(platform_names) > 8:
        platforms_str += f", +{len(platform_names) - 8} more"
    
    print(f"\n{__product__} v{__version__}")
    print(f"{__full_name__}")
    print(f"")
    print(f"Supported AI Platforms ({len(ALL_SIGNATURES)} total):")
    print(f"  {platforms_str}")
    print(f"Supported OS Platforms: Windows, macOS, Linux, iPhone, Android")
    print(f"Supported Browsers:    Chrome, Edge, Firefox, Brave, Safari, Samsung Internet")
    print(f"")
    print(f"Input Formats:")
    print(f"  - E01 forensic images (requires pyewf + pytsk3)")
    print(f"  - ZIP archives (auto-extracted and analyzed)")
    print(f"  - Mounted evidence directories")
    print(f"  - KAPE output folders")
    print(f"")
    print(f"Output Formats:")
    print(f"  - SQLite database + JSON + Markdown + HTML + Governance JSON")
    print(f"")
    for lib_name, purpose in [("pyewf", "E01 parsing"), ("pytsk3", "FS parsing"),
                               ("rich", "Terminal UX"), ("openai", "LLM")]:
        try:
            __import__(lib_name)
            print(f"  {lib_name:18s} Available")
        except ImportError:
            print(f"  {lib_name:18s} NOT INSTALLED ({purpose})")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="trace-ai-fr",
        description=f"{__product__} — {__full_name__}",
    )
    parser.add_argument("--version", action="version",
                        version=f"{__product__} {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run the TRACE-AI-FR 8-layer forensic analysis pipeline",
    )
    analyze_parser.add_argument(
        "--evidence", "-e", required=True,
        help="Path to E01 image or mounted evidence directory",
    )
    analyze_parser.add_argument(
        "--output", "-o", required=True,
        help="Output directory for reports and findings",
    )
    analyze_parser.add_argument(
        "--case-name", default="",
        help="Case name for the report",
    )
    analyze_parser.add_argument(
        "--case-id", default=None,
        help="Case ID (auto-generated if not specified)",
    )
    analyze_parser.add_argument(
        "--examiner", default="",
        help="Examiner name",
    )
    analyze_parser.add_argument(
        "--organization", default="",
        help="Organization name",
    )
    analyze_parser.add_argument(
        "--input-mode", choices=["auto", "e01", "mounted", "zip"], default="auto",
        help="Input mode: auto (default), e01, mounted directory, or zip archive",
    )
    analyze_parser.add_argument(
        "--enable-carving", action="store_true", default=False,
        help="Enable file carving (disabled by default)",
    )
    # Recovery flags (v3.0)
    analyze_parser.add_argument(
        "--recovery-mode",
        choices=["none", "filesystem_metadata", "deleted_file",
                 "signature_carving", "partition_reconstruction", "raw_scan"],
        default="none",
        help="Recovery mode for deleted/carved artifact recovery (default: none)",
    )
    analyze_parser.add_argument(
        "--signature-pack",
        default="",
        help="Path to a custom JSON signature pack for file carving",
    )
    analyze_parser.add_argument(
        "--scan-unallocated", action="store_true", default=False,
        help="Scan unallocated space for file signatures",
    )
    analyze_parser.add_argument(
        "--raw-search", action="store_true", default=False,
        help="Perform raw byte-level keyword/domain/model search",
    )
    analyze_parser.add_argument(
        "--partition-scan", action="store_true", default=False,
        help="Scan for partition tables and assess filesystem health",
    )
    analyze_parser.add_argument(
        "--acquisition-quality",
        choices=["normal", "degraded", "unknown"],
        default="unknown",
        help="Acquisition quality level (default: unknown)",
    )
    analyze_parser.add_argument(
        "--acquisition-log",
        default="",
        help="Path to ddrescue or acquisition log file",
    )
    # v4.0 flags
    analyze_parser.add_argument(
        "--enable-voice-analysis", action="store_true", default=False,
        help="Enable voice/audio evidence scanning",
    )
    analyze_parser.add_argument(
        "--import-transcripts", default="",
        help="Path to directory containing voice transcripts",
    )
    analyze_parser.add_argument(
        "--import-provider-exports", action="store_true", default=False,
        help="Scan for first-party AI provider data exports",
    )
    analyze_parser.add_argument(
        "--import-shared-links", action="store_true", default=False,
        help="Scan for shared AI platform URLs in evidence",
    )
    analyze_parser.add_argument(
        "--include-capability-matrix", action="store_true", default=False,
        help="Include provider capability matrix in reports",
    )
    analyze_parser.add_argument(
        "--surface-summary", action="store_true", default=False,
        help="Include platform surface coverage summary in reports",
    )
    analyze_parser.add_argument(
        "--strict-repo-check", action="store_true", default=False,
        help="Run repo reality check before analysis",
    )
    analyze_parser.add_argument(
        "--emit-migration-notes", action="store_true", default=False,
        help="Emit schema migration notes in report output",
    )
    analyze_parser.add_argument(
        "--allow-report-fallback", action="store_true", default=True,
        help="Allow Markdown fallback if DOCX generation fails (default: true)",
    )
    analyze_parser.add_argument(
        "--verbose", "-v", action="store_true", default=False,
        help="Enable verbose logging",
    )
    analyze_parser.add_argument(
        "--log-file",
        help="Path to write log file",
    )
    analyze_parser.add_argument(
        "--openrouter-api-key",
        help="OpenRouter API key for LLM-enhanced report narratives (preferred). "
             "Gives access to Claude, GPT-4o, Llama, and other models via openrouter.ai. "
             "Can also be set via OPENROUTER_API_KEY environment variable.",
    )
    analyze_parser.add_argument(
        "--openai-api-key",
        help="OpenAI API key for LLM-enhanced report narratives (fallback). "
             "Can also be set via OPENAI_API_KEY environment variable.",
    )
    analyze_parser.add_argument(
        "--llm-model",
        help="LLM model for report narratives. "
             "Default: anthropic/claude-sonnet-4 (OpenRouter) or gpt-4o (OpenAI direct). "
             "Can also be set via AIUEA_LLM_MODEL environment variable.",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    # Info command
    info_parser = subparsers.add_parser(
        "info",
        help="Show TRACE-AI-FR framework information and library status",
    )
    info_parser.set_defaults(func=cmd_info)

    args = parser.parse_args()

    if not args.command:
        if RICH_AVAILABLE:
            _banner()
            console.print("[dim]Use [bold]--help[/bold] to see available commands.[/dim]\n")
        parser.print_help()
        sys.exit(1)

    if hasattr(args, "verbose"):
        setup_logging(verbose=args.verbose, log_file=getattr(args, "log_file", None))
    else:
        setup_logging()

    args.func(args)


if __name__ == "__main__":
    main()
