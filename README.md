# AI Usage Evidence Analyzer

**Version:** 1.0.0-mvp  
**Classification:** Forensic Analysis Tool — Academic / Research / Investigative Use

## Overview

The AI Usage Evidence Analyzer is a forensic tool that accepts E01 forensic images (or mounted/extracted evidence directories) and determines whether ChatGPT-4, Claude, or Gemini were used on the examined endpoint. It reconstructs AI-related activity from endpoint artifacts and generates a forensic-driven report suitable for academic, investigative, validation, and research use.

## Supported Platforms & Artifacts

| Artifact Family | Windows | macOS | iPhone (Logical) |
|---|:---:|:---:|:---:|
| Browser History (Chrome, Edge, Brave, Firefox, Safari) | ✅ | ✅ | ✅ |
| Browser Cookies | ✅ | ✅ | — |
| Browser Downloads | ✅ | ✅ | — |
| Prefetch / Execution Traces | ✅ | — | — |
| Recent Files / LNK | ✅ | ✅ | — |
| UserAssist (binary scan) | ✅ | — | — |
| Recycle Bin | ✅ | — | — |
| AppData / Application Support | ✅ | ✅ | — |
| Quarantine Events | — | ✅ | — |
| AI Content Scanning (Downloads/Docs) | ✅ | ✅ | — |
| Windows Event Logs | 🔲 Stub | — | — |
| macOS Unified Logs | — | 🔲 Stub | — |
| iPhone App Usage | — | — | 🔲 Stub |

## AI Platforms Detected

| Platform | Domains | Model Strings |
|---|---|---|
| **ChatGPT** | chat.openai.com, chatgpt.com | gpt-4, gpt-4-turbo, gpt-4o, gpt-3.5-turbo |
| **Claude** | claude.ai | claude-3-opus, claude-3-sonnet, claude-3-haiku, claude-3.5-sonnet |
| **Gemini** | gemini.google.com, bard.google.com, aistudio.google.com | gemini-pro, gemini-ultra, gemini-1.5-pro, gemini-1.5-flash |

## Installation

```bash
# Clone and install
cd code
pip install -e .

# Or with forensic libraries (Linux/macOS only for pytsk3/pyewf)
pip install -e ".[forensic]"

# Development
pip install -e ".[dev]"
```

## Usage

### Analyze a mounted evidence directory

```bash
python -m ai_usage_evidence_analyzer analyze /path/to/evidence \
    --output ./reports \
    --case-name "Case-2025-001" \
    --examiner "J. Smith"
```

### Analyze an E01 image (requires pytsk3 + pyewf)

```bash
python -m ai_usage_evidence_analyzer analyze /path/to/image.E01 \
    --output ./reports \
    --mode e01
```

### Get tool info

```bash
python -m ai_usage_evidence_analyzer info
```

### CLI Options

| Flag | Description |
|---|---|
| `--output` / `-o` | Output directory for reports (default: `./output`) |
| `--case-name` | Case identifier |
| `--examiner` | Examiner name |
| `--mode` | Input mode: `auto`, `e01`, or `mounted` (default: `auto`) |
| `--formats` | Report formats: `json`, `md`, `html`, `sqlite` (default: all) |

## Output

The tool generates four report formats in the output directory:

| File | Purpose |
|---|---|
| `report.json` | Machine-readable full export |
| `report.md` | Human-readable Markdown report with 15 sections |
| `report.html` | Styled HTML version for presentation |
| `findings.sqlite` | Normalized SQLite database for further querying |

## Architecture

```
ai_usage_evidence_analyzer/
├── __init__.py          # Package metadata
├── __main__.py          # Module entry point
├── cli.py               # CLI (argparse)
├── engine.py            # Main analysis orchestrator (9-step pipeline)
├── models.py            # Data models (enums, dataclasses)
├── signatures.py        # AI platform detection signatures
├── e01_handler.py       # E01 image + mounted directory handler
├── parser_registry.py   # BaseParser ABC + decorator registry
├── parsers/
│   ├── browser_parsers.py   # Chromium, Firefox, Safari
│   ├── windows_parsers.py   # Prefetch, Recent, UserAssist, RecycleBin, AppData
│   ├── macos_parsers.py     # Quarantine, AppSupport, RecentItems, UnifiedLog
│   ├── iphone_parsers.py    # Safari, AppUsage
│   └── content_parsers.py   # AI content/file scanner
├── correlation.py       # Timeline reconstruction & cross-artifact corroboration
├── confidence.py        # Weighted confidence scoring engine
├── matrix.py            # Comparative artifact matrix
├── storage.py           # SQLite export with full schema
└── report_generator.py  # JSON, Markdown, HTML report generators
```

## Forensic Philosophy

- **Read-only evidence handling** — no writes to source evidence; databases are copied to temp before querying.
- **No overclaiming** — confidence scores reflect actual evidence strength. Cookies alone do not prove substantive AI use.
- **Evidence coverage reporting** — the report explicitly states which artifact families were examined, which were found, and which were absent.
- **Stub transparency** — parsers that are not yet fully implemented are marked as stubs with `IS_STUB = True`.
- **Graceful degradation** — the tool works without `pytsk3`/`pyewf` by analyzing mounted directories.

## Running Tests

```bash
pytest
```

## Risks & Controls

| Risk | Mitigation |
|---|---|
| E01 parsing failure | Graceful fallback to mounted directory mode |
| Missing pyewf/pytsk3 | Clear error messages; mounted-dir mode always works |
| SQLite WAL locks | Databases are copied to temp before querying |
| False positives (generic Google cookies) | Domain-specific matching; confidence scoring penalizes weak evidence |
| Clock skew / timezone issues | Timestamps are converted to UTC where possible; `timezone_normalized` flag tracked |

## Future Roadmap

- Full Windows Event Log (EVTX) parsing
- macOS Unified Log parsing
- iPhone app-level database extraction (KnowledgeC, Screen Time)
- Android artifact support
- Memory forensics integration (Volatility)
- Network capture correlation (PCAP)
- LLM-assisted artifact interpretation (optional)

## License

MIT — For academic and research use.
