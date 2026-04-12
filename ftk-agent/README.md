# FTK Forensic AI Agent

> OpenRouter-powered forensic agent for **AI-tool usage detection** inside E01/EWF disk images.  
> Built on the [OpenRouter SDK](https://openrouter.ai/docs) modular agent pattern, inspired by [AionUi](https://github.com/iOfficeAI/AionUi) Cowork architecture.

## Architecture — Seven-Layer FTK Imager Pipeline

| # | Layer | Tool | Description |
|---|-------|------|-------------|
| 1 | Evidence Source Input | `open_e01_image` | Accept .E01 paths, validate EWF signatures |
| 2 | Image/Container Handling | `read_ewf_metadata` | Parse EWF sections (header, volume, data, hash, digest), Adler-32 fixity |
| 3 | Storage Layout Interpretation | `interpret_storage_layout` | Detect partition tables (MBR/GPT), OS types (Windows/macOS/Linux) |
| 4 | Filesystem Enumeration | `enumerate_filesystem` | Recursive Evidence Tree with AI-relevant path filtering |
| 5 | Content Rendering | `render_content` | Text/Hex/Interpreted preview, Hex Value Interpreter (FILETIME, Unix, Chrome timestamps) |
| 6 | Integrity / Verification | `compute_hash` | MD5, SHA-1, SHA-256 hash generation and verification |
| 7 | Export / Report Generation | `generate_forensic_report` | JSON + Markdown forensic reports with case metadata |

### Cross-Cutting Tools
| Tool | Purpose |
|------|---------|
| `scan_ai_indicators` | Scan E01 binary or mounted directory for AI platform signatures (domains, cookies, model strings, LS keys, process names) |
| `carve_sqlite_databases` | Carve embedded SQLite databases from raw E01 data |

## Algorithms & Data-Handling Methods

| Algorithm | Use |
|-----------|-----|
| **MD5** | Integrity verification (FTK standard) |
| **SHA-1** | Integrity verification (FTK standard) |
| **Deflate (zlib)** | EWF compressed data section decompression |
| **Adler-32** | Section-level fixity checking |
| **Chunked random-access** | 32 KB EWF chunk reads with index tables |
| **Hierarchical tree traversal** | Filesystem enumeration (Evidence Tree model) |
| **Hex-to-integer / Hex-to-time** | Windows FILETIME, Unix epoch, Chrome/Webkit timestamp conversion |

## AI Platforms Detected

- ChatGPT / OpenAI
- Anthropic Claude
- GitHub Copilot
- Google Gemini / Bard
- Midjourney
- Stable Diffusion / Stability AI
- Perplexity AI
- Hugging Face

## Quick Start

### Prerequisites
- Node.js 18+
- [OpenRouter API key](https://openrouter.ai/settings/keys)

### Install
```bash
cd ftk-agent
npm install
```

### Set API Key
```bash
# Windows PowerShell
$env:OPENROUTER_API_KEY = "sk-or-YOUR-KEY-HERE"

# Linux/macOS
export OPENROUTER_API_KEY="sk-or-YOUR-KEY-HERE"
```

### Run — Headless (CLI REPL)
```bash
npm run start:headless
```

### Run — Ink TUI
```bash
npm start
```

### Example Prompts
```
forensic> Analyze E01 image at C:\Evidence\ItemA.E01 for AI tool usage
forensic> Scan the mounted evidence at D:\MountedImage for ChatGPT artifacts
forensic> Compute MD5 and SHA-1 of C:\Evidence\ItemA.E01
forensic> Show hex dump of C:\Evidence\History at offset 0x1000
forensic> Generate a forensic report for case "StudentExam-2026"
```

## Project Structure
```
ftk-agent/
├── src/
│   ├── agent.ts       # Standalone agent core with hooks (EventEmitter)
│   ├── tools.ts       # 9 forensic tools (7 FTK layers + 2 cross-cutting)
│   ├── headless.ts    # CLI REPL (no UI dependencies)
│   └── cli.tsx        # Ink TUI (optional, React-based terminal UI)
├── package.json
├── tsconfig.json
└── README.md
```

## How It Works

```
User Query
    │
    ▼
┌─────────────────────────┐
│       Agent Core        │  ← hooks & lifecycle (EventEmitter3)
│   (src/agent.ts)        │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│     OpenRouter SDK      │  ← 300+ LLMs (auto-selects best model)
└────────────┬────────────┘
             │ function_call
             ▼
┌─────────────────────────┐
│    Forensic Tools       │  ← 9 tools covering all 7 FTK layers
│   (src/tools.ts)        │
│                         │
│  L1: open_e01_image     │
│  L2: read_ewf_metadata  │
│  L3: interpret_storage   │
│  L4: enumerate_filesystem│
│  L5: render_content     │
│  L6: compute_hash       │
│  L7: generate_report    │
│  +  scan_ai_indicators  │
│  +  carve_sqlite_dbs    │
└─────────────────────────┘
```

## License

Apache-2.0 — same as [AionUi](https://github.com/iOfficeAI/AionUi)
