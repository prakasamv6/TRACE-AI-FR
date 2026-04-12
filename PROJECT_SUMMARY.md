# TRACE-AI-FR — Transparent Reporting of AI-related Claims in Evidence: A Forensic Reasoning Framework

**Version:** 4.0.0  
**Course:** ITIS-5250-092 — Computer Forensics (UNCC)  
**Date:** April 8, 2026  
**Author:** Hemal  
**License:** MIT

---

## 1. Research Objective

> *"Can a forensic examiner reconstruct the use of ChatGPT, Claude, Gemini, Perplexity, Microsoft Copilot, Meta AI, Grok, and Poe in crime scene investigation workflows from endpoint artifacts on Windows, macOS, and iPhone-related logical evidence — and express those findings within governed, auditable reasoning boundaries?"*

**TRACE-AI-FR** is a forensic reasoning framework and analysis pipeline that accepts **E01 forensic images**, **mounted evidence directories**, or **ZIP archives** and determines whether AI platforms were used on the examined endpoint. It reconstructs AI-related activity through an **8-layer governed pipeline**, produces **Forensic Reasoning and Analysis Units of Evidence (FRAUEs)** as the atomic unit of every claim, enforces **12 inference governance rules**, and generates court-ready forensic reports following **SANS / UNCC standards**.

The framework tracks **8 AI platforms** (ChatGPT, Claude, Gemini, Perplexity, Microsoft Copilot, Meta AI, Grok, Poe), implements a formal **Claim Ladder** that separates artifact observation from platform presence, FRAUE reconstruction, and governed conclusion — ensuring no overclaiming beyond evidentiary support. Version 4.0 adds **acquisition-source normalization**, **platform-surface awareness**, **evidence-confidence classing** (Observed / Corroborated / Suspected / Insufficient), a **provider capability registry** with seeded profiles for all 8 platforms, **first-class voice/audio evidence** support, **generated-asset detection** (DALL-E, C2PA), **shared-link parsing**, **stronger provenance tracking**, **explicit blind-spot reporting** in governance, and a **DOCX-first** forensic reporting strategy with fallback.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│              Rich CLI (cli.py / __main__.py)                         │
│   trace-ai-fr analyze  |  trace-ai-fr info                          │
│   --evidence  --output  --examiner  --openai-api-key                 │
└────────────────────────┬─────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                  Analysis Engine (engine.py)                          │
│  8-Layer Governed Pipeline:                                          │
│    1. Evidence Ingestion (E01 / mounted dir / ZIP archive)           │
│    2. OS & User Profile Detection                                    │
│    3. Parser Execution (all applicable parsers)                      │
│    4. Normalization & Correlation (evidence-source-class tagging)     │
│    5. Claim Ladder Evaluation (4-level claim progression)            │
│    6. FRAUE Adjudication (atomic evidence unit construction)         │
│    7. Governance & Validation (12 rules, persistence, boundaries)    │
│    8. Report Generation (JSON, MD, HTML, SQLite)                     │
└──────┬──────┬──────┬──────┬──────┬──────┬──────┬─────────────────────┘
       │      │      │      │      │      │      │
       ▼      ▼      ▼      ▼      ▼      ▼      ▼
 ┌────────┐┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐┌──────────────────┐
 │  E01   ││Parse ││Corr- ││Claim ││Adjud-││Gover-││Report Gen.       │
 │Handler ││Regis-││elat. ││Ladder││icator││nance ││ + Rich HTML/MD   │
 │        ││try   ││Engine││      ││      ││Valid.││ + LLM Narrator   │
 └────────┘└──────┘└──────┘└──────┘└──────┘└──────┘└──────────────────┘
```

---

## 3. Project Structure

```
code/
├── desktop_app.py                       # Tkinter desktop GUI (dark-theme, E01 tree, report gen)
├── ai_usage_evidence_analyzer/          # Main package (34 modules)
│   ├── __init__.py                      # Version & metadata (TRACE-AI-FR v4.0.0)
│   ├── __main__.py                      # python -m entry point
│   ├── cli.py                           # Rich CLI with panels, tables, progress (v4.0 flags)
│   ├── engine.py                        # 8-layer governed pipeline orchestrator (v4.0 extended)
│   ├── models.py                        # 60+ dataclasses and enums (incl. v4.0 types)
│   ├── signatures.py                    # AI platform detection signatures (8 platforms)
│   ├── e01_handler.py                   # E01 image, binary scanner & mounted dir handling
│   ├── parser_registry.py              # BaseParser + auto-discovery registry
│   ├── correlation.py                   # Timeline + evidence-source-class + acquisition/surface inference
│   ├── confidence.py                    # 7-layer confidence scoring + EvidenceConfidenceClass
│   ├── claim_ladder.py                  # 4-level claim progression evaluation
│   ├── adjudication.py                  # FRAUE construction + confidence-class assignment
│   ├── persistence.py                   # Artifact persistence-state assessment
│   ├── governance.py                    # 12-rule inference governance engine (v4.0 blind spots)
│   ├── validation.py                    # FRAUE & report validation checks
│   ├── matrix.py                        # Comparative artifact matrix
│   ├── storage.py                       # SQLite normalized export (v4.0 schema)
│   ├── report_generator.py             # JSON / Markdown / HTML exporters (Rich UI, v4.0 sections)
│   ├── evidence_exhibit.py             # SANS-compliant exhibit management
│   ├── llm_narrator.py                 # OpenAI LLM narrative generation
│   ├── docx_report.py                  # Word (.docx) report generator (v4.0 sections)
│   ├── docx_parser.py                  # Parse examination questions from .docx files
│   ├── acquisition_bridge.py           # Evidence acquisition metadata bridge
│   ├── carving.py                       # File carving from unallocated space
│   ├── fr_assessment.py                # Forensic readiness assessment
│   ├── partition_analysis.py           # Partition table & filesystem analysis
│   ├── raw_inspector.py                # Raw byte-level evidence inspector
│   ├── recovery.py                      # Recovery engine for deleted/carved artifacts
│   ├── capability_registry.py          # Provider capability registry (8 platforms seeded) [v4.0]
│   ├── voice_evidence.py               # Voice/audio evidence engine [v4.0]
│   ├── repo_reality_check.py           # Repository structure verification [v4.0]
│   └── parsers/                         # Platform-specific parsers (15 modules)
│       ├── browser_parsers.py           #   Chrome, Edge, Firefox, Brave, Safari
│       ├── windows_parsers.py           #   Prefetch, AmCache, UserAssist, JumpList, LNK, Registry Hives
│       ├── macos_parsers.py             #   Plist, Quarantine, LaunchServices
│       ├── iphone_parsers.py            #   iPhone logical artifacts
│       ├── content_parsers.py           #   AI exports, transcripts, screenshots
│       ├── chatgpt_export_parser.py     #   ChatGPT conversation export (conversations.json)
│       ├── plugin_parsers.py            #   Browser extensions & plugins for AI platforms
│       ├── recovery_parsers.py          #   Carved artifact & raw hit parsers
│       ├── antiforensics_parsers.py     #   Anti-forensics detection (wiping, clearing)
│       ├── c2pa_parser.py               #   C2PA content authenticity metadata
│       ├── memory_pcap_parser.py        #   Memory dump & PCAP network capture analysis
│       ├── provider_export_parser.py    #   First-party AI provider data exports [v4.0]
│       ├── shared_link_parser.py        #   Shared AI conversation link detection [v4.0]
│       └── generated_asset_parser.py    #   AI-generated asset detection (DALL-E, C2PA) [v4.0]
├── tests/
│   ├── test_core.py                     # 90 tests across 27 test classes
│   ├── test_recovery.py                 # 41 tests across 12 test classes
│   └── test_v4.py                       # 60 tests across 17+ test classes [v4.0]
├── pyproject.toml                       # Package config & optional deps
├── requirements.txt                     # Dependencies
├── pytest.ini                           # Test configuration
└── README.md                            # Usage documentation
```

**Total:** 45 Python modules (34 package + 15 parsers − 4 shared __init__) + 1 desktop GUI + 3 test files

---

## 4. Core Modules

| Module | Responsibility |
|--------|----------------|
| **models.py** | 60+ dataclasses and enums: `ArtifactRecord`, `ForensicReport`, `FRAUE`, `GovernanceRecord`, `AIPlatform` (11 values incl. 8 tracked platforms), `AIModel` (15 values), `ConfidenceLevel`, `EvidenceSourceClass`, `ArtifactFamily`, `PersistenceState`, `ClaimLevel`, `FRAUEConfidence`, `AccessMode`, `OSPlatform`, v4.0 types (`AcquisitionSource` (14 values), `PlatformSurface` (10 values), `EvidenceConfidenceClass` (4 values), `VoiceArtifactType` (6 values), `ArtifactProvenance`, `VoiceEvidenceRecord`, `SharedLinkRecord`, `GeneratedAssetRecord`, `ProviderCapabilityProfile`), recovery models |
| **signatures.py** | Detection signatures for **8 AI platforms** — ChatGPT, Claude, Gemini, Perplexity, Copilot, Meta AI, Grok, Poe — domains, URL patterns, cookies, app identifiers, model strings, native app paths, registry keys, prefetch names |
| **e01_handler.py** | `E01Handler` (pytsk3/pyewf for real E01 images) and `MountedEvidenceHandler` (directory-based evidence). OS detection and user profile enumeration |
| **parser_registry.py** | `BaseParser` abstract class with `parse()` method; `ParserRegistry` for OS-aware auto-discovery |
| **engine.py** | `AnalysisEngine` — orchestrates the full 8-layer governed pipeline from evidence ingestion through FRAUE adjudication and governance to report export. Supports E01, mounted directories, and ZIP archives (with zip-slip protection, hash computation, and automatic temp cleanup) |
| **correlation.py** | `CorrelationEngine` — cross-artifact corroboration, timeline reconstruction, session estimation, **evidence-source-class assignment**, and v4.0 **acquisition-source inference** and **platform-surface inference** |
| **confidence.py** | `ConfidenceScoringEngine` — 7-layer scoring model (artifact family weight, classification, timestamp trustworthiness, corroboration, platform specificity, redundancy, coverage penalty) |
| **claim_ladder.py** | `ClaimLadder` — 4-level claim progression: (1) Artifact Observation → (2) Platform Presence → (3) FRAUE Reconstruction → (4) Governed Conclusion. Evaluates minimum thresholds for each level before allowing claim escalation |
| **adjudication.py** | `FRAUEAdjudicator` — constructs atomic FRAUE evidence units from correlated artifacts. Each FRAUE has platform, time window, evidence source class, persistence state, confidence, model/access-mode, and v4.0 **confidence class** (Observed/Corroborated/Suspected/Insufficient), **acquisition sources**, **platform surfaces**, and direct/corroborating/missing artifact IDs |
| **persistence.py** | `PersistenceAssessor` — evaluates artifact retention quality: INTACT, PARTIALLY_RETAINED, WEAKLY_RETAINED, NOT_OBSERVED. Considers artifact family, timestamp availability, and source class |
| **governance.py** | `GovernanceEngine` — enforces 12 inference governance rules, builds `GovernanceRecord` with analyst disclosures, tool blind spots, rule compliance matrix. Generates `scope_of_conclusion` and `inference_boundaries`. v4.0 adds **provider capability blind spots**, **acquisition blind spots**, **surface coverage summary**, **direct/corroborating/missing evidence summaries**, and **alternative explanations** |
| **validation.py** | `FrameworkValidator` — validates FRAUEs for required fields, checks governance record completeness, ensures report compliance with TRACE-AI-FR standards |
| **matrix.py** | `build_comparative_matrix()` — generates platform × artifact-type × access-mode comparison tables |
| **storage.py** | `SQLiteStorage` — normalized relational export with tables for artifacts, footprints, timeline, coverage. v4.0 adds `voice_evidence_records`, `shared_link_records`, `generated_asset_records`, and `schema_version` tables, plus 6 new columns on `artifact_records` |
| **report_generator.py** | `JSONExporter`, `MarkdownReportGenerator`, `HTMLReportGenerator` — Rich interactive output with dark-theme HTML (tab navigation, FRAUE cards, governance panel), FRAUE findings in Markdown, governance metadata in JSON |
| **evidence_exhibit.py** | `ExhibitManager` — sequential exhibit numbering, E01 source path tracking, MD5 hashing, Markdown/HTML exhibit reference generation |
| **llm_narrator.py** | OpenAI GPT-4o integration with forensic guardrail system prompt (no overclaiming, passive voice, exhibit references required). Graceful fallback to template-based narratives when no API key |
| **docx_report.py** | Word (.docx) report generator matching the UNCC Digital Forensics Laboratory template — Cambria font, centered header/footer, bold/underlined section headings, examiner signature block, appendix with glossary. v4.0 adds provider capability blind spots, surface coverage, evidence classification, alternative explanations, voice evidence, shared links, generated assets, confidence class summary |
| **docx_parser.py** | Parses examination questions from .docx files for inclusion in analysis |
| **acquisition_bridge.py** | Bridges evidence acquisition metadata into the analysis pipeline |
| **carving.py** | File carving from unallocated space — SQLite databases, browser artifacts, ChatGPT exports |
| **partition_analysis.py** | Partition table scanning (MBR/GPT), filesystem detection (NTFS, HFS+, APFS, EXT4) |
| **raw_inspector.py** | Raw byte-level evidence inspector — zlib decompression, string extraction, domain scanning |
| **recovery.py** | Recovery engine orchestrating carving, raw inspection, and partition analysis into recovered artifacts |
| **fr_assessment.py** | Forensic readiness assessment — evidence coverage evaluation and gap analysis |
| **capability_registry.py** | Provider capability registry with seeded profiles for all 8 AI platforms — export support, voice support, share links, blind spots, retention notes, capability confidence. Singleton `capability_registry` instance [v4.0] |
| **voice_evidence.py** | `VoiceEvidenceEngine` — import transcript files (.txt/.srt/.vtt/.json/.csv), scan evidence for audio files (.mp3/.wav/.m4a/.ogg/.flac/.webm), create `VoiceEvidenceRecord` and linked `ArtifactRecord` entries [v4.0] |
| **repo_reality_check.py** | Repository reality check — verify package version, module existence, core model fields, governance framework version, and report tool version before patching [v4.0] |

---

## 5. Parser Coverage

### Browser Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| ChromiumHistoryParser | URL visits with timestamps from Chrome, Edge, Brave |
| ChromiumCookieParser | AI platform cookies (session, auth, tracking) |
| ChromiumDownloadParser | Downloaded files from AI platforms |
| FirefoxHistoryParser | URL visits from `places.sqlite` |
| FirefoxCookieParser | AI-related cookies from `cookies.sqlite` |

### Windows Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| PrefetchParser | Execution traces for AI-related apps |
| RecentDocsParser | Recently accessed AI-generated files |
| UserAssistParser | GUI program execution counts/timestamps |
| AmCacheParser | Application installation/execution records |
| JumpListParser | Taskbar/start menu AI app references |
| **RegistryHiveParser** | **Full registry hive analysis: NTUSER.DAT (TypedURLs, RunMRU, RecentDocs, OpenSaveMRU, WordWheelQuery, TypedPaths), SOFTWARE (Uninstall, AppPaths, RegisteredApps), SYSTEM (AppCompatCache/ShimCache), UsrClass.dat (Shell Bags), SAM. Structured parsing via python-registry or binary scan fallback** |

### macOS Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| PlistParser | Application preferences and configurations |
| QuarantineParser | Downloaded file quarantine records |
| LaunchServicesParser | App registration and usage records |

### Content Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| AIContentScanner | AI-exported files, transcripts, naming patterns, prompt artifacts |

### ChatGPT Export Parser
| Parser | Artifacts Extracted |
|--------|---------------------|
| ChatGPTExportParser | ChatGPT conversation exports (conversations.json) with message-level parsing |

### Plugin / Extension Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| BrowserExtensionParser | Chrome/Edge/Firefox extensions for all 8 AI platforms, manifest inspection |

### Recovery Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| CarvedArtifactParser | Artifacts from carved files in unallocated space |
| RawHitParser | Domain/cookie references found via raw byte-level inspection |

### Specialized Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| AntiForensicsParser | Detection of history clearing, artifact wiping, privacy tool usage |
| C2PAParser | C2PA content authenticity metadata in AI-generated images |
| MemoryPCAPParser | AI platform references in memory dumps and network captures |

### iPhone Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| iPhoneLogicalParser | App traces from logical extraction backups |

### v4.0 Parsers
| Parser | Artifacts Extracted |
|--------|---------------------|
| **ProviderExportParser** | First-party data exports from ChatGPT (conversations.json), Claude, Gemini, Perplexity — message-level artifacts with timestamps |
| **SharedLinkParser** | Shared AI conversation URLs (chatgpt.com/share/, claude.ai/share/, gemini.google.com/share/, poe.com/s/, perplexity.ai/search/) from text files, bookmarks, history |
| **GeneratedAssetParser** | AI-generated assets: DALL-E filename patterns, C2PA content credentials, .ai_metadata.json sidecars, platform detection |

---

## 6. AI Platforms Detected

| Platform | Domains Monitored | Models Identified | Native App Support |
|----------|-------------------|-------------------|--------------------|
| **ChatGPT** | chatgpt.com, chat.openai.com, openai.com, cdn.oaistatic.com, api.openai.com | GPT-4, GPT-4 Turbo, GPT-4o | Windows & macOS desktop, iOS/Android |
| **Claude** | claude.ai, anthropic.com, api.anthropic.com, console.anthropic.com | Claude 3 Opus, Sonnet, Haiku, 3.5 Sonnet | Windows & macOS desktop, iOS/Android |
| **Gemini** | gemini.google.com, bard.google.com, aistudio.google.com, generativelanguage.googleapis.com | Gemini Pro, Ultra, 1.5 Pro | Android (Google Gemini app) |
| **Perplexity** | perplexity.ai, api.perplexity.ai, labs.perplexity.ai | Sonar / pplx-online | Windows & macOS desktop, iOS/Android |
| **Microsoft Copilot** | copilot.microsoft.com, bing.com/chat, copilot.microsoft365.com, sydney.bing.com | Copilot GPT-4 | Windows 11 integrated, Edge, M365 |
| **Meta AI** | meta.ai, ai.meta.com, llama.meta.com, imagine.meta.com | Llama 3 | Messenger, WhatsApp, Instagram |
| **Grok** | grok.com, x.ai, api.x.ai, console.x.ai | Grok-2 | Windows & macOS desktop |
| **Poe** | poe.com, api.poe.com | Multi-model aggregator | Windows & macOS desktop, iOS/Android |

---

## 7. Confidence Scoring Model

The 7-layer confidence scoring engine evaluates each artifact:

| Layer | Weight | Description |
|-------|--------|-------------|
| 1. Artifact Family | High | Browser history > cookies > prefetch |
| 2. Evidence Classification | High | Direct (URL match) vs. Inferred (cookie only) |
| 3. Timestamp Trustworthiness | Medium | Filesystem vs. database vs. absent |
| 4. Corroboration | Medium | Cross-artifact support from multiple sources |
| 5. Platform Specificity | Medium | Exact domain match vs. generic indicator |
| 6. Redundancy | Low | Multiple artifacts of same type |
| 7. Coverage Penalty | Low | Missing artifact families lower overall confidence |

**Output levels:** `HIGH`, `MODERATE`, `LOW`, `UNSUPPORTED`

---

## 7a. TRACE-AI-FR Claim Ladder

The framework enforces a strict 4-level claim progression. Each level requires the preceding levels to be satisfied before a claim can escalate:

| Level | Name | Requirements |
|-------|------|-------------|
| 1 | **Artifact Observation** | At least one artifact with a valid evidence-source-class assignment |
| 2 | **Platform Presence** | ≥ 2 artifacts from ≥ 2 distinct artifact families for a given platform |
| 3 | **FRAUE Reconstruction** | Complete FRAUE with platform, time window, source class, persistence state, and confidence |
| 4 | **Governed Conclusion** | Full governance record with all 12 rules evaluated, disclosures documented |

---

## 7b. FRAUE — Forensic Reasoning and Analysis Unit of Evidence

A **FRAUE** is the atomic, indivisible unit of every forensic claim. Each FRAUE contains:

| Field | Description |
|-------|-------------|
| `platform` | AI platform (ChatGPT, Claude, Gemini, Perplexity, Copilot, Meta AI, Grok, Poe) |
| `time_window_start/end` | Temporal bounds derived from timestamps |
| `evidence_source_class` | BROWSER_DERIVED, OS_DERIVED, NATIVE_APP_DERIVED, CONTENT_REMNANT_DERIVED, etc. |
| `persistence_state` | INTACT, PARTIALLY_RETAINED, WEAKLY_RETAINED, NOT_OBSERVED |
| `confidence` | HIGH, MODERATE, LOW, INSUFFICIENT |
| `model` | Specific AI model if determinable (e.g., GPT-4o, Claude-3-Opus) |
| `access_mode` | BROWSER or NATIVE_APP when determinable |
| `supporting_artifacts` | List of artifact IDs underpinning the FRAUE |
| `claim_level` | Maximum claim level reached on the ladder |

---

## 7c. Governance Engine — 12 Inference Rules

The governance engine enforces 12 rules that constrain every conclusion:

| # | Rule | Purpose |
|---|------|---------|
| 1 | No overclaiming beyond evidence | Claims cannot exceed supporting artifacts |
| 2 | Absence ≠ Absence of use | Missing artifacts never prove non-use |
| 3 | Temporal precision bounds | Time windows reflect actual timestamp granularity |
| 4 | Evidence-source-class disclosure | Every claim declares its derivation source |
| 5 | Persistence-state transparency | Data retention quality is always documented |
| 6 | Cross-source corroboration | Multi-source claims require independent evidence |
| 7 | Model identification threshold | AI model claims require direct evidence |
| 8 | Access-mode specificity | Browser vs. native-app claims need distinct evidence |
| 9 | Platform attribution boundary | Platform identity requires platform-specific indicators |
| 10 | Inference boundary documentation | All reasoning limits are explicitly stated |
| 11 | Tool blind-spot disclosure | Known gaps in analysis capability are declared |
| 12 | Analyst qualification caveat | Automated findings require human review |

The engine produces a **GovernanceRecord** with disclosures, blind spots, rule compliance matrix, and generates **inference boundaries** and a **scope of conclusion** statement.

---

## 8. Report Generation & Rich UX

### Rich CLI Terminal Output

The CLI uses the **Rich** library for professional terminal output:

- **Colored TRACE-AI-FR banner** with styled framework name
- **Configuration table** showing analysis parameters before execution
- **Progress spinner** during analysis with status updates
- **Results panel** with stats grid (artifacts, FRAUEs, platforms, timeline events)
- **Detected platforms table** with per-platform artifact counts and confidence
- **FRAUE summary table** with platform, time window, confidence badges
- **Graceful fallback** to plain text when Rich is unavailable

### Report Formats

Reports follow the **SANS / UNCC Forensic Report Standard** with TRACE-AI-FR extensions:

1. **Header** — Lab, examiner, case number, date
2. **Overview / Case Summary** — LLM-enhanced narrative of the engagement
3. **Forensic Acquisition & Exam Preparation** — Hash verification, tool details, evidence integrity
4. **Findings and Report** — Numbered findings with exhibit references:
   - AI Platform Detection Summary (table)
   - Per-platform detailed findings (LLM narrative + exhibits)
   - Browser vs. Native App Analysis
   - Crime-Scene Image Analysis Indicators
   - Timeline of AI-Related Activity
   - Comparative Artifact Matrix
   - Evidence Coverage Assessment
5. **FRAUE Findings** — Summary table of all FRAUEs + per-FRAUE detail sections with confidence, evidence class, persistence state, and supporting artifacts
6. **Inference Boundaries & Governance** — Inference boundary list, scope of conclusion, governance record summary with disclosures and blind spots
7. **Conclusion** — Confidence-rated per-platform conclusions with evidentiary caveats
8. **Examiner Signature Block**

### Interactive HTML Report

The HTML report features a modern **dark-theme design**:

- **Sticky navigation bar** with colored TRACE-AI-FR branding
- **Dashboard** with animated stat cards (artifacts, FRAUEs, platforms, timeline events)
- **Tab-based navigation**: Forensic Report | FRAUEs | Governance
- **FRAUE card grid** with color-coded confidence badges (HIGH=green, MODERATE=amber, LOW=orange, INSUFFICIENT=red)
- **Governance panel** with collapsible `<details>` sections for disclosures, blind spots, and rule compliance
- **Scope of conclusion** styled as a blockquote
- **Print media query** (auto-switches to light theme for court printing)
- **JavaScript interactivity** for tab switching

### Output Files

| Format | File | Content |
|--------|------|---------|
| **Markdown** | `{case_id}_report.md` | Full forensic report with FRAUE findings and governance sections |
| **HTML** | `{case_id}_report.html` | Dark-theme interactive report with tabs, dashboard, FRAUE cards || **Word** | `{case_id}_report.docx` | UNCC DFL template-format report (Cambria font, examiner block, glossary appendix) || **JSON** | `{case_id}_findings.json` | Machine-readable with FRAUEs, governance record, inference boundaries |
| **SQLite** | `{case_id}_findings.sqlite` | Normalized database with 7+ tables |

---

## 9. LLM-Enhanced Narratives

When an OpenAI API key is provided (`--openai-api-key` or `OPENAI_API_KEY` env var), the report narratives are generated by **GPT-4o** with a forensic guardrail system prompt:

- No overclaiming beyond evidence
- Every finding references specific exhibits
- Passive voice for objectivity
- No speculation or opinion
- Qualify negative findings appropriately
- Distinguish correlation from causation

**Fallback:** When no API key is available, all narratives use built-in forensic templates that follow the same standards.

---

## 10. Evidence Exhibit System

Every artifact generates a numbered exhibit with:

- **Exhibit Number** — Sequential (Exhibit 1, Exhibit 2, ...)
- **E01 Source Path** — e.g., `evidence.E01:/Users/John/AppData/Local/Google/Chrome/History`
- **Platform** — ChatGPT, Claude, Gemini, Perplexity, Copilot, Meta AI, Grok, or Poe
- **Artifact Family** — Browser History, Cookie, Download, etc.
- **Confidence Level** — HIGH, MODERATE, LOW
- **MD5 Hash** — File integrity verification
- **Timestamp** — When available from the artifact

Exhibits are embedded inline in findings and listed in full in the Appendix.

---

## 10a. Desktop GUI Application

The **desktop_app.py** provides a full-featured tkinter GUI as an alternative to the CLI:

### Features

- **Dark-theme interface** with TRACE-AI-FR branding (purple/teal accent palette)
- **Evidence tree panel** showing E01 internal file structure:
  - Uses pyewf/pytsk3 when available for full filesystem tree
  - Falls back to binary scanning with zlib decompression to extract file paths
  - Detects MBR partition tables and NTFS filesystems
  - Displays hierarchical folder structure with priority folders (Users, Windows, Program Files)
- **Configuration panel** with case name, examiner, organization, output directory, evidence path
- **Tabbed results view**: Dashboard, Artifacts, FRAUEs, Timeline, Governance, Questions, FR Assessment, Log
- **Analysis toolbar** with Run Analysis, Generate Report, and Clear buttons
- **Generate Report** button:
  - Opens a dialog prompting for Forensic Examination Name, "In the matter of", and Examiner Name
  - Generates a Word (.docx) report matching the UNCC DFL template
  - Offers to open the generated file after creation
- **File menu** with Open Evidence, Set Output Folder, Export HTML, Generate Word Report

### Word Report Format (UNCC DFL Template)

The generated `.docx` report follows the UNCC Digital Forensics Laboratory template:

- **Header**: University of North Carolina at Charlotte / Digital Forensics Laboratory / 9201 University Blvd, Charlotte NC 28223 (centered)
- **Title block**: Examiner name (bold, 14pt), "Forensic Examination in the matter of" (bold, underlined)
- **Font**: Cambria throughout (14pt header, 12pt body)
- **Sections**: Overview, Exam Preparation (evidence & hash info), Analysis (partitions, OS, user profiles, platform detection table, FRAUE table, timeline, examination questions), Governance & Inference Boundaries, Conclusion, Examiner Signature, Appendix (8-term forensic glossary)
- **Footer**: "In the matter of: [subject]"

---

## 11. Test Suite

**191 tests across 56+ test classes — all passing (90 core + 41 recovery + 60 v4.0)**

### Core Tests (test_core.py — 90 tests, 27 classes)

| Test Class | Tests | Coverage |
|------------|-------|----------|
| TestModels | 5 | Dataclass creation, serialization, enum values |
| TestSignatures | 11 | Domain matching for all 8 platforms, model strings, signature population (8 entries) |
| TestParserRegistry | 3 | Registry init, OS-specific parser retrieval |
| TestBrowserParsers | 4 | Chrome/Firefox history, cookies, downloads |
| TestWindowsParsers | 2 | Recent files, prefetch parsing |
| TestContentParsers | 1 | AI content file scanning |
| TestCorrelation | 2 | Cross-artifact linking, platform summarization |
| TestConfidenceScoring | 3 | Direct/weak scoring, footprint building |
| TestSQLiteStorage | 2 | Schema creation, full export |
| TestMatrix | 1 | Comparative matrix generation |
| TestReportGeneration | 3 | JSON, Markdown, HTML export |
| TestMountedEvidence | 2 | OS detection, user profile discovery |
| TestIntegration | 2 | Full pipeline, empty evidence handling |
| TestEvidenceExhibit | 5 | Exhibit manager, numbering, filtering, references |
| TestLLMNarrator | 4 | Fallback narratives for all 4 report sections |
| TestReportWithExhibits | 1 | End-to-end exhibit integration |
| TestZIPExtraction | 6 | Auto-detection, artifact extraction, hash computation, invalid ZIP handling, temp cleanup, missing file |
| TestRegistryHiveParser | 6 | Parser registration, NTUSER.DAT binary scan, no-hives handling, SOFTWARE hive scan |
| TestFRAUEModel | 3 | FRAUE creation, to_dict serialization, None model/access_mode handling |
| TestGovernanceRecord | 2 | Default governance record fields, to_dict output |
| TestClaimLadder | 2 | Artifact claim level assignment, platform presence threshold evaluation |
| TestPersistence | 2 | Single artifact persistence assignment, batch assessment |
| TestEvidenceSourceClass | 3 | Browser-derived, native-app-derived, and unknown source-class assignment |
| TestAdjudication | 3 | FRAUE production from artifacts, required fields check, empty input handling |
| TestGovernanceModule | 4 | 12-rule count, governance record building, scope generation, FRAUE-aware scope |
| TestFrameworkEnums | 5 | All 5 new enums: EvidenceSourceClass, PersistenceState, ClaimLevel, FRAUEConfidence, AccessMode |
| TestIntegrationV2 | 3 | Full pipeline produces FRAUEs, JSON export contains FRAUE data, HTML report has tab navigation |

### Recovery Tests (test_recovery.py — 41 tests, 12 classes)

| Test Class | Tests | Coverage |
|------------|-------|----------|
| TestSignatureRuleEngine | 5 | Signature-based rule matching for carved artifacts |
| TestPartitionScanner | 4 | MBR/GPT partition table detection, filesystem identification |
| TestRawInspector | 6 | Byte-level scanning, zlib decompression, domain extraction |
| TestRecoveryEngine | 3 | Full recovery pipeline orchestration |
| TestRecoveryParsers | 3 | Carved artifact parsing, raw hit processing |
| TestRecoveryConfidence | 3 | Confidence scoring for recovered artifacts |
| TestRecoveryPersistence | 2 | Persistence state for recovered/carved data |
| TestAcquisitionBridge | 4 | Acquisition metadata bridging, EWF metadata extraction |
| TestGovernanceRecovery | 2 | Governance rules applied to recovery findings |
| TestStorageRecovery | 1 | SQLite storage of recovery artifacts |
| TestRecoveryModels | 5 | RawHit, PartitionFinding, RecoveryAuditRecord models |
| TestAntiOverclaim | 3 | Anti-overclaiming rules for recovered evidence |

### v4.0 Tests (test_v4.py — 60 tests, 17+ classes)

| Test Class | Tests | Coverage |
|------------|-------|----------|
| TestV4Enums | 5 | AcquisitionSource, PlatformSurface, EvidenceConfidenceClass, VoiceArtifactType, EvidenceSourceClass extensions |
| TestV4ArtifactRecordExtensions | 2 | v4.0 default fields, to_dict serialization |
| TestV4FRAUEExtensions | 2 | v4.0 FRAUE defaults, to_dict with new fields |
| TestV4GovernanceExtensions | 2 | v4.0 governance defaults, to_dict with blind spots |
| TestV4ForensicReportExtensions | 1 | Schema version, tool version, template metadata |
| TestV4NewDataclasses | 4 | VoiceEvidenceRecord, SharedLinkRecord, GeneratedAssetRecord, ProviderCapabilityProfile |
| TestCapabilityRegistry | 7 | Singleton, 8-platform seeding, profile retrieval, blind spots, feature checks, capability matrix |
| TestVoiceEvidence | 4 | Engine creation, empty transcript import, text transcript import, evidence scanning |
| TestProviderExportParser | 2 | ChatGPT conversations.json parsing, empty directory |
| TestSharedLinkParser | 3 | ChatGPT share link detection, Claude share link detection, no-links |
| TestGeneratedAssetParser | 3 | DALL-E filename detection, C2PA sidecar detection, no-assets |
| TestConfidenceClassAssignment | 2 | EvidenceConfidenceClass import, FRAUE default confidence class |
| TestAcquisitionSourceInference | 2 | Acquisition source from browser history, platform surface inference |
| TestGovernanceV4 | 2 | Framework version 4.0.0, blind spot field existence |
| TestSQLiteSchemaV4 | 4 | schema_version table, v4 tables exist, v4 columns, export with v4 fields |
| TestReportV4Metadata | 2 | Report schema/tool version, DOCX fields |
| TestRepoRealityCheck | 2 | Module import, reality check function |
| TestPackageVersion | 2 | Version string, CLI info version reference |
| TestDOCXReport | 3 | Generator import, 8-platform mention, minimal DOCX generation |
| TestArtifactProvenance | 1 | Provenance dataclass creation |
| TestCapabilityMatrixFeatures | 3 | ChatGPT export support, Claude platform name, profile version format |
| TestReportGeneratorV4 | 2 | v4 evidence sections method, generate pipeline inclusion |

---

## 12. Installation & Usage

### Install

```bash
# Basic install
pip install -e .

# With forensic libraries (Linux/macOS)
pip install -e ".[forensic]"

# With LLM support
pip install -e ".[llm]"

# Everything
pip install -e ".[all]"
```

### CLI Usage

```bash
# Analyze mounted evidence directory
python -m ai_usage_evidence_analyzer analyze /path/to/evidence --output ./reports \
    --case-name "Case 2026-001" \
    --examiner "Hemal" \
    --organization "UNCC Forensics Lab"

# Analyze a ZIP archive (auto-extracted)
python -m ai_usage_evidence_analyzer analyze evidence.zip --output ./reports \
    --case-name "Case 2026-002"

# With LLM-enhanced narratives
python -m ai_usage_evidence_analyzer analyze /path/to/evidence --output ./reports \
    --openai-api-key sk-... \
    --llm-model gpt-4o

# Analyze an E01 image
python -m ai_usage_evidence_analyzer analyze evidence.E01 --output ./reports

# Show tool info
python -m ai_usage_evidence_analyzer info
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--evidence` | Path to E01 image or mounted evidence directory |
| `--output` | Output directory for reports |
| `--case-name` | Case name for the report |
| `--case-id` | Case identifier (auto-generated if omitted) |
| `--examiner` | Examiner name |
| `--organization` | Organization name |
| `--input-mode` | `auto`, `e01`, `mounted`, or `zip` |
| `--enable-carving` | Enable file carving in unallocated space |
| `--openai-api-key` | OpenAI API key for LLM narratives |
| `--llm-model` | LLM model name (default: gpt-4o) |
| `--verbose` | Enable verbose logging |
| `--log-file` | Path to write log file |
| `--enable-voice-analysis` | Enable voice/audio evidence scanning [v4.0] |
| `--import-transcripts` | Path to transcript directory for voice import [v4.0] |
| `--import-provider-exports` | Enable first-party provider export parsing [v4.0] |
| `--import-shared-links` | Enable shared AI link detection [v4.0] |
| `--include-capability-matrix` | Include provider capability matrix in reports [v4.0] |
| `--strict-repo-check` | Fail on repository reality check violations [v4.0] |
| `--allow-report-fallback` | Allow HTML fallback if DOCX generation fails [v4.0] |

---

## 13. Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| Python ≥ 3.9 | Runtime | Yes |
| rich | Rich CLI terminal output (panels, tables, progress) | Recommended |
| python-docx | Word (.docx) report generation | Recommended |
| tkinter | Desktop GUI (included with Python) | Included |
| pytest ≥ 7.0 | Testing | Dev only |
| pytsk3 | E01 filesystem access | Optional (forensic) |
| pyewf | E01 image mounting | Optional (forensic) |
| python-registry | Windows registry parsing | Optional (forensic) |
| openai ≥ 1.0 | LLM report narratives | Optional (llm) |

---

## 14. v4.0 Feature Summary

| Feature | Module(s) | Description |
|---------|-----------|-------------|
| **Acquisition-Source Normalization** | models.py, correlation.py | 14-value `AcquisitionSource` enum (E01 Image, Browser Artifact, Provider Export, etc.) inferred per artifact |
| **Platform-Surface Awareness** | models.py, correlation.py | 10-value `PlatformSurface` enum (Browser Web, Native Desktop App, Mobile App, etc.) inferred per artifact |
| **Evidence Confidence Classing** | models.py, adjudication.py | 4-level `EvidenceConfidenceClass` (Observed / Corroborated / Suspected / Insufficient) assigned per FRAUE |
| **Provider Capability Registry** | capability_registry.py | Seeded profiles for all 8 platforms with export, voice, share links, blind spots, retention notes |
| **Voice/Audio Evidence** | voice_evidence.py | Import transcripts, scan for audio files, create VoiceEvidenceRecord entries |
| **Generated Asset Detection** | parsers/generated_asset_parser.py | DALL-E naming patterns, C2PA metadata, .ai_metadata.json sidecars |
| **Shared Link Parsing** | parsers/shared_link_parser.py | Detect shared AI conversation URLs across text files |
| **Provider Export Parsing** | parsers/provider_export_parser.py | Parse first-party data exports (ChatGPT conversations.json, etc.) |
| **Artifact Provenance** | models.py | `ArtifactProvenance` dataclass tracking acquisition source, parser name, extraction method |
| **Blind-Spot Reporting** | governance.py, docx_report.py | Provider capability blind spots, acquisition blind spots, surface coverage in governance |
| **Evidence Classification** | governance.py, docx_report.py | Direct / corroborating / missing evidence summaries with alternative explanations |
| **Repository Reality Check** | repo_reality_check.py | Verify module existence, model fields, versions before patching |
| **v4.0 SQLite Schema** | storage.py | `schema_version`, `voice_evidence_records`, `shared_link_records`, `generated_asset_records` tables |
| **DOCX-First Reporting** | engine.py, docx_report.py | DOCX is primary output; HTML fallback with `--allow-report-fallback` |
| **v4.0 Report Sections** | docx_report.py, report_generator.py | Voice evidence, shared links, generated assets, confidence class summary, template metadata |

---

## 15. Key Design Decisions

1. **No assumptions** — Every finding requires an evidence path. Absence of evidence is explicitly never reported as evidence of absence (Rule 2).
2. **FRAUE as atomic unit** — Every forensic claim is backed by a FRAUE containing platform, time window, evidence source class, persistence state, and confidence.
3. **Claim Ladder enforcement** — Claims cannot escalate beyond the evidence level: artifact observation → platform presence → FRAUE reconstruction → governed conclusion.
4. **12-rule governance** — Every conclusion passes through 12 inference governance rules with a compliance matrix, disclosures, and blind spots.
5. **E01 path tracking** — All exhibits reference the original E01 source path (e.g., `evidence.E01:/path`) for chain-of-custody integrity.
6. **Graceful degradation** — Works without pytsk3/pyewf (binary scan fallback with zlib decompression), without OpenAI (template fallbacks), without python-registry (binary scan fallback), without Rich (plain text CLI fallback), without python-docx (HTML report only).
7. **Read-only processing** — SQLite databases from evidence are copied to temp before querying to avoid WAL lock interference. No modifications to original evidence.
8. **SANS/UNCC compliance** — Report structure follows established forensic reporting standards with mandatory evidentiary caveats.
9. **Rich interactive reports** — Dark-theme HTML with tab navigation, FRAUE cards, governance panels, and print-optimized CSS. Rich CLI with panels, tables, and progress spinners.
10. **ZIP archive support** — Auto-detects `.zip` evidence files, extracts to temp with zip-slip protection, computes MD5/SHA-1 hashes, cleans up after analysis.
11. **Full Registry hive analysis** — Parses 5 registry hives (NTUSER.DAT, UsrClass.dat, SOFTWARE, SYSTEM, SAM) using python-registry or binary scan fallback.
12. **Cross-platform** — Runs on Windows and macOS with no OS-specific dependencies in the core pipeline.
13. **8-platform coverage** — Comprehensive forensic signatures for ChatGPT, Claude, Gemini, Perplexity, Microsoft Copilot, Meta AI, Grok, and Poe with domains, URL patterns, cookies, native app paths, registry keys, process names, and model strings.
14. **Desktop GUI** — Tkinter-based dark-theme application with evidence tree (E01 internal file listing via binary scan), tabbed analysis results, and Word report generation with UNCC DFL template formatting.
15. **Word report generation** — Court-ready .docx reports matching the UNCC Digital Forensics Laboratory template with Cambria font, centered header/footer, examination metadata dialog, and forensic glossary appendix.
