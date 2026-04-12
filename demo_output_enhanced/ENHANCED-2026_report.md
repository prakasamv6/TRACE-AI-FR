<div style="text-align:right">
UNCC Forensics Lab<br>
Digital Forensics Team<br>
Case #ENHANCED-2026<br>
04-12-2026
</div>

# Overview

On 04/12/2026, the requesting agency provided a forensic evidence directory to the forensic laboratory for analysis. The evidence was received by Digital Forensics Team and identified as **demo_evidence**.

The examiner was instructed to perform a forensic analysis to determine whether AI platforms — specifically ChatGPT, Claude, Google Gemini, Perplexity, Microsoft Copilot, Meta AI, Grok, or Poe — were used on the examined Windows endpoint. This analysis includes identification of browser history, cookies, downloads, application traces, cached content, and any other artifacts that indicate AI platform access or usage.


# Forensic Acquisition & Exam Preparation

The forensic analysis was performed using **AI Usage Evidence Analyzer v4.0.0** on the examiner's forensic workstation.

*Note: No hash verification was performed on the evidence source. If the evidence was provided as a mounted directory, hash verification may not be applicable.*

All evidence was processed in **read-only mode**. SQLite databases within the evidence were copied to temporary storage before querying to avoid WAL lock interference. No modifications were made to the original evidence.

The following tools and parsers were used for forensic analysis:

- *ChromiumHistoryParser v1.0.0*
- *FirefoxHistoryParser v1.0.0*
- *WindowsPrefetchParser v1.0.0*
- *WindowsRecentFilesParser v1.0.0*
- *WindowsUserAssistParser v1.0.0*
- *WindowsEventLogParser v2.0.0*
- *WindowsRecycleBinParser v1.0.0*
- *WindowsAppDataParser v1.0.0*
- *WindowsRegistryHiveParser v1.0.0*
- *AIContentScanner v1.0.0*
- *BrowserExtensionParser v1.0.0*
- *ToolChainParser v1.0.0*
- *AntiForensicsDetector v1.0.0*
- *C2PAManifestParser v1.0.0*
- *ChatGPTExportParser v1.0.0*
- *MemoryDumpScanner v1.0.0*
- *PCAPScanner v1.0.0*
- *CarvedArtifactParser v3.0.0*
- *RawHitParser v3.0.0*
- *RecoveredFileClassifier v3.0.0*
- *AIToolScannerParser v1.0.0*



# Findings and Report (Forensic Analysis)

After completing the forensic analysis of the submitted evidence, **23** artifact(s) related to AI platform usage were identified. The following AI platforms were detected: **Adobe Firefly, ChatGPT, Claude, Gemini**.

Of these, **11** artifact(s) constitute direct evidence and **12** artifact(s) are inferred/indirect evidence. See supporting exhibits below.

**1. AI Platform Detection Summary**

| AI Platform | Artifacts Found | Direct | Inferred | Highest Confidence |
|-------------|-----------------|--------|----------|--------------------|
| Adobe Firefly | 1 | 0 | 1 | Low |
| ChatGPT | 11 | 5 | 6 | Moderate |
| Claude | 5 | 3 | 2 | High |
| Gemini | 6 | 3 | 3 | High |

**2. Gemini — Detailed Findings**

Forensic analysis of the submitted evidence identified **6** artifact(s) associated with **Gemini** (3 direct, 3 inferred). The overall confidence for this finding is **High**.

The platform appears to have been accessed via **Browser**.

- Earliest recorded activity: 2024-01-17 23:50:00 UTC
- Latest recorded activity: 2026-04-06 02:22:05 UTC
- Estimated session count: 2

**Supporting Evidence:**

- **Exhibit 1:** URL Visit artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 2:** URL Visit artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 11:** Cookie artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
  - Confidence: Moderate
- **Exhibit 20:** AI Export/Download File artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
  - Confidence: Moderate
- **Exhibit 21:** Content Indicator artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
  - Confidence: Moderate
- **Exhibit 23:** Content Indicator artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
  - Confidence: High
- **Exhibit 24:** URL Visit artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 25:** URL Visit artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 34:** Cookie artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
  - Confidence: Moderate
- **Exhibit 43:** AI Export/Download File artifact indicating Gemini access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
  - Confidence: Moderate



**Supporting Evidence Exhibits:**

> **Exhibit 1: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-18 00:20:00 UTC
> - **Indicator:** https://gemini.google.com/app/xyz789
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_001.bin](exhibits\exhibit_001.bin)*

> **Exhibit 2: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** https://gemini.google.com/app
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_002.bin](exhibits\exhibit_002.bin)*

> **Exhibit 11: Browser Cookies — Gemini**
>
> Cookie artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** .gemini.google.com / NID
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_011.bin](exhibits\exhibit_011.bin)*

> **Exhibit 20: User Content — Gemini**
>
> AI Export/Download File artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: gemini_forensic_notes.md (pattern: gemini.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_020.md](exhibits\exhibit_020.md)*

> **Exhibit 21: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Gemini' in gemini_forensic_notes.md
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_021.md](exhibits\exhibit_021.md)*

> **Exhibit 23: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Model string: Gemini Pro in gemini_forensic_notes.md
> - **Confidence:** High
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_023.md](exhibits\exhibit_023.md)*

> **Exhibit 24: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-18 00:20:00 UTC
> - **Indicator:** https://gemini.google.com/app/xyz789
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_024.bin](exhibits\exhibit_024.bin)*

> **Exhibit 25: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** https://gemini.google.com/app
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_025.bin](exhibits\exhibit_025.bin)*

> **Exhibit 34: Browser Cookies — Gemini**
>
> Cookie artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** .gemini.google.com / NID
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_034.bin](exhibits\exhibit_034.bin)*

> **Exhibit 43: User Content — Gemini**
>
> AI Export/Download File artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: gemini_forensic_notes.md (pattern: gemini.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_043.md](exhibits\exhibit_043.md)*

> **Exhibit 44: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Gemini' in gemini_forensic_notes.md
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_044.md](exhibits\exhibit_044.md)*

> **Exhibit 46: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Model string: Gemini Pro in gemini_forensic_notes.md
> - **Confidence:** High
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_046.md](exhibits\exhibit_046.md)*


**3. ChatGPT — Detailed Findings**

Forensic analysis of the submitted evidence identified **11** artifact(s) associated with **ChatGPT** (5 direct, 6 inferred). The overall confidence for this finding is **Moderate**.

The platform appears to have been accessed via **Browser**.

- Earliest recorded activity: 2024-01-17 21:20:00 UTC
- Latest recorded activity: 2026-04-06 02:22:05 UTC
- Estimated session count: 2

**Supporting Evidence:**

- **Exhibit 3:** URL Visit artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: Moderate
- **Exhibit 5:** URL Visit artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: Moderate
- **Exhibit 7:** URL Visit artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: Moderate
- **Exhibit 8:** Cookie artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
  - Confidence: Moderate
- **Exhibit 9:** Cookie artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
  - Confidence: Moderate
- **Exhibit 12:** Local Storage Key artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log`
  - Confidence: Unsupported
- **Exhibit 13:** Prefetch Reference artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
  - Confidence: Moderate
- **Exhibit 14:** Prefetch Reference artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
  - Confidence: Moderate
- **Exhibit 15:** Prefetch Reference artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
  - Confidence: Moderate
- **Exhibit 16:** Prefetch Reference artifact indicating ChatGPT access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
  - Confidence: Moderate

**Caveats:**

- Model-level attribution not possible; platform-level only.



**Supporting Evidence Exhibits:**

> **Exhibit 3: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:20:00 UTC
> - **Indicator:** https://chat.openai.com/chat
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_003.bin](exhibits\exhibit_003.bin)*

> **Exhibit 5: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** https://chatgpt.com/c/abc123
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_005.bin](exhibits\exhibit_005.bin)*

> **Exhibit 7: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:20:00 UTC
> - **Indicator:** https://chatgpt.com/
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_007.bin](exhibits\exhibit_007.bin)*

> **Exhibit 8: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .chatgpt.com / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_008.bin](exhibits\exhibit_008.bin)*

> **Exhibit 9: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .openai.com / _cfuvid
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_009.bin](exhibits\exhibit_009.bin)*

> **Exhibit 12: Browser Local Storage — ChatGPT**
>
> Local Storage Key artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log`
> - **Indicator:** Key match: 'chatgpt' in chatgpt_trace.log
> - **Confidence:** Unsupported
> - **Artifact Hash (MD5):** `e6a07a97668a54927b2249c03ebf49f5`
>
> *See attached: [exhibits\exhibit_012.log](exhibits\exhibit_012.log)*

> **Exhibit 13: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt.com in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_013.pf](exhibits\exhibit_013.pf)*

> **Exhibit 14: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_014.pf](exhibits\exhibit_014.pf)*

> **Exhibit 15: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_015.pf](exhibits\exhibit_015.pf)*

> **Exhibit 16: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_016.pf](exhibits\exhibit_016.pf)*

> **Exhibit 17: User Content — ChatGPT**
>
> AI Export/Download File artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\ChatGPT_Crime_Scene_Analysis.pdf`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: ChatGPT_Crime_Scene_Analysis.pdf (pattern: chat[-_]?gpt.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4e96f9e5729a4a216cbf044d44ed7b7b`
>
> *See attached: [exhibits\exhibit_017.pdf](exhibits\exhibit_017.pdf)*

> **Exhibit 26: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:20:00 UTC
> - **Indicator:** https://chat.openai.com/chat
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_026.bin](exhibits\exhibit_026.bin)*

> **Exhibit 28: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** https://chatgpt.com/c/abc123
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_028.bin](exhibits\exhibit_028.bin)*

> **Exhibit 30: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:20:00 UTC
> - **Indicator:** https://chatgpt.com/
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_030.bin](exhibits\exhibit_030.bin)*

> **Exhibit 31: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .chatgpt.com / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_031.bin](exhibits\exhibit_031.bin)*

> **Exhibit 32: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .openai.com / _cfuvid
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_032.bin](exhibits\exhibit_032.bin)*

> **Exhibit 35: Browser Local Storage — ChatGPT**
>
> Local Storage Key artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log`
> - **Indicator:** Key match: 'chatgpt' in chatgpt_trace.log
> - **Confidence:** Unsupported
> - **Artifact Hash (MD5):** `e6a07a97668a54927b2249c03ebf49f5`
>
> *See attached: [exhibits\exhibit_035.log](exhibits\exhibit_035.log)*

> **Exhibit 36: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt.com in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_036.pf](exhibits\exhibit_036.pf)*

> **Exhibit 37: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_037.pf](exhibits\exhibit_037.pf)*

> **Exhibit 38: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_038.pf](exhibits\exhibit_038.pf)*

> **Exhibit 39: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_039.pf](exhibits\exhibit_039.pf)*

> **Exhibit 40: User Content — ChatGPT**
>
> AI Export/Download File artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\ChatGPT_Crime_Scene_Analysis.pdf`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: ChatGPT_Crime_Scene_Analysis.pdf (pattern: chat[-_]?gpt.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4e96f9e5729a4a216cbf044d44ed7b7b`
>
> *See attached: [exhibits\exhibit_040.pdf](exhibits\exhibit_040.pdf)*


**4. Claude — Detailed Findings**

Forensic analysis of the submitted evidence identified **5** artifact(s) associated with **Claude** (3 direct, 2 inferred). The overall confidence for this finding is **High**.

The platform appears to have been accessed via **Browser**.

- Earliest recorded activity: 2024-01-17 21:50:00 UTC
- Latest recorded activity: 2026-04-06 02:22:05 UTC
- Estimated session count: 2

**Supporting Evidence:**

- **Exhibit 4:** URL Visit artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 6:** URL Visit artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 10:** Cookie artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
  - Confidence: Moderate
- **Exhibit 18:** AI Export/Download File artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
  - Confidence: Moderate
- **Exhibit 19:** Content Indicator artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
  - Confidence: Moderate
- **Exhibit 27:** URL Visit artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 29:** URL Visit artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
  - Confidence: High
- **Exhibit 33:** Cookie artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
  - Confidence: Moderate
- **Exhibit 41:** AI Export/Download File artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
  - Confidence: Moderate
- **Exhibit 42:** Content Indicator artifact indicating Claude access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
  - Confidence: Moderate



**Supporting Evidence Exhibits:**

> **Exhibit 4: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** https://claude.ai/chat/def456
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_004.bin](exhibits\exhibit_004.bin)*

> **Exhibit 6: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:50:00 UTC
> - **Indicator:** https://claude.ai/
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_006.bin](exhibits\exhibit_006.bin)*

> **Exhibit 10: Browser Cookies — Claude**
>
> Cookie artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** .claude.ai / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_010.bin](exhibits\exhibit_010.bin)*

> **Exhibit 18: User Content — Claude**
>
> AI Export/Download File artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: claude_response_export.txt (pattern: claude.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_018.txt](exhibits\exhibit_018.txt)*

> **Exhibit 19: User Content — Claude**
>
> Content Indicator artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Claude' in claude_response_export.txt
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_019.txt](exhibits\exhibit_019.txt)*

> **Exhibit 27: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** https://claude.ai/chat/def456
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_027.bin](exhibits\exhibit_027.bin)*

> **Exhibit 29: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:50:00 UTC
> - **Indicator:** https://claude.ai/
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_029.bin](exhibits\exhibit_029.bin)*

> **Exhibit 33: Browser Cookies — Claude**
>
> Cookie artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** .claude.ai / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_033.bin](exhibits\exhibit_033.bin)*

> **Exhibit 41: User Content — Claude**
>
> AI Export/Download File artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: claude_response_export.txt (pattern: claude.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_041.txt](exhibits\exhibit_041.txt)*

> **Exhibit 42: User Content — Claude**
>
> Content Indicator artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Claude' in claude_response_export.txt
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_042.txt](exhibits\exhibit_042.txt)*


**5. Adobe Firefly — Detailed Findings**

Forensic analysis of the submitted evidence identified **1** artifact(s) associated with **Adobe Firefly** (0 direct, 1 inferred). The overall confidence for this finding is **Low**.

- Earliest recorded activity: 2026-04-06 02:22:05 UTC
- Latest recorded activity: 2026-04-06 02:22:05 UTC
- Estimated session count: 1

**Supporting Evidence:**

- **Exhibit 22:** Content Indicator artifact indicating Adobe Firefly access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
  - Confidence: Low
- **Exhibit 45:** Content Indicator artifact indicating Adobe Firefly access
  - Source: `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
  - Confidence: Low

**Caveats:**

- No directly observed evidence; all findings are inferred.



**Supporting Evidence Exhibits:**

> **Exhibit 22: User Content — Adobe Firefly**
>
> Content Indicator artifact indicating Adobe Firefly access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Prompt indicator: 'Generate' in gemini_forensic_notes.md
> - **Confidence:** Low
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_022.md](exhibits\exhibit_022.md)*

> **Exhibit 45: User Content — Adobe Firefly**
>
> Content Indicator artifact indicating Adobe Firefly access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Prompt indicator: 'Generate' in gemini_forensic_notes.md
> - **Confidence:** Low
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_045.md](exhibits\exhibit_045.md)*


**6. Browser vs. Native App Analysis**

- Browser-based artifacts: **12**
- Native app artifacts: **0**
- AI platforms appear to have been accessed exclusively via web browser.

**7. Crime-Scene Image Analysis Indicators**

No direct evidence of crime-scene image upload or analysis was identified.

*Note: Image-analysis activity should only be concluded when supported by uploads, file references, session records, app traces, screenshots, or timestamp correlation.*

**8. Timeline of AI-Related Activity**

| # | Timestamp (UTC) | Platform | Event | Confidence | Exhibit |
|---|-----------------|----------|-------|------------|---------|
| 1 | 2024-01-17 21:20:00 | ChatGPT | [ChatGPT] [Browser] (Browser History) https://chatgpt.com/ | Moderate | Ex. 7 |
| 2 | 2024-01-17 21:50:00 | Claude | [Claude] [Browser] (Browser History) https://claude.ai/ | Moderate | Ex. 6 |
| 3 | 2024-01-17 22:20:00 | ChatGPT | [ChatGPT] [Browser] (Browser History) https://chatgpt.com/c/ | Moderate | Ex. 5 |
| 4 | 2024-01-17 22:20:00 | ChatGPT | [ChatGPT] [Browser] (Browser Cookies) .chatgpt.com / __cf_bm | Low | Ex. 5 |
| 5 | 2024-01-17 22:20:00 | ChatGPT | [ChatGPT] [Browser] (Browser Cookies) .openai.com / _cfuvid | Low | Ex. 5 |
| 6 | 2024-01-17 22:50:00 | Claude | [Claude] [Browser] (Browser History) https://claude.ai/chat/ | Moderate | Ex. 4 |
| 7 | 2024-01-17 22:50:00 | Claude | [Claude] [Browser] (Browser Cookies) .claude.ai / __cf_bm | Low | Ex. 4 |
| 8 | 2024-01-17 23:20:00 | ChatGPT | [ChatGPT] [Browser] (Browser History) https://chat.openai.co | Moderate | Ex. 3 |
| 9 | 2024-01-17 23:50:00 | Gemini | [Gemini] [Browser] (Browser History) https://gemini.google.c | Moderate | Ex. 2 |
| 10 | 2024-01-17 23:50:00 | Gemini | [Gemini] [Browser] (Browser Cookies) .gemini.google.com / NI | Low | Ex. 2 |
| 11 | 2024-01-18 00:20:00 | Gemini | [Gemini] [Browser] (Browser History) https://gemini.google.c | Moderate | Ex. 1 |
| 12 | 2026-04-06 02:22:05 | ChatGPT | [ChatGPT] (User Content) File: ChatGPT_Crime_Scene_Analysis. | Low | Ex. 17 |
| 13 | 2026-04-06 02:22:05 | Claude | [Claude] (User Content) File: claude_response_export.txt (pa | Low | Ex. 18 |
| 14 | 2026-04-06 02:22:05 | Claude | [Claude] (User Content) Response indicator: 'Claude' in clau | Low | Ex. 18 |
| 15 | 2026-04-06 02:22:05 | Gemini | [Gemini] (User Content) File: gemini_forensic_notes.md (patt | Low | Ex. 20 |
| 16 | 2026-04-06 02:22:05 | Gemini | [Gemini] (User Content) Response indicator: 'Gemini' in gemi | Low | Ex. 20 |
| 17 | 2026-04-06 02:22:05 | Adobe Firefly | [Adobe Firefly] (User Content) Prompt indicator: 'Generate'  | Low | Ex. 22 |
| 18 | 2026-04-06 02:22:05 | Gemini | [Gemini] (User Content) Model string: Gemini Pro in gemini_f | Low | Ex. 20 |

**9. Comparative Artifact Matrix**

| Platform | Artifact Type | Access Mode | Evidentiary Value | Confidence | Crime Scene Relevance |
|----------|---------------|-------------|-------------------|------------|----------------------|
| Gemini | URL Visit | Browser | Strong | High | Moderate - platform visit (does not prov |
| Gemini | URL Visit | Browser | Strong | High | Moderate - platform visit (does not prov |
| ChatGPT | URL Visit | Browser | Moderate | Moderate | Moderate - platform visit (does not prov |
| Claude | URL Visit | Browser | Strong | High | Moderate - platform visit (does not prov |
| ChatGPT | URL Visit | Browser | Moderate | Moderate | Moderate - platform visit (does not prov |
| Claude | URL Visit | Browser | Strong | High | Moderate - platform visit (does not prov |
| ChatGPT | URL Visit | Browser | Moderate | Moderate | Moderate - platform visit (does not prov |
| ChatGPT | Cookie | Browser | Moderate | Moderate | Low - session/login indicator only |
| ChatGPT | Cookie | Browser | Moderate | Moderate | Low - session/login indicator only |
| Claude | Cookie | Browser | Moderate | Moderate | Low - session/login indicator only |
| Gemini | Cookie | Browser | Moderate | Moderate | Low - session/login indicator only |
| ChatGPT | Local Storage Key | Browser | Weak | Unsupported | Low - indirect or weak indicator |
| ChatGPT | Prefetch Reference | Unknown | Supportive | Moderate | Moderate - program execution indicator |
| ChatGPT | Prefetch Reference | Unknown | Supportive | Moderate | Moderate - program execution indicator |
| ChatGPT | Prefetch Reference | Unknown | Supportive | Moderate | Moderate - program execution indicator |
| ChatGPT | Prefetch Reference | Unknown | Supportive | Moderate | Moderate - program execution indicator |
| ChatGPT | AI Export/Download File | Unknown | Supportive | Moderate | Moderate - AI-related content in user fi |
| Claude | AI Export/Download File | Unknown | Supportive | Moderate | Moderate - AI-related content in user fi |
| Claude | Content Indicator | Unknown | Supportive | Moderate | High - possible interactive AI use |
| Gemini | AI Export/Download File | Unknown | Supportive | Moderate | Moderate - AI-related content in user fi |
| Gemini | Content Indicator | Unknown | Supportive | Moderate | High - possible interactive AI use |
| Adobe Firefly | Content Indicator | Unknown | Weak | Low | High - possible interactive AI use |
| Gemini | Content Indicator | Unknown | Supportive | High | Moderate - AI-related content in user fi |

**Evidence Coverage Assessment**

- Image Type: Full Disk Image
- Full Disk Available: Yes
- Partitions Accessible: 0 / 0
- Encrypted Areas: Not detected
- File Carving: Disabled
- Browsers Detected: Chrome
- Artifact Families Found: Browser Cookies, Browser History, Browser Local Storage, OS Execution Trace, User Content
- Artifact Families Missing: Browser Cache, Browser Downloads, File System, Native Application, OS Event Log, OS Plist, OS Recent Files, OS Registry, OS Unified Log, Screenshot

- *File carving was disabled. Only structured, recoverable artifacts were analyzed.*

**Stub Parsers (not fully implemented in this version):**
- RecoveredFileClassifier

# Forensically Reconstructed AI-Use Events (FRAUEs)

Each FRAUE represents a time-bounded, platform-attributed episode of probable AI-system interaction, reconstructed from corroborated endpoint artifacts and reported with explicit confidence and uncertainty.

| FRAUE ID | Platform | Activity | Time Window | Event Confidence | Claim Level | Artifacts |
|----------|----------|----------|-------------|-----------------|-------------|-----------|
| FRAUE-FD20A9F1 | Gemini | chat session | 01/17 23:50 — 01/18 00:20 | High | Level 4 — Governed Forensic Conclusion | 3 |
| FRAUE-188D7095 | Gemini | content export | 04/06 02:22 — 04/06 02:22 | Low | Level 2 — Platform Presence | 3 |
| FRAUE-7A55BCC4 | ChatGPT | chat session | 01/17 21:20 — 01/17 23:20 | High | Level 4 — Governed Forensic Conclusion | 10 |
| FRAUE-9F5B857F | ChatGPT | content export | 04/06 02:22 — 04/06 02:22 | Low | Level 2 — Platform Presence | 1 |
| FRAUE-7F0B8A0D | Claude | chat session | 01/17 21:50 — 01/17 22:50 | High | Level 4 — Governed Forensic Conclusion | 3 |
| FRAUE-DBD96C47 | Claude | content export | 04/06 02:22 — 04/06 02:22 | Low | Level 2 — Platform Presence | 2 |
| FRAUE-99F4A3B4 | Adobe Firefly | content export | 04/06 02:22 — 04/06 02:22 | Low | Level 2 — Platform Presence | 1 |

### FRAUE 1: FRAUE-FD20A9F1

- **Platform:** Gemini
- **Activity Class:** chat session
- **Event Confidence:** High
- **Claim Level:** Level 4 — Governed Forensic Conclusion
- **Corroboration Met:** Yes
- **Persistence State:** Intact
- **Artifact Families:** 2
- **Source Diversity:** 1 classes
- **Evidence Confidence Class:** Suspected AI Use
- **Acquisition Sources:** Browser Artifact
- **Platform Surfaces:** Browser Web
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - All evidence originates from a single evidence class (A); higher claim levels require independent evidence classes.
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.

### FRAUE 2: FRAUE-188D7095

- **Platform:** Gemini
- **Activity Class:** content export
- **Event Confidence:** Low
- **Claim Level:** Level 2 — Platform Presence
- **Corroboration Met:** No
- **Persistence State:** Partially Retained
- **Artifact Families:** 1
- **Source Diversity:** 1 classes
- **Evidence Confidence Class:** Suspected AI Use
- **Acquisition Sources:** Mounted Directory
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - All corroborating artifacts belong to a single artifact family; claim level is limited by corroboration diversity (Rule 9).
  - All evidence originates from a single evidence class (A); higher claim levels require independent evidence classes.
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.
- **Alternative Explanations:**
  - Single artifact-family evidence could result from automated browser sync, shared device, or background process.
  - All evidence is inferred; platform interaction could be explained by third-party redirects or advertising beacons.

### FRAUE 3: FRAUE-7A55BCC4

- **Platform:** ChatGPT
- **Activity Class:** chat session
- **Event Confidence:** High
- **Claim Level:** Level 4 — Governed Forensic Conclusion
- **Corroboration Met:** Yes
- **Persistence State:** Intact
- **Artifact Families:** 4
- **Source Diversity:** 2 classes
- **Evidence Confidence Class:** Suspected AI Use
- **Acquisition Sources:** Browser Artifact, Mounted Directory
- **Platform Surfaces:** Browser Web
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - All evidence originates from a single evidence class (A); higher claim levels require independent evidence classes.
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.

### FRAUE 4: FRAUE-9F5B857F

- **Platform:** ChatGPT
- **Activity Class:** content export
- **Event Confidence:** Low
- **Claim Level:** Level 2 — Platform Presence
- **Corroboration Met:** No
- **Persistence State:** Partially Retained
- **Artifact Families:** 1
- **Source Diversity:** 1 classes
- **Evidence Confidence Class:** Insufficient Support
- **Acquisition Sources:** Mounted Directory
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.
- **Alternative Explanations:**
  - Single artifact-family evidence could result from automated browser sync, shared device, or background process.
  - All evidence is inferred; platform interaction could be explained by third-party redirects or advertising beacons.

### FRAUE 5: FRAUE-7F0B8A0D

- **Platform:** Claude
- **Activity Class:** chat session
- **Event Confidence:** High
- **Claim Level:** Level 4 — Governed Forensic Conclusion
- **Corroboration Met:** Yes
- **Persistence State:** Intact
- **Artifact Families:** 2
- **Source Diversity:** 1 classes
- **Evidence Confidence Class:** Suspected AI Use
- **Acquisition Sources:** Browser Artifact
- **Platform Surfaces:** Browser Web
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - All evidence originates from a single evidence class (A); higher claim levels require independent evidence classes.
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.

### FRAUE 6: FRAUE-DBD96C47

- **Platform:** Claude
- **Activity Class:** content export
- **Event Confidence:** Low
- **Claim Level:** Level 2 — Platform Presence
- **Corroboration Met:** No
- **Persistence State:** Partially Retained
- **Artifact Families:** 1
- **Source Diversity:** 1 classes
- **Evidence Confidence Class:** Suspected AI Use
- **Acquisition Sources:** Mounted Directory
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - All corroborating artifacts belong to a single artifact family; claim level is limited by corroboration diversity (Rule 9).
  - All evidence originates from a single evidence class (A); higher claim levels require independent evidence classes.
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.
- **Alternative Explanations:**
  - Single artifact-family evidence could result from automated browser sync, shared device, or background process.
  - All evidence is inferred; platform interaction could be explained by third-party redirects or advertising beacons.

### FRAUE 7: FRAUE-99F4A3B4

- **Platform:** Adobe Firefly
- **Activity Class:** content export
- **Event Confidence:** Low
- **Claim Level:** Level 2 — Platform Presence
- **Corroboration Met:** No
- **Persistence State:** Partially Retained
- **Artifact Families:** 1
- **Source Diversity:** 1 classes
- **Evidence Confidence Class:** Insufficient Support
- **Acquisition Sources:** Mounted Directory
- **Caveats:**
  - Reported time window is approximate and derived from artifact timestamps, not from direct session-start/session-end records.
  - Any narrative text in this report is explanatory only; evidentiary facts are the artifacts, exhibits, and scoring decisions (Rule 10).
  - Evidence is limited to presence/installation/configuration; no usage, output, or attribution evidence was identified.
- **Alternative Explanations:**
  - Single artifact-family evidence could result from automated browser sync, shared device, or background process.
  - All evidence is inferred; platform interaction could be explained by third-party redirects or advertising beacons.

# Evidence Confidence Class Summary

- **Insufficient Support:** 2 FRAUE(s)
- **Suspected AI Use:** 5 FRAUE(s)

# Functional Requirements Assessment (FR-1 – FR-9)

The following assessment evaluates this analysis against 9 functional requirements derived from current AI-forensics research gaps (Magnet AXIOM, NIST Generative AI Profile, C2PA, academic literature).

> **Research synthesis:** The state of the art has progressed from 'no AI artifact support' to 'partial, app-specific artifact recovery,' but it still lacks an end-to-end AI-forensics evidence model that consistently unifies acquisition, session reconstruction, provenance, detector validation, third-party dependency tracing, and standardized evidentiary export.

## Assessment Summary

| FR | Requirement | Status |
|:---:|:---|:---|
| FR-1 | Unified AI Evidence Acquisition | ⚠️ Partially Addressed |
| FR-2 | Full Session Reconstruction | ⚠️ Partially Addressed |
| FR-3 | Model, Version, and Configuration Provenance | ⚠️ Partially Addressed |
| FR-4 | Provenance and Authenticity Verification | ⚠️ Partially Addressed |
| FR-5 | Detector Validation with Evidentiary Metrics | ⚠️ Partially Addressed |
| FR-6 | Resilience to Tamper and Anti-Forensics | ✅ Fully Addressed |
| FR-7 | Third-Party Tool-Chain and Plugin Visibility | ⚠️ Partially Addressed |
| FR-8 | Standardized Evidentiary Export | ✅ Fully Addressed |
| FR-9 | Extensible Parser Architecture | ✅ Fully Addressed |

## FR-1: Unified AI Evidence Acquisition

**Status:** Partially Addressed

*A mature AI-forensics platform should acquire evidence from desktop apps, browser sessions, mobile apps, cloud exports, memory, logs, and network captures under one case model. Recent research on ChatGPT, Copilot, and Gemini found that conversation recovery was platform-dependent. The real gap is lack of a normalized cross-provider acquisition workflow.*

**Capability:** Evidence was acquired and parsed, but from a limited subset of available sources.

**Evidence from analysis:**
- Evidence acquired from: C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence
- Evidence type: Full Disk Image
- User profiles identified: JohnDoe
- 20 parsers executed across browser, OS, and content sources
- Artifact families span: BROWSER COOKIES, BROWSER HISTORY, BROWSER LOCAL STORAGE, OS EXECUTION TRACE, USER CONTENT
- Memory dump scanner: executed (no memory dumps found in evidence)
- PCAP scanner: executed (no network captures found in evidence)

**Identified gaps:**
- ⚠ Cloud export API integration (provider-side logs) not available
- ⚠ No memory dumps present in evidence for RAM analysis
- ⚠ No PCAP files present in evidence for network analysis

## FR-2: Full Session Reconstruction

**Status:** Partially Addressed

*The tool should reconstruct the full AI interaction lifecycle: account/user context, device context, timestamps, prompts, responses, edits, deletions, attachments, exports, and surrounding system traces. The missing capability is forensic replay of the full session chain, not just extraction of message text.*

**Capability:** TRACE-AI-FR reconstructs AI interaction sessions via FRAUEs with temporal windows, correlated timelines, and prompt/response remnant detection. Full conversational replay (turn-by-turn prompts and responses) depends on platform-specific artifact availability. ChatGPT export parsing is supported when export data is present.

**Evidence from analysis:**
- 7 FRAUE(s) reconstructed as atomic events
-   FRAUE: Gemini — chat session
-   FRAUE: Gemini — content export
-   FRAUE: ChatGPT — chat session
- 18 timeline events reconstructed with timestamps
- Response remnants found for Gemini
- Response remnants found for Claude
- Prompt remnants found for Adobe Firefly

**Identified gaps:**
- ⚠ No ChatGPT conversation export found for full turn-by-turn replay
- ⚠ Edit and deletion tracking requires platform-specific database access
- ⚠ Attachment/file-upload tracing limited to download records and content remnants

## FR-3: Model, Version, and Configuration Provenance

**Status:** Partially Addressed

*An examiner should be able to say which model or service produced an output, when, under what version or change state, and with what relevant configuration context. NIST's Generative AI Profile stresses logging, metadata, and version history for incident response and governance.*

**Capability:** TRACE-AI-FR identifies AI models when model-specific strings appear in browser artifacts (URLs, cookies, API responses). Version history, configuration state, and change-management records are not available from client-side endpoint evidence alone.

**Evidence from analysis:**
- Platform detected (Gemini) but specific model not determined
- Model identified for ChatGPT: Unknown
- Platform detected (Claude) but specific model not determined
- Platform detected (Adobe Firefly) but specific model not determined
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Unknown
- Artifact-level model indicator: Gemini Pro

**Identified gaps:**
- ⚠ Server-side version/configuration records not accessible from endpoint evidence
- ⚠ NIST-recommended logging and change-management metadata requires provider cooperation
- ⚠ Model version drift (e.g., GPT-4 updates) not trackable from client artifacts

## FR-4: Provenance and Authenticity Verification

**Status:** Partially Addressed

*AI-forensics tooling should verify origin, modifications, cryptographic bindings, signatures, hashes, and AI-use assertions where they exist. C2PA's Content Credentials model defines manifests containing assertions about origin, modification history, and AI use, bound into a verifiable unit. What is commonly missing is native forensic integration of provenance verification across evidence types.*

**Capability:** TRACE-AI-FR provides hash-based integrity verification for evidence files and exhibits, and governance-tracked chain of custody. C2PA Content Credentials parsing is supported but no manifests were found in the analyzed evidence.

**Evidence from analysis:**
- Evidence image hash computed for chain-of-custody integrity
- All exhibits include MD5 hashes for file-level verification
- Governance record documents all inference rules and disclosures
- C2PA manifest parser: executed (no C2PA manifests found in evidence)

**Identified gaps:**
- ⚠ No C2PA Content Credentials manifests found in evidence
- ⚠ External provenance verification service integration not available

## FR-5: Detector Validation with Evidentiary Metrics

**Status:** Partially Addressed

*If a tool labels content as 'AI-generated,' it should report error rates, confidence, thresholds, and limitations. NIST's synthetic-content guidance makes clear that watermarking and verification methods must be evaluated with false positives and false negatives. The requirement is forensic-grade detector validation suitable for evidentiary interpretation.*

**Capability:** TRACE-AI-FR reports multi-layer confidence scores with explicit thresholds and classification (Direct vs. Inferred evidence). It does not perform AI-content detection (i.e., 'was this text written by AI?'). False-positive/negative rate reporting for detection classifiers is not in scope — the framework detects AI platform *use*, not AI-generated *content*.

**Evidence from analysis:**
- 7-layer confidence scoring model with per-artifact and per-FRAUE ratings
- Confidence levels reported: HIGH, MODERATE, LOW, UNSUPPORTED/INSUFFICIENT
- FRAUE confidence distribution: 3 HIGH of 7 total

**Identified gaps:**
- ⚠ AI-content detection (GPTZero, Turnitin-style) not integrated
- ⚠ Watermark detection for AI-generated images/text not implemented
- ⚠ No false-positive/false-negative rate reporting for content classifiers

## FR-6: Resilience to Tamper and Anti-Forensics

**Status:** Fully Addressed

*A useful AI-forensics tool should account for metadata stripping, provenance removal, paraphrasing, recompression, and other attempts to weaken attribution. NIST emphasizes that risk reduction relies on multiple technical approaches rather than a single perfect signal. The gap is a shortage of multi-signal correlation frameworks.*

**Capability:** TRACE-AI-FR uses multi-artifact-family correlation, evidence-source-class tagging, and active anti-forensics detection to resist tampering. The AntiForensicsDetector identifies cleanup tool execution (CCleaner, BleachBit, etc.), browser history gaps, timestamp anomalies, and metadata stripping. Governance Rule 6 requires cross-source corroboration, and Rule 7 notes that cleanup affects persistence, not motive.

**Evidence from analysis:**
- Cross-artifact corroboration across 5 artifact families
- Evidence-source-class tagging enables multi-signal reasoning
- Governance Rule 6 enforces cross-source corroboration for multi-source claims
- 12 known blind spots disclosed
- Anti-forensics detector: executed (no tampering indicators found)

**Identified gaps:**
- ⚠ Paraphrase and recompression detection requires content-level analysis

## FR-7: Third-Party Tool-Chain and Plugin Visibility

**Status:** Partially Addressed

*The tool should capture whether the output was shaped by plugins, retrieval sources, external tools, or third-party inputs. NIST highlights documentation and review of third-party inputs as especially important in generative AI incident handling. Public AI-forensics coverage still centers mostly on the chat artifact itself.*

**Capability:** TRACE-AI-FR includes active scanners for browser extensions, tool-chain automation, ChatGPT plugins, and RAG infrastructure. No third-party tool-chain artifacts were found in the analyzed evidence, but detection capability is implemented.

**Evidence from analysis:**
- Browser extension scanner: executed (no AI extensions found)
- Tool-chain scanner: executed (no tool-chain traces found)
- Browser extension artifacts parsed from Chromium and Firefox profiles
- Content parser scans for AI export files and naming patterns
- Tool-chain detection covers: AutoGPT, LangChain, LlamaIndex, Zapier, IFTTT
- RAG infrastructure scanning: Pinecone, Weaviate, ChromaDB, Qdrant, Milvus

**Identified gaps:**
- ⚠ Network-level API call tracing requires PCAP integration with deep packet inspection

## FR-8: Standardized Evidentiary Export

**Status:** Fully Addressed

*AI evidence should be exportable with chain-of-custody fields, hashes, timestamps, provenance findings, model/version metadata, and incident context in a normalized structure. NIST states that formal channels to report and document AI incidents are not yet standardized. One of the biggest missing pieces is a common AI evidence schema.*

**Capability:** TRACE-AI-FR exports evidence in 5 formats (JSON, SQLite, Markdown, HTML, Governance JSON) with structured case metadata, chain-of-custody hashes, FRAUE-level findings, temporal data, confidence scores, governance records, and inference boundaries. This provides a normalized AI evidence schema suitable for cross-tool interoperability.

**Evidence from analysis:**
- JSON export with full case metadata, artifacts, FRAUEs, governance
- SQLite normalized database with 7+ relational tables
- Markdown report following SANS/UNCC forensic report standard
- HTML interactive report with FRAUE cards and governance panel
- Governance JSON with 12-rule compliance matrix
- All exports include chain-of-custody fields and hashes
- Governance record includes disclosures and inference boundaries

**Identified gaps:**
- ⚠ No CASE/UCO (Cyber-investigation Analysis Standard Expression) mapping yet
- ⚠ STIX/TAXII incident sharing format not directly supported

## FR-9: Extensible Parser Architecture

**Status:** Fully Addressed

*Because AI products and storage patterns change quickly, the platform needs rapidly updateable parsers and a stable internal evidence model. Magnet's public documentation says its ChatGPT artifact support was recently introduced and will continue to expand, evidencing that coverage is still incremental rather than complete.*

**Capability:** TRACE-AI-FR implements a plugin-style parser registry with BaseParser abstract class, OS-aware auto-discovery, and graceful fallbacks (E01 binary scanner when pyewf/pytsk3 are unavailable, binary scan when python-registry is missing). New parsers can be added by subclassing BaseParser and registering with the parser registry.

**Evidence from analysis:**
- 20 parser results from auto-discovery registry
- BaseParser abstract class with OS-aware registration
- Parsers for: Chrome, Edge, Firefox, Brave, Safari, Prefetch, AmCache, Registry, Plist, Quarantine, iPhone logical, AI content scanning
- E01 binary scanner fallback when libraries unavailable
- 5/20 parsers succeeded

**Identified gaps:**
- ⚠ No hot-reload or runtime parser update mechanism
- ⚠ Parser coverage is incremental — new AI apps require new parsers

## Key Caveats

- Scope boundary: This assessment is about forensic investigation of AI-system use and AI-generated or AI-edited content as evidence. It does not evaluate separate claims about using AI to help investigators analyze other evidence.
- Capability boundary: 'Missing' does not mean 'universally absent.' It means the capability is not broadly standardized, not consistently documented in public sources, or not shown end-to-end.
- Provenance boundary: C2PA-style provenance can verify that a credentialed manifest is intact and bound to an asset, but it does not by itself prove that every semantic claim in the content is true.
- Detection boundary: Absence of a watermark, provenance record, or detector hit is not conclusive evidence of human authorship, because NIST treats these methods as imperfect and requiring measured interpretation.
- Admissibility boundary: Forensic recoverability is not the same as courtroom admissibility. Legal admissibility also depends on jurisdiction, validation, chain of custody, and expert testimony.

# Appendix: AI Tool Inventory Checklist (v5.0)

> **IMPORTANT CAVEAT:** The presence of an AI tool installation, configuration file, or browser access record does NOT establish that the tool was actively used for any specific task. Presence of artifacts is NOT equivalent to use. Attribution of tool use to a specific individual requires corroborating evidence beyond installation artifacts. Negative findings are scoped to the evidence examined and do not exclude tool use via other devices, cloud accounts, or portable installations not present in the evidence.

**10 of 37 registered AI tools detected in evidence.**

## Summary Table

| Tool Name | Category | Evidence Status | Confidence | Execution Surface | Artifact Count | Key Caveats |
|:----------|:---------|:----------------|:-----------|:-----------------|:--------------|:------------|
| ChatGPT Desktop | Native Assistant | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Ollama | Local LLM | ❌ NOT_FOUND | N/A | TERMINAL, DESKTOP_APP | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Cursor | AI IDE | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Claude Desktop | Native Assistant | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Poe Desktop | Native Assistant | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| LM Studio | Local LLM | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| GPT4All | Local LLM | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Jan | Local LLM | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| AnythingLLM | Local LLM | ❌ NOT_FOUND | N/A | DESKTOP_APP, DOCKER_CONTAINER, SELF_HOSTED_REMOTE | 0 | LOCAL_WEBUI_LOCALHOST_ONLY, LOCAL_WEBUI_CONTAINER_POSSIBLE, PORTABLE_INSTALL_POSSIBLE |
| Msty | Local LLM | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | REMOTE_INFERENCE_POSSIBLE, NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE |
| Open WebUI | Local LLM | ❌ NOT_FOUND | N/A | SELF_HOSTED_REMOTE, DOCKER_CONTAINER | 0 | LOCAL_WEBUI_LOCALHOST_ONLY, LOCAL_WEBUI_CONTAINER_POSSIBLE, PORTABLE_INSTALL_POSSIBLE |
| Windsurf (Codeium) | AI IDE | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | NEGATIVE_FINDING_SCOPED, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| GitHub Copilot | IDE Extension | ❌ NOT_FOUND | N/A | IDE_EXTENSION | 0 | IDE_CONFIG_NOT_USAGE, CREDENTIAL_FILE_ONLY, ATTRIBUTION_NOT_ESTABLISHED |
| Claude Code | Terminal CLI | ❌ NOT_FOUND | N/A | TERMINAL | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| OpenAI Codex CLI | Terminal CLI | ❌ NOT_FOUND | N/A | TERMINAL | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Tabnine | IDE Extension | ❌ NOT_FOUND | N/A | IDE_EXTENSION | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Continue | IDE Extension | ❌ NOT_FOUND | N/A | IDE_EXTENSION | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Cline (Claude Dev) | IDE Extension | ❌ NOT_FOUND | N/A | IDE_EXTENSION | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Aider | Terminal CLI | ❌ NOT_FOUND | N/A | TERMINAL | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| ComfyUI Desktop | Image Generator | ❌ NOT_FOUND | N/A | DESKTOP_APP | 0 | LOCAL_WEBUI_LOCALHOST_ONLY, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| AUTOMATIC1111 Stable Diffusion WebUI | Image Generator | ❌ NOT_FOUND | N/A | SELF_HOSTED_REMOTE | 0 | LOCAL_WEBUI_LOCALHOST_ONLY, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| InvokeAI | Image Generator | ❌ NOT_FOUND | N/A | DESKTOP_APP, SELF_HOSTED_REMOTE | 0 | LOCAL_WEBUI_LOCALHOST_ONLY, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Google Gemini (Web/App) | Web Assistant | ✅ FOUND | MEDIUM | BROWSER | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Google NotebookLM | Web Assistant | ✅ FOUND | HIGH | BROWSER | 2 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Grok (X/Twitter) | Web Assistant | ✅ FOUND | HIGH | BROWSER | 2 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Perplexity AI | Web Assistant | ✅ FOUND | MEDIUM | BROWSER, DESKTOP_APP | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Microsoft Copilot | Native Assistant | ❌ NOT_FOUND | N/A | BROWSER, DESKTOP_APP | 0 | BROWSER_ACCESS_ONLY, MULTI_SURFACE_PRODUCT, NEGATIVE_FINDING_SCOPED |
| Meta AI | Web Assistant | ✅ FOUND | MEDIUM | BROWSER | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Microsoft Copilot Studio | Enterprise AI | ❌ NOT_FOUND | N/A | BROWSER | 0 | BROWSER_ACCESS_ONLY, BROWSER_HISTORY_CLEARED, PRIVACY_OR_CLEANUP_POSSIBLE |
| Character.AI | Web Assistant | ✅ FOUND | MEDIUM | BROWSER | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| HuggingChat | Web Assistant | ✅ FOUND | MEDIUM | BROWSER | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Le Chat (Mistral) | Web Assistant | ✅ FOUND | MEDIUM | BROWSER | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| DeepSeek | Web Assistant | ✅ FOUND | MEDIUM | BROWSER, DESKTOP_APP | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| Replit AI (Ghostwriter) | Web Assistant | ✅ FOUND | MEDIUM | BROWSER | 1 | BROWSER_ACCESS_ONLY, USE_NOT_ESTABLISHED, REMOTE_INFERENCE_POSSIBLE |
| GitHub Copilot Chat (VSCode) | IDE Extension | ❌ NOT_FOUND | N/A | IDE_EXTENSION | 0 | IDE_CONFIG_NOT_USAGE, PORTABLE_INSTALL_POSSIBLE, CUSTOM_PATH_POSSIBLE |
| Fabric | Terminal CLI | ❌ NOT_FOUND | N/A | TERMINAL | 0 | IDE_CONFIG_NOT_USAGE, CREDENTIAL_FILE_ONLY, ATTRIBUTION_NOT_ESTABLISHED |
| OpenAI API (Generic) | API Credential | ❌ NOT_FOUND | N/A | TERMINAL, IDE_EXTENSION | 0 | IDE_CONFIG_NOT_USAGE, CREDENTIAL_FILE_ONLY, ATTRIBUTION_NOT_ESTABLISHED |

## Detected Tools — Detail

### Google Gemini (Web/App)

**Category:** Web Assistant
**Detection Method:** Browser history, localStorage, cookies for gemini.google.com
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### Google NotebookLM

**Category:** Web Assistant
**Detection Method:** Browser history, localStorage for notebooklm.google.com
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_2_CONFIGURATION_OR_WORKSPACE_INDICATORS
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\History`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
**Notes:** 2 artifact path(s) matched.

### Grok (X/Twitter)

**Category:** Web Assistant
**Detection Method:** Browser history, localStorage for grok.com or x.com/i/grok
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_2_CONFIGURATION_OR_WORKSPACE_INDICATORS
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\History`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
**Notes:** 2 artifact path(s) matched.

### Perplexity AI

**Category:** Web Assistant
**Detection Method:** Browser history, desktop app install, localStorage
**Execution Surface:** BROWSER, DESKTOP_APP
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** USER_PROFILE_LINKED
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- MULTI_SURFACE_PRODUCT
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Product may appear on multiple surfaces; context preserved.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### Meta AI

**Category:** Web Assistant
**Detection Method:** Browser history for meta.ai, WhatsApp/Facebook AI integration artifacts
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### Character.AI

**Category:** Web Assistant
**Detection Method:** Browser history for character.ai, localStorage
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### HuggingChat

**Category:** Web Assistant
**Detection Method:** Browser history for huggingface.co/chat
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### Le Chat (Mistral)

**Category:** Web Assistant
**Detection Method:** Browser history for chat.mistral.ai
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### DeepSeek

**Category:** Web Assistant
**Detection Method:** Browser history for chat.deepseek.com, desktop app install
**Execution Surface:** BROWSER, DESKTOP_APP
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** USER_PROFILE_LINKED
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- MULTI_SURFACE_PRODUCT
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Product may appear on multiple surfaces; context preserved.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

### Replit AI (Ghostwriter)

**Category:** Web Assistant
**Detection Method:** Browser history for replit.com, Replit Desktop app install
**Execution Surface:** BROWSER
**Inference Location:** REMOTE
**Corroboration Level:** LEVEL_1_PRESENCE_OR_ACCESS_ONLY
**Attribution Scope:** DEVICE_LEVEL_ONLY
**Matched Artifact Path(s):**
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb`
**Caveats:**
- BROWSER_ACCESS_ONLY
- USE_NOT_ESTABLISHED
- REMOTE_INFERENCE_POSSIBLE
- PRESENCE_ONLY
- CORROBORATION_LEVEL_LIMITED

**Caveat Enforcement Notes:**
> ⚠ Browser artifacts indicate access, not substantive use.
> ⚠ Use not established from available artifacts.
> ⚠ Remote inference possible; local execution not confirmed.
> ⚠ Artifacts consistent with presence or installation; does not establish use.
> ⚠ Corroboration is limited to a single artifact family or evidence class; higher claim levels require additional independent sources.
**Notes:** 1 artifact path(s) matched.

---

> The presence of AI-related artifacts indicates possible access, installation, configuration, or environmental capability. Such artifacts do not independently establish actual use, authorship, intent, cognitive reliance, or person-level attribution. Conclusions should be interpreted in light of acquisition scope, corroboration level, parser coverage, and any documented limitations.

# Inference Boundaries and Operational Controls

The following boundaries constrain all conclusions in this report:

- This examination looks for traces of AI service usage left on the device. It cannot determine why a person used the service, what they intended, or whether they relied on the AI output.
- The dates and times reported are approximate. They are based on records found on the device, not on live monitoring of the user's activity.
- This examination can identify which AI service (e.g., ChatGPT, Claude) was used, but identifying the specific AI model version requires additional data such as an exported conversation log.
- Not finding evidence of AI use does not mean AI was never used. Evidence may have been deleted or may not have been preserved.
- If the user deleted browsing data, cleared cookies, or logged out, this is reported as a fact. It does not imply the user was trying to hide anything.
- The inability to recover certain files should not be interpreted as proof that AI services were never used. Technical limitations or damage to the device's storage may prevent recovery.
- Recovered or partially damaged files are noted as such and are given lower confidence ratings than complete, undamaged files.

## Scope of Conclusion

Based on the forensic examination of the submitted evidence, the examiner identified 7 instance(s) of AI service usage involving Adobe Firefly, ChatGPT, Claude, Gemini. These findings are based on digital evidence recovered from the device and are subject to the limitations described in this report. This report presents factual findings from the forensic examination; the Court will determine the admissibility and weight of the evidence under applicable rules.

## Governance Record Summary

- **Framework:** TRACE-AI-FR v4.0.0
- **Validation State:** Partially Validated
- **Collection Scope:** Evidence source: C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence; Image type: Full Disk Image; Detected OS: Windows; User profiles: JohnDoe; Browsers detected: Chrome; Full disk available: Yes; File carving: Disabled
- **Known Blind Spots:**
  - File carving was disabled; deleted but not overwritten artifacts were not recovered.
  - Artifact family 'Browser Cache' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'Browser Downloads' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'File System' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'Native Application' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'OS Event Log' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'OS Plist' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'OS Recent Files' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'OS Registry' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'OS Unified Log' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Artifact family 'Screenshot' was not found in the evidence; conclusions about platform use from that family are not possible.
  - Parser 'RecoveredFileClassifier' is a stub and did not produce findings; artifacts that parser targets may be present but unexamined.
- **Required Disclosures (Rule 11):**
  - This report presents the results of a forensic examination. The admissibility of this evidence is subject to the Court's determination under applicable rules of evidence.
  - Explanatory text in this report is intended to help the reader understand the findings. The actual evidence consists of the digital artifacts recovered from the device.
  - The analysis tools used in this examination are subject to ongoing quality checks. The current validation status is documented in the technical appendix.
- **Acquisition Blind Spots:**
  - No data exported directly from the AI service provider was available for this examination. Such exports (for example, a downloaded copy of ChatGPT conversation history) would provide the strongest possible evidence and were not included.
  - No audio recordings or voice transcripts were available. If the user interacted with AI services using voice (such as speaking to ChatGPT), those interactions are not represented here.
- **Platform Surface Coverage:**
  - The following areas of the device were examined: Browser Web, Unknown. Other areas of the device that were not examined may contain additional evidence.
- **Direct Evidence:**
  - 0 item(s) of evidence directly show that an AI service was accessed from this device.
- **Corroborating Evidence:**
  - 23 additional item(s) of evidence provide supporting information that strengthens the findings.
- **Missing / Expected Evidence:**
  - The following types of evidence were expected but not found: Browser Cache, Browser Downloads, File System, Native Application, OS Event Log, OS Plist, OS Recent Files, OS Registry, OS Unified Log, Screenshot. This limits the conclusions that can be drawn about certain types of AI service usage.
- **Alternative Explanations:**
  - Records showing visits to AI websites could have been created automatically by browser syncing between devices, by another person using a shared computer, or by a website loading AI content in the background without the user's knowledge.
  - The presence of AI service cookies on the device does not necessarily mean the user intentionally visited the AI service. Cookies can be set by advertisements, website redirects, or embedded content from third-party websites.

# Conclusion

The forensic analysis strongly supported that **Gemini** was accessed from this endpoint. 6 artifact(s) were identified, of which 3 constitute direct evidence.

The forensic analysis supported at moderate confidence that **ChatGPT** was accessed from this endpoint. 11 artifact(s) were identified, of which 5 constitute direct evidence.

The forensic analysis strongly supported that **Claude** was accessed from this endpoint. 5 artifact(s) were identified, of which 3 constitute direct evidence.

The forensic analysis indicated at low confidence that **Adobe Firefly** was accessed from this endpoint. 1 artifact(s) were identified, of which 0 constitute direct evidence.

**Evidentiary Caveats:**

- A domain visit alone is not enough to conclude substantive AI use.
- A cached object alone is not enough to conclude prompt submission.
- A login trace alone is not enough to conclude active investigative use.
- An export file alone is not enough to prove which model generated it unless corroborated.
- Platform attribution, model attribution, and content attribution are separate analytical layers.
- Absence of evidence must not be reported as evidence of absence.

File carving was disabled. Artifacts in unallocated space were not examined. Additional analysis may yield further findings.

The forensic evidence and reports are being provided to the requesting party. No further analysis as of this report.


---

> **Evidentiary Notice:** The presence of AI-related artifacts indicates possible access, installation, configuration, or environmental capability. Such artifacts do not independently establish actual use, authorship, intent, cognitive reliance, or person-level attribution. Conclusions should be interpreted in light of acquisition scope, corroboration level, parser coverage, and any documented limitations.

---

> **Recommended Notice:** Portions of this report were prepared with AI assistance. Review and validation by a qualified human investigator are strongly recommended before submission for any legal, forensic, or official purpose.

# Appendix: Evidence Exhibits

*Total exhibits: 46*

| Exhibit # | Platform | Artifact Type | E01 Source Path | Confidence | Timestamp |
|-----------|----------|---------------|-----------------|------------|-----------|
| 1 | Gemini | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-18 00:20:00 UTC |
| 2 | Gemini | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-17 23:50:00 UTC |
| 3 | ChatGPT | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | Moderate | 2024-01-17 23:20:00 UTC |
| 4 | Claude | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-17 22:50:00 UTC |
| 5 | ChatGPT | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | Moderate | 2024-01-17 22:20:00 UTC |
| 6 | Claude | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-17 21:50:00 UTC |
| 7 | ChatGPT | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | Moderate | 2024-01-17 21:20:00 UTC |
| 8 | ChatGPT | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 22:20:00 UTC |
| 9 | ChatGPT | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 22:20:00 UTC |
| 10 | Claude | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 22:50:00 UTC |
| 11 | Gemini | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 23:50:00 UTC |
| 12 | ChatGPT | Browser Local Storage | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log` | Unsupported | N/A |
| 13 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 14 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 15 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 16 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 17 | ChatGPT | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\ChatGPT_Crime_Scene_Analysis.pdf` | Moderate | 2026-04-06 02:22:05 UTC |
| 18 | Claude | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt` | Moderate | 2026-04-06 02:22:05 UTC |
| 19 | Claude | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt` | Moderate | 2026-04-06 02:22:05 UTC |
| 20 | Gemini | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | Moderate | 2026-04-06 02:22:05 UTC |
| 21 | Gemini | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | Moderate | 2026-04-06 02:22:05 UTC |
| 22 | Adobe Firefly | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | Low | 2026-04-06 02:22:05 UTC |
| 23 | Gemini | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | High | 2026-04-06 02:22:05 UTC |
| 24 | Gemini | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-18 00:20:00 UTC |
| 25 | Gemini | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-17 23:50:00 UTC |
| 26 | ChatGPT | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | Moderate | 2024-01-17 23:20:00 UTC |
| 27 | Claude | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-17 22:50:00 UTC |
| 28 | ChatGPT | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | Moderate | 2024-01-17 22:20:00 UTC |
| 29 | Claude | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | High | 2024-01-17 21:50:00 UTC |
| 30 | ChatGPT | Browser History | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History` | Moderate | 2024-01-17 21:20:00 UTC |
| 31 | ChatGPT | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 22:20:00 UTC |
| 32 | ChatGPT | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 22:20:00 UTC |
| 33 | Claude | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 22:50:00 UTC |
| 34 | Gemini | Browser Cookies | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies` | Moderate | 2024-01-17 23:50:00 UTC |
| 35 | ChatGPT | Browser Local Storage | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log` | Unsupported | N/A |
| 36 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 37 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 38 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 39 | ChatGPT | OS Execution Trace | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf` | Moderate | N/A |
| 40 | ChatGPT | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\ChatGPT_Crime_Scene_Analysis.pdf` | Moderate | 2026-04-06 02:22:05 UTC |
| 41 | Claude | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt` | Moderate | 2026-04-06 02:22:05 UTC |
| 42 | Claude | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt` | Moderate | 2026-04-06 02:22:05 UTC |
| 43 | Gemini | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | Moderate | 2026-04-06 02:22:05 UTC |
| 44 | Gemini | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | Moderate | 2026-04-06 02:22:05 UTC |
| 45 | Adobe Firefly | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | Low | 2026-04-06 02:22:05 UTC |
| 46 | Gemini | User Content | `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md` | High | 2026-04-06 02:22:05 UTC |

> **Exhibit 1: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-18 00:20:00 UTC
> - **Indicator:** https://gemini.google.com/app/xyz789
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_001.bin](exhibits\exhibit_001.bin)*

> **Exhibit 2: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** https://gemini.google.com/app
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_002.bin](exhibits\exhibit_002.bin)*

> **Exhibit 3: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:20:00 UTC
> - **Indicator:** https://chat.openai.com/chat
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_003.bin](exhibits\exhibit_003.bin)*

> **Exhibit 4: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** https://claude.ai/chat/def456
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_004.bin](exhibits\exhibit_004.bin)*

> **Exhibit 5: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** https://chatgpt.com/c/abc123
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_005.bin](exhibits\exhibit_005.bin)*

> **Exhibit 6: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:50:00 UTC
> - **Indicator:** https://claude.ai/
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_006.bin](exhibits\exhibit_006.bin)*

> **Exhibit 7: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:20:00 UTC
> - **Indicator:** https://chatgpt.com/
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_007.bin](exhibits\exhibit_007.bin)*

> **Exhibit 8: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .chatgpt.com / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_008.bin](exhibits\exhibit_008.bin)*

> **Exhibit 9: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .openai.com / _cfuvid
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_009.bin](exhibits\exhibit_009.bin)*

> **Exhibit 10: Browser Cookies — Claude**
>
> Cookie artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** .claude.ai / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_010.bin](exhibits\exhibit_010.bin)*

> **Exhibit 11: Browser Cookies — Gemini**
>
> Cookie artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** .gemini.google.com / NID
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_011.bin](exhibits\exhibit_011.bin)*

> **Exhibit 12: Browser Local Storage — ChatGPT**
>
> Local Storage Key artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log`
> - **Indicator:** Key match: 'chatgpt' in chatgpt_trace.log
> - **Confidence:** Unsupported
> - **Artifact Hash (MD5):** `e6a07a97668a54927b2249c03ebf49f5`
>
> *See attached: [exhibits\exhibit_012.log](exhibits\exhibit_012.log)*

> **Exhibit 13: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt.com in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_013.pf](exhibits\exhibit_013.pf)*

> **Exhibit 14: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_014.pf](exhibits\exhibit_014.pf)*

> **Exhibit 15: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_015.pf](exhibits\exhibit_015.pf)*

> **Exhibit 16: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_016.pf](exhibits\exhibit_016.pf)*

> **Exhibit 17: User Content — ChatGPT**
>
> AI Export/Download File artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\ChatGPT_Crime_Scene_Analysis.pdf`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: ChatGPT_Crime_Scene_Analysis.pdf (pattern: chat[-_]?gpt.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4e96f9e5729a4a216cbf044d44ed7b7b`
>
> *See attached: [exhibits\exhibit_017.pdf](exhibits\exhibit_017.pdf)*

> **Exhibit 18: User Content — Claude**
>
> AI Export/Download File artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: claude_response_export.txt (pattern: claude.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_018.txt](exhibits\exhibit_018.txt)*

> **Exhibit 19: User Content — Claude**
>
> Content Indicator artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Claude' in claude_response_export.txt
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_019.txt](exhibits\exhibit_019.txt)*

> **Exhibit 20: User Content — Gemini**
>
> AI Export/Download File artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: gemini_forensic_notes.md (pattern: gemini.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_020.md](exhibits\exhibit_020.md)*

> **Exhibit 21: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Gemini' in gemini_forensic_notes.md
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_021.md](exhibits\exhibit_021.md)*

> **Exhibit 22: User Content — Adobe Firefly**
>
> Content Indicator artifact indicating Adobe Firefly access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Prompt indicator: 'Generate' in gemini_forensic_notes.md
> - **Confidence:** Low
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_022.md](exhibits\exhibit_022.md)*

> **Exhibit 23: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Model string: Gemini Pro in gemini_forensic_notes.md
> - **Confidence:** High
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_023.md](exhibits\exhibit_023.md)*

> **Exhibit 24: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-18 00:20:00 UTC
> - **Indicator:** https://gemini.google.com/app/xyz789
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_024.bin](exhibits\exhibit_024.bin)*

> **Exhibit 25: Browser History — Gemini**
>
> URL Visit artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** https://gemini.google.com/app
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_025.bin](exhibits\exhibit_025.bin)*

> **Exhibit 26: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 23:20:00 UTC
> - **Indicator:** https://chat.openai.com/chat
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_026.bin](exhibits\exhibit_026.bin)*

> **Exhibit 27: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** https://claude.ai/chat/def456
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_027.bin](exhibits\exhibit_027.bin)*

> **Exhibit 28: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** https://chatgpt.com/c/abc123
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_028.bin](exhibits\exhibit_028.bin)*

> **Exhibit 29: Browser History — Claude**
>
> URL Visit artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:50:00 UTC
> - **Indicator:** https://claude.ai/
> - **Confidence:** High
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_029.bin](exhibits\exhibit_029.bin)*

> **Exhibit 30: Browser History — ChatGPT**
>
> URL Visit artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\History`
> - **Timestamp:** 2024-01-17 21:20:00 UTC
> - **Indicator:** https://chatgpt.com/
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `042d3513943fa64e82d6caba341b3897`
>
> *See attached: [exhibits\exhibit_030.bin](exhibits\exhibit_030.bin)*

> **Exhibit 31: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .chatgpt.com / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_031.bin](exhibits\exhibit_031.bin)*

> **Exhibit 32: Browser Cookies — ChatGPT**
>
> Cookie artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:20:00 UTC
> - **Indicator:** .openai.com / _cfuvid
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_032.bin](exhibits\exhibit_032.bin)*

> **Exhibit 33: Browser Cookies — Claude**
>
> Cookie artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 22:50:00 UTC
> - **Indicator:** .claude.ai / __cf_bm
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_033.bin](exhibits\exhibit_033.bin)*

> **Exhibit 34: Browser Cookies — Gemini**
>
> Cookie artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Cookies`
> - **Timestamp:** 2024-01-17 23:50:00 UTC
> - **Indicator:** .gemini.google.com / NID
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `93bdef2905bbce0c933a23f4ade31a95`
>
> *See attached: [exhibits\exhibit_034.bin](exhibits\exhibit_034.bin)*

> **Exhibit 35: Browser Local Storage — ChatGPT**
>
> Local Storage Key artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\AppData/Local/Google/Chrome/User Data\Default\Local Storage/leveldb\chatgpt_trace.log`
> - **Indicator:** Key match: 'chatgpt' in chatgpt_trace.log
> - **Confidence:** Unsupported
> - **Artifact Hash (MD5):** `e6a07a97668a54927b2249c03ebf49f5`
>
> *See attached: [exhibits\exhibit_035.log](exhibits\exhibit_035.log)*

> **Exhibit 36: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt.com in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_036.pf](exhibits\exhibit_036.pf)*

> **Exhibit 37: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_037.pf](exhibits\exhibit_037.pf)*

> **Exhibit 38: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** ChatGPT in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_038.pf](exhibits\exhibit_038.pf)*

> **Exhibit 39: OS Execution Trace — ChatGPT**
>
> Prefetch Reference artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Windows\Prefetch\CHROME.EXE-ABC12345.pf`
> - **Indicator:** chatgpt in CHROME.EXE-ABC12345.pf
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `7cc1f97fdd93b20d03ff9332372cf493`
>
> *See attached: [exhibits\exhibit_039.pf](exhibits\exhibit_039.pf)*

> **Exhibit 40: User Content — ChatGPT**
>
> AI Export/Download File artifact indicating ChatGPT access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\ChatGPT_Crime_Scene_Analysis.pdf`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: ChatGPT_Crime_Scene_Analysis.pdf (pattern: chat[-_]?gpt.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4e96f9e5729a4a216cbf044d44ed7b7b`
>
> *See attached: [exhibits\exhibit_040.pdf](exhibits\exhibit_040.pdf)*

> **Exhibit 41: User Content — Claude**
>
> AI Export/Download File artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: claude_response_export.txt (pattern: claude.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_041.txt](exhibits\exhibit_041.txt)*

> **Exhibit 42: User Content — Claude**
>
> Content Indicator artifact indicating Claude access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\claude_response_export.txt`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Claude' in claude_response_export.txt
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `4f579a1a15f5bdf4285fb087f59fae6e`
>
> *See attached: [exhibits\exhibit_042.txt](exhibits\exhibit_042.txt)*

> **Exhibit 43: User Content — Gemini**
>
> AI Export/Download File artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** File: gemini_forensic_notes.md (pattern: gemini.*\.(?:txt|json|md|pdf|html|csv))
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_043.md](exhibits\exhibit_043.md)*

> **Exhibit 44: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Response indicator: 'Gemini' in gemini_forensic_notes.md
> - **Confidence:** Moderate
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_044.md](exhibits\exhibit_044.md)*

> **Exhibit 45: User Content — Adobe Firefly**
>
> Content Indicator artifact indicating Adobe Firefly access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Prompt indicator: 'Generate' in gemini_forensic_notes.md
> - **Confidence:** Low
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_045.md](exhibits\exhibit_045.md)*

> **Exhibit 46: User Content — Gemini**
>
> Content Indicator artifact indicating Gemini access
>
> - **E01 Source Path:** `demo_evidence:/C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence\Users\JohnDoe\Downloads\gemini_forensic_notes.md`
> - **Timestamp:** 2026-04-06 02:22:05 UTC
> - **Indicator:** Model string: Gemini Pro in gemini_forensic_notes.md
> - **Confidence:** High
> - **Artifact Hash (MD5):** `be1a7926eb1fa559f0a5ccf2542c8e78`
>
> *See attached: [exhibits\exhibit_046.md](exhibits\exhibit_046.md)*

---

Signed:

*Digital Forensics Team*

_________________________

Digital Forensics Team  
Digital Forensics Examiner  
UNCC Forensics Lab

---

*Report generated by TRACE-AI-FR v4.0.0*  
*Generated on: 2026-04-12 19:12:35 UTC*