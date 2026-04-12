# TRACE-AI-FR v4.0.0 - Quick Start Guide

## 📦 Executable Details

**File:** `dist\TRACE-AI-FR.exe`  
**Size:** 25.15 MB  
**Built:** April 12, 2026  
**Platform:** Windows 11/10  
**Type:** Standalone executable (no installation required)

---

## 🚀 Launch Methods

### Method 1: Desktop GUI (Recommended)
Simply **double-click** `TRACE-AI-FR.exe` to open the graphical interface.

The GUI provides:
- Evidence directory selection
- Case information input
- Real-time analysis progress
- Multi-format report viewing
- Export options

### Method 2: Command Line
```powershell
# Navigate to the dist folder
cd C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\dist

# Run analysis
.\TRACE-AI-FR.exe analyze --evidence "..\demo_evidence" --output "..\test_output" --case-id "TEST-2026"
```

---

## 🎯 What's New in v4.0.0

### 🆕 9 New Enterprise AI Platforms
1. **Adobe Firefly** - Brand asset creation
2. **Checkr** - Background screening
3. **Tidio** - Customer automation
4. **Lindy** - AI agent employees
5. **Synthesia** - Video creation
6. **Lattice AI** - Employee engagement
7. **DataRobot** - Automated ML
8. **Leena AI** - HR automations
9. **Nexos AI** - Supply chain

### ⚡ Enhanced Parsers (v2.0.0)
- **Windows Event Log Parser**
  - Full .evtx file parsing
  - Application, System, Security logs
  - PowerShell operational logs
  
- **macOS Unified Log Parser**
  - Binary .tracev3 scanning
  - Text log exports
  - Multi-location search
  
- **iPhone App Usage Parser**
  - KnowledgeC.db analysis
  - DataUsage.sqlite network stats
  - App metadata extraction

### 📱 Complete Android/Samsung Support
- Chrome browser artifacts
- Samsung Internet browser
- App installation tracking
- System logcat analysis

---

## 📊 Supported Capabilities

| Category | Count | Details |
|----------|-------|---------|
| **AI Platforms** | 17 | ChatGPT, Claude, Gemini, Perplexity, Copilot, Meta AI, Grok, Poe, Adobe Firefly, Checkr, Tidio, Lindy, Synthesia, Lattice AI, DataRobot, Leena AI, Nexos AI |
| **Forensic Parsers** | 31 | Browser history, cookies, local storage, OS logs, registry, prefetch, app usage |
| **Operating Systems** | 5 | Windows, macOS, Linux, iPhone, Android |
| **Report Formats** | 5 | HTML, DOCX, Markdown, JSON, SQLite |
| **Artifact Families** | 19 | Browser, OS, Apps, Native Tools, File System |

---

## 🔍 Example Analysis Workflow

### Step 1: Prepare Evidence
```
evidence/
├── Users/
│   └── JohnDoe/
│       ├── AppData/
│       ├── Desktop/
│       └── Downloads/
└── Windows/
    └── System32/
        └── config/
```

### Step 2: Launch Application
Double-click `TRACE-AI-FR.exe`

### Step 3: Configure Analysis
- **Evidence Path:** Browse to your evidence folder
- **Output Directory:** Choose where to save reports
- **Case ID:** Enter case number (e.g., "2026-001")
- **OS Platform:** Select from Windows/macOS/Linux/iPhone/Android

### Step 4: Run Analysis
Click **"Analyze Evidence"** and monitor progress:
- Parser execution status
- Artifacts discovered
- AI platforms detected
- Timeline events created

### Step 5: Review Results
The tool generates:
- ✅ **HTML Report** - Interactive web-based report
- ✅ **DOCX Report** - Formal document for court
- ✅ **Markdown Report** - Human-readable text
- ✅ **JSON Export** - Machine-readable data
- ✅ **SQLite Database** - Queryable evidence store
- ✅ **Governance Record** - Chain of custody

---

## 🎨 Example Detection Results

### Detected AI Platforms (from demo_evidence)
```
ChatGPT:        11 artifacts
Gemini:         6 artifacts
Claude:         5 artifacts
Adobe Firefly:  1 artifact (NEW!)
```

### Timeline Events
```
2024-11-15 14:32:15 - ChatGPT conversation started
2024-11-16 09:45:22 - Gemini code generation
2024-11-17 16:20:33 - Claude document analysis
2024-11-18 11:15:44 - Adobe Firefly image created
```

### FRAUE (Forensically Reconstructed AI Usage Events)
- AI interaction patterns
- Platform attribution
- Confidence scoring
- Evidence classification

---

## 📍 Output Directory Structure

```
output_directory/
├── CASEID_report.html         # Interactive HTML report
├── CASEID_report.docx         # Word document
├── CASEID_report.md           # Markdown report
├── CASEID_findings.json       # JSON export
├── CASEID_governance_record.json  # Chain of custody
├── artifacts.db               # SQLite database
└── exhibits/
    ├── exhibit_001.jpg
    ├── exhibit_002.png
    └── ...
```

---

## 🛡️ Forensic Soundness

This tool follows digital forensics best practices:

✅ **Read-Only Access** - No modification of original evidence  
✅ **Hash Verification** - SHA-256 checksums for all artifacts  
✅ **Chain of Custody** - Complete governance records  
✅ **Timestamp Preservation** - Forensically sound time handling  
✅ **Evidence Classification** - Direct, Circumstantial, Inferred  
✅ **Confidence Scoring** - High, Moderate, Low attribution  
✅ **Court Admissibility** - Professional reporting format  

---

## 💡 Tips for Best Results

1. **Use E01 Images** - For forensically sound analysis
2. **Review All Parsers** - Check parser execution logs
3. **Verify Timestamps** - Ensure timezone settings are correct
4. **Export Multiple Formats** - HTML for viewing, DOCX for court
5. **Check Governance Records** - Required for admissibility
6. **Analyze Timeline** - Look for patterns in AI usage
7. **Cross-Reference** - Compare multiple artifact sources

---

## 🔧 Troubleshooting

### Application Won't Launch
- Ensure you're on Windows 10/11
- Check antivirus isn't blocking the .exe
- Run as Administrator if needed

### No Artifacts Found
- Verify evidence path is correct
- Check OS platform selection matches evidence
- Review parser logs in output directory

### Missing AI Platforms
- Ensure evidence contains browser artifacts
- Check for Chrome/Edge/Firefox history files
- Verify date range includes AI usage

---

## 📞 Support

For issues or questions:
- Review log files in output directory
- Check parser execution status
- Examine governance records
- Validate evidence structure

---

## ✅ Ready to Go!

The TRACE-AI-FR v4.0.0 executable is fully functional and ready for:

✨ **Digital forensic investigations**  
✨ **AI usage detection and attribution**  
✨ **Multi-platform evidence analysis**  
✨ **Enterprise AI tool detection**  
✨ **Mobile device forensics**  
✨ **Court-admissible reporting**  

**Start by double-clicking `TRACE-AI-FR.exe` in the dist folder!**
