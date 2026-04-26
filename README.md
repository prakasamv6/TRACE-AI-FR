# TRACE-AI-FR

TRACE-AI-FR (Transparent Reporting of AI-related Claims in Evidence: A Forensic Reasoning Framework) is a digital forensics platform for detecting and reporting AI platform usage from evidence artifacts.

## Start Here (Non-Technical Users)

- Download first from GitHub: https://github.com/prakasamv6/TRACE-AI-FR
- One-page handout: `HOW_TO_RUN.md`
- Printable PDF handout: `HOW_TO_RUN.pdf`
- Read the step-by-step guide: `HOW_TO_RUN_LOCALLY.md`
- Word version for sharing/printing: `HOW_TO_RUN_LOCALLY.docx`

## Windows-Only Runtime

This packaged executable is intended to run on **Windows only**.

- Supported OS: Windows 10/11 (64-bit)
- Executable: `dist\\TRACE-AI-FR.exe`
- Runtime install: none required for the packaged `.exe`

## Git Repository

- GitHub repository: <https://github.com/prakasamv6/TRACE-AI-FR>

Clone with Git:

```powershell
git clone https://github.com/prakasamv6/TRACE-AI-FR.git
cd TRACE-AI-FR
```

## How to Run the Dist Executable (Windows)

From PowerShell in the project root:

```powershell
cd dist
.\TRACE-AI-FR.exe
```

Run analysis mode from CLI:

```powershell
cd dist
.\TRACE-AI-FR.exe analyze --evidence "C:\Evidence" --output "C:\TRACE-Output" --case-id "CASE-001"
```

Show tool info:

```powershell
cd dist
.\TRACE-AI-FR.exe info
```

## Optional: Run from Source (Windows)

If you want to run from Python source instead of the packaged exe:

```powershell
pip install -r requirements.txt
python -m ai_usage_evidence_analyzer info
```

## Project Notes

- Main architecture details: see `ARCHITECTURE.md`
- Quick usage guide: see `QUICK_START.md`
- One-page handout: see `HOW_TO_RUN.md`
- One-page PDF handout: see `HOW_TO_RUN.pdf`
- Local setup and run steps: see `HOW_TO_RUN_LOCALLY.md`
- Word version of local run guide: see `HOW_TO_RUN_LOCALLY.docx`
- Build notes: see `BUILD_SUCCESS.md`
