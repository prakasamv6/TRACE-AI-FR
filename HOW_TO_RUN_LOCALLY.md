# TRACE-AI-FR: Easy Local Setup Guide (Windows, Non-Technical)

This document is written for non-technical users.

## First: Download from GitHub

Before opening the app, download this project from GitHub:

https://github.com/prakasamv6/TRACE-AI-FR

Easy download steps:

1. Open the GitHub link above.
2. Click the green Code button.
3. Click Download ZIP.
4. Extract the ZIP file.
5. Open the extracted TRACE-AI-FR folder.

## What You Need

- A Windows 10 or Windows 11 computer
- The project folder (TRACE-AI-FR)

That is all if you use the packaged app.

## Fastest Way (Recommended)

Use the packaged app file. No coding setup is required.

### Step 1: Open the project folder

Open File Explorer and go to the TRACE-AI-FR folder.

### Step 2: Open the dist folder

Inside TRACE-AI-FR, open the dist folder.

### Step 3: Start the app

Double-click TRACE-AI-FR.exe.

The app window should open.

## Run With PowerShell (Optional)

If you prefer command line, use these steps.

### Step 1: Open PowerShell in the project folder

In File Explorer, open TRACE-AI-FR. Then right-click in empty space and choose Open in Terminal.

### Step 2: Start the app

```powershell
cd dist
.\TRACE-AI-FR.exe
```

## Analyze Evidence (Simple Command)

Use this command to run an analysis from PowerShell:

```powershell
cd dist
.\TRACE-AI-FR.exe analyze --evidence "C:\Evidence\2020JimmyWilson.E01" --output "C:\TRACE-Output" --case-id "CASE-001"
```

Change these parts:

- C:\Evidence\2020JimmyWilson.E01: sample E01 evidence file path
- C:\TRACE-Output: folder where reports will be saved
- CASE-001: your case ID

If you are using this sample E01 file in the app window:

- Evidence: `C:\Evidence\2020JimmyWilson.E01`
- Mode: `e01`

## Test with Included Demo Data

From the project root folder:

```powershell
.\dist\TRACE-AI-FR.exe analyze --evidence demo_evidence --output demo_output_local --case-id LOCAL-TEST-001
```

## Where Results Are Saved

Look in your output folder for files like:

- CASE-001_report.html
- CASE-001_report.md
- CASE-001_findings.json
- CASE-001_governance_record.json
- exhibits folder

## If It Does Not Open

- Confirm you are on Windows 10 or 11.
- Right-click TRACE-AI-FR.exe and choose Run as administrator.
- In file Properties, click Unblock if shown.
- Confirm your evidence folder path is correct.

## Notes

- This packaged app is for Windows only.
- For technical details, read ARCHITECTURE.md.
- For quick feature overview, read QUICK_START.md.