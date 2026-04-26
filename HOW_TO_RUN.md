# TRACE-AI-FR: Self-Help Guide for Input Fields

This guide explains what to type into each input field when testing the application.

It is written for non-technical users.

## Before You Start

Download the project first from GitHub:

https://github.com/prakasamv6/TRACE-AI-FR

Then extract the ZIP file and open the TRACE-AI-FR folder on Windows.

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

## Main Input Fields in the App

When the application opens, look for the Analysis Configuration section.

You will see these fields:

- Evidence
- Output
- Questions
- Case Name
- Examiner
- Organization
- Enable carving
- Mode

## 1. Evidence

This is the most important field.

What it means:

- It tells the app what file or folder to analyze.

What you can enter:

- An evidence image file such as `.E01` or `.EX01`
- A `.zip` file
- A normal evidence folder path

Examples:

- `C:\Cases\Disk01.E01`
- `C:\Evidence\2020JimmyWilson.E01`
- `C:\Cases\phone_export.zip`
- `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_evidence`

Important:

- This field is required.
- If you leave it blank, the app shows: `Please select an evidence source first.`
- The browse button mainly helps you pick files.
- If you want to test using a normal folder, you may need to copy and paste the folder path into the Evidence field.

## 2. Output

What it means:

- This is the folder where the reports will be saved.

Example:

- `C:\TRACE-Output`

Important:

- This field is optional.
- If you leave it blank, the app creates a folder named `trace_output` next to the evidence path.

## 3. Questions

What it means:

- This is an optional Word document containing examination questions.

What to enter:

- A `.docx` file with questions

Example:

- `C:\Cases\questions.docx`

Important:

- This field is optional.
- If you add a questions document, the app previews the questions and can answer them after analysis.

## 4. Case Name

What it means:

- The name of the case or test run.

Example:

- `Test Case 001`

Important:

- This field is optional.
- If left blank, the app uses `Untitled Case`.

## 5. Examiner

What it means:

- The name of the person running the analysis.

Example:

- `John Smith`

Important:

- This field is optional.

## 6. Organization

What it means:

- The company, school, or agency name.

Example:

- `UNC Charlotte`

Important:

- This field is optional.

## 7. Enable Carving

What it means:

- This is a checkbox.
- It turns carving on or off during analysis.

What to do for testing:

- Leave it unchecked for simple tests.
- Check it only if you want to test carving behavior.

## 8. Mode

What it means:

- This tells the app how to treat the input.

Choices:

- `auto`
- `e01`
- `mounted`
- `zip`

What to choose:

- Use `auto` for most tests.
- Use `e01` for E01 evidence images.
- Use `mounted` for a normal extracted folder.
- Use `zip` for ZIP archives.

Important:

- The default is `auto`.

## Best Simple Test Setup

If you just want to test the application quickly, use these values:

- Evidence: `C:\Evidence\2020JimmyWilson.E01`
- Output: `C:\UNCC\ITIS-5250-092(Comp-For)\Project\TRACE-AI-FR\demo_output_test`
- Questions: leave blank
- Case Name: `LOCAL-TEST-001`
- Examiner: your name
- Organization: your organization name
- Enable carving: unchecked
- Mode: `e01`

## Steps to Test the App

1. Open the app.
2. In Evidence, paste your evidence file path or folder path.
3. In Output, choose where you want the reports saved.
4. Fill in Case Name if you want a custom label.
5. Leave Questions blank unless you have a `.docx` question file.
6. If you are using `2020JimmyWilson.E01`, set Mode to `e01`.
7. Click Run Analysis.

## After Analysis

When the run finishes, the app saves files in the output folder.

Common outputs include:

- `*_report.docx`
- `*_report.html`
- `*_report.md`
- `*_findings.json`
- `*_governance_record.json`

## Generate Report Dialog

After analysis, you can click Generate Report.

The report dialog asks for:

- Forensic Examination Name
- Forensic Examination in the matter of
- Examiner Name

Important:

- You must enter at least one of these:
- Forensic Examination Name
- Forensic Examination in the matter of
- If both are blank, the app shows a warning.

## Common Problems and Fixes

### Problem: The app says evidence is missing

Fix:

- Make sure the Evidence field is not empty.
- Paste the full path carefully.

### Problem: I want to test with a folder, not a file

Fix:

- Paste the folder path directly into the Evidence field.
- Set Mode to `mounted`.

### Problem: I do not know what to put in Output

Fix:

- Enter any empty folder location where you want reports saved.
- Or leave it blank and let the app create `trace_output` automatically.

### Problem: I do not have a Questions file

Fix:

- Leave the Questions field blank.

### Problem: I am not sure what Mode to use

Fix:

- Choose `auto` for most tests.

## Quick Reminder

- Evidence is required.
- Output is optional.
- Questions is optional.
- Case Name is optional.
- Examiner is optional.
- Organization is optional.
- Mode defaults to `auto`.
- The app runs on Windows.
