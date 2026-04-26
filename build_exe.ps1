param(
    [switch]$Watch
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = "C:\Users\hemal\AppData\Local\Programs\Python\Python313\python.exe"

if (-not (Test-Path -LiteralPath $PythonExe)) {
    $PythonExe = "python"
}

function Invoke-TraceBuild {
    Push-Location $ProjectRoot
    try {
        Write-Host "Checking desktop_app.py syntax..."
        & $PythonExe -m py_compile desktop_app.py
        if ($LASTEXITCODE -ne 0) {
            throw "Syntax check failed."
        }

        $runningApps = Get-Process -Name "TRACE-AI-FR" -ErrorAction SilentlyContinue
        if ($runningApps) {
            Write-Host "Stopping running TRACE-AI-FR.exe instances so the build can replace the executable..."
            $runningApps | Stop-Process -Force
            Start-Sleep -Seconds 2
        }

        Write-Host "Building dist\TRACE-AI-FR.exe..."
        & $PythonExe -m PyInstaller TRACE-AI-FR.spec --clean --noconfirm
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller build failed."
        }

        if (-not (Test-Path -LiteralPath "$ProjectRoot\dist\TRACE-AI-FR.exe")) {
            throw "Build completed but dist\TRACE-AI-FR.exe was not created."
        }

        Write-Host "Build complete: dist\TRACE-AI-FR.exe"
    }
    finally {
        Pop-Location
    }
}

Invoke-TraceBuild

if ($Watch) {
    Write-Host "Watching Python source and spec files. Press Ctrl+C to stop."
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $ProjectRoot
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true

    $lastBuild = Get-Date
    while ($true) {
        $change = $watcher.WaitForChanged(
            [System.IO.WatcherChangeTypes]::Changed -bor
            [System.IO.WatcherChangeTypes]::Created -bor
            [System.IO.WatcherChangeTypes]::Deleted -bor
            [System.IO.WatcherChangeTypes]::Renamed,
            1000
        )

        if (-not $change.TimedOut) {
            $now = Get-Date
            if (($now - $lastBuild).TotalSeconds -lt 3) {
                continue
            }

            $name = $change.Name
            if ($name -like "build\*" -or $name -like "dist\*" -or $name -like "__pycache__\*") {
                continue
            }

            if ($name -match '\.(py|spec|yaml|toml)$') {
                $lastBuild = $now
                try {
                    Invoke-TraceBuild
                }
                catch {
                    Write-Host "Build failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}
