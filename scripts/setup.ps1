# One-command setup for Windows (PowerShell).
# Creates a virtual environment, installs AdversaryFlow with dev tools,
# and prepares a local .env file.
#
# If script execution is blocked, run this once in the same session:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

# Prefer the Windows 'py' launcher, then python/python3 on PATH.
$python = $null
foreach ($candidate in @("py", "python", "python3")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $python = $candidate
        break
    }
}

if (-not $python) {
    Write-Error "No Python interpreter found. Install Python 3.11+ from https://www.python.org/downloads/ (check 'Add python.exe to PATH')."
    exit 1
}

Write-Host "Using interpreter: $python"
& $python tasks.py setup
