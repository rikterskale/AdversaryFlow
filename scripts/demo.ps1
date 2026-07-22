# Generate the deterministic demo scenario report (Windows / PowerShell).
# Runs setup automatically if the virtual environment is missing.
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

$python = $null
foreach ($candidate in @("py", "python", "python3")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $python = $candidate
        break
    }
}
if (-not $python) {
    Write-Error "No Python interpreter found. Install Python 3.11+ first."
    exit 1
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "No virtual environment found; running setup first ..."
    & $python tasks.py setup
}

& $python tasks.py demo
