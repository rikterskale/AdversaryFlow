$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "AdversaryFlow requires Python 3.10 or newer. Install Python, then retry."
}

if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --requirement requirements.lock
& .\.venv\Scripts\python.exe -m pip install --no-deps --editable .
Write-Host "AdversaryFlow installed. Start it with .\run.ps1"

