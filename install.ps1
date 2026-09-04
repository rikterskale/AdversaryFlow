$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "AdversaryFlow requires Python 3.10 or newer. Install Python, then retry."
}

& py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "AdversaryFlow requires Python 3.10 or newer. Run 'py -3 --version' to inspect the selected interpreter."
}

if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --require-hashes --requirement requirements.lock
& .\.venv\Scripts\python.exe -m pip install --require-hashes --requirement requirements-build.lock
& .\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps --editable .
& .\.venv\Scripts\adversaryflow.exe doctor
Write-Host "AdversaryFlow installed and verified. Start it with .\run.ps1"
