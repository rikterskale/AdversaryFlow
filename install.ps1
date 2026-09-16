$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

$PythonCommand = $null
$PythonPrefix = @()
$PyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($PyLauncher) {
    & $PyLauncher.Source -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $PythonCommand = $PyLauncher.Source
        $PythonPrefix = @("-3")
    }
}
if (-not $PythonCommand) {
    foreach ($CandidateName in @("python", "python3")) {
        $Candidate = Get-Command $CandidateName -ErrorAction SilentlyContinue
        if (-not $Candidate) { continue }
        & $Candidate.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PythonCommand = $Candidate.Source
            break
        }
    }
}
if (-not $PythonCommand) {
    throw "AdversaryFlow requires Python 3.10 or newer. Install Python, ensure py or python is on PATH, then retry."
}

if (-not (Test-Path ".venv")) {
    & $PythonCommand @PythonPrefix -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        throw "Creating the AdversaryFlow virtual environment failed with exit code $LASTEXITCODE."
    }
}

& .\.venv\Scripts\python.exe -m pip install --require-hashes --requirement requirements.lock
if ($LASTEXITCODE -ne 0) {
    throw "Installing runtime dependencies failed with exit code $LASTEXITCODE."
}
& .\.venv\Scripts\python.exe -m pip install --require-hashes --requirement requirements-build.lock
if ($LASTEXITCODE -ne 0) {
    throw "Installing build dependencies failed with exit code $LASTEXITCODE."
}
& .\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps --editable .
if ($LASTEXITCODE -ne 0) {
    throw "Installing AdversaryFlow failed with exit code $LASTEXITCODE."
}
& .\.venv\Scripts\adversaryflow.exe doctor
if ($LASTEXITCODE -ne 0) {
    throw "AdversaryFlow doctor failed. Fix the reported issue, then retry."
}
Write-Host "AdversaryFlow installed and verified. Start it with .\run.ps1"
