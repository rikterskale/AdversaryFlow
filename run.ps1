$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

$Ready = $false
if ((Test-Path ".venv\Scripts\adversaryflow.exe") -and (Test-Path ".venv\Scripts\python.exe")) {
    try {
        & .\.venv\Scripts\python.exe scripts/check_install.py
        $Ready = $LASTEXITCODE -eq 0
    } catch {
        Write-Host "[AdversaryFlow] the installed Python environment could not start."
    }
}
if (-not $Ready) {
    Write-Host "[AdversaryFlow] installing or repairing the local environment..."
    & .\install.ps1
}

Write-Host "[AdversaryFlow] starting; the browser will open when the local service is ready"
& .\.venv\Scripts\adversaryflow.exe --open @args
exit $LASTEXITCODE
