$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

if (-not (Test-Path ".venv\Scripts\adversaryflow.exe")) {
    Write-Host "[AdversaryFlow] first-run installation..."
    & .\install.ps1
}

Write-Host "[AdversaryFlow] starting; the browser will open when ATT&CK data is ready"
& .\.venv\Scripts\adversaryflow.exe --open @args
