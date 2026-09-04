$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

if (-not (Test-Path ".venv\Scripts\adversaryflow.exe")) {
    Write-Host "[AdversaryFlow] first-run installation..."
    & .\install.ps1
}

Write-Host "[AdversaryFlow] starting on http://127.0.0.1:5000"
& .\.venv\Scripts\adversaryflow.exe @args

