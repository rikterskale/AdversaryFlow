param([switch]$Dev)
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$venvRoot = Join-Path $projectRoot ".venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$venvCli = Join-Path $venvRoot "Scripts\adversaryflow.exe"

function Invoke-Checked {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$FailureMessage
    )
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)."
    }
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) {
    throw "Python 3.11 or newer is required. Install it from https://www.python.org/downloads/windows/ and rerun this script."
}

$version = & $python.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0) { throw "Unable to query Python at $($python.Source)." }
$parts = $version.Trim().Split(".")
if ([int]$parts[0] -ne 3 -or [int]$parts[1] -lt 11) {
    throw "Python 3.11 or newer is required; found $version at $($python.Source)."
}

if (Test-Path $venvRoot) {
    if (-not (Test-Path $venvPython -PathType Leaf)) {
        throw "The existing virtual environment at '$venvRoot' is incomplete or was created on another platform. Rename or remove it, then rerun this script."
    }
    & $venvPython -c "import sys; raise SystemExit(0 if sys.prefix != sys.base_prefix and sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw "The existing virtual environment at '$venvRoot' is not a compatible Python 3.11+ environment. Rename or remove it, then rerun this script."
    }
} else {
    Invoke-Checked -Executable $python.Source -Arguments @("-m", "venv", $venvRoot) -FailureMessage "Could not create the virtual environment at '$venvRoot'"
}

Invoke-Checked -Executable $venvPython -Arguments @("-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "pip") -FailureMessage "Could not update pip"
if ($Dev) {
    Invoke-Checked -Executable $venvPython -Arguments @("-m", "pip", "install", "--disable-pip-version-check", "--editable", "$projectRoot[dev]") -FailureMessage "Could not install AdversaryFlow contributor dependencies"
} else {
    Invoke-Checked -Executable $venvPython -Arguments @("-m", "pip", "install", "--disable-pip-version-check", "--upgrade", $projectRoot) -FailureMessage "Could not install AdversaryFlow"
}
Invoke-Checked -Executable $venvPython -Arguments @("-m", "adversaryflow", "doctor", "--fix") -FailureMessage "AdversaryFlow diagnostics failed"
Write-Host "AdversaryFlow installed. Try: `"$venvCli`" demo"
