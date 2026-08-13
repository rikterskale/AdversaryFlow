param([switch]$Dev)
$ErrorActionPreference = "Stop"

$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $python) { throw "Python 3.11 or newer is required. Install it from https://www.python.org/downloads/windows/ and rerun this script." }

$version = & $python.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$parts = $version.Split('.')
if ([int]$parts[0] -ne 3 -or [int]$parts[1] -lt 11) { throw "Python 3.11 or newer is required; found $version." }

if (-not (Test-Path .venv\Scripts\python.exe)) { & $python.Source -m venv .venv }
$venvPython = (Resolve-Path .venv\Scripts\python.exe).Path
& $venvPython -m pip install --upgrade pip
if ($Dev) { & $venvPython -m pip install -e ".[dev]" } else { & $venvPython -m pip install -e "." }
& $venvPython -m adversaryflow doctor --fix
Write-Host "AdversaryFlow installed. Try: .\.venv\Scripts\adversaryflow.exe demo"
