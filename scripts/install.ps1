$ErrorActionPreference = "Stop"
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m adversaryflow doctor
Write-Host "AdversaryFlow installed. Try: .\.venv\Scripts\python.exe -m adversaryflow demo"
