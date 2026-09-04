#!/usr/bin/env bash
# AdversaryFlow launcher — sets up a venv, installs Flask, starts the app.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[AdversaryFlow] creating virtualenv…"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip >/dev/null
pip install -q -r backend/requirements.txt

echo "[AdversaryFlow] starting on http://127.0.0.1:5000"
echo "[AdversaryFlow] first run downloads the live MITRE ATT&CK STIX feed (~35MB)…"
cd backend
exec python app.py
