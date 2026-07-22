#!/usr/bin/env bash
# Generate the deterministic demo scenario report (Linux / macOS).
# Runs setup automatically if the virtual environment is missing.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python

if [ ! -x ".venv/bin/python" ]; then
  echo "No virtual environment found; running setup first ..."
  "$PYTHON" tasks.py setup
fi

"$PYTHON" tasks.py demo
