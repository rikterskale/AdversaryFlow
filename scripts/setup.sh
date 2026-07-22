#!/usr/bin/env bash
# One-command setup for Linux and macOS.
# Creates a virtual environment, installs AdversaryFlow with dev tools,
# and prepares a local .env file.
set -euo pipefail

cd "$(dirname "$0")/.."

# Pick the best available Python (3.11+ required).
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  for candidate in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON="$candidate"
      break
    fi
  done
fi

if [ -z "$PYTHON" ]; then
  echo "Error: no Python interpreter found. Install Python 3.11+ first." >&2
  exit 1
fi

echo "Using interpreter: $PYTHON"
"$PYTHON" tasks.py setup
