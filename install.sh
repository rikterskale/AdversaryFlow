#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$repo_dir"

if ! command -v python3 >/dev/null 2>&1; then
  echo "AdversaryFlow requires Python 3.10 or newer." >&2
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --requirement requirements.lock
.venv/bin/python -m pip install --no-deps --editable .

echo "AdversaryFlow installed. Start it with ./run.sh"

