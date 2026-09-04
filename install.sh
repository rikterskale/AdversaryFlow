#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$repo_dir"

if ! command -v python3 >/dev/null 2>&1; then
  echo "AdversaryFlow requires Python 3.10 or newer." >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "AdversaryFlow requires Python 3.10 or newer; found $(python3 --version 2>&1)." >&2
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --require-hashes --requirement requirements.lock
.venv/bin/python -m pip install --require-hashes --requirement requirements-build.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps --editable .

.venv/bin/adversaryflow doctor

echo "AdversaryFlow installed and verified. Start it with ./run.sh"
