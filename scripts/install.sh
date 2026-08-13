#!/usr/bin/env bash
set -euo pipefail

dev=false
if [[ "${1:-}" == "--dev" ]]; then dev=true; fi
python_bin="$(command -v python3 || true)"
if [[ -z "$python_bin" ]]; then
  echo "Python 3.11 or newer is required. Install python3, python3-venv, and python3-pip, then rerun this script." >&2
  exit 1
fi
if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required." >&2
  exit 1
fi
if [[ ! -x .venv/bin/python ]]; then "$python_bin" -m venv .venv; fi
.venv/bin/python -m pip install --upgrade pip
if [[ "$dev" == true ]]; then .venv/bin/python -m pip install -e '.[dev]'; else .venv/bin/python -m pip install -e .; fi
.venv/bin/python -m adversaryflow doctor --fix
echo 'AdversaryFlow installed. Try: .venv/bin/adversaryflow demo'
