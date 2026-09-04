#!/usr/bin/env bash
# AdversaryFlow launcher — bootstraps once, then starts the installed command.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/adversaryflow ]; then
  echo "[AdversaryFlow] first-run installation…"
  ./install.sh
fi

echo "[AdversaryFlow] starting on http://127.0.0.1:5000"
exec .venv/bin/adversaryflow "$@"
