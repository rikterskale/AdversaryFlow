#!/usr/bin/env bash
# AdversaryFlow launcher — bootstraps once, then starts the installed command.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/adversaryflow ]; then
  echo "[AdversaryFlow] first-run installation…"
  ./install.sh
fi

echo "[AdversaryFlow] starting; the browser will open when ATT&CK data is ready"
exec .venv/bin/adversaryflow --open "$@"
