#!/usr/bin/env bash
# AdversaryFlow launcher — bootstraps once, then starts the installed command.
set -euo pipefail
script_path="${BASH_SOURCE[0]}"
script_dir="${script_path%/*}"
if [ "$script_dir" = "$script_path" ]; then
  script_dir="${script_path%\\*}"
fi
if [ "$script_dir" = "$script_path" ]; then
  script_dir="."
fi
cd "$script_dir"

if [ ! -x .venv/bin/adversaryflow ]; then
  echo "[AdversaryFlow] first-run installation…"
  ./install.sh
fi

echo "[AdversaryFlow] starting; the browser will open when ATT&CK data is ready"
exec .venv/bin/adversaryflow --open "$@"
