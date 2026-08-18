#!/usr/bin/env bash
set -euo pipefail

dev=false
case "${1:-}" in
  --dev) dev=true ;;
  "") ;;
  *)
    echo "Usage: bash scripts/install.sh [--dev]" >&2
    exit 2
    ;;
esac

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
venv_root="$project_root/.venv"
venv_python="$venv_root/bin/python"
venv_cli="$venv_root/bin/adversaryflow"

python_bin="$(command -v python3 || true)"
if [[ -z "$python_bin" ]]; then
  echo "Python 3.11 or newer is required. Install python3, python3-venv, and python3-pip, then rerun this script." >&2
  exit 1
fi
if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  detected="$("$python_bin" -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || echo unknown)"
  echo "Python 3.11 or newer is required; found $detected at $python_bin." >&2
  exit 1
fi

if [[ -e "$venv_root" ]]; then
  if [[ ! -x "$venv_python" ]]; then
    echo "The existing virtual environment at '$venv_root' is incomplete or was created on another platform. Rename or remove it, then rerun this script." >&2
    exit 1
  fi
  if ! "$venv_python" -c 'import sys; raise SystemExit(0 if sys.prefix != sys.base_prefix and sys.version_info >= (3, 11) else 1)'; then
    echo "The existing virtual environment at '$venv_root' is not a compatible Python 3.11+ environment. Rename or remove it, then rerun this script." >&2
    exit 1
  fi
else
  "$python_bin" -m venv "$venv_root"
fi

"$venv_python" -m pip install --disable-pip-version-check --upgrade pip
if [[ "$dev" == true ]]; then
  "$venv_python" -m pip install --disable-pip-version-check --editable "${project_root}[dev]"
else
  "$venv_python" -m pip install --disable-pip-version-check --upgrade "$project_root"
fi
"$venv_python" -m adversaryflow doctor --fix
echo "AdversaryFlow installed. Try: $venv_cli demo"
