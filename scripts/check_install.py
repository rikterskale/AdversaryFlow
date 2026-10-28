"""Fast, offline readiness check for the native source launchers."""

from __future__ import annotations

import importlib
import importlib.metadata
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_install(root: Path = ROOT) -> str | None:
    if sys.version_info < (3, 10):
        return "The installed environment needs Python 3.10 or newer."
    from backend import __version__

    requirements = re.findall(r"(?m)^([\w.-]+)==([^\s\\]+)", (root / "requirements.lock").read_text(encoding="utf-8"))
    for name, expected in [("adversaryflow", __version__), *requirements]:
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return f"The installed environment is missing {name}."
        if installed != expected:
            return f"The installed environment has {name} {installed}; this checkout needs {expected}."
    try:
        importlib.import_module("backend.app")
    except Exception as exc:
        return f"The installed application could not load: {exc}"
    return None


def main() -> int:
    # Running a file under scripts/ otherwise puts only scripts/ on sys.path.
    sys.path.insert(0, str(ROOT))
    problem = check_install()
    if problem:
        print(f"[AdversaryFlow] {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
