"""Run the CI checks that are meaningful on the current machine.

Environment-specific GitHub jobs are reported as skipped rather than silently
pretended to pass. The command exits non-zero only for an available check that
actually fails.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(name: str, command: list[str], *, required: bool = True) -> tuple[str, bool, str]:
    executable = shutil.which(command[0])
    if executable is None:
        return name, not required, "SKIP: executable unavailable"
    result = subprocess.run(command, cwd=ROOT, text=True)
    return name, result.returncode == 0, "PASS" if result.returncode == 0 else f"FAIL ({result.returncode})"


def main() -> int:
    python = sys.executable
    checks: list[tuple[str, list[str], bool]] = [
        ("tests+coverage", [python, "-m", "pytest", "-q", "--cov=adversaryflow", "--cov-branch", "--cov-fail-under=95"], True),
        ("documentation", [python, "scripts/validate_documentation.py"], True),
        ("documentation-gaps", [python, "scripts/documentation_gap_analysis.py"], True),
        ("source-documentation", [python, "scripts/source_documentation_contract.py"], True),
        ("documentation-provenance", [python, "scripts/documentation_provenance.py"], True),
        ("bandit", ["bandit", "-r", "src", "-q"], False),
        ("pip-audit", ["pip-audit"], False),
        ("zizmor", ["zizmor", ".github/workflows"], False),
    ]
    failures = 0
    for name, command, required in checks:
        label, passed, detail = run(name, command, required=required)
        print(f"{label}: {detail}")
        if not passed:
            failures += 1
    if shutil.which("docker"):
        print("docker: AVAILABLE (run the Docker smoke commands documented in docs/INSTALL.md)")
    else:
        print("docker: SKIP: Docker is unavailable on this host")
    print("github-only: CodeQL, Gitleaks, and multi-OS release journeys remain enforced in GitHub Actions")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
