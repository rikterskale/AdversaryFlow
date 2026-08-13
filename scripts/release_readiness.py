"""Enforce the new-user release-readiness standard in CI."""

import sys
from pathlib import Path

try:
    from .artifact_journey import journey
except ImportError:  # Executed directly as python scripts/release_readiness.py.
    from artifact_journey import journey


REQUIRED_DOCUMENTATION = {
    "README.md": [
        "adversaryflow doctor",
        "adversaryflow guide",
        "adversaryflow manager --open",
        "simulation-only",
    ],
    "docs/INSTALL.md": [
        "guided diagnostics",
        "--fallback-offline",
        "campaign cancel",
        "Complete offline journey",
    ],
    "docs/RELEASE_READINESS.md": [
        "Proven installation",
        "Guided troubleshooting",
        "Full-feature validation",
        "Tested recovery paths",
        "Documentation",
    ],
}


def validate_documentation(root: str | Path = ".") -> None:
    base = Path(root)
    for relative, required in REQUIRED_DOCUMENTATION.items():
        text = (base / relative).read_text(encoding="utf-8")
        missing = [item for item in required if item not in text]
        if missing:
            raise RuntimeError(f"{relative} is missing release-readiness documentation: {', '.join(missing)}")


def validate_release_readiness(release_dir: str | Path) -> list[str]:
    validate_documentation()
    return journey(release_dir)


if __name__ == "__main__":
    release_path = sys.argv[1] if len(sys.argv) > 1 else "artifacts/release"
    completed = validate_release_readiness(release_path)
    print("Release-readiness standard passed for:")
    print("\n".join(completed))
