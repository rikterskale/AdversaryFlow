"""Verify required docs, local Markdown links, and CLI reference coverage."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRECTORIES = {".git", ".venv", ".venv-security", "artifacts", "build"}
REQUIRED = {
    "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md",
    "docs/INSTALL.md", "docs/CLI_REFERENCE.md", "docs/USAGE.md", "docs/ARCHITECTURE.md",
    "docs/TROUBLESHOOTING.md", "docs/FAQ.md", "docs/EXAMPLES.md", "docs/DEVELOPMENT.md",
    "docs/RELEASE_CHECKLIST.md",
}
CLI_MARKERS = ("validate", "plan", "draft", "demo", "doctor", "support-bundle", "capabilities", "guide", "provider", "campaign", "manager")


def main() -> None:
    missing = [path for path in sorted(REQUIRED) if not (ROOT / path).is_file()]
    if missing:
        raise SystemExit("Missing required documentation: " + ", ".join(missing))
    broken = []
    documents = (
        path
        for path in ROOT.rglob("*.md")
        if not any(part in EXCLUDED_DIRECTORIES for part in path.relative_to(ROOT).parts)
    )
    for document in documents:
        for target in re.findall(r"\[[^]]*\]\(([^)#]+)(?:#[^)]+)?\)", document.read_text(encoding="utf-8")):
            if "://" not in target and not (document.parent / target).resolve().is_file():
                broken.append(f"{document.relative_to(ROOT)} -> {target}")
    if broken:
        raise SystemExit("Broken local documentation links: " + "; ".join(broken))
    reference = (ROOT / "docs/CLI_REFERENCE.md").read_text(encoding="utf-8")
    absent = [marker for marker in CLI_MARKERS if marker not in reference]
    if absent:
        raise SystemExit("CLI reference is missing commands: " + ", ".join(absent))
    print("documentation validation passed")


if __name__ == "__main__":
    main()
