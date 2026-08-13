"""Verify required docs, local Markdown links, and parser-derived CLI coverage."""

import ast
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
DOCTOR_CHECK_DOCUMENTS = (
    "docs/CLI_REFERENCE.md",
    "docs/TROUBLESHOOTING.md",
    "docs/modules/diagnostics-and-support.md",
)


def _parser_surface() -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse((ROOT / "src/adversaryflow/cli.py").read_text(encoding="utf-8"))
    commands: set[str] = set()
    options: set[str] = set()
    defaults: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "add_parser" and node.args and isinstance(node.args[0], ast.Constant):
            commands.add(str(node.args[0].value))
        if node.func.attr != "add_argument" or not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        argument = str(node.args[0].value)
        if argument.startswith("--"):
            options.add(argument)
        for keyword in node.keywords:
            if keyword.arg == "default" and isinstance(keyword.value, ast.Constant) and keyword.value.value is not None:
                defaults.add(str(keyword.value.value))
    return commands, options, defaults


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
    commands, options, defaults = _parser_surface()
    missing_commands = sorted(command for command in commands if command not in reference)
    missing_options = sorted(option for option in options if option not in reference)
    missing_defaults = sorted(default for default in defaults if default not in reference)
    if missing_commands or missing_options or missing_defaults:
        missing_surface = []
        if missing_commands:
            missing_surface.append("commands: " + ", ".join(missing_commands))
        if missing_options:
            missing_surface.append("options: " + ", ".join(missing_options))
        if missing_defaults:
            missing_surface.append("defaults: " + ", ".join(missing_defaults))
        raise SystemExit("CLI reference is missing parser surface: " + "; ".join(missing_surface))
    missing_doctor_check = [path for path in DOCTOR_CHECK_DOCUMENTS if "execution-adapter" not in (ROOT / path).read_text(encoding="utf-8")]
    if missing_doctor_check:
        raise SystemExit("Doctor documentation is missing execution-adapter coverage: " + ", ".join(missing_doctor_check))
    print("documentation validation passed")


if __name__ == "__main__":
    main()
