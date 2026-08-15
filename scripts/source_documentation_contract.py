"""Enforce source-derived documentation parity for the public repository surface.

This check intentionally compares literal source evidence with documentation. It
does not infer behavior from names, docstrings, or prose and it does not try to
generate documentation.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI_REFERENCE = ROOT / "docs/CLI_REFERENCE.md"
MANAGER_GUIDE = ROOT / "docs/modules/local-manager.md"
PROVIDER_GUIDE = ROOT / "docs/modules/providers.md"
SCHEMAS = ROOT / "docs/SCHEMAS.md"
ALL_USER_DOCS = tuple(ROOT.rglob("*.md"))


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def cli_surface() -> tuple[set[str], set[str], set[str]]:
    tree = ast.parse(read(ROOT / "src/adversaryflow/cli.py"))
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


def manager_routes() -> set[str]:
    source = read(ROOT / "src/adversaryflow/manager.py")
    routes = set(re.findall(r'path\s*==\s*["\'](/api/[^"\']+)', source))
    routes.update({
        "/api/actor-profiles/{name}",
        "/api/actor-profiles/{name}/plan",
        "/api/actor-profiles/{name}/run",
        "/api/campaigns/{campaign_id}",
        "/api/campaigns/{campaign_id}/report",
        "/api/campaigns/{campaign_id}/approve",
        "/api/campaigns/{campaign_id}/reject",
        "/api/campaigns/{campaign_id}/cancel",
        "/api/campaigns/{campaign_id}/reset",
    })
    return routes


def source_environment_names() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "src", ROOT / "scripts"):
        for file in path.rglob("*.py"):
            names.update(re.findall(r"ADVERSARYFLOW_[A-Z0-9_]+", read(file)))
    # This is a serialized synthetic-event marker, not an environment variable.
    return names - {"ADVERSARYFLOW_SYNTHETIC"}


def source_artifact_names() -> set[str]:
    names: set[str] = set()
    pattern = re.compile(r'(?:/|writestr\()\s*["\']([A-Za-z0-9_.-]+\.(?:json|jsonl|yaml|md|html|pdf|zip|csv))["\']')
    for path in (ROOT / "src", ROOT / "scripts"):
        for file in path.rglob("*.py"):
            for line in read(file).splitlines():
                if any(marker in line for marker in ("write_text", "write_bytes", "writestr", "source_zip")):
                    names.update(pattern.findall(line))
    return names


def find_gaps() -> list[str]:
    cli = read(CLI_REFERENCE)
    manager = read(MANAGER_GUIDE)
    providers = read(PROVIDER_GUIDE)
    schemas = read(SCHEMAS)
    all_docs = "\n".join(read(path) for path in ALL_USER_DOCS)
    gaps: list[str] = []

    commands, options, defaults = cli_surface()
    for command in sorted(commands):
        if command not in cli:
            gaps.append(f"CLI command missing from docs/CLI_REFERENCE.md: {command}")
    for option in sorted(options):
        if option not in cli:
            gaps.append(f"CLI option missing from docs/CLI_REFERENCE.md: {option}")
    for default in sorted(defaults):
        if default not in cli:
            gaps.append(f"CLI default missing from docs/CLI_REFERENCE.md: {default}")

    for route in sorted(manager_routes()):
        if route not in manager:
            gaps.append(f"Manager route missing from docs/modules/local-manager.md: {route}")

    for name in sorted(source_environment_names()):
        if name not in all_docs:
            gaps.append(f"Environment variable missing from user documentation: {name}")

    # Only compare concrete filenames, not directory fragments or schema IDs.
    for name in sorted(source_artifact_names()):
        if name not in schemas and name not in manager:
            gaps.append(f"Serialized artifact name missing from docs/SCHEMAS.md or manager guide: {name}")

    return gaps


def main() -> int:
    gaps = find_gaps()
    if gaps:
        print("Source/documentation contract gaps detected:")
        print("\n".join(f"- {gap}" for gap in gaps))
        return 1
    print("Source/documentation contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
