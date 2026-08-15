"""Fail CI when known documentation coverage gaps are present.

This is deliberately a gap detector, not a documentation generator.  Its
checks are anchored to repository source and report the exact documentation
surface that is missing.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _cli_commands() -> set[str]:
    tree = ast.parse(_read("src/adversaryflow/cli.py"))
    commands: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            commands.add(str(node.args[0].value))
    return commands


def _manager_endpoints() -> set[str]:
    source = _read("src/adversaryflow/manager.py")
    return set(re.findall(r'path\s*==\s*"(/api/[^"?]+)"', source))


def find_gaps() -> list[str]:
    cli_reference = _read("docs/CLI_REFERENCE.md")
    examples = _read("docs/EXAMPLES.md")
    architecture = _read("docs/ARCHITECTURE.md")
    manager_docs = _read("docs/modules/local-manager.md")
    source_manager = _read("src/adversaryflow/manager.py")
    gaps: list[str] = []

    # The CLI reference is the declared single source of truth for commands.
    # The parser surface check remains in validate_documentation.py; this
    # check specifically requires representative, runnable examples for the
    # newer operational commands.
    example_commands = {
        "intel-sync": "DOC-GAP-002",
        "telemetry normalize": "DOC-GAP-003",
        "telemetry export": "DOC-GAP-004",
        "detection export": "DOC-GAP-005",
        "coverage": "DOC-GAP-006",
        "campaign retest": "DOC-GAP-007",
    }
    for command, gap_id in example_commands.items():
        if command not in examples:
            gaps.append(f"{gap_id}: docs/EXAMPLES.md has no worked example for `{command}`.")

    # Manager-only operations are implemented behind the HTTP API.  Require
    # the public endpoint names in the manager module guide so the API surface
    # cannot silently outgrow its documentation.
    documented_endpoints = {
        endpoint
        for endpoint in _manager_endpoints()
        if endpoint in manager_docs
    }
    missing_endpoints = sorted(_manager_endpoints() - documented_endpoints)
    if missing_endpoints:
        gaps.append(
            "DOC-GAP-001: docs/modules/local-manager.md does not document "
            "manager API endpoints: " + ", ".join(missing_endpoints) + "."
        )

    manager_features = {
        "actor profiles": ("actor-profile", "DOC-GAP-008"),
        "benign procedures": ("benign-procedure", "DOC-GAP-009"),
        "CTID fixtures": ("ctid-fixture", "DOC-GAP-010"),
        "archive controls": ("retention", "DOC-GAP-011"),
        "executive summaries": ("executive-summary", "DOC-GAP-012"),
        "RoE editor": ("RoE editor", "DOC-GAP-013"),
    }
    for feature, (marker, gap_id) in manager_features.items():
        if marker.lower() not in manager_docs.lower():
            gaps.append(f"{gap_id}: local-manager documentation omits {feature}.")

    # These schemas are emitted or consumed by user-facing workflows and
    # currently have no dedicated documentation surface.
    schema_markers = {
        "ADVERSARYFLOW-ABILITY-CATALOG-1": "DOC-GAP-014",
        "ADVERSARYFLOW-BENIGN-PROCEDURES-1": "DOC-GAP-015",
        "ADVERSARYFLOW-TELEMETRY-1": "DOC-GAP-016",
    }
    schema_docs = "\n".join(
        _read(path)
        for path in (
            "docs/CLI_REFERENCE.md",
            "docs/USAGE.md",
            "docs/modules/local-manager.md",
            "docs/modules/providers.md",
            "docs/DETECTION_VALIDATION.md",
        )
    )
    for schema, gap_id in schema_markers.items():
        if schema not in schema_docs:
            gaps.append(f"{gap_id}: no user documentation identifies schema `{schema}`.")

    # The bundled page contains contradictory approval instructions.  Keep
    # this check until the stale copy is removed or explicitly reconciled.
    cli_only = "approval is deliberately CLI-only" in source_manager or "Use CLI" in source_manager
    browser_approval = "approve and run local synthetic emulation" in source_manager
    if cli_only and browser_approval:
        gaps.append(
            "DOC-GAP-017: src/adversaryflow/manager.py contains contradictory "
            "browser approval instructions; reconcile the stale page copy."
        )

    # Keep the command extraction live so a future parser change cannot make
    # this script silently stop checking the CLI reference.
    undocumented_commands = sorted(command for command in _cli_commands() if command not in cli_reference)
    if undocumented_commands:
        gaps.append(
            "DOC-GAP-018: docs/CLI_REFERENCE.md omits parser commands: "
            + ", ".join(undocumented_commands)
            + "."
        )
    return gaps


def main() -> int:
    gaps = find_gaps()
    if gaps:
        print("Documentation gaps detected:")
        print("\n".join(f"- {gap}" for gap in gaps))
        return 1
    print("Documentation gap analysis passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
