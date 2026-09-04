"""Shared helpers for the extended lab-command part files."""
from __future__ import annotations
from typing import Any, Dict

from .command_safety import command_record


def c(platform: str, command: str, note: str = "", cleanup: str = "", **metadata: Any) -> Dict[str, Any]:
    return command_record(platform, command, note, cleanup, **metadata)


# Default example target used by catalog entries.
EXAMPLE_HOST = "example.com"
