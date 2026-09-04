"""Shared helpers for the extended lab-command part files."""
from __future__ import annotations
from typing import Dict


def c(platform: str, command: str, note: str = "", cleanup: str = "") -> Dict[str, str]:
    return {"platform": platform, "command": command, "note": note, "cleanup": cleanup}


# Default example target used by catalog entries.
EXAMPLE_HOST = "example.com"
