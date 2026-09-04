"""Shared helpers for the extended benign-command part files."""
from __future__ import annotations
from typing import Dict


def c(platform: str, command: str, note: str = "", cleanup: str = "") -> Dict[str, str]:
    return {"platform": platform, "command": command, "note": note, "cleanup": cleanup}


# Operator should repoint this at infrastructure they own before running.
SAFE_HOST = "example.com"
