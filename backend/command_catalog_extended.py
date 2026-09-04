"""
Extended command catalog for AdversaryFlow development labs.

Precise, technique-specific lab detection-validation tests for every ATT&CK
technique used by any actor that is not already covered by the hand-curated core
in ``command_catalog.py``. Authored across reviewable ``ext_part*.py`` files and
auto-merged here into a single ``EXTENDED`` dict.

Each entry declares a platform, command, operational note, and optional cleanup
command. Pre-compromise entries use the platform label ``PRE``.
"""

from __future__ import annotations

import importlib
from typing import Dict, List

EXTENDED: Dict[str, List[Dict[str, str]]] = {}

_PART_MODULES = tuple(f"ext_part{number}" for number in range(1, 15))

for _name in _PART_MODULES:
    _mod = importlib.import_module(f"{__package__}.{_name}")
    _part = getattr(_mod, "PART", None)
    if not isinstance(_part, dict):
        raise RuntimeError(f"{_name} does not expose a PART dictionary")
    _duplicates = set(EXTENDED).intersection(_part)
    if _duplicates:
        raise RuntimeError(f"duplicate extended technique ids in {_name}: {sorted(_duplicates)}")
    EXTENDED.update(_part)

if len(EXTENDED) != 437:
    raise RuntimeError(f"extended catalog integrity failure: expected 437 ids, found {len(EXTENDED)}")
