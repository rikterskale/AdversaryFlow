"""
Extended benign command library for AdversaryFlow.

Precise, technique-specific benign detection-validation tests for every ATT&CK
technique used by any actor that is not already covered by the hand-curated core
in ``benign_commands.py``. Authored across reviewable ``ext_part*.py`` files and
auto-merged here into a single ``EXTENDED`` dict.

Safety contract (identical to the core library):
  * No data destruction, no reboot-surviving persistence, no privilege changes,
    no real C2 callbacks. Destructive-sounding techniques get read-only or
    echo-only proxies that change nothing.
  * Anything that writes creates a clearly-labelled temp artifact + `cleanup`.
  * Pre-compromise (Reconnaissance / Resource Development, platform "PRE")
    techniques are host-benign OSINT/planning proxies — they will not fire
    endpoint detections and are labelled as such.
"""

from __future__ import annotations

import glob
import importlib
import os
import re
from typing import Dict, List

EXTENDED: Dict[str, List[Dict[str, str]]] = {}

_here = os.path.dirname(__file__)
for _path in sorted(glob.glob(os.path.join(_here, "ext_part*.py")),
                    key=lambda p: int(re.search(r"ext_part(\d+)", p).group(1))):
    _mod = importlib.import_module(os.path.splitext(os.path.basename(_path))[0])
    EXTENDED.update(getattr(_mod, "PART", {}))
