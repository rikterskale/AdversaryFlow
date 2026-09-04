#!/usr/bin/env python3
"""Create a deterministic CycloneDX SBOM from the locked runtime set."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path

from backend import __version__


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    components = []
    for raw in (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "--")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^ \\]+)", line)
        if not match:
            continue
        name, version = match.groups()
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        })
    components.sort(key=lambda item: item["name"].lower())
    serial_seed = json.dumps(components, sort_keys=True).encode()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(serial_seed).hexdigest())}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "adversaryflow",
                "version": __version__,
                "purl": f"pkg:pypi/adversaryflow@{__version__}",
            }
        },
        "components": components,
    }
    output = ROOT / "dist" / "adversaryflow.cdx.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
