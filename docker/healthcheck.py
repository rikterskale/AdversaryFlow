"""Container readiness probe for the bearer-protected local API."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TOKEN_FILE = Path("/run/adversaryflow/api-token")


def _health_url() -> str:
    """Probe the configured container port without depending on its bind address."""
    port = int(os.environ.get("ADVERSARYFLOW_PORT", "5000"))
    if not 1 <= port <= 65535:
        raise ValueError("ADVERSARYFLOW_PORT must be between 1 and 65535")
    return f"http://127.0.0.1:{port}/api/health"


def main() -> int:
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        request = urllib.request.Request(
            _health_url(),
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            document: Any = json.load(response)
        return 0 if response.status == 200 and document.get("ready") is True else 1
    except (OSError, ValueError, urllib.error.URLError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
