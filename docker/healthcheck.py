"""Container readiness probe for the bearer-protected local API."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TOKEN_FILE = Path("/run/adversaryflow/api-token")
HEALTH_URL = "http://127.0.0.1:5000/api/health"


def main() -> int:
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        request = urllib.request.Request(
            HEALTH_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            document: Any = json.load(response)
        return 0 if response.status == 200 and document.get("ready") is True else 1
    except (OSError, ValueError, urllib.error.URLError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
