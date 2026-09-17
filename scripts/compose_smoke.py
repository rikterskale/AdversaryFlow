"""Build the Compose stack and wait for its authenticated readiness endpoint."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import List

PROJECT = "adversaryflow-smoke"
PORT = os.environ.get("ADVERSARYFLOW_SMOKE_PORT", "5010")
TIMEOUT_SECONDS = int(os.environ.get("ADVERSARYFLOW_SMOKE_TIMEOUT", "600"))


def compose(arguments: List[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "ADVERSARYFLOW_PORT": PORT}
    return subprocess.run(
        ["docker", "compose", "--project-name", PROJECT, *arguments],
        check=False,
        capture_output=capture,
        text=True,
        env=environment,
    )


def token() -> str:
    result = compose(
        ["exec", "-T", "adversaryflow", "cat", "/run/adversaryflow/api-token"],
        capture=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def ready(api_token: str) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/api/health",
        headers={"Authorization": f"Bearer {api_token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            document = json.load(response)
        return response.status == 200 and document.get("status") == "ready" and document.get("ready") is True
    except (OSError, ValueError, urllib.error.URLError):
        return False


def main() -> int:
    if compose(["config", "--quiet"]).returncode != 0:
        print("Compose configuration is invalid.", file=sys.stderr)
        return 1

    try:
        if compose(["up", "--build", "--detach", "--wait", "--wait-timeout", str(TIMEOUT_SECONDS)]).returncode != 0:
            print("Compose stack did not become healthy.", file=sys.stderr)
            compose(["logs", "--no-color"])
            return 1

        api_token = token()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if api_token and ready(api_token):
                print(f"Compose smoke test passed: http://127.0.0.1:{PORT}/api/health is ready")
                return 0
            time.sleep(1)
            api_token = api_token or token()

        print("Container became healthy but the authenticated readiness request failed.", file=sys.stderr)
        compose(["logs", "--no-color"])
        return 1
    finally:
        compose(["down", "--remove-orphans"])


if __name__ == "__main__":
    raise SystemExit(main())
