"""Build the Compose stack and wait for its authenticated readiness endpoint."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import List

PROJECT = f"adversaryflow-smoke-{uuid.uuid4().hex[:10]}"
COMPOSE_FILES: List[str] = []
PORT = os.environ.get("ADVERSARYFLOW_SMOKE_PORT", "5010")
TIMEOUT_SECONDS = int(os.environ.get("ADVERSARYFLOW_SMOKE_TIMEOUT", "600"))


def compose(arguments: List[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "ADVERSARYFLOW_PORT": PORT}
    return subprocess.run(
        ["docker", "compose", *COMPOSE_FILES, "--project-name", PROJECT, *arguments],
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


def smoke(*, fresh: bool, image: str | None) -> int:
    if compose(["config", "--quiet"]).returncode != 0:
        print("Compose configuration is invalid.", file=sys.stderr)
        return 1

    try:
        if fresh and compose(["build", "--pull", "--no-cache"]).returncode != 0:
            return 1
        build_option = "--no-build" if fresh or image else "--build"
        if compose(["up", build_option, "--detach", "--wait", "--wait-timeout", str(TIMEOUT_SECONDS)]).returncode != 0:
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
        # Both project and volume names are unique to this run. Never touch the
        # operator's regular Compose stack or its persistent ATT&CK cache.
        compose(["down", "--volumes", "--remove-orphans"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh", action="store_true", help="pull base images and build with no layer cache")
    parser.add_argument("--image", help="test an already-built image with an empty, isolated cache volume")
    args = parser.parse_args()
    if args.fresh and args.image:
        parser.error("choose --fresh or --image")
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="adversaryflow-compose-") as directory:
        override = Path(directory) / "override.json"
        config = {
            "volumes": {"adversaryflow-stix-cache": {"name": f"{PROJECT}-cache"}},
            "services": {"adversaryflow": {"image": args.image or f"adversaryflow:{PROJECT}"}},
        }
        override.write_text(json.dumps(config), encoding="utf-8")
        COMPOSE_FILES[:] = ["--file", str(root / "docker-compose.yml"), "--file", str(override)]
        return smoke(fresh=args.fresh, image=args.image)


if __name__ == "__main__":
    raise SystemExit(main())
