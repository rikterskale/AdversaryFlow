"""Host self-tests shared by the CLI and the read-only diagnostics API."""

from __future__ import annotations

import importlib.metadata
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from . import __version__, attack_data

MINIMUM_PYTHON = (3, 10)
MINIMUM_FREE_BYTES = 256 * 1024 * 1024
NETWORK_TIMEOUT_SECONDS = 5.0
CONTAINER_TOKEN_FILE = Path("/run/adversaryflow/api-token")


def _result(
    check_id: str,
    label: str,
    passed: bool,
    detail: str,
    fix: str,
    *,
    required: bool = True,
) -> Dict[str, Any]:
    return {
        "id": check_id,
        "label": label,
        "status": "PASS" if passed else "FAIL",
        "required": required,
        "detail": detail,
        "fix": "No action required." if passed else fix,
    }


def _python_check() -> Dict[str, Any]:
    version = ".".join(str(part) for part in sys.version_info[:3])
    passed = sys.version_info >= MINIMUM_PYTHON
    return _result(
        "python",
        "Python runtime",
        passed,
        f"Python {version}; minimum supported version is {'.'.join(map(str, MINIMUM_PYTHON))}.",
        "Install Python 3.10 or newer, recreate the virtual environment, and rerun adversaryflow doctor.",
    )


def _run_version_command(command: List[str]) -> subprocess.CompletedProcess[str]:
    kwargs: Dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": 5,
        "check": False,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.run(command, **kwargs)


def _running_in_container() -> bool:
    """Detect a conventional OCI/container runtime without invoking it."""
    if Path("/.dockerenv").is_file():
        return True
    try:
        control_groups = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False
    return any(marker in control_groups for marker in ("docker", "containerd", "kubepods", "podman"))


def _docker_check(*, containerized: bool | None = None) -> Dict[str, Any]:
    if containerized is None:
        containerized = _running_in_container()
    if containerized:
        return _result(
            "docker",
            "Docker and Compose context",
            True,
            "Running inside a container; the host Docker Engine and Compose plugin are intentionally outside this namespace.",
            "Run docker version and docker compose version on the host if the stack cannot be started.",
            required=False,
        )
    executable = shutil.which("docker")
    fix = "Install Docker Engine or Docker Desktop with the Compose v2 plugin, then ensure docker is on PATH."
    if not executable:
        return _result("docker", "Docker and Compose", False, "Docker was not found on PATH.", fix, required=False)
    try:
        engine = _run_version_command([executable, "version", "--format", "{{.Server.Version}}"])
        compose = _run_version_command([executable, "compose", "version", "--short"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _result("docker", "Docker and Compose", False, f"Docker version check failed: {exc}.", fix, required=False)
    engine_version = engine.stdout.strip()
    compose_version = compose.stdout.strip()
    passed = engine.returncode == 0 and compose.returncode == 0 and bool(engine_version and compose_version)
    if passed:
        detail = f"Docker {engine_version}; Compose {compose_version}."
    else:
        diagnostic = compose.stderr.strip() or engine.stderr.strip() or "version information was unavailable"
        detail = f"Docker or Compose could not report a version: {diagnostic}."
    return _result("docker", "Docker and Compose", passed, detail, fix, required=False)


def _frontend_check(frontend_dir: str) -> Dict[str, Any]:
    missing = [name for name in ("index.html", "styles.css", "app.js") if not (Path(frontend_dir) / name).is_file()]
    return _result(
        "frontend",
        "Frontend assets",
        not missing,
        f"Frontend assets are available at {frontend_dir}." if not missing else f"Missing: {', '.join(missing)}.",
        "Reinstall AdversaryFlow from a complete release or set ADVERSARYFLOW_FRONTEND_DIR to the built frontend directory.",
    )


def _dependency_check() -> tuple[Dict[str, Any], Dict[str, str | None]]:
    versions: Dict[str, str | None] = {}
    for package in ("Flask", "waitress"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    missing = [name for name, version in versions.items() if version is None]
    detail = ", ".join(f"{name} {version}" for name, version in versions.items() if version)
    return _result(
        "dependencies",
        "Pinned runtime dependencies",
        not missing,
        detail if not missing else f"Missing: {', '.join(missing)}.",
        "Reinstall from requirements.lock with --require-hashes, or reinstall the published wheel with pipx.",
    ), versions


def _container_service_is_live(port: int) -> bool:
    """Return whether this container's configured port belongs to AdversaryFlow."""
    try:
        token = CONTAINER_TOKEN_FILE.read_text(encoding="utf-8").strip()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        request = urllib.request.Request(f"http://127.0.0.1:{port}/api/live", headers=headers)
        with urllib.request.urlopen(request, timeout=1) as response:
            document: Any = json.load(response)
        return response.status == 200 and isinstance(document, dict) and document.get("status") == "live"
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _port_check(host: str, port: int, port_is_service: bool, *, containerized: bool = False) -> Dict[str, Any]:
    fix = f"Stop the process using {host}:{port}, or choose another port with --port or ADVERSARYFLOW_PORT."
    if port_is_service:
        return _result("port", "Service port", True, f"This AdversaryFlow service is listening on {host}:{port}.", fix)
    if containerized and _container_service_is_live(port):
        return _result(
            "port",
            "Service port",
            True,
            f"This container's AdversaryFlow service is already listening on port {port}.",
            fix,
        )
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise OSError(f"could not resolve {host}")
        errors: List[str] = []
        for family, socktype, protocol, _, address in addresses:
            try:
                with socket.socket(family, socktype, protocol) as probe:
                    if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    probe.bind(address)
                return _result("port", "Service port", True, f"{host}:{port} is available.", fix)
            except OSError as exc:
                errors.append(str(exc))
        raise OSError(errors[-1] if errors else "bind failed")
    except (OSError, OverflowError) as exc:
        return _result("port", "Service port", False, f"{host}:{port} is unavailable: {exc}.", fix)


def _cache_writable_check() -> tuple[Dict[str, Any], bool, str | None]:
    try:
        os.makedirs(attack_data.CACHE_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".adversaryflow-doctor-", dir=attack_data.CACHE_DIR):
            pass
        return _result(
            "cache_writable",
            "Cache directory",
            True,
            f"{attack_data.CACHE_DIR} is writable.",
            "Choose a writable directory with --cache-dir or ADVERSARYFLOW_CACHE_DIR.",
        ), True, None
    except OSError as exc:
        return _result(
            "cache_writable",
            "Cache directory",
            False,
            f"{attack_data.CACHE_DIR} is not writable: {exc}.",
            "Grant the current user write access, or choose a writable directory with --cache-dir or ADVERSARYFLOW_CACHE_DIR.",
        ), False, str(exc)


def _cache_integrity_check() -> Dict[str, Any]:
    present: List[str] = []
    invalid: List[str] = []
    for domain in attack_data.STIX_SOURCES:
        path = attack_data._cache_path(domain)
        if not os.path.isfile(path):
            continue
        present.append(domain)
        try:
            with attack_data._CACHE_LOCKS[domain]:
                metadata_path = attack_data._metadata_path(domain)
                if os.path.isfile(metadata_path):
                    with open(metadata_path, encoding="utf-8") as metadata_file:
                        metadata = json.load(metadata_file)
                    if not isinstance(metadata, dict):
                        raise ValueError("cache metadata is not a JSON object")
                attack_data._load_validated(path, domain)
        except (OSError, ValueError, TypeError) as exc:
            invalid.append(f"{domain}: {exc}")
    if invalid:
        return _result(
            "cache_integrity",
            "STIX cache integrity",
            False,
            "; ".join(invalid),
            "Run adversaryflow cache-clear --yes while the service is stopped, then restart online to download verified bundles.",
        )
    detail = (
        f"Validated cached STIX bundles: {', '.join(present)}."
        if present
        else "No cached STIX bundle exists yet; first launch will download and validate one."
    )
    return _result(
        "cache_integrity",
        "STIX cache integrity",
        True,
        detail,
        "Clear and refresh any invalid bundle with adversaryflow cache-clear --yes.",
    )


def _disk_space_check() -> Dict[str, Any]:
    fix = "Free at least 256 MiB on the cache volume, or move ADVERSARYFLOW_CACHE_DIR to a larger writable disk."
    try:
        os.makedirs(attack_data.CACHE_DIR, exist_ok=True)
        free = shutil.disk_usage(attack_data.CACHE_DIR).free
    except OSError as exc:
        return _result("disk_space", "Cache disk space", False, f"Disk space could not be read: {exc}.", fix)
    passed = free >= MINIMUM_FREE_BYTES
    return _result(
        "disk_space",
        "Cache disk space",
        passed,
        f"{free / (1024 * 1024):.0f} MiB free; 256 MiB minimum recommended.",
        fix,
    )


def _network_check(timeout: float) -> Dict[str, Any]:
    fix = (
        "Allow HTTPS to raw.githubusercontent.com, correct DNS/proxy/TLS settings, or start with --offline after populating the cache."
    )
    if attack_data.OFFLINE:
        return _result(
            "attack_feed",
            "ATT&CK feed reachability",
            False,
            "Offline mode is enabled, so the ATT&CK source was not contacted.",
            "Restart without --offline to test or refresh the live ATT&CK feed.",
            required=False,
        )
    source = attack_data.STIX_SOURCES["enterprise"]
    request = urllib.request.Request(
        source,
        headers={"User-Agent": f"AdversaryFlow/{__version__}"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
        passed = 200 <= status < 400
        detail = f"Official MITRE ATT&CK source responded over HTTPS with HTTP {status}."
        return _result("attack_feed", "ATT&CK feed reachability", passed, detail, fix, required=False)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return _result(
            "attack_feed",
            "ATT&CK feed reachability",
            False,
            f"Official MITRE ATT&CK source was unreachable: {exc}.",
            fix,
            required=False,
        )


def collect_diagnostics(
    frontend_dir: str,
    *,
    host: str = "127.0.0.1",
    port: int = 5000,
    port_is_service: bool = False,
    network_timeout: float = NETWORK_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Return a stable diagnostics contract without changing application state."""
    containerized = _running_in_container()
    dependency, versions = _dependency_check()
    writable, cache_writable, cache_error = _cache_writable_check()
    checks = [
        _python_check(),
        _docker_check(containerized=containerized),
        _frontend_check(frontend_dir),
        dependency,
        _port_check(host, port, port_is_service, containerized=containerized),
        writable,
        _cache_integrity_check(),
        _disk_space_check(),
        _network_check(network_timeout),
    ]
    required_failures = [check for check in checks if check["required"] and check["status"] == "FAIL"]
    passed = sum(1 for check in checks if check["status"] == "PASS")
    report: Dict[str, Any] = {
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": not required_failures,
        "summary": {
            "passed": passed,
            "failed": len(checks) - passed,
            "required_failed": len(required_failures),
        },
        "checks": checks,
        # Preserve the established machine-readable keys for installers and
        # operators that consumed the original doctor contract.
        "python": sys.version.split()[0],
        "frontend_dir": frontend_dir,
        "frontend_available": next(check["status"] == "PASS" for check in checks if check["id"] == "frontend"),
        "cache": attack_data.cache_status(),
        "cache_writable": cache_writable,
        "dependencies": versions,
    }
    if cache_error:
        report["cache_error"] = cache_error
    return report
