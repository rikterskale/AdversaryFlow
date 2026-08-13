import importlib
import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from .emulation import default_catalog_path, load_catalog
from .models import RulesOfEngagement
from .platforms import detect_platform, platform_supported


def _check(name: str, passed: bool, detail: str, remediation: str = "") -> dict[str, str | bool]:
    return {"name": name, "passed": passed, "detail": detail, "remediation": remediation}


def apply_safe_fixes(root: str | Path = ".") -> list[str]:
    """Create local AdversaryFlow folders without changing system configuration."""
    base = Path(root)
    created: list[str] = []
    for relative in ("artifacts", "artifacts/runs", "artifacts/campaigns", "artifacts/support"):
        path = base / relative
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created.append(relative)
    return created


def run_doctor(
    roe_path: str = "examples/roe.yaml",
    catalog_path: str = "content/abilities/catalog.json",
    fix: bool = False,
) -> dict[str, Any]:
    fixes_applied = apply_safe_fixes() if fix else []
    checks: list[dict[str, str | bool]] = []
    if not Path(roe_path).exists() and roe_path == "examples/roe.yaml":
        roe_path = str(__import__("importlib.resources", fromlist=["files"]).files("adversaryflow.resources").joinpath("roe.yaml"))
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    detected = detect_platform()
    checks.append(_check("supported-platform", platform_supported(), detected, "Supported platforms: Windows, Debian, Ubuntu, and Kali."))
    version_ok = sys.version_info >= (3, 11)
    checks.append(_check("python", version_ok, platform.python_version(), "Install Python 3.11 or newer."))
    try:
        importlib.import_module("yaml")
        checks.append(_check("dependency:PyYAML", True, "available"))
    except ImportError:
        checks.append(_check("dependency:PyYAML", False, "missing", "Run: pip install -e ."))
    try:
        with Path(roe_path).open(encoding="utf-8") as handle:
            RulesOfEngagement.from_mapping(__import__("yaml").safe_load(handle) or {})
        checks.append(_check("roe", True, f"valid: {roe_path}"))
    except Exception as exc:
        checks.append(_check("roe", False, str(exc), f"Fix or recreate {roe_path}."))
    try:
        abilities = load_catalog(catalog_path)
        checks.append(_check("ability-catalog", bool(abilities), f"{len(abilities)} abilities loaded"))
    except Exception as exc:
        checks.append(_check("ability-catalog", False, str(exc), f"Fix {catalog_path}."))
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
        checks.append(_check("loopback", True, "127.0.0.1 is available"))
    except OSError as exc:
        checks.append(_check("loopback", False, str(exc), "Allow local loopback binding."))
    checks.append(_check("offline-mode", True, "available; no provider key required"))
    failed = [item for item in checks if not item["passed"]]
    guidance = [
        {"check": item["name"], "problem": item["detail"], "fix": item["remediation"]}
        for item in failed
        if item["remediation"]
    ]
    return {
        "product": "AdversaryFlow",
        "version": "0.1.0",
        "platform": detected,
        "platform_detail": platform.platform(),
        "cwd": os.getcwd(),
        "supported_platforms": ["Windows", "Debian", "Ubuntu", "Kali"],
        "passed": not failed,
        "checks": checks,
        "fixes_applied": fixes_applied,
        "guided_fixes": guidance,
    }
