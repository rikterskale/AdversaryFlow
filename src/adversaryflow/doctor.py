import importlib
import json
import os
import platform
import socket
import sys
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any

from .emulation import default_catalog_path, load_catalog
from .adapters import adapter_readiness
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
    abilities = ()
    try:
        abilities = load_catalog(catalog_path)
        checks.append(_check("ability-catalog", bool(abilities), f"{len(abilities)} abilities loaded"))
    except Exception as exc:
        checks.append(_check("ability-catalog", False, str(exc), f"Fix {catalog_path}."))
    readiness = adapter_readiness(abilities)
    checks.append(_check("execution-adapter", bool(readiness["compatible"]), str(readiness["detail"]), "Use a reviewed catalog with the built-in local-synthetic adapter."))
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
        checks.append(_check("loopback", True, "127.0.0.1 is available"))
    except OSError as exc:
        checks.append(_check("loopback", False, str(exc), "Allow local loopback binding."))
    checks.append(_check("offline-mode", True, "available; no provider key required"))
    from .provider import load_provider_config, validate_provider_config
    provider_config = load_provider_config()
    provider_errors = validate_provider_config(provider_config)
    provider_detail = "offline mode is active" if provider_config.name == "offline" else (f"profile '{provider_config.profile_name}' is policy-approved and ready" if not provider_errors else "Hosted provider is not ready; run adversaryflow provider diagnose.")
    provider_readiness = {"ready": not provider_errors, "configuration": provider_config.as_dict(), "detail": provider_detail, "next": "Run: adversaryflow provider policy status, then allow the reviewed profile before a hosted request." if provider_errors else "Provider profile and policy are ready."}
    failed = [item for item in checks if not item["passed"]]
    guidance = [
        {"check": item["name"], "problem": item["detail"], "fix": item["remediation"]}
        for item in failed
        if item["remediation"]
    ]
    try:
        product_version = package_version("adversaryflow")
    except PackageNotFoundError:
        product_version = "0.2.3"
    return {
        "product": "AdversaryFlow",
        "version": product_version,
        "platform": detected,
        "platform_detail": platform.platform(),
        "cwd": os.getcwd(),
        "supported_platforms": ["Windows", "Debian", "Ubuntu", "Kali"],
        "passed": not failed,
        "checks": checks,
        "fixes_applied": fixes_applied,
        "guided_fixes": guidance,
        "adapter_readiness": readiness,
        "provider_readiness": provider_readiness,
    }
