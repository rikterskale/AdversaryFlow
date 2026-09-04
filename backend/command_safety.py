"""Structured safety metadata for catalog commands.

The catalog predates the safety model, so metadata is derived conservatively
from each command and note. Individual entries can override any derived field
by passing keyword arguments through the catalog helpers.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


_NETWORK_MARKERS = (
    "http://", "https://", "invoke-webrequest", "downloadstring", "curl ", "wget ", "nslookup",
    "resolve-dnsname", "test-netconnection", "ping ", "git ls-remote",
    "net view", "net use", "tracert", "traceroute", "ssh ",
)
_WRITE_MARKERS = (
    "reg add", "reg save", "schtasks /create", "sc.exe create", "net user adversaryflow",
    "set-content", "add-content", "out-file", "copy ", "mkdir", "md ",
    " >", "compress-archive", "tar czf", "crontab -",
)
_HIGH_RISK_MARKERS = (
    "reg save hklm\\sam", "net user adversaryflow", "sc.exe create", "lockworkstation",
    "schtasks /create", "crontab -", "hklm\\security", "sysvol",
)


def _network_targets(command: str) -> List[str]:
    targets = re.findall(r"https?://([^/\s'\"]+)", command, flags=re.IGNORECASE)
    if "example.com" in command.lower() and "example.com" not in targets:
        targets.append("example.com")
    return list(dict.fromkeys(targets))


def command_record(
    platform: str,
    command: str,
    note: str = "",
    cleanup: str = "",
    **overrides: Any,
) -> Dict[str, Any]:
    """Return a command with conservative, machine-readable safety metadata."""
    text = f"{command} {note}".lower()
    requires_network = any(marker in text for marker in _NETWORK_MARKERS)
    writes_state = any(marker in text for marker in _WRITE_MARKERS)
    requires_admin = "requires admin" in text or any(
        marker in text for marker in ("reg save hklm", "sc.exe create", "hklm\\security")
    )
    high_risk = any(marker in text for marker in _HIGH_RISK_MARKERS)
    risk = "high" if high_risk else "medium" if (writes_state or requires_network) else "low"

    side_effects: List[str] = []
    if writes_state:
        side_effects.append("changes_local_state")
    if requires_network:
        side_effects.append("network_activity")
    if "credential" in text or "password" in text or "sam" in text:
        side_effects.append("credential_store_access")
    if "lockworkstation" in text or "locks screen" in text:
        side_effects.append("interactive_session_disruption")
    if not side_effects:
        side_effects.append("read_only_or_process_telemetry")

    record: Dict[str, Any] = {
        "platform": platform,
        "command": command,
        "note": note,
        "cleanup": cleanup,
        "risk": risk,
        "side_effects": side_effects,
        "requires_admin": requires_admin,
        "requires_network": requires_network,
        "network_targets": _network_targets(command),
        "prerequisites": [f"{platform} command environment", "authorized disposable lab"],
        "expected_telemetry": "Process and command-line telemetry aligned to the selected ATT&CK technique.",
        "expected_output": note or "Command-specific output; verify the expected telemetry in the detection platform.",
        "timeout_seconds": 60,
        "rollback": cleanup,
        "cleanup_required": bool(cleanup),
        "acknowledgment_required": risk in {"medium", "high"},
    }
    record.update(overrides)
    return record
