"""Shared helpers for the extended lab-command part files."""
from __future__ import annotations

from typing import Any, Dict

from .command_safety import command_record


def c(platform: str, command: str, note: str = "", cleanup: str = "", **metadata: Any) -> Dict[str, Any]:
    return command_record(platform, command, note, cleanup, **metadata)


# Loopback-only stand-ins for former public-Internet probes. Catalog commands
# must not contact third-party hosts; operators who need a real target can edit.
LOOPBACK_TCP = (
    "powershell -NoProfile -Command \"Test-NetConnection 127.0.0.1 -Port 9 | "
    "Select ComputerName,TcpTestSucceeded\""
)
LOOPBACK_TCP_NOTE = "Loopback-only connection check. Does not contact the public internet."
LOOPBACK_DNS = "nslookup localhost"
LOOPBACK_PING = "ping -n 1 127.0.0.1"


def loopback_tcp(note: str = LOOPBACK_TCP_NOTE) -> Dict[str, Any]:
    # Loopback-only: exempt from the external-network guardrail but still
    # labelled with a loopback target for operator review.
    return c("windows", LOOPBACK_TCP, note, network_targets=["127.0.0.1"])
