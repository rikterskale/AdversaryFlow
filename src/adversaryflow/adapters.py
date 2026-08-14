"""Fixed synthetic and benign local-behavior execution adapters.

Adapters receive reviewed ability metadata, never operator-provided commands. The
synthetic adapter may use an engine-owned loopback sink. The behavioral adapter
can invoke only code-owned, read-only commands and cannot contact a campaign
target.
"""

import hashlib
import shutil
import subprocess  # nosec B404 - fixed registry only; shell execution is never used
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .ai import AICampaignDraft
from .emulation import Ability, validate_ability
from .idpt import execute as execute_idpt, readiness as idpt_readiness
from .idpt_registry import resolve_scenario
from .loopback import LoopbackSink


MAX_ADAPTER_TIMEOUT_SECONDS = 60
ADAPTER_CONTRACT_VERSION = "ADVERSARYFLOW-ADAPTER-1"


@dataclass(frozen=True)
class AdapterRequest:
    """Reviewed inputs made available to a fixed execution adapter."""

    draft: AICampaignDraft
    abilities: tuple[Ability, ...]
    run_id: str
    timeout_seconds: int = 30
    work_root: str | None = None
    approval_id: str | None = None
    approver: str | None = None
    approved_at: str | None = None
    parent_plan_hash: str | None = None


@dataclass(frozen=True)
class AdapterResult:
    adapter: str
    events: tuple[dict, ...]


@dataclass(frozen=True)
class AdapterPreflight:
    """Evidence that the fixed adapter accepted only reviewed, safe inputs."""

    contract_version: str
    adapter: str
    ability_ids: tuple[str, ...]
    network_scopes: tuple[str, ...]


class ExecutionAdapter(Protocol):
    name: str

    def execute(self, request: AdapterRequest) -> AdapterResult: ...


def validate_adapter_request(request: AdapterRequest) -> None:
    """Fail closed unless the request remains inside the simulation boundary."""
    if not request.run_id:
        raise ValueError("adapter run_id is required")
    if not 1 <= request.timeout_seconds <= MAX_ADAPTER_TIMEOUT_SECONDS:
        raise ValueError(f"adapter timeout must be between 1 and {MAX_ADAPTER_TIMEOUT_SECONDS} seconds")
    if not request.abilities:
        raise ValueError("adapter requires at least one reviewed ability")
    selected_ids = {ability.id for ability in request.abilities}
    if selected_ids != set(request.draft.ability_ids):
        raise ValueError("adapter abilities must exactly match the reviewed draft")
    for ability in request.abilities:
        validate_ability(ability)
        if ability.fidelity not in {"synthetic", "behavioral"}:
            raise ValueError("adapter supports synthetic and loopback behavioral abilities only")


class LocalSyntheticAdapter:
    """Emit synthetic events and optional engine-owned loopback markers."""

    name = "local-synthetic"

    def execute(self, request: AdapterRequest) -> AdapterResult:
        validate_adapter_request(request)
        events: list[dict] = []
        with LoopbackSink() as sink:
            for ability in request.abilities:
                observed = []
                if ability.network_scope == "loopback":
                    sink.send_marker(request.run_id)
                    observed = sink.received
                events.append({
                    "event": "simulation_completed",
                    "run_id": request.run_id,
                    "host_id": request.draft.target,
                    "ability_id": ability.id,
                    "technique_id": ability.technique_id,
                    "target": request.draft.target,
                    "behavior_success": True,
                    "telemetry": [asdict(item) for item in ability.expected_telemetry],
                    "observed_loopback_requests": observed,
                    "network_scope": ability.network_scope,
                    "execution": "synthetic-harness-only",
                    "adapter": self.name,
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                    "cleanup_status": "not-required",
                })
        return AdapterResult(adapter=self.name, events=tuple(events))


_FIXED_BEHAVIOR_ACTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "windows-current-identity": ("whoami.exe", ("/all",)),
    "windows-system-information": ("powershell.exe", ("-NoProfile", "-NonInteractive", "-Command", "[System.Environment]::OSVersion.VersionString; [System.Runtime.InteropServices.RuntimeInformation]::OSDescription")),
    "windows-network-configuration": ("ipconfig.exe", ("/all",)),
    "windows-process-discovery": ("powershell.exe", ("-NoProfile", "-NonInteractive", "-Command", "Get-Process | Select-Object -First 200 -Property Id,ProcessName,Path | ConvertTo-Csv -NoTypeInformation")),
    "windows-local-administrators": ("net.exe", ("localgroup", "administrators")),
    "linux-current-identity": ("id", ()),
    "linux-system-information": ("uname", ("-a",)),
    "linux-process-discovery": ("ps", ("-eo", "pid,comm")),
    "macos-current-identity": ("id", ()),
    "macos-system-information": ("sw_vers", ()),
    "macos-process-discovery": ("ps", ("-axo", "pid,comm")),
}


class LocalBehavioralAdapter:
    """Execute only fixed, code-reviewed, read-only local behavior actions."""

    name = "local-behavioral"

    def execute(self, request: AdapterRequest) -> AdapterResult:
        validate_adapter_request(request)
        if not request.work_root:
            raise ValueError("behavioral adapter requires a run-owned work root")
        work_root = Path(request.work_root).resolve()
        work_root.mkdir(parents=True, exist_ok=True)
        events: list[dict] = []
        for ability in request.abilities:
            action = ability.execution_action
            if action not in _FIXED_BEHAVIOR_ACTIONS:
                raise ValueError(f"No reviewed behavioral action is registered for {ability.id}")
            command, args = _FIXED_BEHAVIOR_ACTIONS[action]
            executable = shutil.which(command)
            started = time.monotonic()
            event = {
                "event": "behavior_completed", "run_id": request.run_id, "host_id": request.draft.target,
                "ability_id": ability.id, "technique_id": ability.technique_id, "target": request.draft.target,
                "telemetry": [asdict(item) for item in ability.expected_telemetry], "network_scope": ability.network_scope,
                "execution": "fixed-local-behavior", "execution_action": action, "adapter": self.name,
                "executed_at": datetime.now(timezone.utc).isoformat(), "cleanup_status": "not-required",
            }
            if executable is None:
                event.update({"behavior_success": False, "failure": f"Required executable is unavailable: {command}", "exit_code": None})
            else:
                try:
                    # The executable is resolved locally and every argument comes
                    # from the code-owned registry above, never campaign input.
                    completed = subprocess.run(  # nosec B603
                        [executable, *args],
                        cwd=work_root,
                        capture_output=True,
                        timeout=min(ability.execution_timeout_seconds, request.timeout_seconds),
                        check=False,
                    )
                    stdout = completed.stdout[:65536]; stderr = completed.stderr[:65536]
                    event.update({
                        "behavior_success": completed.returncode == 0, "exit_code": completed.returncode,
                        "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                        "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "output_truncated": len(completed.stdout) > len(stdout) or len(completed.stderr) > len(stderr),
                    })
                    if completed.returncode != 0:
                        event["failure"] = f"Fixed behavioral action exited with code {completed.returncode}"
                except subprocess.TimeoutExpired:
                    event.update({"behavior_success": False, "failure": "Fixed behavioral action timed out", "exit_code": None})
            event["duration_ms"] = round((time.monotonic() - started) * 1000)
            events.append(event)
        return AdapterResult(adapter=self.name, events=tuple(events))


class IdptLocalAdapter:
    """Delegate one fixed scenario to an exact reviewed local IDPT checkout."""

    name = "idpt-local"

    def execute(self, request: AdapterRequest) -> AdapterResult:
        validate_adapter_request(request)
        if not request.work_root:
            raise ValueError("idpt-local requires a run-owned work root")
        required = {
            "approval_id": request.approval_id,
            "approver": request.approver,
            "approved_at": request.approved_at,
            "parent_plan_hash": request.parent_plan_hash,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"idpt-local requires approval context: {', '.join(missing)}")
        events = execute_idpt(
            draft=request.draft,
            abilities=request.abilities,
            run_id=request.run_id,
            work_root=request.work_root,
            timeout_seconds=request.timeout_seconds,
            approval_id=request.approval_id or "",
            approver=request.approver or "",
            approved_at=request.approved_at or "",
            parent_plan_hash=request.parent_plan_hash or "",
        )
        return AdapterResult(adapter=self.name, events=events)


_REGISTERED_ADAPTERS: dict[str, ExecutionAdapter] = {
    "local-synthetic": LocalSyntheticAdapter(),
    "local-behavioral": LocalBehavioralAdapter(),
    "idpt-local": IdptLocalAdapter(),
}


def resolve_adapter(name: str = "local-synthetic") -> ExecutionAdapter:
    """Return a built-in adapter only; external adapter loading is deliberately absent."""
    try:
        return _REGISTERED_ADAPTERS[name]
    except KeyError as error:
        raise ValueError(f"Unsupported execution adapter: {name}") from error


def preflight_adapter(name: str, request: AdapterRequest) -> tuple[ExecutionAdapter, AdapterPreflight]:
    """Resolve and validate a built-in adapter before it receives any execution work."""
    adapter = resolve_adapter(name)
    validate_adapter_request(request)
    if name == "local-behavioral" and any(ability.execution_action not in _FIXED_BEHAVIOR_ACTIONS for ability in request.abilities):
        raise ValueError("Behavioral plans may contain only registered fixed execution actions")
    if name == "idpt-local":
        resolve_scenario({ability.id for ability in request.abilities})
    return adapter, AdapterPreflight(
        contract_version=ADAPTER_CONTRACT_VERSION,
        adapter=adapter.name,
        ability_ids=tuple(ability.id for ability in request.abilities),
        network_scopes=tuple(sorted({ability.network_scope for ability in request.abilities})),
    )


def adapter_readiness(abilities: tuple[Ability, ...], name: str = "local-synthetic") -> dict:
    """Return a read-only compatibility report for the fixed adapter boundary."""
    try:
        adapter = resolve_adapter(name)
        for ability in abilities:
            validate_ability(ability)
            if ability.fidelity not in {"synthetic", "behavioral"}:
                raise ValueError(f"Unsupported ability fidelity: {ability.fidelity}")
            if name == "local-behavioral" and ability.execution_action not in _FIXED_BEHAVIOR_ACTIONS:
                raise ValueError(f"No reviewed behavioral action is registered for {ability.id}")
        if name == "idpt-local":
            resolve_scenario({ability.id for ability in abilities})
        scopes = sorted({ability.network_scope for ability in abilities})
        external = idpt_readiness(abilities) if name == "idpt-local" else {}
        return {
            "adapter": adapter.name,
            "contract_version": ADAPTER_CONTRACT_VERSION,
            "execution_boundary": "pinned-idpt-local" if name == "idpt-local" else ("fixed-local-behavior" if name == "local-behavioral" else "simulation-only"),
            "allowed_network_scopes": ["none", "loopback"],
            "catalog_network_scopes": scopes,
            "ability_count": len(abilities),
            "compatible": bool(abilities),
            "detail": f"{len(abilities)} reviewed abilities are compatible with {adapter.name}.",
            **external,
        }
    except ValueError as error:
        return {
            "adapter": name,
            "contract_version": ADAPTER_CONTRACT_VERSION,
            "execution_boundary": "simulation-only",
            "compatible": False,
            "detail": str(error),
        }
