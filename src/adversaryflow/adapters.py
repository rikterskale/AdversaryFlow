"""Fixed, simulation-only execution adapters.

Adapters receive reviewed ability metadata, never operator-provided commands. The
only registered adapter is local synthetic emulation; it may use an engine-owned
loopback sink, but cannot contact a campaign target.
"""

from dataclasses import asdict, dataclass
from typing import Protocol

from .ai import AICampaignDraft
from .emulation import Ability, validate_ability
from .loopback import LoopbackSink


MAX_ADAPTER_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class AdapterRequest:
    """Reviewed inputs made available to a fixed execution adapter."""

    draft: AICampaignDraft
    abilities: tuple[Ability, ...]
    run_id: str
    timeout_seconds: int = 30


@dataclass(frozen=True)
class AdapterResult:
    adapter: str
    events: tuple[dict, ...]


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
                    "ability_id": ability.id,
                    "technique_id": ability.technique_id,
                    "target": request.draft.target,
                    "behavior_success": True,
                    "telemetry": [asdict(item) for item in ability.expected_telemetry],
                    "observed_loopback_requests": observed,
                    "network_scope": ability.network_scope,
                    "execution": "synthetic-harness-only",
                    "adapter": self.name,
                })
        return AdapterResult(adapter=self.name, events=tuple(events))


_REGISTERED_ADAPTERS: dict[str, ExecutionAdapter] = {"local-synthetic": LocalSyntheticAdapter()}


def resolve_adapter(name: str = "local-synthetic") -> ExecutionAdapter:
    """Return a built-in adapter only; external adapter loading is deliberately absent."""
    try:
        return _REGISTERED_ADAPTERS[name]
    except KeyError as error:
        raise ValueError(f"Unsupported execution adapter: {name}") from error
