from __future__ import annotations

from typing import Any

from adversaryflow.pipeline.node_runner import NodeRunner, RetryPolicy


class FlakyProvider:
    def __init__(self) -> None:
        self.call_count = 0

    async def complete_json(
        self,
        *,
        call_name: str,
        system_prompt: str,
        user_payload: dict[str, Any],
    ) -> dict[str, Any]:
        self.call_count += 1
        if self.call_count == 1:
            return {"canonical_name": "APT29", "unexpected": True}
        return {
            "canonical_name": "APT29",
            "attack_id": "G0016",
            "aliases": [],
            "confidence": "high",
            "ambiguity_notes": [],
            "queries": ["APT29 ATT&CK"],
        }


async def test_schema_failure_triggers_repair_call() -> None:
    provider = FlakyProvider()
    runner = NodeRunner(
        llm=provider,
        retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0),
    )
    output = await runner.run("actor_identity", {"actor": "APT29"})
    assert output.canonical_name == "APT29"
    assert provider.call_count == 2
    assert runner.repair_call_count == 1
    assert runner.trace["actor_identity"]["attempt_count"] == 2
