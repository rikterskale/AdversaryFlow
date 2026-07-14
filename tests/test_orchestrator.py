from adversaryflow.config import DEFAULT_ALLOWED_DOMAINS
from adversaryflow.models import ScenarioRequest
from adversaryflow.pipeline.orchestrator import ScenarioOrchestrator
from adversaryflow.providers.demo import DemoLLMProvider
from adversaryflow.providers.search import NullSearchProvider
from adversaryflow.retrieval.url_validator import URLValidator
from adversaryflow.safety.policy import SafetyPolicy


async def test_demo_pipeline_makes_twelve_calls() -> None:
    request = ScenarioRequest.model_validate(
        {
            "actor": "APT29",
            "objective": "Validate defensive controls in an isolated lab.",
            "mode": "emulation_plan",
            "environment": {
                "name": "Lab",
                "platforms": ["Windows"],
                "designated_test_assets": ["LAB-01"],
            },
            "roe": {
                "authorized_assets": ["LAB-01"],
                "no_real_funds_or_transactions": True,
                "no_destructive_execution": True,
            },
        }
    )
    llm = DemoLLMProvider()
    orchestrator = ScenarioOrchestrator(
        llm=llm,
        search=NullSearchProvider(),
        safety_policy=SafetyPolicy(),
        url_validator=URLValidator(allowed_domains=set(DEFAULT_ALLOWED_DOMAINS)),
    )
    pack = await orchestrator.generate(request)
    assert pack.qa.safety_gate_passed
    assert pack.qa.model_call_count == 12
    assert len(pack.attack_path) == 4
