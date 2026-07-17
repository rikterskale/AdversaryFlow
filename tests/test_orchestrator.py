from adversaryflow.config import DEFAULT_ALLOWED_DOMAINS
from adversaryflow.models import (
    SourceChunk,
    SourceDocument,
    SourceRecord,
    SourceTier,
    ScenarioRequest,
)
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


async def test_ad_hoc_pipeline_skips_ttp_retrieval_and_grounding() -> None:
    request = ScenarioRequest.model_validate(
        {
            "actor": "Ad Hoc Exercise",
            "objective": "Validate suspicious data access response with synthetic records.",
            "scenario_kind": "ad_hoc",
            "ad_hoc_scenario": (
                "An exercise identity accesses synthetic records from a lab workstation to "
                "validate identity, endpoint, and data monitoring without actor TTP mapping."
            ),
            "mode": "emulation_plan",
            "environment": {
                "name": "Lab",
                "platforms": ["Windows", "SaaS CRM"],
                "designated_test_assets": ["LAB-02"],
            },
            "roe": {
                "authorized_assets": ["LAB-02"],
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
    assert pack.qa.model_call_count == 7
    assert pack.trace["retrieval"]["ad_hoc"] is True
    assert pack.trace["retrieval"]["candidate_count"] == 0
    assert pack.dossier.techniques == []
    assert "Ad Hoc" in pack.title


def test_post_2020_policy_excludes_unknown_and_old_sources() -> None:
    request = ScenarioRequest.model_validate(
        {
            "actor": "APT29",
            "objective": "Validate defensive controls in an isolated lab.",
            "environment": {"name": "Lab", "designated_test_assets": ["LAB-01"]},
            "roe": {"authorized_assets": ["LAB-01"]},
        }
    )
    documents = [
        SourceDocument(
            source=SourceRecord(
                url="https://example.com/old",
                title="Old",
                domain="example.com",
                tier=SourceTier.FIRST_PARTY,
                published_at="2019-12-31",
            ),
            text="old",
            chunks=[
                SourceChunk(
                    chunk_id="old",
                    source_url="https://example.com/old",
                    text="old",
                    ordinal=0,
                    sha256="a" * 64,
                )
            ],
        ),
        SourceDocument(
            source=SourceRecord(
                url="https://example.com/new",
                title="New",
                domain="example.com",
                tier=SourceTier.FIRST_PARTY,
                published_at="2021-01-01",
            ),
            text="new",
            chunks=[
                SourceChunk(
                    chunk_id="new",
                    source_url="https://example.com/new",
                    text="new",
                    ordinal=0,
                    sha256="b" * 64,
                )
            ],
        ),
    ]

    accepted, excluded = ScenarioOrchestrator._filter_recent_sources(documents, request)

    assert [str(document.source.url) for document in accepted] == ["https://example.com/new"]
    assert excluded == ["https://example.com/old"]
