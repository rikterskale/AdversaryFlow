from adversaryflow.models import ScenarioRequest
from adversaryflow.models import ProcedureStep, SafetyClassification
from adversaryflow.safety.policy import SafetyPolicy


def _request() -> ScenarioRequest:
    return ScenarioRequest.model_validate(
        {
            "actor": "Example Actor",
            "objective": "Validate defensive controls in a lab.",
            "mode": "emulation_plan",
            "environment": {
                "name": "Lab",
                "designated_test_assets": ["LAB-01"],
            },
            "roe": {
                "authorized_assets": ["LAB-01"],
                "no_real_funds_or_transactions": True,
                "no_destructive_execution": True,
            },
        }
    )


def test_request_passes() -> None:
    decision = SafetyPolicy().evaluate_request(_request())
    assert decision.passed


def test_real_transactions_blocked() -> None:
    payload = _request().model_dump(mode="json")
    payload["roe"]["no_real_funds_or_transactions"] = False
    request = ScenarioRequest.model_validate(payload)
    decision = SafetyPolicy().evaluate_request(request)
    assert not decision.passed


def test_paraphrased_destructive_action_is_blocked() -> None:
    step = ProcedureStep(
        sequence=1,
        phase="Impact",
        objective="Validate response safely",
        technique_ids=[],
        action_summary="Render the production fileshare unusable.",
        safe_equivalent="Create a reversible marker on the designated lab asset.",
        designated_test_asset="LAB-01",
        stop_conditions=["Stop on unexpected impact"],
        cleanup=["Remove marker"],
        safety_classification=SafetyClassification.CONTROLLED_EMULATION,
    )

    decision = SafetyPolicy().evaluate_steps(_request(), [step])

    assert not decision.passed
