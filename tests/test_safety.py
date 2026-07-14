from adversaryflow.models import ScenarioRequest
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
