import json
import http.client
import threading
import urllib.request
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from uuid import uuid4

from adversaryflow.manager import _approval_readiness, _campaign_detail, _decision_timeline, _input, _manager_context, _offline_draft, _portfolio_summary, _report_summary, _terminal_next_step, make_handler, serve
from adversaryflow.models import RulesOfEngagement
from adversaryflow.profiles import list_profiles, remove_profile, save_profile, use_profile
from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.workflow import save_campaign_draft
import pytest
import adversaryflow.manager as manager_module


def test_provider_profiles_never_store_credentials():
    root = __import__("pathlib").Path("artifacts") / f"profiles-{uuid4()}"
    save_profile("approved", "openai-compatible", "https://example.test/v1", "model", "TEAM_AI_KEY", root)
    profile_file = root / "profiles.json"
    assert "api_key" not in profile_file.read_text(encoding="utf-8")
    use_profile("approved", root)
    assert list_profiles(root)["active"] == "approved"
    remove_profile("approved", root)
    assert list_profiles(root)["active"] == "offline"


def test_removing_an_inactive_profile_preserves_the_active_selection():
    root = __import__("pathlib").Path("artifacts") / f"profiles-inactive-{uuid4()}"
    save_profile("first", "openai-compatible", "https://example.test/v1", "model", "FIRST_KEY", root)
    save_profile("second", "openai-compatible", "https://example.test/v1", "model", "SECOND_KEY", root)
    use_profile("first", root)
    remove_profile("second", root)
    assert list_profiles(root)["active"] == "first"


@pytest.mark.parametrize("name,provider,endpoint,model,credential_env", [
    ("bad name", "openai-compatible", "https://example.test/v1", "model", "TEAM_AI_KEY"),
    ("approved", "unsupported", "https://example.test/v1", "model", "TEAM_AI_KEY"),
    ("approved", "openai-compatible", "http://example.test/v1", "model", "TEAM_AI_KEY"),
    ("approved", "openai-compatible", "https://example.test/v1", "", "TEAM_AI_KEY"),
    ("approved", "openai-compatible", "https://example.test/v1", "model", "invalid-key"),
])
def test_provider_profiles_reject_unsafe_or_incomplete_settings(name, provider, endpoint, model, credential_env):
    with pytest.raises(ValueError):
        save_profile(name, provider, endpoint, model, credential_env, "artifacts/profiles-invalid")


def test_manager_health_and_campaign_listing():
    root = __import__("pathlib").Path("artifacts") / f"manager-{uuid4()}"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        health = json.loads(urllib.request.urlopen(base + "/api/health").read())
        context = json.loads(urllib.request.urlopen(base + "/api/context").read())
        campaigns = json.loads(urllib.request.urlopen(base + "/api/campaigns").read())
        assert health["ok"] is True
        assert health["mode"] == "local-guided-manager"
        assert context["mode"] == "offline-only"
        assert context["roe"]["approved_targets"] == ["local-lab"]
        assert context["roe"]["excluded_targets"] == ["production"]
        assert context["catalog"] == {"ability_count": 2, "technique_count": 2}
        assert campaigns["campaigns"] == []
        assert campaigns["summary"] == {"total": 0, "statuses": {"awaiting-approval": 0, "completed": 0, "rejected": 0, "cancelled": 0, "other": 0}}
        page = urllib.request.urlopen(base + "/").read().decode()
        assert "Campaign Guide" in page
        assert "Start a safe campaign in five clear steps" in page
        assert "Create safe offline draft" in page
        assert "Your setup checklist" in page
        assert "Saved in this browser only" in page
        assert "function statusLabel(status)" in page
        assert "function doctorSummary(result)" in page
        assert "Copy fix" in page
        assert "Current local scope" in page
        assert '<select id="target" disabled onchange="updateDraftPreview()">' in page
        assert "active local RoE" in page
        assert 'id="create-draft" onclick="createDraft()" disabled' in page
        assert "It will not contact a target, run a command, use a hosted provider, approve a campaign, or start emulation." in page
        assert "function updateDraftPreview()" in page
        with pytest.raises(HTTPError) as missing_campaign:
            urllib.request.urlopen(base + "/api/campaigns/campaign-missing")
        assert missing_campaign.value.code == 404
        assert json.loads(missing_campaign.value.read())["error"].startswith("Campaign not found")
        with pytest.raises(HTTPError) as unknown_route:
            urllib.request.urlopen(base + "/not-a-route")
        assert unknown_route.value.code == 404
        request = urllib.request.Request(base + "/api/doctor", method="POST")
        doctor = json.loads(urllib.request.urlopen(request).read())
        assert doctor["passed"] is True
        with pytest.raises(HTTPError) as unsupported_post:
            urllib.request.urlopen(urllib.request.Request(base + "/api/not-allowed", method="POST"))
        assert unsupported_post.value.code == 404
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_manager_includes_existing_html_report_for_completed_campaign():
    root = __import__("pathlib").Path("artifacts") / f"manager-report-{uuid4()}"
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    campaign = save_campaign_draft(draft, "hash", "offline", root)
    report = campaign / "campaign-report.html"
    report.write_text("<h1>Report</h1>", encoding="utf-8")
    (campaign / "telemetry-gap-report.json").write_text(json.dumps({
        "behavior_success": True,
        "telemetry_expected": 3,
        "telemetry_observed": 2,
        "detection_gap_count": 1,
        "gaps": [{"category": "process", "description": "missing alert"}],
        "assessment": "Use this synthetic finding to define a focused retest.",
    }), encoding="utf-8")
    metadata_path = campaign / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update({"status": "completed", "run_dir": str(campaign)})
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/campaigns").read())
        report_url = payload["campaigns"][0]["report_url"]
        assert report_url == f"/api/campaigns/{campaign.name}/report"
        assert "Report" in urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}{report_url}").read().decode()
        detail = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/campaigns/{campaign.name}").read())
        assert detail["detail"]["report_url"] == report_url
        assert "report is available" in detail["detail"]["report_review"]
        summary = detail["detail"]["report_summary"]
        assert summary["status"] == "available"
        assert summary["telemetry_expected"] == 3
        assert summary["gaps"][0]["description"] == "missing alert"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_manager_uses_packaged_defaults_outside_the_source_checkout(monkeypatch):
    """An installed user can start the manager without copied example files."""
    from pathlib import Path

    original_exists = Path.exists

    def missing_checkout_defaults(path):
        if str(path) in {"examples\\roe.yaml", "content\\abilities\\catalog.json"}:
            return False
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", missing_checkout_defaults)
    context = _manager_context("examples/roe.yaml", "content/abilities/catalog.json")
    assert context["roe"]["approved_targets"] == ["local-lab"]
    assert context["catalog"]["ability_count"] == 2

    root = Path("artifacts") / f"manager-packaged-{uuid4()}"
    created = _offline_draft(str(root), "examples/roe.yaml", "content/abilities/catalog.json", {
        "actor": "APT29", "target": "local-lab", "objective": "validate installed manager defaults",
    })
    detail = _campaign_detail(str(root), created["campaign_id"], "examples/roe.yaml", "content/abilities/catalog.json")
    assert detail["detail"]["integrity"]["status"] == "verified"


def _manager_post(base, path, payload):
    request = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(request).read())


def test_manager_creates_offline_drafts_and_records_non_execution_decisions():
    root = __import__("pathlib").Path("artifacts") / f"manager-control-{uuid4()}"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        created = _manager_post(base, "/api/campaigns", {"actor": "APT29", "target": "local-lab", "objective": "validate endpoint visibility"})
        assert created["provider"] == "offline"
        assert created["approval_required"] is True
        campaign_id = created["campaign_id"]
        inspected = json.loads(urllib.request.urlopen(base + f"/api/campaigns/{campaign_id}").read())
        assert inspected["metadata"]["status"] == "awaiting-approval"
        assert inspected["metadata"]["provider"] == "offline"
        assert inspected["detail"]["integrity"]["status"] == "verified"
        assert inspected["detail"]["scope"]["target"] == "local-lab"
        assert inspected["detail"]["abilities"]
        assert "CLI" in inspected["detail"]["next_action"]
        readiness = inspected["detail"]["approval_readiness"]
        assert readiness["ready"] is True
        assert all(check["passed"] for check in readiness["checks"])
        assert inspected["detail"]["terminal_next"] == {
            "label": "Copy CLI approval command",
            "command": f"adversaryflow campaign --campaign-id {campaign_id} --approve --approver \"manager@example.test\"",
            "detail": "Copy this command only after the named RoE approver confirms schedule and scope.",
        }
        with pytest.raises(HTTPError) as wrong_approver:
            _manager_post(base, f"/api/campaigns/{campaign_id}/reject", {"approver": "not-the-approver", "reason": "not scheduled"})
        assert wrong_approver.value.code == 403
        rejected = _manager_post(base, f"/api/campaigns/{campaign_id}/reject", {"approver": "manager@example.test", "reason": "not scheduled"})
        assert rejected["status"] == "rejected"
        rejected_detail = json.loads(urllib.request.urlopen(base + f"/api/campaigns/{campaign_id}").read())
        assert [entry["event"] for entry in rejected_detail["detail"]["decision_timeline"]] == [
            "Draft created",
            "Rejection recorded by manager@example.test",
        ]
        assert rejected_detail["detail"]["decision_timeline"][1]["detail"] == "not scheduled"
        assert rejected_detail["detail"]["approval_readiness"]["ready"] is False
        assert rejected_detail["detail"]["approval_readiness"]["checks"][0]["passed"] is False
        assert rejected_detail["detail"]["terminal_next"]["label"] == "Copy CLI inspection command"
        assert rejected_detail["detail"]["terminal_next"]["command"] == f"adversaryflow campaign inspect --campaign-id {campaign_id}"
        summary = json.loads(urllib.request.urlopen(base + "/api/campaigns").read())["summary"]
        assert summary["total"] == 1
        assert summary["statuses"]["rejected"] == 1
        second = _manager_post(base, "/api/campaigns", {"actor": "APT29", "target": "local-lab", "objective": "validate process visibility"})
        cancelled = _manager_post(base, f"/api/campaigns/{second['campaign_id']}/cancel", {"reason": "operator requested stop"})
        assert cancelled["status"] == "cancelled"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_manager_next_step_quotes_roE_approver_as_one_cli_argument():
    result = _terminal_next_step("campaign-safe", "awaiting-approval", {"ready": True}, 'manager "blue team"')
    assert result["command"] == 'adversaryflow campaign --campaign-id campaign-safe --approve --approver "manager blue team"'


@pytest.mark.parametrize("payload", [{}, {"actor": "   "}, {"actor": 7}, {"actor": "x" * 201}])
def test_manager_input_validation_rejects_empty_nonstring_and_oversized_values(payload):
    with pytest.raises(ValueError):
        _input(payload, "actor")


def test_manager_report_and_portfolio_helpers_preserve_local_boundaries():
    assert _report_summary({})["status"] == "not-available"
    assert "outside this workspace" in _report_summary({"run_dir": str(__import__("pathlib").Path.cwd().parent)})["detail"]
    root = __import__("pathlib").Path("artifacts") / f"manager-summary-{uuid4()}"
    root.mkdir(parents=True)
    assert "No telemetry-gap summary" in _report_summary({"run_dir": str(root)})["detail"]
    (root / "telemetry-gap-report.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        _report_summary({"run_dir": str(root)})
    (root / "telemetry-gap-report.json").write_text(json.dumps({"gaps": "not-a-list"}), encoding="utf-8")
    assert _report_summary({"run_dir": str(root)})["gaps"] == []
    summary = _portfolio_summary([{"status": "awaiting-approval"}, {"status": "unexpected"}])
    assert summary["statuses"]["awaiting-approval"] == 1
    assert summary["statuses"]["other"] == 1


def test_manager_rejects_malformed_and_oversized_json_request_bodies():
    root = __import__("pathlib").Path("artifacts") / f"manager-body-{uuid4()}"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        for body in (b"[]", b"x" * 4097):
            request = urllib.request.Request(base + "/api/campaigns", data=body, headers={"Content-Type": "application/json"}, method="POST")
            with pytest.raises(HTTPError) as error:
                urllib.request.urlopen(request)
            assert error.value.code == 400
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        connection.putrequest("POST", "/api/campaigns")
        connection.putheader("Content-Length", "not-a-number")
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 400
        assert "Content-Length must be an integer" in response.read().decode()
        connection.close()
        with pytest.raises(HTTPError) as unsupported_campaign_path:
            urllib.request.urlopen(base + "/api/campaigns/campaign-safe/unexpected")
        assert unsupported_campaign_path.value.code == 404
        with pytest.raises(HTTPError) as unsupported_campaign_post:
            _manager_post(base, "/api/campaigns/campaign-safe/unexpected", {"reason": "fixture"})
        assert unsupported_campaign_post.value.code == 404
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_manager_review_helpers_handle_integrity_mismatch_and_local_timeline_records():
    root = __import__("pathlib").Path("artifacts") / f"manager-edges-{uuid4()}"
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test edge cases"), load_catalog("content/abilities/catalog.json"))
    campaign = save_campaign_draft(draft, "hash", "offline", root)
    metadata_path = campaign / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update({"roe_sha256": "1" * 64, "catalog_sha256": "2" * 64, "status": "unknown"})
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    detail = _campaign_detail(str(root), campaign.name, "examples/roe.yaml", "content/abilities/catalog.json")["detail"]
    assert detail["integrity"]["status"] == "review-required"
    assert detail["terminal_next"]["label"] == "Copy CLI inspection command"
    (campaign / "approval.json").write_text(json.dumps({"approved_at": "2099-01-02T00:00:00Z", "approver": "manager", "decision": "approved"}), encoding="utf-8")
    (campaign / "cancellation.json").write_text(json.dumps({"cancelled_at": "2099-01-03T00:00:00Z", "reason": "fixture stop"}), encoding="utf-8")
    (campaign / "rejection.json").write_text("[]", encoding="utf-8")
    events = _decision_timeline(str(campaign), metadata)
    assert [event["event"] for event in events] == ["Draft created", "Approval recorded by manager", "Cancellation recorded"]
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "a", "approved_targets": ["other"]})
    assert _approval_readiness("unknown", draft, roe, [], {"status": "review-required"})["ready"] is False
    assert _terminal_next_step(campaign.name, "awaiting-approval", {"ready": False}, "manager")["label"] == "Copy CLI inspection command"


def test_manager_rejects_absent_reports_and_nonloopback_binding():
    root = __import__("pathlib").Path("artifacts") / f"manager-report-missing-{uuid4()}"
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test report"), load_catalog("content/abilities/catalog.json"))
    campaign = save_campaign_draft(draft, "hash", "offline", root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(HTTPError) as error:
            urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/campaigns/{campaign.name}/report")
        assert error.value.code == 404
    finally:
        server.shutdown()
        thread.join(timeout=2)
    with pytest.raises(ValueError, match="loopback"):
        serve("0.0.0.0")


def test_manager_startup_remains_loopback_only_without_opening_a_real_service(monkeypatch, capsys):
    calls = {}

    class Server:
        server_port = 8787
        def serve_forever(self): calls["served"] = True

    class Timer:
        def __init__(self, _delay, callback, args): self.callback, self.args = callback, args
        def start(self): calls["browser_url"] = self.args[0]

    monkeypatch.setattr(manager_module, "ThreadingHTTPServer", lambda address, handler: calls.update(address=address, handler=handler) or Server())
    monkeypatch.setattr(manager_module.threading, "Timer", Timer)
    serve("127.0.0.1", 0, "artifacts/manager-startup", open_browser=True)
    assert calls["address"] == ("127.0.0.1", 0)
    assert calls["served"] is True
    assert calls["browser_url"] == "http://127.0.0.1:8787"
    assert "listening on http://127.0.0.1:8787" in capsys.readouterr().out
