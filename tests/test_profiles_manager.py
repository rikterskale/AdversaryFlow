import json
import http.client
import threading
import urllib.request
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from uuid import uuid4

from adversaryflow.manager import _allow_provider_profile, _approval_readiness, _campaign_detail, _decision_timeline, _input, _manager_context, _mitre_plan, _offline_draft, _operator_readiness, _portfolio_summary, _provider_draft, _provider_status, _provider_test, _remove_provider_profile, _report_summary, _reset_saved_campaign, _run_demo, _save_provider_profile, _terminal_next_step, _use_provider_profile, make_handler, serve
from adversaryflow.provider import ProviderConfig
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
        provider = json.loads(urllib.request.urlopen(base + "/api/provider").read())
        campaigns = json.loads(urllib.request.urlopen(base + "/api/campaigns").read())
        assert health["ok"] is True
        assert health["mode"] == "local-guided-manager"
        assert context["mode"] == "offline-only"
        assert context["roe"]["approved_targets"] == ["local-lab"]
        assert context["roe"]["excluded_targets"] == ["production"]
        assert context["catalog"] == {"ability_count": 2, "technique_count": 2}
        assert "configuration" in provider
        assert "api_key" not in json.dumps(provider)
        assert campaigns["campaigns"] == []
        assert campaigns["summary"] == {"total": 0, "statuses": {"awaiting-approval": 0, "completed": 0, "rejected": 0, "cancelled": 0, "other": 0}}
        page = urllib.request.urlopen(base + "/").read().decode()
        assert "Campaign Guide" in page
        assert '/assets/manager.css' in page
        assert '/assets/manager.js' in page
        assert "Create a review draft" in page
        assert "First time here?" in page
        assert "Your next step" in page
        assert "Provider setup and troubleshooting" in page
        assert "Run safe local demo" in page
        assert "Common questions" in page
        assert "Campaign archive and stakeholder export" in page
        assert "Provider compatibility wizard" in page
        assert "ATT&amp;CK learning hub" in page
        assert "Rules of Engagement editor" in page
        script = urllib.request.urlopen(base + "/assets/manager.js").read().decode()
        assert "function draft(provider)" in script
        assert "function approve(id)" in script
        assert "function providerTest()" in script
        assert "function fixReadiness()" in script
        assert "function explainError" in script
        assert "function archiveSearch()" in script
        assert "function providerCompatibility()" in script
        assert "function learnTechnique()" in script
        assert "function detectionMappings()" in script
        assert "function archiveControls(id)" in script
        assert "function saveRoeEditor()" in script
        compatibility = json.loads(urllib.request.urlopen(base + "/api/provider/compatibility").read())
        assert "checks" in compatibility
        learning = json.loads(urllib.request.urlopen(base + "/api/learning?technique=T1059").read())
        assert learning["abilities"]
        mappings = json.loads(urllib.request.urlopen(base + "/api/detection-mappings?technique=T1059").read())
        assert mappings["mappings"]
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
        fixed = json.loads(urllib.request.urlopen(urllib.request.Request(base + "/api/doctor/fix", method="POST")).read())
        assert "fixes_applied" in fixed
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
        assert "approve and run" in inspected["detail"]["next_action"]
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


def test_manager_http_journey_drafts_approves_and_reports():
    root = __import__("pathlib").Path("artifacts") / f"manager-journey-{uuid4()}"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        draft = _manager_post(base, "/api/campaigns", {"actor": "APT29", "target": "local-lab", "objective": "browser journey"})
        campaign_id = draft["campaign_id"]
        completed = _manager_post(base, f"/api/campaigns/{campaign_id}/approve", {
            "approver": "manager@example.test", "confirmation": f"APPROVE {campaign_id}",
        })
        assert completed["stage"] == "completed"
        detail = json.loads(urllib.request.urlopen(base + f"/api/campaigns/{campaign_id}").read())
        assert detail["metadata"]["status"] == "completed"
        assert "campaign-report.html" in detail["reports"]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_manager_next_step_quotes_roE_approver_as_one_cli_argument():
    result = _terminal_next_step("campaign-safe", "awaiting-approval", {"ready": True}, 'manager "blue team"')
    assert result["command"] == 'adversaryflow campaign --campaign-id campaign-safe --approve --approver "manager blue team"'


def test_manager_mitre_plan_is_dry_run_and_records_no_execution(monkeypatch):
    class Audit:
        def __init__(self, *_args): pass
        def record(self, *_args, **_kwargs): pass

    monkeypatch.setattr(manager_module, "AuditLog", Audit)
    monkeypatch.setattr(manager_module, "fetch_attack_bundle", lambda: {"objects": [{
        "name": "Command and Scripting Interpreter",
        "external_references": [{"external_id": "T1059"}],
    }]})
    result = _mitre_plan("examples/roe.yaml", {"actor": "APT29", "target": "local-lab", "technique": "t1059"})
    assert result["notice"] == "DRY RUN ONLY"
    assert result["plan"]["steps"][0]["technique_id"] == "T1059"


def test_manager_operator_readiness_and_campaign_reset_confirmation():
    readiness = _operator_readiness("examples/roe.yaml", "content/abilities/catalog.json")
    assert readiness["roe"]["approved_targets"] == ["local-lab"]
    assert readiness["adapter"]["execution_boundary"] == "simulation-only"
    assert readiness["capabilities"]["format"] == "ADVERSARYFLOW-CAPABILITIES-1"

    root = f"artifacts/test-manager-reset-{uuid4()}"
    campaign_id = _offline_draft(root, "examples/roe.yaml", "content/abilities/catalog.json", {
        "actor": "APT29", "target": "local-lab", "objective": "verify reset confirmation",
    })["campaign_id"]
    with pytest.raises(PermissionError, match="Type 'RESET"):
        _reset_saved_campaign(root, campaign_id, {"confirmation": "RESET another-campaign"})
    assert _reset_saved_campaign(root, campaign_id, {"confirmation": f"RESET {campaign_id}"})["status"] == "reset"
    assert not (__import__("pathlib").Path(root) / campaign_id).exists()


def test_manager_provider_draft_uses_active_offline_provider(monkeypatch):
    monkeypatch.setenv("ADVERSARYFLOW_PROVIDER", "offline")
    root = f"artifacts/test-manager-provider-draft-{uuid4()}"
    result = _provider_draft(root, "examples/roe.yaml", "content/abilities/catalog.json", {
        "actor": "APT29", "target": "local-lab", "objective": "verify provider GUI draft", "platform": "linux",
    })
    assert result["stage"] == "drafted"
    assert result["provider"] == "offline"
    assert (__import__("pathlib").Path(root) / result["campaign_id"] / "draft.json").is_file()


def test_manager_demo_and_profile_removal_require_typed_confirmation():
    with pytest.raises(PermissionError, match="RUN LOCAL DEMO"):
        _run_demo("examples/roe.yaml", "content/abilities/catalog.json", {
            "actor": "APT29", "objective": "verify demo guard", "confirmation": "no",
        })
    with pytest.raises(PermissionError, match="REMOVE example"):
        _remove_provider_profile({"name": "example", "confirmation": "REMOVE another"})


def test_manager_profile_helpers_return_only_non_secret_summaries(monkeypatch):
    monkeypatch.setattr(manager_module, "save_profile", lambda *_args: __import__("pathlib").Path("profiles.json"))
    monkeypatch.setattr(manager_module, "use_profile", lambda *_args: __import__("pathlib").Path("profiles.json"))
    monkeypatch.setattr(manager_module, "allow_profile", lambda *_args: __import__("pathlib").Path("policy.json"))
    monkeypatch.setattr(manager_module, "remove_profile", lambda *_args: None)
    monkeypatch.setattr(manager_module, "list_profiles", lambda: {"active": "offline", "profiles": {}})
    monkeypatch.setattr(manager_module, "activation_summary", lambda: {"active": "offline", "ready": True})
    monkeypatch.setattr(manager_module, "policy_summary", lambda: {"configured": False})
    payload = {"name": "team", "endpoint": "https://example.test/v1", "model": "model", "credential_env": "TEAM_KEY"}
    assert _save_provider_profile(payload)["saved"] == "team"
    assert _use_provider_profile({"name": "team"})["active"] == "team"
    assert _allow_provider_profile({"name": "team"})["allowed"] == "team"
    assert _remove_provider_profile({"name": "team", "confirmation": "REMOVE team"})["removed"] == "team"


def test_manager_provider_fallback_and_demo_execution(monkeypatch):
    monkeypatch.setattr(manager_module, "load_provider_config", lambda: ProviderConfig("unsupported", None, None, False))
    root = f"artifacts/test-manager-provider-fallback-{uuid4()}"
    fallback = _provider_draft(root, "examples/roe.yaml", "content/abilities/catalog.json", {
        "actor": "APT29", "target": "local-lab", "objective": "verify fallback", "platform": "linux", "fallback_offline": True,
    })
    assert fallback["provider"] == "offline-fallback"

    with pytest.raises(ValueError, match="openai-compatible"):
        _provider_test("examples/roe.yaml", "content/abilities/catalog.json", {"actor": "APT29", "target": "local-lab", "objective": "test"})
    monkeypatch.undo()
    demo = _run_demo("examples/roe.yaml", "content/abilities/catalog.json", {
        "actor": "APT29", "objective": "verify GUI demo", "confirmation": "RUN LOCAL DEMO",
    })
    assert demo["stage"] == "completed"


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
