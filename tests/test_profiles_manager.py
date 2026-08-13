import json
import threading
import urllib.request
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from uuid import uuid4

from adversaryflow.manager import make_handler
from adversaryflow.profiles import list_profiles, remove_profile, save_profile, use_profile
from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.workflow import save_campaign_draft
import pytest


def test_provider_profiles_never_store_credentials():
    root = __import__("pathlib").Path("artifacts") / f"profiles-{uuid4()}"
    save_profile("approved", "openai-compatible", "https://example.test/v1", "model", "TEAM_AI_KEY", root)
    profile_file = root / "profiles.json"
    assert "api_key" not in profile_file.read_text(encoding="utf-8")
    use_profile("approved", root)
    assert list_profiles(root)["active"] == "approved"
    remove_profile("approved", root)
    assert list_profiles(root)["active"] == "offline"


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
        campaigns = json.loads(urllib.request.urlopen(base + "/api/campaigns").read())
        assert health["ok"] is True
        assert health["mode"] == "local-guided-manager"
        assert campaigns["campaigns"] == []
        page = urllib.request.urlopen(base + "/").read().decode()
        assert "Campaign Guide" in page
        assert "Start a safe campaign in five clear steps" in page
        assert "Create safe offline draft" in page
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
    finally:
        server.shutdown()
        thread.join(timeout=2)


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
        with pytest.raises(HTTPError) as wrong_approver:
            _manager_post(base, f"/api/campaigns/{campaign_id}/reject", {"approver": "not-the-approver", "reason": "not scheduled"})
        assert wrong_approver.value.code == 403
        rejected = _manager_post(base, f"/api/campaigns/{campaign_id}/reject", {"approver": "manager@example.test", "reason": "not scheduled"})
        assert rejected["status"] == "rejected"
        second = _manager_post(base, "/api/campaigns", {"actor": "APT29", "target": "local-lab", "objective": "validate process visibility"})
        cancelled = _manager_post(base, f"/api/campaigns/{second['campaign_id']}/cancel", {"reason": "operator requested stop"})
        assert cancelled["status"] == "cancelled"
    finally:
        server.shutdown()
        thread.join(timeout=2)
