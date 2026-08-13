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
        assert "Create my draft command" in page
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
    finally:
        server.shutdown()
        thread.join(timeout=2)
