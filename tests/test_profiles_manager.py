import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from uuid import uuid4

from adversaryflow.manager import make_handler
from adversaryflow.profiles import list_profiles, remove_profile, save_profile, use_profile


def test_provider_profiles_never_store_credentials():
    root = __import__("pathlib").Path("artifacts") / f"profiles-{uuid4()}"
    save_profile("approved", "openai-compatible", "https://example.test/v1", "model", "TEAM_AI_KEY", root)
    profile_file = root / "profiles.json"
    assert "api_key" not in profile_file.read_text(encoding="utf-8")
    use_profile("approved", root)
    assert list_profiles(root)["active"] == "approved"
    remove_profile("approved", root)
    assert list_profiles(root)["active"] == "offline"


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
        assert campaigns["campaigns"] == []
    finally:
        server.shutdown()
        thread.join(timeout=2)
