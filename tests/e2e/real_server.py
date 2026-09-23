"""Ephemeral, loopback-only fixture service for browser/API integration tests.

Control routes exist only in this test process, never in the shipped service.
No live feeds are downloaded and no catalog commands are executed.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from flask import jsonify, request
from waitress import create_server

from backend import app as service
from backend import attack_data
from tests.test_attack_data import stix_bundle


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="adversaryflow-browser-") as directory:
        cache_file = Path(directory) / "enterprise-attack.json"

        def seed(version: str = "fixture") -> None:
            bundle = stix_bundle()
            bundle["id"] = f"bundle--{version}"
            bundle["objects"].extend([
                {"type": "attack-pattern", "id": "attack-pattern--task", "name": "Scheduled Task",
                 "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T1053.005"}]},
                {"type": "relationship", "id": "relationship--task", "relationship_type": "uses",
                 "source_ref": "intrusion-set--zeta", "target_ref": "attack-pattern--task"},
            ])
            cache_file.write_text(json.dumps(bundle), encoding="utf-8")
            attack_data.clear_memory_cache()
            attack_data.get_index(["enterprise"])
            service._mark_ready()

        attack_data.configure_cache_dir(directory)
        attack_data.configure_offline(False)
        service.LOG_LEVEL = "error"
        service.REMOTE_MODE = True
        service.API_TOKEN = "browser-fixture-token"

        @service.app.post("/test-control")
        def control():
            body = request.get_json()
            action = body.get("action")
            if action == "reset":
                service.API_TOKEN = "browser-fixture-token"
                service._csrf_token = "fixture-csrf"
                service._last_refresh = 0
                seed()
            elif action == "csrf":
                service._csrf_token = "rotated-fixture-csrf"
            elif action == "token":
                service.API_TOKEN = "rotated-fixture-token"
            elif action == "version":
                seed("updated")
            return jsonify({"ok": True})

        with patch.object(attack_data, "_download", side_effect=OSError("Fixture upstream unavailable")):
            seed()
            server = create_server(service.app, host="127.0.0.1", port=0, threads=4)
            print(f"READY http://127.0.0.1:{server.effective_port}", flush=True)
            server.run()


if __name__ == "__main__":
    main()
