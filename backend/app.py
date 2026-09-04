"""
AdversaryFlow — AI-assisted adversary-emulation workflow planner.

Flask backend: serves the frontend and a small JSON API that maps a chosen
MITRE ATT&CK threat-actor group/campaign to an end-to-end, kill-chain-ordered
workflow, with a benign detection-validation command attached to every TTP.

FOR AUTHORIZED PURPLE-TEAM / DETECTION-ENGINEERING USE ONLY.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory

import attack_data
import benign_commands

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

app = Flask(__name__, static_folder=None)


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path: str):
    return send_from_directory(FRONTEND_DIR, path)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/actors")
def actors():
    """List threat-actor groups & campaigns that have techniques mapped."""
    domains = _domains_from_request()
    idx = attack_data.get_index(domains)
    return jsonify({"actors": idx.list_actors(), "domains": domains})


@app.route("/api/refresh", methods=["POST"])
def refresh():
    """Force a re-download of the live ATT&CK STIX feed."""
    domains = _domains_from_request()
    for d in domains:
        attack_data.load_bundle(d, force_refresh=True)
    attack_data.get_index(domains, rebuild=True)
    return jsonify({"status": "refreshed", "domains": domains})


@app.route("/api/workflow/<stix_id>")
def workflow(stix_id: str):
    """Build the full attack workflow for one actor."""
    domains = _domains_from_request()
    idx = attack_data.get_index(domains)

    actor = idx.get_actor(stix_id)
    if not actor:
        return jsonify({"error": "actor not found"}), 404

    techniques = idx.actor_techniques(stix_id)

    # Kill-chain order comes from the live STIX matrix (see AttackIndex), so the
    # workflow stays correct as ATT&CK evolves its tactics.
    tactic_order = idx.tactic_order or attack_data.TACTIC_ORDER
    tactic_titles = idx.tactic_titles or attack_data.TACTIC_TITLES

    # Group techniques into kill-chain stages. A technique can appear in more
    # than one tactic, so it can show up in multiple stages of the workflow.
    stages: Dict[str, List[Dict[str, Any]]] = {t: [] for t in tactic_order}
    unmapped: List[Dict[str, Any]] = []

    curated_count = 0
    total_techniques = len(techniques)

    for tech in techniques:
        cmd_result = benign_commands.get_commands(
            tech["attack_id"], tech["name"], tech["tactics"]
        )
        if cmd_result["source"] == "curated":
            curated_count += 1

        enriched = {
            **tech,
            "benign": cmd_result["commands"],
            "benign_source": cmd_result["source"],
        }

        placed = False
        for tac in tech["tactics"]:
            if tac in stages:
                stages[tac].append(enriched)
                placed = True
        if not placed:
            unmapped.append(enriched)

    # Emit stages in kill-chain order, skipping empty ones.
    ordered_stages = []
    for tac in tactic_order:
        techs = stages[tac]
        if not techs:
            continue
        techs.sort(key=lambda t: t["attack_id"])
        ordered_stages.append({
            "tactic": tac,
            "title": tactic_titles.get(tac, tac),
            "techniques": techs,
        })

    attack_id = attack_data.AttackIndex._attack_id(actor)

    return jsonify({
        "actor": {
            "stix_id": actor["id"],
            "attack_id": attack_id,
            "name": actor.get("name"),
            "type": "group" if actor.get("type") == "intrusion-set" else "campaign",
            "aliases": [a for a in actor.get("aliases", []) if a != actor.get("name")],
            "description": (actor.get("description") or "").split("\n")[0],
        },
        "summary": {
            "total_techniques": total_techniques,
            "unique_stages": len(ordered_stages),
            "curated_commands": curated_count,
            "fallback_commands": total_techniques - curated_count,
        },
        "kill_chain": [{"tactic": t, "title": tactic_titles.get(t, t)} for t in tactic_order],
        "stages": ordered_stages,
        "unmapped": unmapped,
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domains_from_request() -> List[str]:
    raw = request.args.get("domains") or (request.json or {}).get("domains") if request.is_json else request.args.get("domains")
    if not raw:
        return ["enterprise"]
    domains = [d.strip() for d in raw.split(",") if d.strip() in attack_data.STIX_SOURCES]
    return domains or ["enterprise"]


if __name__ == "__main__":
    # Warm the enterprise cache on startup so the first request is fast.
    print("AdversaryFlow: loading MITRE ATT&CK data (first run downloads ~35MB)...")
    try:
        attack_data.get_index(["enterprise"])
        print("AdversaryFlow: ATT&CK data ready.")
    except Exception as exc:  # noqa: BLE001
        print(f"AdversaryFlow: WARNING could not preload ATT&CK data: {exc}")
    app.run(host="127.0.0.1", port=5000, debug=False)
