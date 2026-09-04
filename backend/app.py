"""AdversaryFlow development-lab emulation workflow planner.

The Flask backend serves the frontend and a JSON API that maps a chosen MITRE
ATT&CK group or campaign to a kill-chain-ordered workflow with ATT&CK-aligned
lab commands.
"""

from __future__ import annotations

import argparse
import os
import sysconfig
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from . import __version__, attack_data, command_catalog


def _frontend_dir() -> str:
    configured = os.environ.get("ADVERSARYFLOW_FRONTEND_DIR")
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    source_tree = Path(__file__).resolve().parent.parent / "frontend"
    if source_tree.is_dir():
        return str(source_tree)
    installed = Path(sysconfig.get_path("data")) / "share" / "adversaryflow" / "frontend"
    return str(installed)


FRONTEND_DIR = _frontend_dir()

app = Flask(__name__, static_folder=None)
_runtime: Dict[str, Any] = {"ready": False, "error": "ATT&CK data has not been loaded"}


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
    index_status = attack_data.loaded_index_status()
    ready = bool(_runtime["ready"] and index_status["ready"])
    return jsonify({
        "status": "ready" if ready else "degraded",
        "ready": ready,
        "version": __version__,
        "error": None if ready else _runtime["error"],
        "attack_data": index_status,
    }), 200 if ready else 503


@app.route("/api/actors")
def actors():
    """List threat-actor groups & campaigns that have techniques mapped."""
    domains = _domains_from_request()
    idx = attack_data.get_index(domains)
    _mark_ready()
    return jsonify({
        "actors": idx.list_actors(),
        "domains": idx.domains,
        "data_version": idx.data_version,
        "version": __version__,
    })


@app.route("/api/refresh", methods=["POST"])
def refresh():
    """Force a re-download of the live ATT&CK STIX feed."""
    domains = _domains_from_request()
    for d in domains:
        attack_data.load_bundle(d, force_refresh=True)
    idx = attack_data.get_index(domains, rebuild=True)
    _mark_ready()
    return jsonify({
        "status": "refreshed",
        "domains": idx.domains,
        "data_version": idx.data_version,
    })


@app.route("/api/workflow/<stix_id>")
def workflow(stix_id: str):
    """Build the full attack workflow for one actor."""
    domains = _domains_from_request()
    idx = attack_data.get_index(domains)
    _mark_ready()

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
        cmd_result = command_catalog.get_commands(
            tech["attack_id"], tech["name"], tech["tactics"]
        )
        if cmd_result["source"] == "curated":
            curated_count += 1

        enriched = {
            **tech,
            "commands": cmd_result["commands"],
            "command_source": cmd_result["source"],
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
        "metadata": {
            "domains": idx.domains,
            "data_version": idx.data_version,
            "version": __version__,
        },
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domains_from_request() -> List[str]:
    raw: Any = request.args.get("domains")
    if not raw and request.is_json:
        raw = (request.get_json(silent=True) or {}).get("domains")
    if not raw:
        return ["enterprise"]
    values = raw if isinstance(raw, list) else str(raw).split(",")
    domains = list(dict.fromkeys(
        str(domain).strip()
        for domain in values
        if str(domain).strip() in attack_data.STIX_SOURCES
    ))
    return domains or ["enterprise"]


def _mark_ready() -> None:
    _runtime["ready"] = True
    _runtime["error"] = None


def _mark_error(exc: Exception) -> None:
    _runtime["ready"] = False
    _runtime["error"] = str(exc)


@app.errorhandler(Exception)
def api_error(exc: Exception):
    if not request.path.startswith("/api/"):
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception("Frontend request failed")
        return "Internal Server Error", 500
    if isinstance(exc, HTTPException):
        return jsonify({
            "error": exc.name.lower().replace(" ", "_"),
            "message": exc.description,
            "version": __version__,
        }), exc.code
    app.logger.exception("API request failed")
    _mark_error(exc)
    return jsonify({
        "error": "request failed",
        "message": str(exc),
        "version": __version__,
    }), 500


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adversaryflow",
        description="Guided MITRE ATT&CK adversary-emulation workflow planner",
    )
    parser.add_argument("--host", default=os.environ.get("ADVERSARYFLOW_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ADVERSARYFLOW_PORT", "5000")))
    parser.add_argument("--cache-dir", default=os.environ.get("ADVERSARYFLOW_CACHE_DIR"))
    parser.add_argument("--offline", action="store_true", default=os.environ.get("ADVERSARYFLOW_OFFLINE", "").lower() in {"1", "true", "yes"}, help="use cached ATT&CK data without downloading")
    parser.add_argument("--no-preload", action="store_true", help="start before loading ATT&CK data")
    parser.add_argument("--version", action="version", version=f"AdversaryFlow {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cache_dir:
        attack_data.configure_cache_dir(args.cache_dir)
    attack_data.configure_offline(args.offline)

    if not args.no_preload:
        print("AdversaryFlow: loading MITRE ATT&CK data...")
        try:
            attack_data.get_index(["enterprise"])
            _mark_ready()
            print("AdversaryFlow: ATT&CK data ready.")
        except Exception as exc:  # noqa: BLE001
            _mark_error(exc)
            print(f"AdversaryFlow: WARNING could not preload ATT&CK data: {exc}")

    from waitress import serve

    print(f"AdversaryFlow {__version__}: http://{args.host}:{args.port}")
    serve(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
