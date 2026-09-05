"""AdversaryFlow development-lab emulation workflow planner.

The Flask backend serves the frontend and a JSON API that maps a chosen MITRE
ATT&CK group or campaign to a kill-chain-ordered workflow with ATT&CK-aligned
lab commands.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import io
import ipaddress
import json
import os
import re
import secrets
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.parse
import uuid
import webbrowser
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, abort, g, jsonify, request, send_file, send_from_directory
from werkzeug.exceptions import HTTPException

from . import __version__, attack_data, command_catalog, execution_kit


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
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
EXECUTION_KIT_MAX_CONTENT_LENGTH = 5 * 1024 * 1024
_runtime: Dict[str, Any] = {
    "ready": False,
    "loading": False,
    "phase": "not_started",
    "error": "ATT&CK data has not been loaded",
    "started_at": None,
    "completed_at": None,
    "requests_total": 0,
    "requests_by_status": {},
}
_runtime_lock = threading.RLock()
_refresh_lock = threading.Lock()
_last_refresh = 0.0
_csrf_token = secrets.token_urlsafe(32)
REFRESH_COOLDOWN_SECONDS = 5
LOG_LEVEL = os.environ.get("ADVERSARYFLOW_LOG_LEVEL", "info").lower()
REMOTE_MODE = False
API_TOKEN = ""
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path: str):
    return send_from_directory(FRONTEND_DIR, path)


@app.before_request
def begin_request() -> None:
    supplied_request_id = request.headers.get("X-Request-ID", "")
    g.request_id = supplied_request_id if REQUEST_ID_PATTERN.fullmatch(supplied_request_id) else uuid.uuid4().hex
    g.request_started = time.monotonic()
    # Complete actor plans can contain hundreds of command records. Flask 3.1
    # supports a route-specific request cap, so unrelated endpoints retain the
    # much smaller global body limit.
    if request.path == "/api/execution-kit":
        request.max_content_length = EXECUTION_KIT_MAX_CONTENT_LENGTH
    if REMOTE_MODE and request.path.startswith("/api/"):
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {API_TOKEN}"
        if not secrets.compare_digest(supplied, expected):
            abort(401, description="A valid bearer token is required for remote API access")


@app.after_request
def secure_response(response):
    response.headers["X-Request-ID"] = getattr(g, "request_id", "unknown")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    with _runtime_lock:
        _runtime["requests_total"] += 1
        key = str(response.status_code)
        _runtime["requests_by_status"][key] = _runtime["requests_by_status"].get(key, 0) + 1
    _log_event("request", method=request.method, path=request.path, status=response.status_code,
               duration_ms=round((time.monotonic() - getattr(g, "request_started", time.monotonic())) * 1000, 1))
    return response


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/api/live")
def live():
    """Liveness: the process can answer. Readiness is /api/health."""
    return jsonify({"status": "live", "version": __version__})


@app.route("/api/health")
def health():
    index_status = attack_data.loaded_index_status()
    ready = bool(_runtime["ready"] and index_status["ready"])
    return jsonify({
        "status": "ready" if ready else "degraded",
        "ready": ready,
        "version": __version__,
        "loading": bool(_runtime["loading"]),
        "phase": _runtime["phase"],
        "error": None if ready else _runtime["error"],
        "attack_data": index_status,
        "service": _runtime_snapshot(),
    }), 200 if ready else 503


@app.route("/api/bootstrap", methods=["GET", "POST"])
def bootstrap():
    if request.method == "POST":
        _require_csrf()
        if not _start_bootstrap():
            return jsonify({"status": "already_loading", "runtime": _runtime_snapshot()}), 202
    status = 200 if _runtime["ready"] else 202 if _runtime["loading"] else 503
    return jsonify({"status": _runtime["phase"], "runtime": _runtime_snapshot(), "cache": attack_data.cache_status()}), status


@app.route("/api/session")
def session():
    """Issue a same-origin CSRF token for mutating local API operations."""
    return jsonify({"csrf_token": _csrf_token, "version": __version__})


@app.route("/api/actors")
def actors():
    """List threat-actor groups & campaigns that have techniques mapped."""
    if _runtime["loading"]:
        abort(503, description="ATT&CK data is still loading; poll /api/bootstrap")
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
    global _last_refresh
    _require_csrf()
    if _runtime["loading"]:
        return jsonify({"error": "bootstrap_in_progress", "message": "Wait for initial ATT&CK setup to finish.", "version": __version__}), 409
    if time.monotonic() - _last_refresh < REFRESH_COOLDOWN_SECONDS:
        return jsonify({"error": "refresh_rate_limited", "message": "Wait a few seconds before refreshing again.", "version": __version__}), 429
    # Validate before taking the lock: aborting inside the guarded block would
    # skip the release and wedge every later refresh on a 409.
    domains = _domains_from_request()
    if not _refresh_lock.acquire(blocking=False):
        return jsonify({"error": "refresh_in_progress", "message": "An ATT&CK refresh is already running.", "version": __version__}), 409
    try:
        with _runtime_lock:
            _runtime.update(ready=False, loading=True, phase="refreshing", error=None)
        try:
            idx = attack_data.refresh_index(domains)
        except Exception as exc:
            # A failed download must not strand health at 503 when a previous
            # index is still in memory and can keep serving plans.
            if attack_data.loaded_index_status().get("ready"):
                _mark_ready()
            else:
                _mark_error(exc)
            raise
        _mark_ready()
        _last_refresh = time.monotonic()
        return jsonify({
            "status": "refreshed",
            "domains": idx.domains,
            "data_version": idx.data_version,
            "cache": attack_data.cache_status(),
        })
    finally:
        _refresh_lock.release()


@app.route("/api/workflow/<stix_id>")
def workflow(stix_id: str):
    """Build the full attack workflow for one actor."""
    if _runtime["loading"]:
        abort(503, description="ATT&CK data is still loading; poll /api/bootstrap")
    domains = _domains_from_request()
    idx = attack_data.get_index(domains)
    _mark_ready()

    actor = idx.get_actor(stix_id)
    if not actor:
        return jsonify({
            "error": "actor_not_found",
            "message": f"No ATT&CK group or campaign matches {stix_id} in the selected domains.",
            "version": __version__,
        }), 404

    techniques = idx.actor_techniques(stix_id)

    # Kill-chain order comes from the live STIX matrix (see AttackIndex), so the
    # workflow stays correct as ATT&CK evolves its tactics.
    tactic_order = idx.tactic_order or attack_data.TACTIC_ORDER
    tactic_titles = idx.tactic_titles or attack_data.TACTIC_TITLES

    # Group techniques into kill-chain stages. A technique can appear in more
    # than one tactic, so it can show up in multiple stages of the workflow.
    stages: Dict[str, List[Dict[str, Any]]] = {t: [] for t in tactic_order}

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

        for tac in tech["tactics"]:
            if tac in stages:
                stages[tac].append(enriched)

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
        "metadata": {
            "domains": idx.domains,
            "data_version": idx.data_version,
            "version": __version__,
        },
    })


@app.route("/api/execution-kit", methods=["POST"])
def execution_kit_download():
    """Build a portable CSV plus PowerShell/Bash runner without executing it."""
    _require_csrf()
    document = request.get_json(silent=True)
    if document is None:
        abort(400, description="A JSON AdversaryFlow plan is required")
    try:
        archive, filename = execution_kit.build_execution_kit(document)
    except execution_kit.ExecutionKitError as exc:
        abort(400, description=str(exc))
    _log_event("execution_kit_generated", platform=document.get("scope", {}).get("command_platform"),
               size_bytes=len(archive))
    response = send_file(
        io.BytesIO(archive),
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


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
    supplied = [str(domain).strip() for domain in values if str(domain).strip()]
    domains = list(dict.fromkeys(
        str(domain).strip()
        for domain in supplied
        if str(domain).strip() in attack_data.STIX_SOURCES
    ))
    invalid = [domain for domain in supplied if domain not in attack_data.STIX_SOURCES]
    if invalid:
        abort(400, description=f"Unknown ATT&CK domain(s): {', '.join(invalid)}")
    return domains or ["enterprise"]


def _mark_ready() -> None:
    with _runtime_lock:
        _runtime.update(ready=True, loading=False, phase="ready", error=None,
                        completed_at=time.time())


def _mark_error(exc: Exception) -> None:
    with _runtime_lock:
        _runtime.update(ready=False, loading=False, phase="failed", error=str(exc),
                        completed_at=time.time())


def _runtime_snapshot() -> Dict[str, Any]:
    with _runtime_lock:
        return dict(_runtime)


def _require_csrf() -> None:
    origin = request.headers.get("Origin")
    if origin:
        host = urllib.parse.urlparse(origin).hostname
        expected = (request.host or "").split(":")[0]
        if host and host != expected:
            abort(403, description="Cross-origin request refused")
    if not secrets.compare_digest(request.headers.get("X-AdversaryFlow-CSRF", ""), _csrf_token):
        abort(403, description="Missing or invalid same-origin request token")


def _bootstrap_worker() -> None:
    try:
        attack_data.get_index(["enterprise"])
        _mark_ready()
        _log_event("bootstrap_ready")
    except Exception as exc:
        # The worker owns the whole bootstrap: any failure must become a
        # reportable phase rather than an unhandled thread exception.
        _mark_error(exc)
        _log_event("bootstrap_failed", level="error", error=str(exc))


def _start_bootstrap() -> bool:
    with _runtime_lock:
        if _runtime["loading"]:
            return False
        _runtime.update(ready=False, loading=True, phase="loading", error=None,
                        started_at=time.time(), completed_at=None)
    threading.Thread(target=_bootstrap_worker, name="attack-bootstrap", daemon=True).start()
    return True


def _log_event(event: str, level: str = "info", **fields: Any) -> None:
    levels = {"debug": 10, "info": 20, "warning": 30, "error": 40}
    if levels.get(level, 20) < levels.get(LOG_LEVEL, 20):
        return
    record = {"timestamp": time.time(), "level": level, "event": event, **fields}
    print(json.dumps(record, sort_keys=True), flush=True)


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
    # Per-request failures must not flip process-wide readiness. Bootstrap and
    # refresh workers call _mark_error themselves when ATT&CK data is actually
    # unusable.
    _log_event("request_failed", level="error", error=type(exc).__name__,
               request_id=getattr(g, "request_id", "unknown"))
    return jsonify({
        "error": "request_failed",
        "message": "The request failed. Check the server log with the request ID.",
        "request_id": getattr(g, "request_id", "unknown"),
        "version": __version__,
    }), 500


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adversaryflow",
        description="Guided MITRE ATT&CK adversary-emulation workflow planner",
    )
    parser.add_argument("command", nargs="?", default="serve",
                        choices=["serve", "doctor", "cache-status", "cache-refresh", "cache-clear"])
    parser.add_argument("--host", default=os.environ.get("ADVERSARYFLOW_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ADVERSARYFLOW_PORT", "5000")))
    parser.add_argument("--cache-dir", default=os.environ.get("ADVERSARYFLOW_CACHE_DIR"))
    parser.add_argument("--offline", action="store_true", default=os.environ.get("ADVERSARYFLOW_OFFLINE", "").lower() in {"1", "true", "yes"}, help="use cached ATT&CK data without downloading")
    parser.add_argument("--no-preload", action="store_true", help="start before loading ATT&CK data")
    parser.add_argument("--open", action="store_true", dest="open_browser", help="open the browser when the service is ready")
    parser.add_argument("--allow-remote", action="store_true", help="explicitly permit a non-loopback bind address")
    parser.add_argument("--api-token", default=os.environ.get("ADVERSARYFLOW_API_TOKEN", ""),
                        help="bearer token required for non-loopback API access (or ADVERSARYFLOW_API_TOKEN)")
    parser.add_argument("--yes", action="store_true", help="confirm a destructive maintenance operation")
    parser.add_argument("--domains", default="enterprise", help="comma-separated domains for cache-refresh")
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"],
                        default=os.environ.get("ADVERSARYFLOW_LOG_LEVEL", "info"))
    parser.add_argument("--version", action="version", version=f"AdversaryFlow {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    global API_TOKEN, LOG_LEVEL, REMOTE_MODE
    args = _parser().parse_args(argv)
    LOG_LEVEL = args.log_level
    if args.cache_dir:
        attack_data.configure_cache_dir(args.cache_dir)
    attack_data.configure_offline(args.offline)

    if args.command == "doctor":
        return _doctor()
    if args.command == "cache-status":
        print(json.dumps(attack_data.cache_status(), indent=2, sort_keys=True))
        return 0
    if args.command == "cache-refresh":
        domains = [item.strip() for item in args.domains.split(",") if item.strip()]
        invalid = [item for item in domains if item not in attack_data.STIX_SOURCES]
        if invalid:
            print(f"Unknown ATT&CK domain(s): {', '.join(invalid)}")
            return 2
        attack_data.refresh_index(domains)
        print(json.dumps(attack_data.cache_status(), indent=2, sort_keys=True))
        return 0
    if args.command == "cache-clear":
        if not args.yes:
            print("Refusing to clear the cache without --yes.")
            return 2
        print(json.dumps({"removed": attack_data.clear_disk_cache()}, indent=2))
        return 0

    if not _is_loopback_host(args.host) and not args.allow_remote:
        print("Refusing a non-loopback bind without --allow-remote. Read docs/OPERATIONS.md first.")
        return 2
    if not _is_loopback_host(args.host) and not args.api_token:
        print("Refusing a non-loopback bind without --api-token or ADVERSARYFLOW_API_TOKEN.")
        return 2

    REMOTE_MODE = not _is_loopback_host(args.host)
    API_TOKEN = args.api_token
    if args.api_token and os.environ.get("ADVERSARYFLOW_API_TOKEN") != args.api_token:
        print("WARNING: --api-token is visible in process listings; prefer ADVERSARYFLOW_API_TOKEN.")

    if not args.no_preload:
        _start_bootstrap()

    from waitress import serve

    url_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    url = f"http://{url_host}:{args.port}"
    print(f"AdversaryFlow {__version__}: {url}")
    if not _is_loopback_host(args.host):
        print("WARNING: remote binding is enabled; every API request requires the configured bearer token.")
    if args.open_browser:
        threading.Thread(target=_open_when_ready, args=(url,), daemon=True).start()
    serve(
        app,
        host=args.host,
        port=args.port,
        threads=8,
        channel_timeout=120,
        ident=f"AdversaryFlow/{__version__}",
    )
    return 0


def _is_loopback_host(host: str) -> bool:
    name = host.strip().lower()
    if name in {"localhost"}:
        return True
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return False
    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    if mapped is not None:
        return mapped.is_loopback
    return address.is_loopback


def _open_when_ready(url: str) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if _runtime["ready"] or _runtime["phase"] == "failed":
            webbrowser.open(url)
            return
        time.sleep(0.2)


def _doctor() -> int:
    checks: Dict[str, Any] = {
        "version": __version__,
        "python": sys.version.split()[0],
        "frontend_dir": FRONTEND_DIR,
        "frontend_available": all((Path(FRONTEND_DIR) / name).is_file() for name in ("index.html", "styles.css", "app.js")),
        "cache": attack_data.cache_status(),
        "dependencies": {},
    }
    for package in ("Flask", "waitress"):
        try:
            checks["dependencies"][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            checks["dependencies"][package] = None
    try:
        os.makedirs(attack_data.CACHE_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".adversaryflow-doctor-", dir=attack_data.CACHE_DIR):
            checks["cache_writable"] = True
    except OSError as exc:
        checks["cache_writable"] = False
        checks["cache_error"] = str(exc)
    ok = checks["frontend_available"] and checks["cache_writable"] and all(checks["dependencies"].values())
    checks["ok"] = ok
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
