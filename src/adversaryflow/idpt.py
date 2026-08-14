"""Pinned local integration with IDPT Emulation v2.

AdversaryFlow never imports or executes commands from a campaign catalog. This
module invokes one reviewed IDPT scenario from an exact, clean Git commit and
translates its evidence back into AdversaryFlow's event contract.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - fixed git/node commands with shell disabled
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .ai import AICampaignDraft
from .emulation import Ability


SUPPORTED_IDPT_COMMIT = "dcdac0f3e82469a95975a170bc201b06e164b7b6"
SUPPORTED_IDPT_CONTENT_VERSION = "2.0.0"
IDPT_SCENARIO_ID = "scenario--windows-safe-collection-flow"
IDPT_ABILITY_MAP = {
    "ability-idpt-powershell-marker": "ability--10000000-0000-4000-8000-000000000013",
    "ability-idpt-file-discovery": "ability--10000000-0000-4000-8000-000000000006",
    "ability-idpt-local-data": "ability--10000000-0000-4000-8000-000000000007",
    "ability-idpt-local-staging": "ability--10000000-0000-4000-8000-000000000008",
    "ability-idpt-loopback-collection": "ability--10000000-0000-4000-8000-000000000012",
}
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_PLAN_ID = re.compile(rf"^plan--{_UUID}$")
_RUN_ID = re.compile(rf"^run--{_UUID}$")
_MAX_TOOL_OUTPUT = 1024 * 1024


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _run(args: list[str], cwd: Path, timeout: int, accepted: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(  # nosec B603
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("IDPT command timed out") from error
    if len(completed.stdout) > _MAX_TOOL_OUTPUT or len(completed.stderr) > _MAX_TOOL_OUTPUT:
        raise ValueError("IDPT command output exceeded the integration limit")
    if completed.returncode not in accepted:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic output"
        raise ValueError(f"IDPT command failed with exit code {completed.returncode}: {detail[:2048]}")
    return completed


def _json_output(completed: subprocess.CompletedProcess[str], operation: str) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"IDPT {operation} did not return valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"IDPT {operation} returned an invalid response")
    return value


def _compatible_abilities(abilities: tuple[Ability, ...]) -> None:
    ids = [ability.id for ability in abilities]
    if len(ids) != len(IDPT_ABILITY_MAP) or set(ids) != set(IDPT_ABILITY_MAP):
        raise ValueError("idpt-local requires the complete packaged idpt-windows-collection catalog")
    if any(ability.platform != "windows" for ability in abilities):
        raise ValueError("idpt-local currently supports only the reviewed Windows collection scenario")


def validate_checkout(root_value: str | None = None, timeout: int = 30) -> dict[str, Any]:
    """Verify an exact clean checkout before any IDPT JavaScript is executed."""
    configured = root_value or os.environ.get("ADVERSARYFLOW_IDPT_ROOT")
    if not configured:
        raise ValueError("ADVERSARYFLOW_IDPT_ROOT must name the reviewed IDPT checkout")
    root = Path(configured).expanduser().resolve()
    cli = root / "src" / "cli.mjs"
    if not root.is_dir() or not cli.is_file():
        raise ValueError("ADVERSARYFLOW_IDPT_ROOT does not contain src/cli.mjs")
    git = shutil.which("git")
    node = shutil.which("node")
    if not git or not node:
        raise ValueError("idpt-local requires git and Node.js 20 or newer")
    node_version = _run([node, "--version"], root, timeout).stdout.strip()
    match = re.fullmatch(r"v(\d+)(?:\.\d+){2}", node_version)
    if not match or int(match.group(1)) < 20:
        raise ValueError("idpt-local requires Node.js 20 or newer")
    head = _run([git, "-C", str(root), "rev-parse", "HEAD"], root, timeout).stdout.strip().lower()
    if head != SUPPORTED_IDPT_COMMIT:
        raise ValueError(f"IDPT checkout must be pinned to reviewed commit {SUPPORTED_IDPT_COMMIT}")
    dirty = _run([git, "-C", str(root), "status", "--porcelain", "--untracked-files=no"], root, timeout).stdout.strip()
    if dirty:
        raise ValueError("IDPT checkout has modified tracked files; restore the reviewed commit before execution")
    validation = _json_output(_run([node, str(cli), "validate"], root, timeout), "validation")
    if validation.get("status") != "valid" or validation.get("content_version") != SUPPORTED_IDPT_CONTENT_VERSION:
        raise ValueError(f"IDPT must report valid content version {SUPPORTED_IDPT_CONTENT_VERSION}")
    return {"root": root, "cli": cli, "node": node, "node_version": node_version, "commit": head, "validation": validation}


def readiness(abilities: tuple[Ability, ...]) -> dict[str, Any]:
    _compatible_abilities(abilities)
    checkout = validate_checkout()
    return {
        "idpt_commit": checkout["commit"],
        "idpt_content_version": checkout["validation"]["content_version"],
        "idpt_scenario": IDPT_SCENARIO_ID,
        "idpt_root": str(checkout["root"]),
        "node_version": checkout["node_version"],
    }


def execute(
    *,
    draft: AICampaignDraft,
    abilities: tuple[Ability, ...],
    run_id: str,
    work_root: str,
    timeout_seconds: int,
    approval_id: str,
    approver: str,
    approved_at: str,
    parent_plan_hash: str,
) -> tuple[dict[str, Any], ...]:
    """Run one exact local IDPT scenario and import verified result evidence."""
    _compatible_abilities(abilities)
    checkout = validate_checkout(timeout=timeout_seconds)
    root = Path(work_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    integration_root = root / "idpt"
    output_root = integration_root / "output"
    integration_root.mkdir(parents=True, exist_ok=True)
    hosts_path = integration_root / "hosts.json"
    hosts = {
        "schema_version": "1.0",
        "hosts": [{
            "id": draft.target,
            "role": "endpoint",
            "platform": "windows",
            "transport": {"type": "local"},
            "labels": {"lab-approved": "true", "orchestrator": "adversaryflow"},
        }],
    }
    hosts_path.write_text(json.dumps(hosts, indent=2), encoding="utf-8")

    plan_response = _json_output(_run([
        checkout["node"], str(checkout["cli"]), "plan",
        "--scenario", IDPT_SCENARIO_ID,
        "--hosts", str(hosts_path),
        "--allow-generic-baseline",
        "--output", str(output_root),
    ], checkout["root"], timeout_seconds), "plan")
    plan_directory = Path(str(plan_response.get("plan_directory", ""))).resolve()
    if not _within(output_root.resolve(), plan_directory):
        raise ValueError("IDPT returned a plan directory outside the run-owned output root")
    plan_path = plan_directory / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan_id = str(plan.get("plan_id", ""))
    plan_sha256 = str(plan_response.get("plan_sha256", ""))
    if not _PLAN_ID.fullmatch(plan_id) or plan_sha256 != _canonical_hash(plan):
        raise ValueError("IDPT plan identity or canonical hash is invalid")
    if plan.get("scenario", {}).get("id") != IDPT_SCENARIO_ID:
        raise ValueError("IDPT returned an unexpected scenario")
    actions = plan.get("actions", [])
    if not isinstance(actions, list) or {item.get("ability_id") for item in actions} != set(IDPT_ABILITY_MAP.values()):
        raise ValueError("IDPT plan actions do not exactly match the reviewed integration mapping")
    by_external_id = {external: ability for ability in abilities for external in [IDPT_ABILITY_MAP[ability.id]]}
    for action in actions:
        ability = by_external_id[action["ability_id"]]
        if action.get("technique", {}).get("id") != ability.technique_id or action.get("host_id") != draft.target:
            raise ValueError("IDPT plan technique or host mapping drifted from the reviewed campaign")

    now = datetime.now(timezone.utc)
    roe_path = integration_root / "roe.json"
    roe = {
        "schema_version": "1.0",
        "engagement_id": run_id,
        "approval_reference": approval_id,
        "approved": True,
        "approved_by": approver,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(minutes=10)).isoformat(),
        "allowed_host_ids": [draft.target],
        "allowed_plan_ids": [plan_id],
        "allowed_plan_sha256": [plan_sha256],
        "allowed_scenarios": [IDPT_SCENARIO_ID],
        "allowed_techniques": [ability.technique_id for ability in abilities],
        "environment_labels": {"lab-approved": "true"},
        "notes": f"Derived from AdversaryFlow approval {approval_id} at {approved_at}; parent plan {parent_plan_hash}.",
    }
    roe_path.write_text(json.dumps(roe, indent=2), encoding="utf-8")
    run_response = _json_output(_run([
        checkout["node"], str(checkout["cli"]), "run",
        "--plan-file", str(plan_path),
        "--roe", str(roe_path),
        "--host-id", draft.target,
        "--output", str(output_root),
    ], checkout["root"], timeout_seconds, accepted=(0, 2)), "run")
    external_run_id = str(run_response.get("run_id", ""))
    run_directory = Path(str(run_response.get("run_directory", ""))).resolve()
    if not _RUN_ID.fullmatch(external_run_id) or not _within(output_root.resolve(), run_directory):
        raise ValueError("IDPT returned an invalid run identity or evidence directory")
    run_path = run_directory / "run.json"
    run_data = json.loads(run_path.read_text(encoding="utf-8"))
    if run_data.get("run_id") != external_run_id or run_data.get("status") != run_response.get("status"):
        raise ValueError("IDPT run summary does not match the returned run identity or status")
    results = run_data.get("results", [])
    if not isinstance(results, list) or {item.get("ability_id") for item in results} != set(IDPT_ABILITY_MAP.values()):
        raise ValueError("IDPT run results do not exactly match the reviewed integration mapping")
    verification = _json_output(_run([
        checkout["node"], str(checkout["cli"]), "verify", "--run-dir", str(run_directory),
    ], checkout["root"], timeout_seconds), "evidence verification")
    if verification.get("status") != "integrity-verified":
        raise ValueError("IDPT evidence verification did not report integrity-verified")
    evidence_manifest = run_directory / "evidence-manifest.json"
    evidence_sha256 = hashlib.sha256(evidence_manifest.read_bytes()).hexdigest()

    integration_record = {
        "contract": "ADVERSARYFLOW-IDPT-1",
        "idpt_commit": checkout["commit"],
        "idpt_content_version": checkout["validation"]["content_version"],
        "parent_run_id": run_id,
        "parent_plan_hash": parent_plan_hash,
        "idpt_plan_id": plan_id,
        "idpt_plan_sha256": plan_sha256,
        "idpt_run_id": external_run_id,
        "idpt_run_directory": str(run_directory),
        "evidence_manifest_sha256": evidence_sha256,
        "evidence_verification": verification,
        "ability_mapping": IDPT_ABILITY_MAP,
    }
    (integration_root / "integration.json").write_text(json.dumps(integration_record, indent=2), encoding="utf-8")

    result_by_id = {item["ability_id"]: item for item in results}
    events = []
    for ability in abilities:
        external_id = IDPT_ABILITY_MAP[ability.id]
        result = result_by_id[external_id]
        behavior_success = result.get("status") == "behavior-passed"
        event = {
            "event": "behavior_completed",
            "run_id": run_id,
            "host_id": draft.target,
            "ability_id": ability.id,
            "technique_id": ability.technique_id,
            "target": draft.target,
            "behavior_success": behavior_success,
            "cleanup_status": result.get("cleanup", {}).get("status", "not-run"),
            "telemetry": [asdict(item) for item in ability.expected_telemetry],
            "network_scope": ability.network_scope,
            "execution": "idpt-local",
            "adapter": "idpt-local",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "external_ability_id": external_id,
            "external_run_id": external_run_id,
            "external_plan_id": plan_id,
            "external_plan_sha256": plan_sha256,
            "external_status": result.get("status"),
            "external_telemetry_status": result.get("telemetry", {}).get("status", "not-configured"),
            "evidence_manifest_sha256": evidence_sha256,
        }
        if not behavior_success:
            event["failure"] = f"IDPT action status: {result.get('status', 'unknown')}"
        events.append(event)
    return tuple(events)
