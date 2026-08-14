import json
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from adversaryflow import idpt
from adversaryflow.adapters import AdapterRequest, IdptLocalAdapter, adapter_readiness
from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import idpt_windows_collection_catalog_path, load_catalog


def _abilities():
    return load_catalog("content/abilities/idpt-windows-collection.json")


def _draft(abilities):
    return OfflinePlanner().draft(CampaignRequest("baseline", "local-lab", "validate IDPT", "windows"), abilities)


def _completed(stdout, returncode=0, stderr=""):
    return SimpleNamespace(stdout=json.dumps(stdout), stderr=stderr, returncode=returncode)


def _install_fake_idpt(monkeypatch, work_root, *, failure=None):
    checkout_root = work_root / "checkout"
    cli = checkout_root / "src" / "cli.mjs"
    cli.parent.mkdir(parents=True)
    cli.write_text("// fixture", encoding="utf-8")
    monkeypatch.setattr(idpt, "validate_checkout", lambda **_kwargs: {
        "root": checkout_root,
        "cli": cli,
        "node": "node",
        "node_version": "v24.0.0",
        "commit": idpt.SUPPORTED_IDPT_COMMIT,
        "validation": {"status": "valid", "content_version": idpt.SUPPORTED_IDPT_CONTENT_VERSION},
    })

    def fake_run(args, _cwd, _timeout, accepted=(0,)):
        command = args[2]
        if command == "plan":
            output = Path(args[args.index("--output") + 1])
            plan_directory = work_root / "outside-plan" if failure == "plan-outside" else output / "plans" / "fixture"
            plan_directory.mkdir(parents=True)
            external_ids = list(idpt.IDPT_ABILITY_MAP.values())
            if failure == "plan-actions":
                external_ids.pop()
            reverse = {value: key for key, value in idpt.IDPT_ABILITY_MAP.items()}
            technique = {ability.id: ability.technique_id for ability in _abilities()}
            plan = {
                "schema_version": "1.0",
                "plan_id": "plan--11111111-1111-4111-8111-111111111111",
                "scenario": {"id": idpt.IDPT_SCENARIO_ID},
                "hosts": [{"id": "local-lab"}],
                "actions": [{
                    "id": f"action-{index}",
                    "ability_id": external,
                    "host_id": "local-lab",
                    "technique": {"id": technique[reverse[external]]},
                } for index, external in enumerate(external_ids)],
            }
            if failure == "scenario":
                plan["scenario"]["id"] = "scenario--unexpected"
            if failure == "technique":
                plan["actions"][0]["technique"]["id"] = "T0000"
            (plan_directory / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
            return _completed({
                "status": "planned",
                "plan_id": plan["plan_id"],
                "plan_sha256": "0" * 64 if failure == "plan-hash" else idpt._canonical_hash(plan),
                "plan_directory": str(plan_directory),
            })
        if command == "run":
            output = Path(args[args.index("--output") + 1])
            external_run_id = "run--22222222-2222-4222-8222-222222222222"
            run_directory = work_root / "outside-run" if failure == "run-outside" else output / "runs" / "2026-08-14" / external_run_id
            run_directory.mkdir(parents=True)
            results = [{
                "ability_id": external,
                "status": "behavior-failed" if failure == "behavior" and index == 0 else "behavior-passed",
                "cleanup": {"status": "verified" if index == 3 else "not-required"},
                "telemetry": {"status": "not-configured"},
            } for index, external in enumerate(idpt.IDPT_ABILITY_MAP.values())]
            if failure == "run-results":
                results.pop()
            run_status = "failed" if failure == "run-summary" else "passed"
            (run_directory / "run.json").write_text(json.dumps({"run_id": external_run_id, "status": run_status, "results": results}), encoding="utf-8")
            (run_directory / "evidence-manifest.json").write_text(json.dumps({"files": {"run.json": "fixture"}}), encoding="utf-8")
            return _completed({"status": "passed", "run_id": external_run_id, "run_directory": str(run_directory)})
        if command == "verify":
            status = "verification-failed" if failure == "verify" else "integrity-verified"
            return _completed({"status": status, "files": 2})
        raise AssertionError(args)

    monkeypatch.setattr(idpt, "_run", fake_run)


def test_idpt_adapter_imports_verified_behavior_without_claiming_detection(monkeypatch):
    work_root = Path("artifacts") / f"idpt-fixture-{uuid4()}"
    _install_fake_idpt(monkeypatch, work_root)
    abilities = _abilities()
    events = idpt.execute(
        draft=_draft(abilities),
        abilities=abilities,
        run_id="run-parent",
        work_root=str(work_root / "work"),
        timeout_seconds=60,
        approval_id="approval-one",
        approver="manager@example.test",
        approved_at="2026-08-14T00:00:00+00:00",
        parent_plan_hash="a" * 64,
    )
    assert len(events) == 5
    assert all(event["behavior_success"] for event in events)
    assert all(event["external_telemetry_status"] == "not-configured" for event in events)
    assert all(event["external_run_id"].startswith("run--") for event in events)
    record = json.loads((work_root / "work" / "idpt" / "integration.json").read_text(encoding="utf-8"))
    assert record["idpt_commit"] == idpt.SUPPORTED_IDPT_COMMIT
    assert record["ability_mapping"] == idpt.IDPT_ABILITY_MAP


def test_idpt_adapter_rejects_plan_mapping_drift(monkeypatch):
    work_root = Path("artifacts") / f"idpt-drift-{uuid4()}"
    _install_fake_idpt(monkeypatch, work_root, failure="plan-actions")
    abilities = _abilities()
    with pytest.raises(ValueError, match="exactly match"):
        idpt.execute(
            draft=_draft(abilities), abilities=abilities, run_id="run-parent",
            work_root=str(work_root / "work"), timeout_seconds=60,
            approval_id="approval", approver="manager@example.test",
            approved_at="2026-08-14T00:00:00+00:00", parent_plan_hash="b" * 64,
        )


def test_idpt_adapter_requires_complete_catalog_and_approval_context():
    abilities = _abilities()
    draft = _draft(abilities)
    readiness = adapter_readiness(abilities[:-1], "idpt-local")
    assert readiness["compatible"] is False
    assert "complete packaged" in readiness["detail"]
    request = AdapterRequest(draft, abilities, "run-parent", work_root="artifacts/idpt-missing-context")
    with pytest.raises(ValueError, match="approval context"):
        IdptLocalAdapter().execute(request)


def test_idpt_checkout_fails_closed_on_unpinned_commit(monkeypatch):
    root = Path("artifacts") / f"idpt-checkout-{uuid4()}"
    (root / "src").mkdir(parents=True)
    (root / "src" / "cli.mjs").write_text("// fixture", encoding="utf-8")
    monkeypatch.setattr(idpt.shutil, "which", lambda command: command)
    monkeypatch.setattr(idpt, "_run", lambda args, *_rest, **_kwargs: SimpleNamespace(
        stdout="v24.0.0\n" if args[1:] == ["--version"] else "0" * 40 + "\n",
        stderr="", returncode=0,
    ))
    with pytest.raises(ValueError, match="pinned"):
        idpt.validate_checkout(str(root))


def test_idpt_command_and_json_boundaries(monkeypatch, tmp_path):
    completed = subprocess.CompletedProcess(["idpt"], 0, stdout='{"status":"ok"}', stderr="")
    monkeypatch.setattr(idpt.subprocess, "run", lambda *_args, **_kwargs: completed)
    assert idpt._run(["idpt"], tmp_path, 1) is completed
    assert idpt._json_output(completed, "test") == {"status": "ok"}

    monkeypatch.setattr(idpt.subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess(
        ["idpt"], 1, stdout="", stderr="failure detail",
    ))
    with pytest.raises(ValueError, match="exit code 1: failure detail"):
        idpt._run(["idpt"], tmp_path, 1)

    monkeypatch.setattr(idpt.subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess(
        ["idpt"], 0, stdout="x" * (idpt._MAX_TOOL_OUTPUT + 1), stderr="",
    ))
    with pytest.raises(ValueError, match="output exceeded"):
        idpt._run(["idpt"], tmp_path, 1)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["idpt"], 1)

    monkeypatch.setattr(idpt.subprocess, "run", timeout)
    with pytest.raises(ValueError, match="timed out"):
        idpt._run(["idpt"], tmp_path, 1)
    with pytest.raises(ValueError, match="valid JSON"):
        idpt._json_output(SimpleNamespace(stdout="not-json"), "test")
    with pytest.raises(ValueError, match="invalid response"):
        idpt._json_output(SimpleNamespace(stdout="[]"), "test")


def test_idpt_checkout_validation_and_readiness(monkeypatch, tmp_path):
    cli = tmp_path / "src" / "cli.mjs"
    cli.parent.mkdir()
    cli.write_text("// fixture", encoding="utf-8")
    monkeypatch.setenv("ADVERSARYFLOW_IDPT_ROOT", str(tmp_path))
    monkeypatch.setattr(idpt.shutil, "which", lambda command: command)

    def valid_run(args, *_rest, **_kwargs):
        if args[1:] == ["--version"]:
            return SimpleNamespace(stdout="v24.0.0\n", stderr="", returncode=0)
        if "rev-parse" in args:
            return SimpleNamespace(stdout=idpt.SUPPORTED_IDPT_COMMIT + "\n", stderr="", returncode=0)
        if "status" in args:
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        return _completed({"status": "valid", "content_version": idpt.SUPPORTED_IDPT_CONTENT_VERSION})

    monkeypatch.setattr(idpt, "_run", valid_run)
    checkout = idpt.validate_checkout()
    assert checkout["root"] == tmp_path.resolve()
    status = idpt.readiness(_abilities())
    assert status["idpt_commit"] == idpt.SUPPORTED_IDPT_COMMIT
    assert status["node_version"] == "v24.0.0"


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing-root", "must name"),
        ("missing-cli", "does not contain"),
        ("missing-tool", "requires git and Node"),
        ("old-node", "Node.js 20"),
        ("dirty", "modified tracked files"),
        ("invalid-content", "valid content version"),
    ],
)
def test_idpt_checkout_rejects_invalid_environment(monkeypatch, tmp_path, case, message):
    monkeypatch.delenv("ADVERSARYFLOW_IDPT_ROOT", raising=False)
    if case == "missing-root":
        with pytest.raises(ValueError, match=message):
            idpt.validate_checkout()
        return
    root = tmp_path / "checkout"
    root.mkdir()
    if case != "missing-cli":
        cli = root / "src" / "cli.mjs"
        cli.parent.mkdir()
        cli.write_text("// fixture", encoding="utf-8")
    if case == "missing-cli":
        with pytest.raises(ValueError, match=message):
            idpt.validate_checkout(str(root))
        return
    monkeypatch.setattr(idpt.shutil, "which", lambda command: None if case == "missing-tool" and command == "node" else command)

    def fake_run(args, *_rest, **_kwargs):
        if args[1:] == ["--version"]:
            version = "v18.0.0" if case == "old-node" else "v24.0.0"
            return SimpleNamespace(stdout=version + "\n", stderr="", returncode=0)
        if "rev-parse" in args:
            return SimpleNamespace(stdout=idpt.SUPPORTED_IDPT_COMMIT + "\n", stderr="", returncode=0)
        if "status" in args:
            return SimpleNamespace(stdout=" M src/cli.mjs\n" if case == "dirty" else "", stderr="", returncode=0)
        version = "0.0.0" if case == "invalid-content" else idpt.SUPPORTED_IDPT_CONTENT_VERSION
        return _completed({"status": "valid", "content_version": version})

    monkeypatch.setattr(idpt, "_run", fake_run)
    with pytest.raises(ValueError, match=message):
        idpt.validate_checkout(str(root))


def test_idpt_rejects_non_windows_catalog():
    abilities = _abilities()
    mixed = (replace(abilities[0], platform="linux"), *abilities[1:])
    with pytest.raises(ValueError, match="only the reviewed Windows"):
        idpt._compatible_abilities(mixed)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("plan-outside", "outside the run-owned"),
        ("plan-hash", "identity or canonical hash"),
        ("scenario", "unexpected scenario"),
        ("technique", "mapping drifted"),
        ("run-outside", "invalid run identity"),
        ("run-summary", "run summary"),
        ("run-results", "run results"),
        ("verify", "integrity-verified"),
    ],
)
def test_idpt_execution_rejects_untrusted_evidence(monkeypatch, tmp_path, failure, message):
    _install_fake_idpt(monkeypatch, tmp_path, failure=failure)
    abilities = _abilities()
    with pytest.raises(ValueError, match=message):
        idpt.execute(
            draft=_draft(abilities), abilities=abilities, run_id="run-parent",
            work_root=str(tmp_path / "work"), timeout_seconds=60,
            approval_id="approval", approver="manager@example.test",
            approved_at="2026-08-14T00:00:00+00:00", parent_plan_hash="c" * 64,
        )


def test_idpt_execution_reports_behavior_failure(monkeypatch, tmp_path):
    _install_fake_idpt(monkeypatch, tmp_path, failure="behavior")
    abilities = _abilities()
    events = idpt.execute(
        draft=_draft(abilities), abilities=abilities, run_id="run-parent",
        work_root=str(tmp_path / "work"), timeout_seconds=60,
        approval_id="approval", approver="manager@example.test",
        approved_at="2026-08-14T00:00:00+00:00", parent_plan_hash="d" * 64,
    )
    failed = [event for event in events if not event["behavior_success"]]
    assert len(failed) == 1
    assert failed[0]["failure"] == "IDPT action status: behavior-failed"


def test_packaged_idpt_catalog_matches_source_catalog():
    source = json.loads(Path("content/abilities/idpt-windows-collection.json").read_text(encoding="utf-8"))
    packaged = json.loads(idpt_windows_collection_catalog_path().read_text(encoding="utf-8"))
    assert packaged == source
