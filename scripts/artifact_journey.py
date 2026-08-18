"""Run the documented first-user journey against built release artifacts."""

import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def isolated_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    if overrides:
        environment.update(overrides)
    return environment


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        command,
        cwd=cwd,
        check=True,
        env=env if env is not None else isolated_environment(),
    )


def run_capture(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env if env is not None else isolated_environment(),
    )
    return result.stdout


def run_expect_failure(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env if env is not None else isolated_environment(),
    )
    if result.returncode == 0:
        raise RuntimeError(f"Expected command to fail: {' '.join(command)}")
    # CLI diagnostics conventionally use stderr; assert against both streams so
    # the release standard verifies the guidance the operator actually sees.
    return result.stdout + result.stderr


def journey(release_dir: str | Path) -> list[str]:
    release = Path(release_dir).resolve()
    artifacts = [*release.glob("*.whl"), *release.glob("*.tar.gz")]
    source_zip = release / "adversaryflow-source.zip"
    if source_zip.exists():
        artifacts.append(source_zip)
    if not artifacts:
        raise FileNotFoundError(f"No release artifacts found in {release}")
    completed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="adversaryflow-journey-") as temp:
        root = Path(temp)
        for artifact in artifacts:
            name = artifact.name.replace(".", "-")
            env_root = root / name
            env_root.mkdir()
            if artifact.suffix == ".zip":
                source = env_root / "source"
                source.mkdir()
                with zipfile.ZipFile(artifact) as archive:
                    archive.extractall(source)
                install_target = next(source.iterdir())
            else:
                install_target = artifact
            venv = env_root / "venv"
            run([sys.executable, "-m", "venv", str(venv)], env_root)
            python = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
            console = venv / ("Scripts/adversaryflow.exe" if sys.platform == "win32" else "bin/adversaryflow")
            run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], env_root)
            run([str(python), "-m", "pip", "install", str(install_target)], env_root)
            run([
                str(python),
                "-I",
                "-c",
                "import pathlib, adversaryflow; "
                f"assert pathlib.Path(adversaryflow.__file__).resolve().is_relative_to(pathlib.Path({str(venv)!r}).resolve())",
            ], env_root)
            roe = env_root / "roe.yaml"
            roe.write_text(
                "engagement_name: Release artifact validation\n"
                "operator_name: operator@example.test\n"
                "approver_name: manager@example.test\n"
                "environment: local-lab\n"
                "approved_targets:\n  - local-lab\n"
                "excluded_targets:\n  - production\n"
                "dry_run: true\n"
                "allowed_actions:\n  - simulation\n  - telemetry_validation\n",
                encoding="utf-8",
            )
            module = [str(python), "-I", "-m", "adversaryflow"]
            run([str(console), "doctor", "--json"], env_root)
            run([*module, "doctor", "--fix", "--json"], env_root)
            run([*module, "validate", str(roe)], env_root)
            run([*module, "capabilities"], env_root)
            run([*module, "adapter", "status"], env_root)
            run([*module, "draft", "--roe", str(roe), "--actor", "APT29", "--objective", "release draft"], env_root)
            attack_bundle = env_root / "attack-release-fixture.stix"
            attack_bundle.write_text(json.dumps({"objects": [{
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"external_id": "T1059"}],
            }]}), encoding="utf-8")
            plan_output = run_capture([
                *module, "plan", "--roe", str(roe),
                "--actor", "APT29", "--technique", "T1059", "--attack-bundle", str(attack_bundle),
            ], env_root)
            if "DRY RUN ONLY" not in plan_output:
                raise RuntimeError(f"MITRE dry-run planning did not complete for {artifact.name}")
            missing_technique = run_expect_failure([
                *module, "plan", "--roe", str(roe),
                "--actor", "APT29", "--technique", "T0000", "--attack-bundle", str(attack_bundle),
            ], env_root)
            if "Technique not found in MITRE ATT&CK source" not in missing_technique:
                raise RuntimeError(f"MITRE troubleshooting did not explain a missing technique for {artifact.name}")
            guide = run_capture([*module, "guide"], env_root)
            if "Approve the local synthetic emulation" not in guide or "manager --open" not in guide:
                raise RuntimeError(f"Campaign guidance missing for {artifact.name}")
            run([*module, "manager", "--help"], env_root)
            manager_smoke = """import json, threading, urllib.request
from http.server import ThreadingHTTPServer
from adversaryflow.manager import make_handler
root = 'manager-campaigns'
server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(root))
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    base = f'http://127.0.0.1:{server.server_port}'
    page = urllib.request.urlopen(base + '/').read().decode()
    assert '/assets/manager.js' in page and '/assets/manager.css' in page
    assert 'function draft(provider)' in urllib.request.urlopen(base + '/assets/manager.js').read().decode()
    request = urllib.request.Request(base + '/api/campaigns', data=json.dumps({'actor': 'APT29', 'target': 'local-lab', 'objective': 'installed manager smoke'}).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    created = json.loads(urllib.request.urlopen(request).read())
    detail = json.loads(urllib.request.urlopen(base + '/api/campaigns/' + created['campaign_id']).read())
    assert created['stage'] == 'drafted' and detail['metadata']['status'] == 'awaiting-approval'
finally:
    server.shutdown(); thread.join(timeout=2)
"""
            run([str(python), "-c", manager_smoke], env_root)
            run([*module, "demo", "--output", str(env_root / "runs")], env_root)
            run([*module, "provider", "validate"], env_root)
            run([*module, "provider", "configure"], env_root)
            run([*module, "provider", "diagnose"], env_root)
            run([*module, "provider", "profile", "list"], env_root)
            run([*module, "provider", "profile", "save", "release-test", "--endpoint", "https://example.test/v1", "--model", "test-model", "--credential-env", "RELEASE_TEST_KEY"], env_root)
            run([*module, "provider", "profile", "use", "release-test"], env_root)
            run([*module, "provider", "profile", "status"], env_root)
            run([*module, "provider", "policy", "status"], env_root)
            run([*module, "provider", "policy", "allow", "release-test"], env_root)
            run([*module, "provider", "profile", "remove", "release-test"], env_root)
            provider_test = run_expect_failure([*module, "provider", "test"], env_root)
            if "Provider test requires" not in provider_test:
                raise RuntimeError(f"Provider-test recovery was not actionable for {artifact.name}")
            campaign_output = run_capture([
                *module, "campaign", "--actor", "APT29",
                "--objective", "validate endpoint process visibility", "--approve",
                "--approver", "manager@example.test", "--output", str(env_root / "campaign-runs"),
                "--campaign-root", str(env_root / "campaigns"),
            ], env_root)
            campaign_result = json.loads(campaign_output)
            if campaign_result.get("stage") != "completed":
                raise RuntimeError(f"Campaign did not complete for {artifact.name}")
            failure_env = isolated_environment({"ADVERSARYFLOW_PROVIDER": "unsupported-provider"})
            fallback_output = run_capture([
                *module, "campaign", "--actor", "APT29",
                "--objective", "provider recovery rehearsal", "--fallback-offline", "--approve",
                "--approver", "manager@example.test", "--output", str(env_root / "fallback-runs"),
                "--campaign-root", str(env_root / "fallback-campaigns"),
            ], env_root, env=failure_env)
            if json.loads(fallback_output).get("provider") != "offline-fallback":
                raise RuntimeError(f"Offline provider fallback was not exercised for {artifact.name}")
            draft_output = run_capture([
                *module, "campaign", "--actor", "APT29",
                "--objective", "cancellation recovery rehearsal", "--campaign-root", str(env_root / "recovery-campaigns"),
            ], env_root)
            draft_id = json.loads(draft_output)["campaign_id"]
            run([*module, "campaign", "list", "--campaign-root", str(env_root / "recovery-campaigns")], env_root)
            run([*module, "campaign", "inspect", "--campaign-id", draft_id, "--campaign-root", str(env_root / "recovery-campaigns")], env_root)
            cancel_output = run_capture([
                *module, "campaign", "cancel", "--campaign-id", draft_id,
                "--reason", "operator requested stop", "--campaign-root", str(env_root / "recovery-campaigns"),
            ], env_root)
            if json.loads(cancel_output).get("status") != "cancelled":
                raise RuntimeError(f"Campaign cancellation recovery was not exercised for {artifact.name}")
            rejected = run_capture([
                *module, "campaign", "--actor", "APT29", "--objective", "rejection rehearsal",
                "--campaign-root", str(env_root / "rejection-campaigns"),
            ], env_root)
            rejected_id = json.loads(rejected)["campaign_id"]
            run([*module, "campaign", "reject", "--campaign-id", rejected_id, "--approver", "manager@example.test", "--reason", "not scheduled", "--campaign-root", str(env_root / "rejection-campaigns")], env_root)
            reset = run_capture([
                *module, "campaign", "--actor", "APT29", "--objective", "reset rehearsal",
                "--campaign-root", str(env_root / "reset-campaigns"),
            ], env_root)
            reset_id = json.loads(reset)["campaign_id"]
            run([*module, "campaign", "reset", "--campaign-id", reset_id, "--confirm", "--campaign-root", str(env_root / "reset-campaigns")], env_root)
            invalid_provider = run_expect_failure([
                *module, "provider", "validate",
            ], env_root, env=isolated_environment({"ADVERSARYFLOW_PROVIDER": "unsupported-provider"}))
            if "Unsupported provider" not in invalid_provider:
                raise RuntimeError(f"Provider troubleshooting did not explain invalid configuration for {artifact.name}")
            run([*module, "support-bundle", "--output", str(env_root / "support")], env_root)
            if not list((env_root / "runs").rglob("telemetry-gap-report.json")):
                raise RuntimeError(f"Demo report missing for {artifact.name}")
            if not list((env_root / "support").glob("*.zip")):
                raise RuntimeError(f"Support bundle missing for {artifact.name}")
            completed.append(artifact.name)
    return completed


if __name__ == "__main__":
    release_path = sys.argv[1] if len(sys.argv) > 1 else "artifacts/release"
    print("\n".join(journey(release_path)))
