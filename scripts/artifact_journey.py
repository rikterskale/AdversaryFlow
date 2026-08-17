"""Run the documented first-user journey against built release artifacts."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run(command: list[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def run_capture(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True, env=env)
    return result.stdout


def run_expect_failure(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, env=env)
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
            run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], env_root)
            run([str(python), "-m", "pip", "install", str(install_target)], env_root)
            run([str(python), "-m", "adversaryflow", "doctor", "--json"], env_root)
            run([str(python), "-m", "adversaryflow", "doctor", "--fix", "--json"], env_root)
            run([str(python), "-m", "adversaryflow", "validate", "examples/roe.yaml"], env_root)
            run([str(python), "-m", "adversaryflow", "capabilities"], env_root)
            run([str(python), "-m", "adversaryflow", "adapter", "status"], env_root)
            run([str(python), "-m", "adversaryflow", "draft", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "release draft"], env_root)
            attack_bundle = env_root / "attack-release-fixture.stix"
            attack_bundle.write_text(json.dumps({"objects": [{
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "external_references": [{"external_id": "T1059"}],
            }]}), encoding="utf-8")
            plan_output = run_capture([
                str(python), "-m", "adversaryflow", "plan", "--roe", "examples/roe.yaml",
                "--actor", "APT29", "--technique", "T1059", "--attack-bundle", str(attack_bundle),
            ], env_root)
            if "DRY RUN ONLY" not in plan_output:
                raise RuntimeError(f"MITRE dry-run planning did not complete for {artifact.name}")
            missing_technique = run_expect_failure([
                str(python), "-m", "adversaryflow", "plan", "--roe", "examples/roe.yaml",
                "--actor", "APT29", "--technique", "T0000", "--attack-bundle", str(attack_bundle),
            ], env_root)
            if "Technique not found in MITRE ATT&CK source" not in missing_technique:
                raise RuntimeError(f"MITRE troubleshooting did not explain a missing technique for {artifact.name}")
            guide = run_capture([str(python), "-m", "adversaryflow", "guide"], env_root)
            if "Approve the local synthetic emulation" not in guide or "manager --open" not in guide:
                raise RuntimeError(f"Campaign guidance missing for {artifact.name}")
            run([str(python), "-m", "adversaryflow", "manager", "--help"], env_root)
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
            run([str(python), "-m", "adversaryflow", "demo", "--output", str(env_root / "runs")], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "validate"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "configure"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "diagnose"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "profile", "list"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "profile", "save", "release-test", "--endpoint", "https://example.test/v1", "--model", "test-model", "--credential-env", "RELEASE_TEST_KEY"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "profile", "use", "release-test"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "profile", "status"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "policy", "status"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "policy", "allow", "release-test"], env_root)
            run([str(python), "-m", "adversaryflow", "provider", "profile", "remove", "release-test"], env_root)
            provider_test = run_expect_failure([str(python), "-m", "adversaryflow", "provider", "test"], env_root)
            if "Provider test requires" not in provider_test:
                raise RuntimeError(f"Provider-test recovery was not actionable for {artifact.name}")
            campaign_output = run_capture([
                str(python), "-m", "adversaryflow", "campaign", "--actor", "APT29",
                "--objective", "validate endpoint process visibility", "--approve",
                "--approver", "manager@example.test", "--output", str(env_root / "campaign-runs"),
                "--campaign-root", str(env_root / "campaigns"),
            ], env_root)
            campaign_result = json.loads(campaign_output)
            if campaign_result.get("stage") != "completed":
                raise RuntimeError(f"Campaign did not complete for {artifact.name}")
            failure_env = dict(os.environ)
            failure_env.update({"ADVERSARYFLOW_PROVIDER": "unsupported-provider"})
            fallback_output = run_capture([
                str(python), "-m", "adversaryflow", "campaign", "--actor", "APT29",
                "--objective", "provider recovery rehearsal", "--fallback-offline", "--approve",
                "--approver", "manager@example.test", "--output", str(env_root / "fallback-runs"),
                "--campaign-root", str(env_root / "fallback-campaigns"),
            ], env_root, env=failure_env)
            if json.loads(fallback_output).get("provider") != "offline-fallback":
                raise RuntimeError(f"Offline provider fallback was not exercised for {artifact.name}")
            draft_output = run_capture([
                str(python), "-m", "adversaryflow", "campaign", "--actor", "APT29",
                "--objective", "cancellation recovery rehearsal", "--campaign-root", str(env_root / "recovery-campaigns"),
            ], env_root)
            draft_id = json.loads(draft_output)["campaign_id"]
            run([str(python), "-m", "adversaryflow", "campaign", "list", "--campaign-root", str(env_root / "recovery-campaigns")], env_root)
            run([str(python), "-m", "adversaryflow", "campaign", "inspect", "--campaign-id", draft_id, "--campaign-root", str(env_root / "recovery-campaigns")], env_root)
            cancel_output = run_capture([
                str(python), "-m", "adversaryflow", "campaign", "cancel", "--campaign-id", draft_id,
                "--reason", "operator requested stop", "--campaign-root", str(env_root / "recovery-campaigns"),
            ], env_root)
            if json.loads(cancel_output).get("status") != "cancelled":
                raise RuntimeError(f"Campaign cancellation recovery was not exercised for {artifact.name}")
            rejected = run_capture([
                str(python), "-m", "adversaryflow", "campaign", "--actor", "APT29", "--objective", "rejection rehearsal",
                "--campaign-root", str(env_root / "rejection-campaigns"),
            ], env_root)
            rejected_id = json.loads(rejected)["campaign_id"]
            run([str(python), "-m", "adversaryflow", "campaign", "reject", "--campaign-id", rejected_id, "--approver", "manager@example.test", "--reason", "not scheduled", "--campaign-root", str(env_root / "rejection-campaigns")], env_root)
            reset = run_capture([
                str(python), "-m", "adversaryflow", "campaign", "--actor", "APT29", "--objective", "reset rehearsal",
                "--campaign-root", str(env_root / "reset-campaigns"),
            ], env_root)
            reset_id = json.loads(reset)["campaign_id"]
            run([str(python), "-m", "adversaryflow", "campaign", "reset", "--campaign-id", reset_id, "--confirm", "--campaign-root", str(env_root / "reset-campaigns")], env_root)
            invalid_provider = run_expect_failure([
                str(python), "-m", "adversaryflow", "provider", "validate",
            ], env_root, env={**os.environ, "ADVERSARYFLOW_PROVIDER": "unsupported-provider"})
            if "Unsupported provider" not in invalid_provider:
                raise RuntimeError(f"Provider troubleshooting did not explain invalid configuration for {artifact.name}")
            run([str(python), "-m", "adversaryflow", "support-bundle", "--output", str(env_root / "support")], env_root)
            if not list((env_root / "runs").rglob("telemetry-gap-report.json")):
                raise RuntimeError(f"Demo report missing for {artifact.name}")
            if not list((env_root / "support").glob("*.zip")):
                raise RuntimeError(f"Support bundle missing for {artifact.name}")
            completed.append(artifact.name)
    return completed


if __name__ == "__main__":
    release_path = sys.argv[1] if len(sys.argv) > 1 else "artifacts/release"
    print("\n".join(journey(release_path)))
