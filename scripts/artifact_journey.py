"""Run the documented first-user journey against built release artifacts."""

import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run(command: list[str], cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)


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
            run([str(python), "-m", "adversaryflow", "demo", "--output", str(env_root / "runs")], env_root)
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
