import json
import platform
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .doctor import run_doctor


def create_support_bundle(output: str | Path = "artifacts/support", roe_path: str = "examples/roe.yaml") -> Path:
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle = root / f"adversaryflow-support-{stamp}.zip"
    diagnostics: dict[str, Any] = {"product": "AdversaryFlow", "python": sys.version, "platform": platform.platform(), "doctor": run_doctor(roe_path)}
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", json.dumps(diagnostics, indent=2))
        archive.writestr("README.txt", "Redacted AdversaryFlow diagnostics. No secrets or provider credentials are included.\n")
    return bundle
