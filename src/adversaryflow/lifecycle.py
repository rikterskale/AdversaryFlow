import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _campaign_dir(root: str | Path, campaign_id: str) -> Path:
    base = Path(root).resolve()
    candidate = (base / campaign_id).resolve()
    if candidate.parent != base or not candidate.name.startswith("campaign-"):
        raise ValueError("campaign ID must name a campaign-* directory directly under the campaign root")
    return candidate


def list_campaigns(root: str | Path = "artifacts/campaigns") -> list[dict[str, Any]]:
    base = Path(root)
    if not base.exists():
        return []
    results = []
    for directory in sorted(base.glob("campaign-*")):
        metadata_path = directory / "metadata.json"
        if metadata_path.exists():
            results.append(json.loads(metadata_path.read_text(encoding="utf-8")))
    return results


def inspect_campaign(root: str | Path, campaign_id: str) -> dict[str, Any]:
    directory = _campaign_dir(root, campaign_id)
    if not directory.is_dir():
        raise FileNotFoundError(f"Campaign not found: {campaign_id}")
    result: dict[str, Any] = {"campaign_dir": str(directory)}
    for name in ("metadata.json", "draft.json", "approval.json"):
        path = directory / name
        if path.exists():
            result[name.removesuffix(".json")] = json.loads(path.read_text(encoding="utf-8"))
    result["reports"] = [path.name for path in directory.glob("campaign-report.*")]
    return result


def reject_campaign(root: str | Path, campaign_id: str, approver: str, reason: str) -> Path:
    directory = _campaign_dir(root, campaign_id)
    if not directory.is_dir():
        raise FileNotFoundError(f"Campaign not found: {campaign_id}")
    metadata_path = directory / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    rejection = {"approver": approver, "decision": "rejected", "reason": reason, "rejected_at": datetime.now(timezone.utc).isoformat(), "plan_hash": metadata["plan_hash"]}
    (directory / "rejection.json").write_text(json.dumps(rejection, indent=2), encoding="utf-8")
    metadata.update({"status": "rejected", "rejection": "rejection.json"})
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return directory / "rejection.json"


def reset_campaign(root: str | Path, campaign_id: str, confirm: bool) -> None:
    if not confirm:
        raise PermissionError("Reset requires --confirm")
    directory = _campaign_dir(root, campaign_id)
    if not directory.is_dir():
        raise FileNotFoundError(f"Campaign not found: {campaign_id}")
    shutil.rmtree(directory)

