import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if any(token in key.lower() for token in ("secret", "password", "token", "key")) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def record(self, event: str, **details: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, "details": redact(details)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

