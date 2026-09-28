"""SQLite persistence for immutable engagement plan revisions."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from . import attack_data


MAX_STORED_ENGAGEMENTS = 10_000
MAX_REVISIONS_PER_ENGAGEMENT = 2_000


class EngagementStoreError(ValueError):
    """The requested engagement operation is invalid."""


def _database_path() -> Path:
    configured = os.environ.get("ADVERSARYFLOW_ENGAGEMENT_DB")
    if configured:
        return Path(os.path.abspath(os.path.expanduser(configured)))
    return Path(attack_data.CACHE_DIR) / "engagements.sqlite3"


def _connect() -> sqlite3.Connection:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(document: Mapping[str, Any]) -> tuple[str, str]:
    try:
        text = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EngagementStoreError("Plan must be JSON serializable") from exc
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def initialize() -> None:
    """Create the local store schema if it does not already exist."""
    with _connect() as connection:
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            actor_name TEXT NOT NULL,
            data_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS plan_revisions (
            engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            schema_version TEXT NOT NULL,
            plan_sha256 TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (engagement_id, revision)
        );
        CREATE INDEX IF NOT EXISTS plan_revisions_digest_idx
            ON plan_revisions(plan_sha256);
        """)


def _ensure_initialized() -> None:
    # The schema creation is idempotent and cheap; calling it at the public
    # boundary also supports deployments that upgrade without a startup hook.
    initialize()


def save_revision(plan: Mapping[str, Any], engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """Create an engagement or append a new immutable plan revision."""
    _ensure_initialized()
    actor = plan.get("actor")
    if not isinstance(actor, Mapping):
        raise EngagementStoreError("Plan actor metadata is incomplete")
    actor_id = str(actor.get("attack_id") or "").strip()
    actor_name = str(actor.get("name") or "").strip()
    data_version = str(plan.get("data_version") or "").strip()
    if not actor_id or not actor_name or not data_version:
        raise EngagementStoreError("Plan actor and ATT&CK data version are required")
    schema_version = str(plan.get("schema_version") or "")
    plan_json, digest = _canonical(plan)
    now = _utc_now()
    if engagement_id is not None:
        if not isinstance(engagement_id, str):
            raise EngagementStoreError("Engagement ID must be a UUID string")
        try:
            if str(uuid.UUID(engagement_id)) != engagement_id:
                raise ValueError("non-canonical UUID")
        except ValueError as exc:
            raise EngagementStoreError("Engagement ID must be a canonical UUID") from exc
    key = engagement_id or str(uuid.uuid4())
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute("SELECT actor_id FROM engagements WHERE id = ?", (key,)).fetchone()
        if current is None:
            count = connection.execute("SELECT COUNT(*) AS n FROM engagements").fetchone()["n"]
            if count >= MAX_STORED_ENGAGEMENTS:
                raise EngagementStoreError("The local engagement store reached its capacity")
            if engagement_id is not None:
                raise EngagementStoreError("Engagement was not found")
            connection.execute(
                "INSERT INTO engagements (id, actor_id, actor_name, data_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (key, actor_id, actor_name, data_version, now, now),
            )
        else:
            if current["actor_id"] != actor_id:
                raise EngagementStoreError("A revision cannot change the engagement actor")
            connection.execute(
                "UPDATE engagements SET actor_name = ?, data_version = ?, updated_at = ? WHERE id = ?",
                (actor_name, data_version, now, key),
            )
        revision = connection.execute(
            "SELECT COALESCE(MAX(revision), 0) + 1 AS next_revision FROM plan_revisions WHERE engagement_id = ?",
            (key,),
        ).fetchone()["next_revision"]
        if revision > MAX_REVISIONS_PER_ENGAGEMENT:
            raise EngagementStoreError("This engagement reached the revision limit")
        connection.execute(
            "INSERT INTO plan_revisions (engagement_id, revision, schema_version, plan_sha256, plan_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key, revision, schema_version, digest, plan_json, now),
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {"engagement_id": key, "revision": revision, "plan_sha256": digest, "created_at": now}


def list_engagements(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_initialized()
    if not 1 <= limit <= 200:
        raise EngagementStoreError("Engagement list limit must be between 1 and 200")
    with _connect() as connection:
        rows = connection.execute("""
            SELECT e.id, e.actor_id, e.actor_name, e.data_version, e.created_at, e.updated_at,
                   r.revision, r.schema_version, r.plan_sha256
            FROM engagements AS e
            JOIN plan_revisions AS r ON r.engagement_id = e.id
            WHERE r.revision = (SELECT MAX(r2.revision) FROM plan_revisions AS r2 WHERE r2.engagement_id = e.id)
            ORDER BY e.updated_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_engagement(engagement_id: str) -> Optional[Dict[str, Any]]:
    _ensure_initialized()
    with _connect() as connection:
        row = connection.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        if row is None:
            return None
        revisions = connection.execute(
            "SELECT revision, schema_version, plan_sha256, created_at FROM plan_revisions WHERE engagement_id = ? ORDER BY revision DESC",
            (engagement_id,),
        ).fetchall()
        latest = connection.execute(
            "SELECT plan_json FROM plan_revisions WHERE engagement_id = ? ORDER BY revision DESC LIMIT 1",
            (engagement_id,),
        ).fetchone()
    result = dict(row)
    result["revisions"] = [dict(item) for item in revisions]
    result["latest_plan"] = json.loads(latest["plan_json"]) if latest else None
    return result


def get_revision(engagement_id: str, revision: int) -> Optional[Dict[str, Any]]:
    _ensure_initialized()
    with _connect() as connection:
        row = connection.execute(
            "SELECT engagement_id, revision, schema_version, plan_sha256, plan_json, created_at FROM plan_revisions WHERE engagement_id = ? AND revision = ?",
            (engagement_id, revision),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["plan"] = json.loads(result.pop("plan_json"))
    return result
