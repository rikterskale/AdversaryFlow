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

from . import attack_data, content_pack


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
            content_pack_sha256 TEXT NOT NULL DEFAULT '',
            content_packs_json TEXT NOT NULL DEFAULT '[]',
            plan_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (engagement_id, revision)
        );
        CREATE INDEX IF NOT EXISTS plan_revisions_digest_idx
            ON plan_revisions(plan_sha256);
        CREATE TABLE IF NOT EXISTS ability_backlog (
            id TEXT PRIMARY KEY,
            item_key TEXT NOT NULL UNIQUE,
            technique_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            gap TEXT NOT NULL,
            reason TEXT NOT NULL,
            ability_id TEXT,
            procedure_candidate_ids_json TEXT NOT NULL,
            owner TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ability_backlog_status_idx
            ON ability_backlog(status, updated_at DESC);
        CREATE TABLE IF NOT EXISTS run_records (
            engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            run_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT NOT NULL,
            receipt_count INTEGER NOT NULL,
            receipt_set_sha256 TEXT NOT NULL,
            telemetry_refs_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (engagement_id, revision, run_id),
            FOREIGN KEY (engagement_id, revision) REFERENCES plan_revisions(engagement_id, revision) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS run_records_run_idx ON run_records(run_id);
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(plan_revisions)").fetchall()}
        if "content_pack_sha256" not in columns:
            connection.execute("ALTER TABLE plan_revisions ADD COLUMN content_pack_sha256 TEXT NOT NULL DEFAULT ''")
        if "content_packs_json" not in columns:
            connection.execute("ALTER TABLE plan_revisions ADD COLUMN content_packs_json TEXT NOT NULL DEFAULT '[]'")
        empty_pack_digest = _canonical({"packs": []})[1]
        connection.execute("UPDATE plan_revisions SET content_pack_sha256 = ? WHERE content_pack_sha256 = ''",
                           (empty_pack_digest,))


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
    try:
        content_packs, _, _ = content_pack.installed_packs()
    except content_pack.ContentPackError as exc:
        raise EngagementStoreError(f"Cannot pin an invalid content-pack set: {exc}") from exc
    content_packs.sort(key=lambda item: item["pack_id"])
    content_packs_json, content_pack_sha256 = _canonical({"packs": content_packs})
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
            "INSERT INTO plan_revisions (engagement_id, revision, schema_version, plan_sha256, content_pack_sha256, content_packs_json, plan_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (key, revision, schema_version, digest, content_pack_sha256, content_packs_json, plan_json, now),
        )
        _persist_run_records(connection, key, revision, plan, now)
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {"engagement_id": key, "revision": revision, "plan_sha256": digest,
            "content_pack_sha256": content_pack_sha256, "content_packs": content_packs, "created_at": now}


def list_engagements(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_initialized()
    if not 1 <= limit <= 200:
        raise EngagementStoreError("Engagement list limit must be between 1 and 200")
    with _connect() as connection:
        rows = connection.execute("""
            SELECT e.id, e.actor_id, e.actor_name, e.data_version, e.created_at, e.updated_at,
                   r.revision, r.schema_version, r.plan_sha256, r.content_pack_sha256
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
            "SELECT revision, schema_version, plan_sha256, content_pack_sha256, created_at FROM plan_revisions WHERE engagement_id = ? ORDER BY revision DESC",
            (engagement_id,),
        ).fetchall()
        latest = connection.execute(
            "SELECT plan_json, content_pack_sha256, content_packs_json FROM plan_revisions WHERE engagement_id = ? ORDER BY revision DESC LIMIT 1",
            (engagement_id,),
        ).fetchone()
        latest_revision = revisions[0]["revision"] if revisions else None
        runs = connection.execute(
            "SELECT * FROM run_records WHERE engagement_id = ? AND revision = ? ORDER BY started_at, run_id",
            (engagement_id, latest_revision),
        ).fetchall() if latest_revision else []
    result = dict(row)
    result["revisions"] = [dict(item) for item in revisions]
    result["latest_plan"] = json.loads(latest["plan_json"]) if latest else None
    result["latest_content_pack_sha256"] = latest["content_pack_sha256"] if latest else None
    result["latest_content_packs"] = json.loads(latest["content_packs_json"]) if latest else []
    result["latest_runs"] = [_run_record(item) for item in runs]
    return result


def engagement_exists(engagement_id: str) -> bool:
    _ensure_initialized()
    with _connect() as connection:
        return connection.execute("SELECT 1 FROM engagements WHERE id = ?", (engagement_id,)).fetchone() is not None


def revision_exists(engagement_id: str, revision: int) -> bool:
    _ensure_initialized()
    with _connect() as connection:
        return connection.execute("SELECT 1 FROM plan_revisions WHERE engagement_id = ? AND revision = ?",
                                  (engagement_id, revision)).fetchone() is not None


def get_revision(engagement_id: str, revision: int) -> Optional[Dict[str, Any]]:
    _ensure_initialized()
    with _connect() as connection:
        row = connection.execute(
        "SELECT engagement_id, revision, schema_version, plan_sha256, content_pack_sha256, content_packs_json, plan_json, created_at FROM plan_revisions WHERE engagement_id = ? AND revision = ?",
            (engagement_id, revision),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["plan"] = json.loads(result.pop("plan_json"))
    result["content_packs"] = json.loads(result.pop("content_packs_json"))
    result["runs"] = list_run_records(engagement_id, revision, limit=4_000)
    return result


def _persist_run_records(connection: sqlite3.Connection, engagement_id: str, revision: int,
                         plan: Mapping[str, Any], created_at: str) -> None:
    receipt_index: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for entry in plan.get("receipts", []) if isinstance(plan.get("receipts", []), list) else []:
        if isinstance(entry, Mapping) and isinstance(entry.get("technique_id"), str) and isinstance(entry.get("run_id"), str):
            receipt = entry.get("receipt")
            if isinstance(receipt, Mapping):
                receipt_index[(entry["technique_id"], entry["run_id"])] = receipt

    groups: Dict[str, List[Dict[str, Any]]] = {}
    for stage in plan.get("stages", []) if isinstance(plan.get("stages", []), list) else []:
        if not isinstance(stage, Mapping) or not isinstance(stage.get("techniques"), list):
            continue
        for technique in stage["techniques"]:
            if not isinstance(technique, Mapping):
                continue
            execution = technique.get("execution")
            if not isinstance(execution, Mapping) or not isinstance(execution.get("run_id"), str):
                continue
            run_id = execution["run_id"]
            technique_id = str(technique.get("id", ""))
            receipt = receipt_index.get((technique_id, run_id))
            groups.setdefault(run_id, []).append({
                "technique_id": technique_id,
                "tactic": str(stage.get("tactic", "")),
                "outcome": execution.get("outcome", "not_run"),
                "detection_result": execution.get("detection_result", "not_assessed"),
                "evidence_source": execution.get("evidence_source"),
                "started_at": execution.get("started_at"),
                "completed_at": execution.get("completed_at"),
                "exit_code": execution.get("exit_code"),
                "receipt_sha256": execution.get("receipt_sha256"),
                "receipt_verified": execution.get("receipt_verified", False),
                "telemetry_refs": execution.get("telemetry_refs", []),
                "receipt": dict(receipt) if receipt else None,
            })

    platform = str(plan.get("scope", {}).get("command_platform", "unknown")) if isinstance(plan.get("scope"), Mapping) else "unknown"
    for run_id, evidence in groups.items():
        starts = sorted(item["started_at"] for item in evidence if isinstance(item.get("started_at"), str))
        completions = sorted(item["completed_at"] for item in evidence if isinstance(item.get("completed_at"), str))
        outcomes = {item["outcome"] for item in evidence}
        result = "failed" if "failed" in outcomes else "passed" if "passed" in outcomes else "skipped" if outcomes == {"skipped"} else "recorded"
        receipts = [item["receipt"] for item in evidence if isinstance(item.get("receipt"), Mapping)]
        receipt_digests = sorted(item["receipt_sha256"] for item in evidence if isinstance(item.get("receipt_sha256"), str))
        telemetry_refs = sorted({ref for item in evidence for ref in item.get("telemetry_refs", []) if isinstance(ref, str)})
        canonical_evidence = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        receipt_hash = hashlib.sha256(json.dumps(receipts, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        connection.execute("""
            INSERT INTO run_records
            (engagement_id, revision, run_id, platform, started_at, completed_at, result,
             receipt_count, receipt_set_sha256, telemetry_refs_json, evidence_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (engagement_id, revision, run_id, platform, starts[0] if starts else None,
              completions[-1] if completions else None, result, len(receipts), receipt_hash,
              json.dumps(telemetry_refs, separators=(",", ":")), canonical_evidence, created_at))


def _run_record(row: sqlite3.Row) -> Dict[str, Any]:
    result = dict(row)
    result["telemetry_refs"] = json.loads(result.pop("telemetry_refs_json"))
    result["evidence"] = json.loads(result.pop("evidence_json"))
    return result


def list_run_records(engagement_id: str, revision: Optional[int] = None, limit: int = 200) -> List[Dict[str, Any]]:
    _ensure_initialized()
    if not 1 <= limit <= 4_000:
        raise EngagementStoreError("Run list limit must be between 1 and 4000")
    with _connect() as connection:
        if revision is None:
            rows = connection.execute("SELECT * FROM run_records WHERE engagement_id = ? ORDER BY revision DESC, started_at, run_id LIMIT ?", (engagement_id, limit)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM run_records WHERE engagement_id = ? AND revision = ? ORDER BY started_at, run_id LIMIT ?", (engagement_id, revision, limit)).fetchall()
    return [_run_record(row) for row in rows]


def upsert_ability_gaps(gaps: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Persist generated gap rows without overwriting existing ownership/status."""
    _ensure_initialized()
    results: List[Dict[str, Any]] = []
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        for gap in gaps:
            key_fields = {
                "technique_id": str(gap.get("technique_id", "")),
                "platform": str(gap.get("platform", "")),
                "gap": str(gap.get("gap", "")),
                "ability_id": gap.get("ability_id"),
                "procedure_candidate_ids": sorted(str(value) for value in gap.get("procedure_candidate_ids", [])),
            }
            item_key = hashlib.sha256(json.dumps(key_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            now = _utc_now()
            row = connection.execute("SELECT * FROM ability_backlog WHERE item_key = ?", (item_key,)).fetchone()
            if row is None:
                item_id = str(uuid.uuid4())
                connection.execute("""
                    INSERT INTO ability_backlog
                    (id, item_key, technique_id, platform, gap, reason, ability_id,
                     procedure_candidate_ids_json, owner, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'open', ?, ?)
                """, (item_id, item_key, key_fields["technique_id"], key_fields["platform"], key_fields["gap"],
                      str(gap.get("reason", ""))[:1000], key_fields["ability_id"],
                      json.dumps(key_fields["procedure_candidate_ids"], separators=(",", ":")), now, now))
            else:
                item_id = row["id"]
                connection.execute("UPDATE ability_backlog SET reason = ?, updated_at = ? WHERE id = ?",
                                   (str(gap.get("reason", ""))[:1000], now, item_id))
            saved = connection.execute("SELECT * FROM ability_backlog WHERE id = ?", (item_id,)).fetchone()
            results.append(_backlog_record(saved))
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return results


def _backlog_record(row: sqlite3.Row) -> Dict[str, Any]:
    result = dict(row)
    result["procedure_candidate_ids"] = json.loads(result.pop("procedure_candidate_ids_json"))
    result.pop("item_key", None)
    return result


def list_ability_gaps(limit: int = 100, status: Optional[str] = None) -> List[Dict[str, Any]]:
    _ensure_initialized()
    if not 1 <= limit <= 200:
        raise EngagementStoreError("Backlog limit must be between 1 and 200")
    if status is not None and status not in {"open", "in_progress", "accepted", "closed"}:
        raise EngagementStoreError("Invalid backlog status")
    with _connect() as connection:
        if status:
            rows = connection.execute("SELECT * FROM ability_backlog WHERE status = ? ORDER BY updated_at DESC LIMIT ?", (status, limit)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM ability_backlog ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
    return [_backlog_record(row) for row in rows]


def update_ability_gap(item_id: str, *, owner: Optional[str], status: str) -> Optional[Dict[str, Any]]:
    _ensure_initialized()
    if not isinstance(status, str) or status not in {"open", "in_progress", "accepted", "closed"}:
        raise EngagementStoreError("Invalid backlog status")
    if owner is not None:
        if not isinstance(owner, str) or len(owner.strip()) > 120:
            raise EngagementStoreError("Backlog owner must be at most 120 characters")
        owner = owner.strip() or None
    now = _utc_now()
    with _connect() as connection:
        cursor = connection.execute("UPDATE ability_backlog SET owner = ?, status = ?, updated_at = ? WHERE id = ?",
                                    (owner, status, now, item_id))
        if cursor.rowcount != 1:
            return None
        row = connection.execute("SELECT * FROM ability_backlog WHERE id = ?", (item_id,)).fetchone()
    return _backlog_record(row)
