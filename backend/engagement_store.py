"""SQLite persistence for immutable engagement plan revisions."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

from . import attack_data, content_pack, webhook

MAX_STORED_ENGAGEMENTS = 10_000
MAX_REVISIONS_PER_ENGAGEMENT = 2_000
MAX_AUDIT_EVENTS = 200_000
MAX_WEBHOOK_DELIVERIES = 200_000


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
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
    except Exception:
        connection.close()
        raise
    return connection


@contextmanager
def _session() -> Iterator[sqlite3.Connection]:
    # SQLite's own context manager ends transactions but does not close the
    # connection. Always release file handles, including on early returns.
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


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
    with _session() as connection:
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
        CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            principal TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            revision INTEGER,
            payload_json TEXT NOT NULL,
            previous_digest TEXT NOT NULL,
            event_digest TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_events_type_idx ON audit_events(event_type, sequence DESC);
        CREATE TABLE IF NOT EXISTS webhook_outbox (
            delivery_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            run_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            next_attempt_at TEXT NOT NULL,
            lease_until TEXT,
            last_attempt_at TEXT,
            delivered_at TEXT,
            last_error TEXT,
            FOREIGN KEY (engagement_id, revision) REFERENCES plan_revisions(engagement_id, revision) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS webhook_outbox_due_idx ON webhook_outbox(status, next_attempt_at);
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
        execution_context = plan.get("execution_context")
        principal = str(execution_context.get("operator", "")).strip()[:120] if isinstance(execution_context, Mapping) else ""
        raw_scope = plan.get("scope")
        scope: Mapping[str, Any] = raw_scope if isinstance(raw_scope, Mapping) else {}
        _, scope_digest = _canonical(scope)
        stages = plan.get("stages")
        technique_count = sum(len(stage.get("techniques", [])) for stage in stages
                              if isinstance(stage, Mapping) and isinstance(stage.get("techniques"), list)) if isinstance(stages, list) else 0
        _insert_audit_event(connection, event_type="engagement_revision_saved", principal=principal or "unknown",
                             entity_type="engagement", entity_id=key, revision=revision,
                             payload={"plan_sha256": digest, "content_pack_sha256": content_pack_sha256,
                                      "data_version": data_version, "scope_sha256": scope_digest,
                                      "technique_count": technique_count})
        _queue_run_webhooks(connection, key, revision, digest, content_pack_sha256, now)
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
    with _session() as connection:
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
    with _session() as connection:
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
    with _session() as connection:
        return connection.execute("SELECT 1 FROM engagements WHERE id = ?", (engagement_id,)).fetchone() is not None


def revision_exists(engagement_id: str, revision: int) -> bool:
    _ensure_initialized()
    with _session() as connection:
        return connection.execute("SELECT 1 FROM plan_revisions WHERE engagement_id = ? AND revision = ?",
                                  (engagement_id, revision)).fetchone() is not None


def get_revision(engagement_id: str, revision: int) -> Optional[Dict[str, Any]]:
    _ensure_initialized()
    with _session() as connection:
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
    with _session() as connection:
        if revision is None:
            rows = connection.execute("SELECT * FROM run_records WHERE engagement_id = ? ORDER BY revision DESC, started_at, run_id LIMIT ?", (engagement_id, limit)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM run_records WHERE engagement_id = ? AND revision = ? ORDER BY started_at, run_id LIMIT ?", (engagement_id, revision, limit)).fetchall()
    return [_run_record(row) for row in rows]


def _insert_audit_event(connection: sqlite3.Connection, *, event_type: str, principal: str,
                        entity_type: str, entity_id: str, revision: Optional[int],
                        payload: Mapping[str, Any]) -> Dict[str, Any]:
    sequence_tip = connection.execute("SELECT COALESCE(MAX(sequence), 0) AS n FROM audit_events").fetchone()["n"]
    if sequence_tip >= MAX_AUDIT_EVENTS:
        raise EngagementStoreError("The audit log reached its configured capacity")
    previous = connection.execute("SELECT * FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
    if previous is not None:
        previous_payload = json.loads(previous["payload_json"])
        previous_record = {
            "sequence": previous["sequence"],
            "event_id": previous["event_id"], "occurred_at": previous["occurred_at"],
            "event_type": previous["event_type"], "principal": previous["principal"],
            "entity_type": previous["entity_type"], "entity_id": previous["entity_id"],
            "revision": previous["revision"], "payload": previous_payload,
            "previous_digest": previous["previous_digest"],
        }
        _, previous_expected = _canonical(previous_record)
        predecessor = connection.execute("SELECT event_digest FROM audit_events WHERE sequence < ? ORDER BY sequence DESC LIMIT 1",
                                         (previous["sequence"],)).fetchone()
        expected_link = predecessor["event_digest"] if predecessor else "0" * 64
        if previous["previous_digest"] != expected_link or not hmac.compare_digest(previous["event_digest"], previous_expected):
            raise EngagementStoreError(f"Audit log hash chain verification failed at sequence {previous['sequence']}")
    previous_digest = previous["event_digest"] if previous else "0" * 64
    now = _utc_now()
    event_id = str(uuid.uuid4())
    sequence = sequence_tip + 1
    payload_json, _ = _canonical(payload)
    record = {
        "sequence": sequence,
        "event_id": event_id, "occurred_at": now, "event_type": event_type,
        "principal": principal, "entity_type": entity_type, "entity_id": entity_id,
        "revision": revision, "payload": json.loads(payload_json), "previous_digest": previous_digest,
    }
    _, event_digest = _canonical(record)
    connection.execute("""
        INSERT INTO audit_events
        (sequence, event_id, occurred_at, event_type, principal, entity_type, entity_id, revision,
         payload_json, previous_digest, event_digest)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (sequence, event_id, now, event_type, principal, entity_type, entity_id, revision,
          payload_json, previous_digest, event_digest))
    return {**record, "event_digest": event_digest}


def _verify_audit_chain(connection: sqlite3.Connection) -> int:
    rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence")
    previous = "0" * 64
    count = 0
    for row in rows:
        count += 1
        if count > MAX_AUDIT_EVENTS:
            raise EngagementStoreError("The audit log exceeds its verification limit")
        payload = json.loads(row["payload_json"])
        record = {
            "sequence": row["sequence"],
            "event_id": row["event_id"], "occurred_at": row["occurred_at"],
            "event_type": row["event_type"], "principal": row["principal"],
            "entity_type": row["entity_type"], "entity_id": row["entity_id"],
            "revision": row["revision"], "payload": payload,
            "previous_digest": row["previous_digest"],
        }
        _, expected = _canonical(record)
        if row["previous_digest"] != previous or not hmac.compare_digest(row["event_digest"], expected):
            raise EngagementStoreError(f"Audit log hash chain verification failed at sequence {row['sequence']}")
        previous = row["event_digest"]
    return count


def _queue_run_webhooks(connection: sqlite3.Connection, engagement_id: str, revision: int,
                        plan_sha256: str, content_pack_sha256: str, created_at: str) -> int:
    try:
        if webhook.load_config() is None:
            return 0
    except webhook.WebhookConfigurationError as exc:
        raise EngagementStoreError(str(exc)) from exc
    runs = connection.execute("SELECT * FROM run_records WHERE engagement_id = ? AND revision = ? ORDER BY run_id",
                              (engagement_id, revision)).fetchall()
    if not runs:
        return 0
    retained = connection.execute("SELECT COUNT(*) AS n FROM webhook_outbox").fetchone()["n"]
    if retained + len(runs) > MAX_WEBHOOK_DELIVERIES:
        raise EngagementStoreError("The run webhook outbox reached its configured capacity; archive or prune delivered events before saving more runs")
    for run in runs:
        event_id = str(uuid.uuid4())
        delivery_id = str(uuid.uuid4())
        payload = {
            "schema_version": "1.0", "event": "run_recorded", "event_id": event_id,
            "occurred_at": created_at, "engagement_id": engagement_id, "revision": revision,
            "plan_sha256": plan_sha256, "content_pack_sha256": content_pack_sha256,
            "run": {
                "run_id": run["run_id"], "platform": run["platform"], "started_at": run["started_at"],
                "completed_at": run["completed_at"], "result": run["result"],
                "receipt_count": run["receipt_count"], "receipt_set_sha256": run["receipt_set_sha256"],
                "telemetry_refs": json.loads(run["telemetry_refs_json"]),
            },
        }
        payload_json, payload_digest = _canonical(payload)
        connection.execute("""
            INSERT INTO webhook_outbox
            (delivery_id, event_id, engagement_id, revision, run_id, payload_json,
             status, attempts, created_at, next_attempt_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)
        """, (delivery_id, event_id, engagement_id, revision, run["run_id"], payload_json, created_at, created_at))
        _insert_audit_event(connection, event_type="run_webhook_queued", principal="service",
                            entity_type="engagement", entity_id=engagement_id, revision=revision,
                            payload={"event_id": event_id, "run_id": run["run_id"],
                                     "payload_sha256": payload_digest})
    return len(runs)


def claim_webhook_deliveries(limit: int = 10) -> List[Dict[str, Any]]:
    """Lease due notifications for one worker process."""
    _ensure_initialized()
    if not 1 <= limit <= 100:
        raise EngagementStoreError("Webhook delivery claim limit must be 1-100")
    now = datetime.now(timezone.utc)
    now_text = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    lease_text = (now + timedelta(seconds=60)).isoformat(timespec="seconds").replace("+00:00", "Z")
    claimed: List[Dict[str, Any]] = []
    with _session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            rows = connection.execute("""
                SELECT delivery_id FROM webhook_outbox
                WHERE (status = 'pending' AND next_attempt_at <= ?)
                   OR (status = 'in_flight' AND lease_until <= ?)
                ORDER BY created_at, delivery_id LIMIT ?
            """, (now_text, now_text, limit)).fetchall()
            for item in rows:
                connection.execute("""
                    UPDATE webhook_outbox
                    SET status = 'in_flight', attempts = attempts + 1, last_attempt_at = ?, lease_until = ?
                    WHERE delivery_id = ?
                """, (now_text, lease_text, item["delivery_id"]))
                row = connection.execute("SELECT * FROM webhook_outbox WHERE delivery_id = ?", (item["delivery_id"],)).fetchone()
                value = dict(row)
                value["payload"] = json.loads(value.pop("payload_json"))
                claimed.append(value)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    return claimed


def complete_webhook_delivery(delivery_id: str, *, success: bool, error: str = "",
                              max_attempts: int = 12) -> None:
    """Record delivery success or schedule bounded exponential retry."""
    _ensure_initialized()
    with _session() as connection:
        row = connection.execute("SELECT attempts FROM webhook_outbox WHERE delivery_id = ?", (delivery_id,)).fetchone()
        if row is None:
            raise EngagementStoreError("Webhook delivery was not found")
        now = datetime.now(timezone.utc)
        now_text = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        if success:
            connection.execute("UPDATE webhook_outbox SET status = 'delivered', delivered_at = ?, lease_until = NULL, last_error = NULL WHERE delivery_id = ?",
                               (now_text, delivery_id))
            return
        attempts = row["attempts"]
        if attempts >= max_attempts:
            connection.execute("UPDATE webhook_outbox SET status = 'dead', lease_until = NULL, last_error = ? WHERE delivery_id = ?",
                               (error[:500], delivery_id))
            return
        delays = [5, 15, 60, 300, 900, 3600]
        delay = delays[min(max(attempts - 1, 0), len(delays) - 1)]
        next_text = (now + timedelta(seconds=delay)).isoformat(timespec="seconds").replace("+00:00", "Z")
        connection.execute("UPDATE webhook_outbox SET status = 'pending', next_attempt_at = ?, lease_until = NULL, last_error = ? WHERE delivery_id = ?",
                           (next_text, error[:500], delivery_id))


def list_webhook_deliveries(limit: int = 100) -> List[Dict[str, Any]]:
    _ensure_initialized()
    if not 1 <= limit <= 1_000:
        raise EngagementStoreError("Webhook delivery list limit must be 1-1000")
    with _session() as connection:
        rows = connection.execute("""
            SELECT delivery_id, event_id, engagement_id, revision, run_id, status, attempts,
                   created_at, next_attempt_at, last_attempt_at, delivered_at, last_error
            FROM webhook_outbox ORDER BY created_at DESC, delivery_id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def append_audit_event(*, event_type: str, principal: str = "unknown", entity_type: str,
                       entity_id: str, revision: Optional[int] = None,
                       payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Append a bounded, hash-chained audit event in its own transaction."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", event_type):
        raise EngagementStoreError("Audit event type is invalid")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", entity_type):
        raise EngagementStoreError("Audit entity type is invalid")
    if not isinstance(entity_id, str) or not entity_id or len(entity_id) > 128:
        raise EngagementStoreError("Audit entity ID is invalid")
    if not isinstance(principal, str) or not principal.strip() or len(principal) > 120:
        raise EngagementStoreError("Audit principal is invalid")
    if revision is not None and (isinstance(revision, bool) or not isinstance(revision, int) or revision < 1):
        raise EngagementStoreError("Audit revision is invalid")
    event_payload = {} if payload is None else payload
    if not isinstance(event_payload, Mapping):
        raise EngagementStoreError("Audit payload must be a JSON object")
    payload_json, _ = _canonical(event_payload)
    if len(payload_json.encode("utf-8")) > 8_192:
        raise EngagementStoreError("Audit payload exceeds 8 KiB")
    _ensure_initialized()
    with _session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            record = _insert_audit_event(connection, event_type=event_type, principal=principal.strip(),
                                         entity_type=entity_type, entity_id=entity_id, revision=revision,
                                         payload=event_payload)
            connection.execute("COMMIT")
            return record
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise


def list_audit_events(limit: int = 100, after_sequence: int = 0) -> Dict[str, Any]:
    """Verify the full chain and return a bounded audit-log page."""
    _ensure_initialized()
    if (not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1_000
            or not isinstance(after_sequence, int) or isinstance(after_sequence, bool) or after_sequence < 0):
        raise EngagementStoreError("Audit event page values are invalid")
    with _session() as connection:
        count = _verify_audit_chain(connection)
        rows = connection.execute("SELECT * FROM audit_events WHERE sequence > ? ORDER BY sequence LIMIT ?",
                                  (after_sequence, limit)).fetchall()
        tip = connection.execute("SELECT event_digest FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
    events = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        events.append(item)
    return {"events": events, "chain_valid": True, "event_count": count,
            "chain_tip": tip["event_digest"] if tip else "0" * 64}


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
        if results:
            backlog_ids_digest = hashlib.sha256(
                "\n".join(sorted(item["id"] for item in results)).encode("utf-8")
            ).hexdigest()
            _insert_audit_event(connection, event_type="ability_backlog_generated", principal="unknown",
                                entity_type="ability_backlog", entity_id=f"sha256:{backlog_ids_digest}",
                                revision=None, payload={"item_count": len(results),
                                                        "backlog_ids_sha256": backlog_ids_digest})
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
    with _session() as connection:
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
    with _session() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            previous = connection.execute("SELECT owner, status FROM ability_backlog WHERE id = ?", (item_id,)).fetchone()
            if previous is None:
                connection.execute("ROLLBACK")
                return None
            cursor = connection.execute("UPDATE ability_backlog SET owner = ?, status = ?, updated_at = ? WHERE id = ?",
                                    (owner, status, now, item_id))
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            row = connection.execute("SELECT * FROM ability_backlog WHERE id = ?", (item_id,)).fetchone()
            _insert_audit_event(connection, event_type="ability_backlog_updated", principal="unknown",
                                entity_type="ability_gap", entity_id=item_id, revision=None,
                                payload={"previous_owner": previous["owner"], "previous_status": previous["status"],
                                         "owner": owner, "status": status})
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
    return _backlog_record(row)
