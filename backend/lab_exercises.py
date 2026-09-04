"""Bounded, technique-relevant lab exercises for unsafe ATT&CK behaviours.

The exercises in this module never target external systems or real accounts.
They use synthetic records, loopback services, child processes, and temporary
directories to exercise a telemetry surface related to the mapped technique.
Each run emits a self-reported, digest-protected receipt.  The receipt is useful
execution evidence, but it is not an endpoint or SIEM attestation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import uuid
import zipfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List


@dataclass(frozen=True)
class ExerciseSpec:
    scenario: str
    summary: str
    expected_telemetry: str


SCENARIOS: Dict[str, ExerciseSpec] = {
    "controlled_exception": ExerciseSpec(
        "controlled_exception",
        "Launch a child process that raises and reports a controlled exception.",
        "Child-process creation, non-zero exit, and exception/error output.",
    ),
    "mock_authentication": ExerciseSpec(
        "mock_authentication",
        "Send five rejected synthetic credentials to an ephemeral loopback authentication service.",
        "Five loopback HTTP 401 authentication failures with synthetic user names.",
    ),
    "password_cracking": ExerciseSpec(
        "password_cracking",
        "Compare five synthetic password candidates with a synthetic SHA-256 verifier entirely offline.",
        "Five offline password-hash comparisons, candidate count, and a controlled match result.",
    ),
    "synthetic_input": ExerciseSpec(
        "synthetic_input",
        "Pipe a fixed synthetic secret into a child process and record only its digest.",
        "Child-process stdin read plus digest output; no keyboard hook or real input capture.",
    ),
    "module_search": ExerciseSpec(
        "module_search",
        "Load a harmless temporary module through a controlled search path.",
        "Temporary module creation, child interpreter start, and module-load path output.",
    ),
    "web_content": ExerciseSpec(
        "web_content",
        "Create, request, modify, and restore a temporary web document over loopback.",
        "Loopback HTTP request plus web-content create, modify, hash, restore, and delete events.",
    ),
    "loopback_transfer": ExerciseSpec(
        "loopback_transfer",
        "Transfer a bounded marker through an ephemeral loopback TCP listener.",
        "Loopback connection, bounded send/receive byte counts, and matching payload digests.",
    ),
    "loopback_proxy": ExerciseSpec(
        "loopback_proxy",
        "Relay a bounded marker through an ephemeral two-hop loopback proxy.",
        "Two loopback connections with relay byte counts and end-to-end digest verification.",
    ),
    "system_control": ExerciseSpec(
        "system_control",
        "Invoke a harmless child control operation and record its result without changing system state.",
        "Control-utility or child-process invocation with exit code and captured output.",
    ),
    "email_artifact": ExerciseSpec(
        "email_artifact",
        "Build and parse a synthetic RFC 822 message without sending it.",
        "Message and attachment creation/read events plus parsed sender, recipient, and subject fields.",
    ),
    "data_repository": ExerciseSpec(
        "data_repository",
        "Query synthetic records from a temporary SQLite repository.",
        "Database open, SELECT, returned-row count, and database cleanup events.",
    ),
    "network_configuration": ExerciseSpec(
        "network_configuration",
        "Parse a synthetic network-device configuration and enumerate security-relevant statements.",
        "Configuration-file read plus parsed route, ACL, account, and service records.",
    ),
    "credential_material": ExerciseSpec(
        "credential_material",
        "Read synthetic credentials from an isolated store and emit redacted identifiers and hashes.",
        "Synthetic credential-store read with account identifiers and secret digests only.",
    ),
    "content_obfuscation": ExerciseSpec(
        "content_obfuscation",
        "Encode, package, decode, and verify a harmless marker.",
        "Encoding/archive operations with before/after digests and successful decode verification.",
    ),
    "application_control": ExerciseSpec(
        "application_control",
        "Create and inspect a harmless control/script artifact using a child process.",
        "Control-file creation, child-process inspection, content hash, and cleanup.",
    ),
    "persistence_configuration": ExerciseSpec(
        "persistence_configuration",
        "Add, enumerate, and remove a technique-specific persistence entry in an isolated configuration.",
        "Persistence-configuration write, enumeration, removal, and cleanup verification.",
    ),
    "supply_chain": ExerciseSpec(
        "supply_chain",
        "Build a synthetic package manifest, detect a controlled mutation, and restore it.",
        "Manifest and component hashes, integrity mismatch detection, restoration, and cleanup.",
    ),
    "cloud_identity": ExerciseSpec(
        "cloud_identity",
        "Apply and audit a synthetic identity or federation change in a temporary local database.",
        "Synthetic identity/configuration update with before/after audit rows and rollback.",
    ),
    "virtualization": ExerciseSpec(
        "virtualization",
        "Inspect synthetic hypervisor or appliance inventory records without contacting a device.",
        "Virtualization inventory read, selected-object count, and configuration digest.",
    ),
    "social_engineering": ExerciseSpec(
        "social_engineering",
        "Create and inspect a synthetic lure or request without contacting a person.",
        "Synthetic content creation and indicator extraction; no message, call, or notification sent.",
    ),
    "osint_work_product": ExerciseSpec(
        "osint_work_product",
        "Query a synthetic organization-public-data set and produce a scoped research result.",
        "Local structured-data query with source, query, result count, and output digest.",
    ),
    "infrastructure_work_product": ExerciseSpec(
        "infrastructure_work_product",
        "Create and validate a synthetic infrastructure planning manifest without provisioning anything.",
        "Planning-manifest create, schema validation, resource count, digest, and cleanup.",
    ),
    "staging_work_product": ExerciseSpec(
        "staging_work_product",
        "Stage and verify a harmless marker in a temporary local directory without publishing it.",
        "Staged-artifact write, manifest/hash verification, and directory cleanup.",
    ),
    "transaction_dry_run": ExerciseSpec(
        "transaction_dry_run",
        "Validate a zero-value synthetic transaction and stop before submission.",
        "Transaction validation and explicit dry-run decision with no external request.",
    ),
    "wireless_capture": ExerciseSpec(
        "wireless_capture",
        "Generate and parse a tiny synthetic wireless-management capture.",
        "Synthetic capture creation, management-frame identification, digest, and cleanup.",
    ),
}


_SCENARIO_TECHNIQUES: Dict[str, tuple[str, ...]] = {
    "controlled_exception": ("T1203", "T1190", "T1068", "T1211", "T1212"),
    "mock_authentication": ("T1110", "T1110.001", "T1110.003", "T1110.004", "T1187", "T1621"),
    "password_cracking": ("T1110.002",),
    "synthetic_input": ("T1056", "T1056.001", "T1056.003", "T1056.004", "T1111", "T1674"),
    "module_search": ("T1574.001", "T1574.002", "T1574.013", "T1204.005"),
    "web_content": ("T1505.003", "T1491.001", "T1491.002"),
    "loopback_transfer": ("T1030",),
    "loopback_proxy": ("T1090.003",),
    "system_control": ("T1529",),
    "email_artifact": ("T1667", "T1566", "T1566.001", "T1566.003", "T1566.004", "T1534", "T1070.008", "T1564.008"),
    "data_repository": ("T1213", "T1213.001", "T1213.002", "T1213.004", "T1213.005", "T1213.006", "T1671", "T1505.001"),
    "network_configuration": ("T1602.002", "T1686.002", "T1599", "T1059.008"),
    "credential_material": ("T1552.008", "T1556", "T1556.001", "T1556.006", "T1556.007", "T1606.002"),
    "content_obfuscation": ("T1027.002", "T1027.005", "T1027.012", "T1027.016"),
    "application_control": ("T1218.003", "T1218.015", "T1221", "T1564.011", "T1559.002"),
    "persistence_configuration": ("T1137.004", "T1546.016", "T1114.003"),
    "supply_chain": ("T1195", "T1195.001", "T1195.002", "T1199", "T1542.002", "T1677", "T1689"),
    "cloud_identity": ("T1550.004", "T1556.009", "T1136.003", "T1098.002", "T1136.002"),
    "virtualization": ("T1059.012", "T1675", "T1505.006"),
    "social_engineering": ("T1598", "T1598.001", "T1598.002", "T1598.003", "T1598.004", "T1684", "T1684.001"),
    "osint_work_product": (
        "T1589.001",
        "T1589.002",
        "T1589.003",
        "T1590.006",
        "T1591.001",
        "T1591.002",
        "T1591.004",
        "T1593",
        "T1593.001",
        "T1593.002",
        "T1595.003",
        "T1596.005",
        "T1597",
        "T1597.002",
        "T1681",
        "T1682",
    ),
    "infrastructure_work_product": (
        "T1583",
        "T1583.003",
        "T1583.004",
        "T1583.005",
        "T1583.007",
        "T1583.008",
        "T1584",
        "T1584.003",
        "T1584.004",
        "T1584.005",
        "T1584.006",
        "T1584.008",
        "T1585",
        "T1585.001",
        "T1585.002",
        "T1585.003",
        "T1586.001",
        "T1586.002",
        "T1586.003",
        "T1587",
        "T1587.001",
        "T1587.004",
        "T1588",
        "T1588.001",
        "T1588.003",
        "T1588.004",
        "T1588.005",
        "T1588.006",
        "T1588.007",
        "T1650",
        "T1683",
        "T1683.001",
        "T1683.002",
    ),
    "staging_work_product": ("T1608", "T1608.001", "T1608.002", "T1608.003", "T1608.004", "T1608.005", "T1608.006"),
    "transaction_dry_run": ("T1657",),
    "wireless_capture": ("T1557.004",),
}


TECHNIQUE_SCENARIOS: Dict[str, str] = {}
for _scenario, _techniques in _SCENARIO_TECHNIQUES.items():
    for _technique in _techniques:
        if _technique in TECHNIQUE_SCENARIOS:
            raise RuntimeError(f"duplicate technique exercise: {_technique}")
        TECHNIQUE_SCENARIOS[_technique] = _scenario


def get_spec(technique_id: str) -> ExerciseSpec:
    """Return the declared exercise specification for a mapped technique."""
    try:
        return SCENARIOS[TECHNIQUE_SCENARIOS[technique_id]]
    except KeyError as exc:
        raise KeyError(f"no bounded exercise is registered for {technique_id}") from exc


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _child(code: str, stdin: str = "") -> Dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-c", code],
        input=stdin,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return {
        "exit_code": completed.returncode,
        "stdout_sha256": _sha(completed.stdout.encode()),
        "stderr_sha256": _sha(completed.stderr.encode()),
        "stdout": completed.stdout.strip()[:240],
    }


def _controlled_exception(_: str, __: Path) -> List[Dict[str, Any]]:
    child = _child("raise RuntimeError('AdversaryFlow controlled exception')")
    return [{"event": "controlled_exception", **child}]


def _mock_authentication(technique_id: str, _: Path) -> List[Dict[str, Any]]:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    attempts: List[Dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            supplied = self.headers.get("Authorization", "")
            attempts.append({"path": self.path, "authorization_sha256": _sha(supplied.encode())})
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="AdversaryFlowLab"')
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    statuses = []
    try:
        import urllib.error
        import urllib.request

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for number in range(5):
            if technique_id == "T1110.001":
                credential = f"af-user:guess-{number}"
                mode = "password_guessing"
            elif technique_id == "T1110.003":
                credential = f"af-user-{number}:shared-wrong-password"
                mode = "password_spraying"
            elif technique_id == "T1110.004":
                credential = f"stuffed-user-{number}:stuffed-wrong-{number}"
                mode = "credential_stuffing"
            elif technique_id == "T1621":
                credential = f"af-mfa-user:request-{number}"
                mode = "mfa_request_generation"
            elif technique_id == "T1187":
                credential = f"af-forced-auth:challenge-{number}"
                mode = "forced_authentication"
            else:
                credential = f"af-user-{number}:wrong-{technique_id}"
                mode = "bounded_brute_force"
            token = base64.b64encode(credential.encode()).decode()
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/login",
                headers={"Authorization": f"Basic {token}"},
            )
            try:
                opener.open(request, timeout=3).close()
            except urllib.error.HTTPError as exc:
                statuses.append(exc.code)
                exc.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    return [{"event": "authentication_failures", "mode": mode, "attempts": len(attempts), "statuses": statuses, "target": "127.0.0.1"}]


def _password_cracking(_: str, __: Path) -> List[Dict[str, Any]]:
    expected = _sha(b"synthetic-match")
    candidates = [b"guess-0", b"guess-1", b"synthetic-match", b"guess-3", b"guess-4"]
    matches = [number for number, candidate in enumerate(candidates) if _sha(candidate) == expected]
    return [{"event": "offline_password_hash_comparison", "attempts": len(candidates), "matched_indexes": matches}]


def _synthetic_input(_: str, __: Path) -> List[Dict[str, Any]]:
    child = _child("import hashlib,sys; d=sys.stdin.read().encode(); print(len(d), hashlib.sha256(d).hexdigest())", "AF-SYNTHETIC-INPUT")
    return [{"event": "synthetic_input_read", **child}]


def _module_search(_: str, root: Path) -> List[Dict[str, Any]]:
    module = root / "af_decoy.py"
    module.write_text("MARKER = 'AF-MODULE-LOAD'\n", encoding="utf-8")
    code = f"import sys; sys.path.insert(0, {str(root)!r}); import af_decoy; print(af_decoy.__file__, af_decoy.MARKER)"
    return [{"event": "controlled_module_load", "module_sha256": _sha(module.read_bytes()), **_child(code)}]


def _web_content(_: str, root: Path) -> List[Dict[str, Any]]:
    import urllib.request
    from functools import partial
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    original = b"<html>AF ORIGINAL</html>"
    changed = b"<html>AF CONTROLLED CHANGE</html>"
    page = root / "index.html"
    page.write_bytes(original)
    page.write_bytes(changed)
    changed_hash = _sha(page.read_bytes())
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

    handler = partial(QuietHandler, directory=str(root))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{server.server_port}/index.html", timeout=3) as response:
            served_hash = _sha(response.read())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    page.write_bytes(original)
    return [
        {
            "event": "web_content_change",
            "before_sha256": _sha(original),
            "changed_sha256": changed_hash,
            "served_sha256": served_hash,
            "served_changed_content": served_hash == changed_hash,
            "restored": page.read_bytes() == original,
        }
    ]


def _tcp_once(payload: bytes, relay: bool = False) -> Dict[str, Any]:
    if relay:
        return _tcp_proxy(payload)
    received: List[bytes] = []
    ready = threading.Event()
    address: List[int] = []

    def server() -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            address.append(listener.getsockname()[1])
            ready.set()
            connection, _peer = listener.accept()
            with connection:
                data = connection.recv(4096)
                received.append(data)
                connection.sendall(data)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    ready.wait(3)
    with socket.create_connection(("127.0.0.1", address[0]), timeout=3) as client:
        client.sendall(payload)
        echoed = client.recv(4096)
    thread.join(timeout=3)
    return {
        "event": "loopback_transfer",
        "hops": 1,
        "bytes": len(payload),
        "digest_match": _sha(echoed) == _sha(payload) == _sha(received[0]),
    }


def _tcp_proxy(payload: bytes) -> Dict[str, Any]:
    target_ready = threading.Event()
    proxy_ready = threading.Event()
    target_port: List[int] = []
    proxy_port: List[int] = []
    target_received: List[bytes] = []

    def target() -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            target_port.append(listener.getsockname()[1])
            target_ready.set()
            connection, _ = listener.accept()
            with connection:
                data = connection.recv(4096)
                target_received.append(data)
                connection.sendall(data)

    def proxy() -> None:
        target_ready.wait(3)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            proxy_port.append(listener.getsockname()[1])
            proxy_ready.set()
            incoming, _ = listener.accept()
            with incoming, socket.create_connection(("127.0.0.1", target_port[0]), timeout=3) as outgoing:
                data = incoming.recv(4096)
                outgoing.sendall(data)
                incoming.sendall(outgoing.recv(4096))

    target_thread = threading.Thread(target=target, daemon=True)
    proxy_thread = threading.Thread(target=proxy, daemon=True)
    target_thread.start()
    proxy_thread.start()
    proxy_ready.wait(3)
    with socket.create_connection(("127.0.0.1", proxy_port[0]), timeout=3) as client:
        client.sendall(payload)
        echoed = client.recv(4096)
    target_thread.join(timeout=3)
    proxy_thread.join(timeout=3)
    return {
        "event": "loopback_proxy",
        "hops": 2,
        "bytes": len(payload),
        "digest_match": bool(target_received) and _sha(echoed) == _sha(payload) == _sha(target_received[0]),
    }


def _loopback_transfer(technique_id: str, _: Path) -> List[Dict[str, Any]]:
    payload = (f"AF-{technique_id}-" * 8).encode()
    return [_tcp_once(payload[:512])]


def _loopback_proxy(technique_id: str, _: Path) -> List[Dict[str, Any]]:
    return [_tcp_once(f"AF-PROXY-{technique_id}".encode(), relay=True)]


def _system_control(_: str, __: Path) -> List[Dict[str, Any]]:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    child.terminate()
    exit_code = child.wait(timeout=5)
    return [{"event": "bounded_process_shutdown", "child_pid": child.pid, "child_exit_code": exit_code, "system_shutdown": False}]


def _email_artifact(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    message = EmailMessage()
    message["From"] = "sender@invalid.example"
    message["To"] = "recipient@invalid.example"
    message["Subject"] = f"AdversaryFlow {technique_id} synthetic message"
    message.set_content("Synthetic message for an isolated lab. https://example.invalid/lure")
    message.add_attachment(b"AF harmless attachment", maintype="application", subtype="octet-stream", filename="exercise.txt")
    path = root / "message.eml"
    path.write_bytes(message.as_bytes())
    parsed = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    if technique_id == "T1667":
        for number in range(20):
            (root / f"bulk-{number:02d}.eml").write_bytes(message.as_bytes())
        return [{"event": "synthetic_email_burst", "messages_created": 20, "messages_sent": 0}]
    if technique_id == "T1070.008":
        original = path.read_bytes()
        path.unlink()
        deleted = not path.exists()
        path.write_bytes(original)
        return [{"event": "synthetic_mailbox_delete_restore", "deleted": deleted, "restored": path.read_bytes() == original}]
    if technique_id == "T1564.008":
        rule = root / "mail-hiding-rule.json"
        rule.write_text(json.dumps({"subject": "AdversaryFlow", "action": "hide", "enabled": True}), encoding="utf-8")
        found = json.loads(rule.read_text())["action"] == "hide"
        rule.unlink()
        return [{"event": "synthetic_email_hiding_rule", "rule_detected": found, "rule_removed": not rule.exists()}]
    return [
        {
            "event": "synthetic_email_parsed",
            "subject": str(parsed["Subject"]),
            "attachments": len(list(parsed.iter_attachments())),
            "message_sha256": _sha(path.read_bytes()),
            "sent": False,
        }
    ]


def _data_repository(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    path = root / "repository.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.execute("create table records(source text, value text)")
        db.executemany("insert into records values (?, ?)", [("synthetic", f"{technique_id}-{n}") for n in range(3)])
        if technique_id == "T1505.001":
            db.create_function("af_stored_action", 1, lambda value: f"AF-PROC:{value}")
            rows = db.execute("select af_stored_action(value) from records").fetchall()
            event = "synthetic_database_function_invoked"
        else:
            rows = db.execute("select source, value from records where source = ?", ("synthetic",)).fetchall()
            event = "repository_query"
    return [{"event": event, "rows": len(rows), "database_sha256": _sha(path.read_bytes())}]


def _network_configuration(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    content = (
        f"hostname af-lab\nusername synthetic privilege 1\nip route 10.0.0.0/24 Null0\naccess-list 101 deny ip any any\n! {technique_id}\n"
    )
    path = root / "device.conf"
    path.write_text(content, encoding="utf-8")
    statements = [line for line in content.splitlines() if line.startswith(("username", "ip route", "access-list"))]
    return [{"event": "network_configuration_parsed", "statements": len(statements), "configuration_sha256": _sha(path.read_bytes())}]


def _credential_material(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    records = [{"account": f"af-user-{n}", "secret": f"synthetic-{technique_id}-{n}"} for n in range(2)]
    path = root / "synthetic-credentials.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    redacted = [{"account": row["account"], "secret_sha256": _sha(row["secret"].encode())} for row in json.loads(path.read_text())]
    return [{"event": "synthetic_credential_store_read", "records": redacted}]


def _content_obfuscation(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    marker = f"AdversaryFlow harmless marker {technique_id}".encode()
    encoded = base64.b64encode(marker)
    archive = root / "encoded.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("marker.b64", encoded)
    with zipfile.ZipFile(archive) as bundle:
        decoded = base64.b64decode(bundle.read("marker.b64"))
    return [
        {
            "event": "content_encode_decode",
            "input_sha256": _sha(marker),
            "archive_sha256": _sha(archive.read_bytes()),
            "decoded_match": decoded == marker,
        }
    ]


def _application_control(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    path = root / f"control-{technique_id.replace('.', '-')}.txt"
    path.write_text(f"AF harmless application-control record for {technique_id}\n", encoding="utf-8")
    child = _child(f"from pathlib import Path; p=Path({str(path)!r}); print(p.name, len(p.read_bytes()))")
    return [{"event": "application_control_artifact", "artifact_sha256": _sha(path.read_bytes()), **child}]


def _persistence_configuration(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    path = root / "startup.json"
    path.write_text(json.dumps({"entries": []}), encoding="utf-8")
    data = json.loads(path.read_text())
    entry: Dict[str, Any] = {"name": technique_id, "command": "AF-HARMLESS-MARKER"}
    if technique_id == "T1114.003":
        entry = {"name": technique_id, "forward_to": "archive@invalid.example", "enabled": True}
    data["entries"].append(entry)
    path.write_text(json.dumps(data), encoding="utf-8")
    enumerated = len(json.loads(path.read_text())["entries"])
    path.write_text(json.dumps({"entries": []}), encoding="utf-8")
    return [{"event": "synthetic_startup_entry", "enumerated": enumerated, "removed": not json.loads(path.read_text())["entries"]}]


def _supply_chain(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    if technique_id == "T1689":
        versions = {"approved": 2, "selected": 1}
        path = root / "versions.json"
        path.write_text(json.dumps(versions), encoding="utf-8")
        return [{"event": "synthetic_downgrade_detected", "approved_version": 2, "selected_version": 1, "blocked": True}]
    if technique_id == "T1677":
        pipeline = root / "pipeline.json"
        trusted = {"steps": ["build", "test"]}
        pipeline.write_text(json.dumps(trusted), encoding="utf-8")
        expected = _sha(pipeline.read_bytes())
        pipeline.write_text(json.dumps({"steps": ["build", "synthetic-untrusted-step", "test"]}), encoding="utf-8")
        detected = _sha(pipeline.read_bytes()) != expected
        pipeline.write_text(json.dumps(trusted), encoding="utf-8")
        return [{"event": "poisoned_pipeline_mutation", "mutation_detected": detected, "restored": _sha(pipeline.read_bytes()) == expected}]
    component = root / "component.txt"
    component.write_text("AF trusted component", encoding="utf-8")
    expected = _sha(component.read_bytes())
    component.write_text("AF controlled mutation", encoding="utf-8")
    detected = _sha(component.read_bytes()) != expected
    component.write_text("AF trusted component", encoding="utf-8")
    return [
        {
            "event": "supply_chain_integrity_check",
            "component_kind": "firmware" if technique_id == "T1542.002" else "software",
            "expected_sha256": expected,
            "mutation_detected": detected,
            "restored": _sha(component.read_bytes()) == expected,
        }
    ]


def _cloud_identity(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    path = root / "identity.sqlite"
    with closing(sqlite3.connect(path)) as db:
        db.execute("create table audit(action text, subject text)")
        db.execute("insert into audit values (?, ?)", ("synthetic_change", technique_id))
        applied = db.execute("select count(*) from audit").fetchone()[0]
        db.execute("delete from audit")
        rolled_back = db.execute("select count(*) from audit").fetchone()[0] == 0
    return [{"event": "synthetic_identity_audit", "audit_rows": applied, "rolled_back": rolled_back}]


def _virtualization(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    inventory = {"hypervisor": "af-synthetic", "objects": [{"name": "vm-1", "state": "off"}], "technique": technique_id}
    path = root / "inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    loaded = json.loads(path.read_text())
    return [{"event": "virtualization_inventory_read", "objects": len(loaded["objects"]), "inventory_sha256": _sha(path.read_bytes())}]


def _social_engineering(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    content = f"SYNTHETIC ONLY\nTechnique: {technique_id}\nLink: https://example.invalid/training\nAttachment: exercise.txt\n"
    path = root / "lure.txt"
    path.write_text(content, encoding="utf-8")
    indicators = [line for line in content.splitlines() if line.startswith(("Link:", "Attachment:"))]
    return [
        {
            "event": "synthetic_lure_inspected",
            "indicators": len(indicators),
            "content_sha256": _sha(path.read_bytes()),
            "contacted_person": False,
        }
    ]


def _work_product(technique_id: str, root: Path, kind: str) -> List[Dict[str, Any]]:
    document = {
        "kind": kind,
        "technique_id": technique_id,
        "scope": "synthetic-authorized-lab",
        "resources": [{"name": "af-example", "provisioned": False}],
    }
    path = root / f"{kind}.json"
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    loaded = json.loads(path.read_text())
    return [
        {
            "event": f"{kind}_validated",
            "resources": len(loaded["resources"]),
            "document_sha256": _sha(path.read_bytes()),
            "external_action": False,
        }
    ]


def _osint_work_product(t: str, r: Path) -> List[Dict[str, Any]]:
    records = [
        {"source": "synthetic-public-registry", "kind": "organization", "value": "Example Industries"},
        {"source": "synthetic-search-index", "kind": "employee", "value": "Example Person"},
        {"source": "synthetic-threat-feed", "kind": "appliance", "value": "AF-Gateway"},
    ]
    path = r / "synthetic-public-data.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    results = [row for row in json.loads(path.read_text()) if row["source"].startswith("synthetic-")]
    return [{"event": "synthetic_osint_query", "query": t, "sources": sorted({row["source"] for row in results}), "results": len(results), "output_sha256": _sha(path.read_bytes())}]


def _infrastructure_work_product(t: str, r: Path) -> List[Dict[str, Any]]:
    return _work_product(t, r, "infrastructure_plan")


def _staging_work_product(t: str, r: Path) -> List[Dict[str, Any]]:
    payload = r / "harmless-stage.bin"
    payload.write_bytes(f"AF-STAGED-{t}".encode())
    manifest = r / "staging_manifest.json"
    manifest.write_text(json.dumps({"artifact": payload.name, "sha256": _sha(payload.read_bytes()), "published": False}), encoding="utf-8")
    loaded = json.loads(manifest.read_text())
    return [{"event": "local_artifact_staged", "manifest_verified": loaded["sha256"] == _sha(payload.read_bytes()), "published": False}]


def _transaction_dry_run(technique_id: str, root: Path) -> List[Dict[str, Any]]:
    transaction = {"technique_id": technique_id, "amount": 0, "currency": "TEST", "submit": False}
    path = root / "transaction.json"
    path.write_text(json.dumps(transaction), encoding="utf-8")
    return [
        {
            "event": "transaction_dry_run",
            "valid": transaction["amount"] == 0 and not transaction["submit"],
            "submitted": False,
            "transaction_sha256": _sha(path.read_bytes()),
        }
    ]


def _wireless_capture(_: str, root: Path) -> List[Dict[str, Any]]:
    capture = b"AFPCAP\x00BEACON\x00SSID=AdversaryFlow-Synthetic"
    path = root / "wireless.pcap"
    path.write_bytes(capture)
    return [
        {"event": "synthetic_wireless_capture", "beacon_found": b"BEACON" in path.read_bytes(), "capture_sha256": _sha(path.read_bytes())}
    ]


_RUNNERS: Dict[str, Callable[[str, Path], List[Dict[str, Any]]]] = {
    name.removeprefix("_"): value
    for name, value in globals().copy().items()
    if name.startswith("_") and callable(value) and name.removeprefix("_") in SCENARIOS
}


def run_exercise(technique_id: str) -> Dict[str, Any]:
    """Run one bounded exercise and return its self-reported evidence receipt."""
    spec = get_spec(technique_id)
    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc)
    status = "passed"
    error = None
    events: List[Dict[str, Any]] = []
    try:
        marker = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; print(' '.join(sys.argv[1:]))",
                "adversaryflow-run-marker",
                "--run-id",
                run_id,
                "--technique-id",
                technique_id,
                "--scenario",
                spec.scenario,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        events.append(
            {
                "event": "telemetry_correlation_marker",
                "run_id": run_id,
                "child_exit_code": marker.returncode,
                "marker_emitted": marker.returncode == 0 and run_id in marker.stdout,
            }
        )
        with tempfile.TemporaryDirectory(prefix=f"adversaryflow-{technique_id.replace('.', '-')}-") as directory:
            workspace = Path(directory)
            scenario_events = _RUNNERS[spec.scenario](technique_id, workspace)
            events.extend(scenario_events)
            for event in scenario_events:
                event.setdefault("technique_id", technique_id)
        cleanup_verified = not workspace.exists()
    except Exception as exc:
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"
        cleanup_verified = False
    completed = datetime.now(timezone.utc)
    receipt: Dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "technique_id": technique_id,
        "scenario": spec.scenario,
        "exercise_summary": spec.summary,
        "expected_telemetry": spec.expected_telemetry,
        "status": status,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_ms": max(0, round((completed - started).total_seconds() * 1000)),
        "exit_code": 0 if status == "passed" else 1,
        "events": events,
        "cleanup_verified": cleanup_verified,
        "attestation": "self-reported; correlate run_id and timestamps with endpoint or SIEM telemetry",
        "error": error,
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    receipt["receipt_sha256"] = _sha(canonical)
    return receipt


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a bounded AdversaryFlow technique exercise")
    parser.add_argument("technique_id", choices=sorted(TECHNIQUE_SCENARIOS))
    args = parser.parse_args(list(argv) if argv is not None else None)
    receipt = run_exercise(args.technique_id)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return int(receipt["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
