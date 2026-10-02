"""Real HTTPS delivery, signing, durable retries and redirect refusal."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from backend import engagement_store, webhook
from tests.test_execution_kit import plan_fixture


class WebhookConfigurationTests(unittest.TestCase):
    def test_disabled_and_invalid_configuration(self):
        with patch.dict(os.environ, {"ADVERSARYFLOW_RUN_WEBHOOK_URL": "", "ADVERSARYFLOW_RUN_WEBHOOK_SECRET": ""}):
            self.assertIsNone(webhook.load_config())
            self.assertFalse(webhook.start_worker())
        for url, secret in (("https://example.org", ""), ("", "s" * 32), ("https://example.org", "short"),
                            ("http://example.org", "s" * 32), ("https://user@example.org", "s" * 32),
                            ("https://example.org/#fragment", "s" * 32), ("https://example.org:0", "s" * 32),
                            ("https://example.org:invalid", "s" * 32)):
            with self.subTest(url=url, secret_length=len(secret)), patch.dict(os.environ, {
                "ADVERSARYFLOW_RUN_WEBHOOK_URL": url, "ADVERSARYFLOW_RUN_WEBHOOK_SECRET": secret,
            }), self.assertRaises(webhook.WebhookConfigurationError):
                webhook.load_config()


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "install requirements-test.lock for HTTPS integration tests")
class WebhookHttpsTests(unittest.TestCase):
    def test_tls_signature_retry_redirect_dead_letter_and_automatic_worker(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        database = root / "engagements.sqlite3"
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local integration test")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                       .not_valid_after(now + timedelta(hours=1))
                       .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                       .sign(private, hashes.SHA256()))
        cert_file, key_file = root / "tls.pem", root / "tls.key"
        cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        received: list[tuple[dict[str, str], bytes]] = []
        replies = [503, 204, 302, 503, 204]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((dict(self.headers), self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(replies.pop(0))
                self.send_header("Location", "/must-not-follow")
                self.end_headers()

            def log_message(self, *args):
                pass

        endpoint = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_file, key_file)
        endpoint.socket = tls.wrap_socket(endpoint.socket, server_side=True)
        thread = threading.Thread(target=endpoint.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(endpoint.server_close)
        self.addCleanup(endpoint.shutdown)
        environment = patch.dict(os.environ, {
            "SSL_CERT_FILE": str(cert_file), "ADVERSARYFLOW_ENGAGEMENT_DB": str(database),
            "ADVERSARYFLOW_RUN_WEBHOOK_URL": f"https://127.0.0.1:{endpoint.server_port}/events",
            "ADVERSARYFLOW_RUN_WEBHOOK_SECRET": "s" * 32,
        })
        environment.start()
        self.addCleanup(environment.stop)
        config = webhook.load_config()
        assert config is not None
        plan = plan_fixture()

        def save(run_id: str) -> None:
            plan["stages"][0]["techniques"][0]["execution"] = {"outcome": "passed", "run_id": run_id}
            engagement_store.save_revision(plan)

        save("retry-run")
        delivery = engagement_store.claim_webhook_deliveries()[0]
        with self.assertRaisesRegex(RuntimeError, "503"):
            webhook._deliver(config, delivery)
        engagement_store.complete_webhook_delivery(delivery["delivery_id"], success=False, error="RuntimeError")
        self.assertEqual(engagement_store.claim_webhook_deliveries(), [])
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("UPDATE webhook_outbox SET next_attempt_at='2000-01-01T00:00:00Z'")
        retry = engagement_store.claim_webhook_deliveries()[0]
        self.assertEqual(retry["attempts"], 2)
        webhook._deliver(config, retry)
        engagement_store.complete_webhook_delivery(retry["delivery_id"], success=True)
        self.assertEqual(engagement_store.list_webhook_deliveries()[0]["status"], "delivered")
        self.assertEqual(received[0], received[1])

        save("redirect-run")
        redirect = engagement_store.claim_webhook_deliveries()[0]
        with self.assertRaisesRegex(RuntimeError, "302"):
            webhook._deliver(config, redirect)
        self.assertEqual(len(received), 3)
        engagement_store.complete_webhook_delivery(redirect["delivery_id"], success=False, max_attempts=1)
        dead = next(row for row in engagement_store.list_webhook_deliveries() if row["run_id"] == "redirect-run")
        self.assertEqual(dead["status"], "dead")

        # Exercise the daemon's real retry schedule in a child process so no
        # permanent worker survives this test or captures its temporary DB.
        save("automatic-run")
        script = (
            "import json,time;from backend import webhook,engagement_store as s;"
            "assert webhook.start_worker();assert not webhook.start_worker();deadline=time.monotonic()+15\n"
            "while time.monotonic()<deadline:\n"
            " row=next(r for r in s.list_webhook_deliveries() if r['run_id']=='automatic-run')\n"
            " if row['status']=='delivered':print(json.dumps(row));break\n"
            " time.sleep(0.1)\n"
            "else:raise RuntimeError('Worker delivery deadline exceeded')\n"
        )
        worker = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(worker.returncode, 0, worker.stderr)
        self.assertEqual(json.loads(worker.stdout)["attempts"], 2)
        self.assertEqual(len(received), 5)
        self.assertEqual(received[3], received[4])
        for headers, body in received:
            expected = "sha256=" + hmac.new(config.secret, body, hashlib.sha256).hexdigest()
            self.assertEqual(headers["X-Adversaryflow-Signature"], expected)
            self.assertTrue(headers["X-Adversaryflow-Event-Id"])
        public = json.dumps(engagement_store.list_webhook_deliveries()).encode()
        self.assertNotIn(config.secret, public)
        self.assertNotIn(config.url.encode(), public)
