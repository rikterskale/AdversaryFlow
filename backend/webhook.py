"""HMAC-signed, retryable webhook delivery for persisted run records."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("adversaryflow.webhook")
REQUEST_TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 2_048
MAX_ATTEMPTS = 12
_worker_lock = threading.Lock()
_worker_started = False


class WebhookConfigurationError(ValueError):
    """Webhook environment configuration is incomplete or unsafe."""


@dataclass(frozen=True)
class WebhookConfig:
    url: str
    secret: bytes


def load_config() -> Optional[WebhookConfig]:
    """Load administrator-configured HTTPS endpoint and HMAC secret."""
    url = os.environ.get("ADVERSARYFLOW_RUN_WEBHOOK_URL", "").strip()
    secret = os.environ.get("ADVERSARYFLOW_RUN_WEBHOOK_SECRET", "")
    if not url and not secret:
        return None
    if not url or not secret:
        raise WebhookConfigurationError("Both RUN_WEBHOOK_URL and RUN_WEBHOOK_SECRET are required")
    if len(secret.encode("utf-8")) < 32:
        raise WebhookConfigurationError("RUN_WEBHOOK_SECRET must contain at least 32 UTF-8 bytes")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or len(url) > 2_000):
        raise WebhookConfigurationError("RUN_WEBHOOK_URL must be an HTTPS URL without embedded credentials or a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebhookConfigurationError("RUN_WEBHOOK_URL has an invalid port") from exc
    if port == 0:
        raise WebhookConfigurationError("RUN_WEBHOOK_URL has an invalid port")
    return WebhookConfig(url=url, secret=secret.encode("utf-8"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req: Any, _fp: Any, _code: int, _msg: str, _headers: Any, _newurl: str):
        return None


def _deliver(config: WebhookConfig, delivery: Dict[str, Any]) -> None:
    body = json.dumps(delivery["payload"], ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    signature = hmac.new(config.secret, body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        config.url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "AdversaryFlow/1",
            "X-AdversaryFlow-Event-ID": delivery["event_id"],
            "X-AdversaryFlow-Signature": f"sha256={signature}",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Webhook returned HTTP {response.status}")
            response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise RuntimeError(f"Webhook returned HTTP {exc.code}") from exc


def _worker() -> None:
    from . import engagement_store

    while True:
        try:
            config = load_config()
            if config is None:
                time.sleep(5)
                continue
            deliveries = engagement_store.claim_webhook_deliveries(limit=10)
            if not deliveries:
                time.sleep(2)
                continue
            for delivery in deliveries:
                try:
                    _deliver(config, delivery)
                    engagement_store.complete_webhook_delivery(delivery["delivery_id"], success=True)
                except Exception as exc:
                    logger.warning("Run webhook delivery failed (%s)", type(exc).__name__)
                    engagement_store.complete_webhook_delivery(
                        delivery["delivery_id"], success=False,
                        # Do not persist endpoint-specific exception messages: urllib
                        # can include the configured hostname or URL in them.
                        error=type(exc).__name__, max_attempts=MAX_ATTEMPTS,
                    )
        except WebhookConfigurationError as exc:
            logger.error("Run webhook is disabled by invalid configuration: %s", exc)
            time.sleep(10)
        except Exception:
            logger.exception("Run webhook worker encountered an internal error")
            time.sleep(5)


def start_worker() -> bool:
    """Start one process-local daemon worker; delivery remains disabled by default."""
    global _worker_started
    try:
        if load_config() is None:
            return False
    except WebhookConfigurationError as exc:
        logger.error("Run webhook is disabled by invalid configuration: %s", exc)
        return False
    with _worker_lock:
        if _worker_started:
            return False
        thread = threading.Thread(target=_worker, name="run-webhook", daemon=True)
        thread.start()
        _worker_started = True
    return True
