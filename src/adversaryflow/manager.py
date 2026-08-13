"""Small local-only campaign manager API and browser page."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .lifecycle import inspect_campaign, list_campaigns


PAGE = """<!doctype html><html><head><meta charset='utf-8'><title>AdversaryFlow Manager</title></head>
<body><h1>AdversaryFlow Manager</h1><p>Local campaign visibility; execution remains RoE-gated.</p>
<pre id='output'>Loading…</pre><script>fetch('/api/campaigns').then(r=>r.json()).then(x=>output.textContent=JSON.stringify(x,null,2))</script></body></html>"""


def make_handler(campaign_root: str):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: object, content_type: str = "application/json") -> None:
            body = payload.encode() if isinstance(payload, str) else json.dumps(payload, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/":
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/api/health":
                self._send(200, {"ok": True, "mode": "local-manager"})
            elif path == "/api/campaigns":
                self._send(200, {"campaigns": list_campaigns(campaign_root)})
            elif path.startswith("/api/campaigns/"):
                try:
                    self._send(200, inspect_campaign(campaign_root, path.rsplit("/", 1)[-1]))
                except (OSError, ValueError) as exc:
                    self._send(404, {"error": str(exc)})
            else:
                self._send(404, {"error": "not found"})

        def log_message(self, *_args) -> None:
            return

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787, campaign_root: str = "artifacts/campaigns") -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Manager must bind to loopback only")
    server = ThreadingHTTPServer((host, port), make_handler(campaign_root))
    print(f"AdversaryFlow Manager listening on http://{host}:{port}")
    server.serve_forever()
