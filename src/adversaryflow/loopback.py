"""Engine-owned loopback sink for safe local network emulation."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen


class _SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.received.append({"method": "POST", "path": self.path, "body": body.decode("utf-8", "replace")})  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"accepted":true}')

    def log_message(self, *_args) -> None:
        return


class LoopbackSink:
    """Short-lived HTTP sink bound exclusively to 127.0.0.1."""

    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _SinkHandler)
        self._server.received = []  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def received(self) -> list[dict[str, str]]:
        return list(self._server.received)  # type: ignore[attr-defined]

    def __enter__(self) -> "LoopbackSink":
        self._thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def send_marker(self, run_id: str) -> None:
        payload = json.dumps({"marker": "ADVERSARYFLOW_SYNTHETIC", "run_id": run_id}).encode()
        request = Request(f"{self.url}/beacon", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=2) as response:  # noqa: S310 - URL is constructed from the local bound sink.
            if response.status != 200:
                raise RuntimeError("loopback sink rejected synthetic marker")

