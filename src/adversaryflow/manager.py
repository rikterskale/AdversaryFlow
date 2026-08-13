"""Local-only guided campaign manager and JSON API."""

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .lifecycle import inspect_campaign, list_campaigns


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AdversaryFlow Campaign Guide</title>
<style>body{margin:0;background:#09111e;color:#e8eef8;font:16px system-ui,sans-serif}main{max-width:1000px;margin:auto;padding:36px 20px}h1{margin-bottom:4px}.sub{color:#aab8cb}.banner{background:#12304a;border-left:4px solid #58c4dc;padding:14px;margin:24px 0}.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.card{background:#111d2e;border:1px solid #293b54;border-radius:10px;padding:18px}.num{color:#58c4dc;font-weight:bold}label{display:block;margin-top:12px;color:#c9d6e8}input{box-sizing:border-box;width:100%;padding:9px;margin-top:4px;background:#07101c;border:1px solid #40536c;border-radius:6px;color:#fff}button{margin-top:16px;background:#58c4dc;border:0;border-radius:6px;padding:10px 14px;font-weight:bold;cursor:pointer}code{display:block;white-space:pre-wrap;background:#07101c;padding:12px;border-radius:6px;overflow:auto}.help{color:#b6c8e0;font-size:.92rem}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #293b54}a{color:#75d9f1}</style></head><body><main>
<h1>AdversaryFlow Campaign Guide</h1><p class="sub">A local-only, simulation-first walkthrough. No exploit payloads or external targets are available here.</p>
<div class="banner"><strong>Safety checkpoint:</strong> draft first, review scope and telemetry, then let the RoE-named approver authorize the local synthetic emulation.</div>
<section class="steps"><div class="card"><span class="num">1. Scope</span><p>Confirm the target is in the RoE allowlist. Start with <code>adversaryflow doctor --json</code></p></div><div class="card"><span class="num">2. Draft</span><p>Create a reviewable plan. This does not run an emulation.</p></div><div class="card"><span class="num">3. Review</span><p>Check abilities, telemetry expectations, stop conditions, and plan integrity.</p></div><div class="card"><span class="num">4. Approve & learn</span><p>Only the named RoE approver can run the local synthetic harness. Review its gap report afterwards.</p></div></section>
<section class="card" style="margin-top:16px"><h2>Build a safe draft command</h2><p class="help">This form only creates a copyable CLI command; it does not send data or execute anything.</p><label>Threat actor<input id="actor" value="APT29"></label><label>Objective<input id="objective" value="validate endpoint process visibility"></label><label>Target<input id="target" value="local-lab"></label><button onclick="draft()">Create command</button><code id="command">Fill in the fields to generate a draft command.</code><button onclick="copyCommand()">Copy command</button><p class="help">After drafting, use the campaign ID shown by the CLI to inspect it here or resume it with <code>adversaryflow campaign --campaign-id campaign-... --approve --approver manager@example.test</code>.</p></section>
<section class="card" style="margin-top:16px"><h2>Saved campaigns</h2><p class="help">Refreshes from this machine's configured campaign folder only.</p><button onclick="loadCampaigns()">Refresh campaigns</button><div id="campaigns">Loading…</div></section>
</main><script>function q(id){return document.getElementById(id)}function draft(){q('command').textContent='adversaryflow campaign --actor "'+q('actor').value.replaceAll('"','')+'" --target "'+q('target').value.replaceAll('"','')+'" --objective "'+q('objective').value.replaceAll('"','')+'"'}function copyCommand(){navigator.clipboard.writeText(q('command').textContent)}async function loadCampaigns(){let r=await fetch('/api/campaigns'),d=await r.json();if(!d.campaigns.length){q('campaigns').textContent='No saved campaigns yet. Create a draft using the command above.';return}q('campaigns').innerHTML='<table><tr><th>ID</th><th>Status</th><th>Provider</th><th>Next step</th></tr>'+d.campaigns.map(c=>'<tr><td>'+c.campaign_id+'</td><td>'+c.status+'</td><td>'+c.provider+'</td><td>'+next(c)+'</td></tr>').join('')+'</table>'}function next(c){return c.status==='awaiting-approval'?'Review draft, then approve from the CLI.':c.status==='completed'?'Open the campaign report and plan a retest.':'Inspect the recorded decision.'}loadCampaigns()</script></body></html>"""


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
                self._send(200, {"ok": True, "mode": "local-guided-manager"})
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


def serve(host: str = "127.0.0.1", port: int = 8787, campaign_root: str = "artifacts/campaigns", open_browser: bool = False) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Manager must bind to loopback only")
    server = ThreadingHTTPServer((host, port), make_handler(campaign_root))
    url = f"http://{host}:{server.server_port}"
    print(f"AdversaryFlow Campaign Guide listening on {url}")
    if open_browser:
        threading.Timer(0.2, webbrowser.open, args=(url,)).start()
    server.serve_forever()
