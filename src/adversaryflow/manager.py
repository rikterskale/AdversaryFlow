"""Local-only guided campaign manager and JSON API."""

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .doctor import run_doctor
from .lifecycle import inspect_campaign, list_campaigns


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AdversaryFlow Campaign Guide</title><style>
:root{color-scheme:dark;--bg:#08111f;--panel:#112239;--line:#31516e;--text:#edf5fc;--muted:#b8c9db;--accent:#62d4e8;--safe:#8de0ac}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#143a61 0,var(--bg) 40%);color:var(--text);font:16px/1.5 system-ui,sans-serif}main{max-width:1060px;margin:auto;padding:42px 20px 80px}h1{font-size:clamp(2.2rem,5vw,3.6rem);line-height:1.05;margin:.2rem 0}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:.78rem}.lede,.muted{color:var(--muted)}.notice,.card{background:linear-gradient(145deg,#142940,#0e1b2d);border:1px solid var(--line);border-radius:16px;padding:22px;margin-top:20px}.notice{border-color:#277291}.journey{display:grid;grid-template-columns:repeat(5,1fr);gap:9px;margin-top:24px}.step{margin:0;padding:13px;background:var(--panel);border:1px solid var(--line);border-radius:10px;color:var(--text);font:inherit;text-align:left;cursor:pointer}.step:hover,.step[aria-current="step"]{border-color:var(--accent);background:#123552}.step b{display:block;color:var(--accent);font-size:.8rem}.step span{display:block;font-weight:750;margin:4px 0}.step small{color:var(--muted)}.layout{display:grid;grid-template-columns:1fr 1fr;gap:22px}.next{border-left:4px solid var(--safe);padding:12px 14px;background:#112f29;border-radius:0 8px 8px 0}code{display:block;white-space:pre-wrap;overflow:auto;background:#07111e;padding:13px;border-radius:8px;color:#d9f4fa}button{margin:12px 8px 0 0;padding:11px 15px;background:var(--accent);border:0;border-radius:8px;color:#06212a;font:700 15px system-ui;cursor:pointer}button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent)}button:disabled{opacity:.45;cursor:not-allowed}label{display:block;margin-top:12px;font-weight:650}input{width:100%;margin-top:4px;padding:11px;background:#07111e;color:var(--text);border:1px solid #41647f;border-radius:8px;font:inherit}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-weight:650}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:10px 7px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}a{color:var(--accent)}ul{padding-left:20px}@media(max-width:760px){main{padding-top:28px}.journey,.layout{grid-template-columns:1fr}.step{min-height:auto}table{display:block;overflow:auto}}
</style></head><body><main>
<p class="eyebrow">Local-only campaign workspace</p><h1>Start a safe campaign in five clear steps.</h1><p class="lede">Follow one step at a time. This guide can run explicitly allowlisted safe checks, but never contacts an external target, creates an exploit, or bypasses approval.</p><div class="notice"><strong>Before you begin:</strong> use only an RoE-approved target. The named RoE approver—not this page—authorizes local synthetic emulation.</div>
<nav class="journey" aria-label="Campaign walkthrough"><button class="step" onclick="showStep(0)"><b>Step 1</b><span>Check</span><small>Verify your setup.</small></button><button class="step" onclick="showStep(1)"><b>Step 2</b><span>Draft</span><small>Describe the goal.</small></button><button class="step" onclick="showStep(2)"><b>Step 3</b><span>Review</span><small>Check the plan.</small></button><button class="step" onclick="showStep(3)"><b>Step 4</b><span>Approve</span><small>Authorize safely.</small></button><button class="step" onclick="showStep(4)"><b>Step 5</b><span>Learn</span><small>Use the report.</small></button></nav>
<section class="card" id="walkthrough" aria-live="polite"><p class="eyebrow" id="guide-count">Guided walkthrough · step 1 of 5</p><h2 id="guide-title">Check your setup</h2><p id="guide-detail">Before creating a campaign, confirm the local environment, RoE, and safe ability catalog are healthy.</p><code id="guide-command">adversaryflow doctor --json</code><p class="next" id="guide-next"><strong>Do this now:</strong> Run the health check in your terminal. Continue only after it passes.</p><button id="run-safe-check" onclick="runDoctor()">Run health check here</button><button class="secondary" id="guide-back" onclick="moveStep(-1)">Back</button><button id="guide-forward" onclick="moveStep(1)">Next: create a draft</button><code id="safe-result" hidden></code><p class="muted">You can jump to any step above. The detailed help below stays available when you need it.</p></section>
<section class="card" id="draft-helper"><h2>Create a reviewable draft</h2><p class="muted">Enter three details. The button creates a command to copy; it does not execute it.</p><div class="layout"><div><label>Threat actor<input id="actor" value="APT29"></label><label>Defensive objective<input id="objective" value="validate endpoint process visibility"></label><label>RoE-approved target<input id="target" value="local-lab"></label><button onclick="draft()">Create my draft command</button><button class="secondary" onclick="copyCommand()">Copy command</button></div><div><h3>Your safe next command</h3><code id="command">Enter your details, then choose “Create my draft command.”</code><p class="next" id="command-next"><strong>Then:</strong> Run the command in your terminal. It returns a campaign ID for review.</p></div></div></section>
<section class="card"><h2>What happens after the draft?</h2><div class="layout"><div><h3>Review</h3><code>adversaryflow campaign inspect --campaign-id campaign-...</code><p class="muted">Check scope, selected abilities, telemetry, assumptions, and stop conditions. Use <code>campaign reject</code> if it should not proceed.</p></div><div><h3>Approve only when scheduled</h3><code>adversaryflow campaign --campaign-id campaign-... --approve --approver &lt;RoE-approver&gt;</code><p class="muted">Resuming verifies the saved draft, RoE, and ability catalog before the local simulation.</p></div></div></section>
<section class="card"><h2>Saved campaigns</h2><p class="muted">Your local campaign records and their next actions.</p><button onclick="loadCampaigns()">Refresh campaign list</button><div id="campaigns" class="muted">Loading local campaigns…</div></section>
<section class="card"><h2>Common questions</h2><details><summary>My setup is not ready.</summary><p>Run <code>adversaryflow doctor --fix --json</code>. It only creates local artifact folders, then explains remaining problems.</p></details><details><summary>My provider is unavailable.</summary><p>Run <code>adversaryflow provider diagnose</code>. Use <code>--fallback-offline</code> for a safe local rehearsal.</p></details><details><summary>I need to stop a draft.</summary><p>Run <code>adversaryflow campaign cancel --campaign-id campaign-... --reason "operator requested stop"</code>.</p></details><details><summary>I prefer the terminal.</summary><p>Run <code>adversaryflow guide --interactive</code> for the same step-by-step workflow.</p></details></section>
</main><script>
function q(id){return document.getElementById(id)}function clean(v){return v.replaceAll('"','')}
const steps=[['Check your setup','Before creating a campaign, confirm the local environment, RoE, and safe ability catalog are healthy.','adversaryflow doctor --json','Run the health check in your terminal. Continue only after it passes.','Next: create a draft'],['Create a reviewable draft','Describe a defensive objective and an RoE-approved target. Drafting saves a plan for review; it does not run an emulation.','Use the draft helper below.','Fill in the three fields, copy the command, and run it in your terminal.','Next: review the draft'],['Review the saved plan','Use the returned campaign ID to inspect abilities, expected telemetry, assumptions, and stop conditions.','adversaryflow campaign inspect --campaign-id campaign-...','If the campaign is not appropriate or not scheduled, reject it instead of editing it.','Next: obtain approval'],['Obtain explicit approval','Only the approver named in the RoE can authorize the local synthetic emulation.','adversaryflow campaign --campaign-id campaign-... --approve --approver &lt;RoE-approver&gt;','Confirm schedule and scope, then run the approval command in your terminal.','Next: learn from results'],['Learn and retest','Open the completed report, review detection gaps, and create a new focused draft for any retest.','Open a report link in Saved campaigns.','Do not modify an approved campaign. Use the report to define a new defensive objective.','Finish walkthrough']];let currentStep=0;
function showStep(index){currentStep=Math.max(0,Math.min(steps.length-1,index));let s=steps[currentStep];q('guide-count').textContent='Guided walkthrough · step '+(currentStep+1)+' of 5';q('guide-title').textContent=s[0];q('guide-detail').textContent=s[1];q('guide-command').textContent=s[2];q('guide-next').innerHTML='<strong>Do this now:</strong> '+s[3];q('guide-back').disabled=currentStep===0;q('guide-forward').textContent=s[4];q('run-safe-check').hidden=currentStep!==0;document.querySelectorAll('.step').forEach((el,i)=>el.setAttribute('aria-current',i===currentStep?'step':'false'));q('walkthrough').scrollIntoView({behavior:'smooth',block:'nearest'})}function moveStep(delta){showStep(currentStep+delta)}async function runDoctor(){let button=q('run-safe-check'),output=q('safe-result');button.disabled=true;button.textContent='Checking…';let response=await fetch('/api/doctor',{method:'POST'}),result=await response.json();output.hidden=false;output.textContent=JSON.stringify(result,null,2);button.textContent=result.passed?'Health check passed':'Health check needs attention';q('guide-next').innerHTML=result.passed?'<strong>Ready:</strong> Your local checks passed. Continue to create a draft.':'<strong>Pause:</strong> Review the failed checks and follow their remediation before creating a draft.';button.disabled=false}
function draft(){q('command').textContent='adversaryflow campaign --actor "'+clean(q('actor').value)+'" --target "'+clean(q('target').value)+'" --objective "'+clean(q('objective').value)+'"';q('command-next').innerHTML='<strong>Then:</strong> Run this command in your terminal. It creates a draft only; inspect the returned campaign ID before approval.';showStep(2)}function copyCommand(){navigator.clipboard.writeText(q('command').textContent);q('command-next').innerHTML='<strong>Copied:</strong> Paste the command into your terminal when you are ready to create a draft.'}
async function loadCampaigns(){let r=await fetch('/api/campaigns'),d=await r.json();if(!d.campaigns.length){q('campaigns').textContent='No saved campaigns yet. Create a draft after you complete step 1.';return}q('campaigns').innerHTML='<table><tr><th>Campaign</th><th>Status</th><th>Provider</th><th>What to do next</th></tr>'+d.campaigns.map(c=>'<tr><td>'+c.campaign_id+'</td><td>'+c.status+'</td><td>'+c.provider+'</td><td>'+next(c)+'</td></tr>').join('')+'</table>'}function next(c){if(c.status==='awaiting-approval')return 'Inspect the draft. Approve only when the RoE approver confirms the schedule.';if(c.status==='completed'){let link=c.report_url?'<a href="'+c.report_url+'">Open report</a> · ':'';return link+'Use detection gaps to define a new retest objective.'}if(c.status==='cancelled')return 'The stop request is recorded. Inspect the campaign before deciding whether to create a new draft.';return 'Inspect the recorded decision and create a new draft only if the scope changes.'}showStep(0);loadCampaigns()
</script></body></html>"""


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
                campaigns = list_campaigns(campaign_root)
                for campaign in campaigns:
                    report = Path(campaign_root) / campaign["campaign_id"] / "campaign-report.html"
                    campaign["report_url"] = f"/api/campaigns/{campaign['campaign_id']}/report" if report.exists() else None
                self._send(200, {"campaigns": campaigns})
            elif path.startswith("/api/campaigns/"):
                try:
                    parts = path.split("/")
                    campaign_id = parts[3]
                    if len(parts) == 5 and parts[4] == "report":
                        campaign = inspect_campaign(campaign_root, campaign_id)
                        report = Path(campaign["campaign_dir"]) / "campaign-report.html"
                        if not report.is_file():
                            raise FileNotFoundError(f"Campaign report not found: {campaign_id}")
                        self._send(200, report.read_text(encoding="utf-8"), "text/html; charset=utf-8")
                    elif len(parts) == 4:
                        self._send(200, inspect_campaign(campaign_root, campaign_id))
                    else:
                        self._send(404, {"error": "not found"})
                except (OSError, ValueError) as exc:
                    self._send(404, {"error": str(exc)})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path == "/api/doctor":
                self._send(200, run_doctor())
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
