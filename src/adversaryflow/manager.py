"""Loopback-only, simulation-only campaign manager and JSON API."""

import json
import threading
import webbrowser
from importlib.resources import files
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .ai import CampaignRequest, OfflinePlanner, validate_ai_draft
from .doctor import run_doctor
from .emulation import default_catalog_path, load_catalog
from .lifecycle import cancel_campaign, inspect_campaign, list_campaigns, reject_campaign
from .models import RulesOfEngagement
from .workflow import campaign_integrity_hashes, load_campaign_draft, save_campaign_draft


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AdversaryFlow Campaign Guide</title><style>
:root{color-scheme:dark;--bg:#08111f;--panel:#112239;--line:#31516e;--text:#edf5fc;--muted:#b8c9db;--accent:#62d4e8;--safe:#8de0ac;--warn:#f3cb72}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#143a61 0,var(--bg) 40%);color:var(--text);font:16px/1.5 system-ui,sans-serif}main{max-width:1060px;margin:auto;padding:42px 20px 80px}h1{font-size:clamp(2.2rem,5vw,3.6rem);line-height:1.05;margin:.2rem 0}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:.78rem}.lede,.muted{color:var(--muted)}.notice,.card{background:linear-gradient(145deg,#142940,#0e1b2d);border:1px solid var(--line);border-radius:16px;padding:22px;margin-top:20px}.notice{border-color:#277291}.journey{display:grid;grid-template-columns:repeat(5,1fr);gap:9px;margin-top:24px}.step{margin:0;padding:13px;background:var(--panel);border:1px solid var(--line);border-radius:10px;color:var(--text);font:inherit;text-align:left;cursor:pointer}.step:hover,.step[aria-current="step"]{border-color:var(--accent);background:#123552}.step b{display:block;color:var(--accent);font-size:.8rem}.step span{display:block;font-weight:750;margin:4px 0}.step small{color:var(--muted)}.layout{display:grid;grid-template-columns:1fr 1fr;gap:22px}.next{border-left:4px solid var(--safe);padding:12px 14px;background:#112f29;border-radius:0 8px 8px 0}code,pre{display:block;white-space:pre-wrap;overflow:auto;background:#07111e;padding:13px;border-radius:8px;color:#d9f4fa}button{margin:12px 8px 0 0;padding:11px 15px;background:var(--accent);border:0;border-radius:8px;color:#06212a;font:700 15px system-ui;cursor:pointer}button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent)}button.warn{background:transparent;color:var(--warn);border:1px solid var(--warn)}button:disabled{opacity:.45;cursor:not-allowed}label{display:block;margin-top:12px;font-weight:650}input{width:100%;margin-top:4px;padding:11px;background:#07111e;color:var(--text);border:1px solid #41647f;border-radius:8px;font:inherit}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-weight:650}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:10px 7px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}a{color:var(--accent)}.inline button{margin-top:4px;padding:6px 9px;font-size:.8rem}@media(max-width:760px){main{padding-top:28px}.journey,.layout{grid-template-columns:1fr}.step{min-height:auto}table{display:block;overflow:auto}}
</style></head><body><main>
<p class="eyebrow">Local-only campaign workspace</p><h1>Start a safe campaign in five clear steps.</h1><p class="lede">Follow one step at a time. This guide can run an allowlisted health check and create an offline draft. It never contacts an external target, creates an exploit, or bypasses approval.</p><div class="notice"><strong>Boundary:</strong> browser actions are limited to local drafts, inspection, rejection, and cancellation. The named RoE approver—not this page—authorizes local synthetic emulation in the CLI.</div>
<nav class="journey" aria-label="Campaign walkthrough"><button class="step" onclick="showStep(0)"><b>Step 1</b><span>Check</span><small>Verify setup.</small></button><button class="step" onclick="showStep(1)"><b>Step 2</b><span>Draft</span><small>Save offline plan.</small></button><button class="step" onclick="showStep(2)"><b>Step 3</b><span>Review</span><small>Inspect scope.</small></button><button class="step" onclick="showStep(3)"><b>Step 4</b><span>Approve</span><small>Use CLI.</small></button><button class="step" onclick="showStep(4)"><b>Step 5</b><span>Learn</span><small>Review report.</small></button></nav>
<section class="card" id="walkthrough" aria-live="polite"><p class="eyebrow" id="guide-count">Guided walkthrough · step 1 of 5</p><h2 id="guide-title">Check your setup</h2><p id="guide-detail">Confirm the local environment, RoE, and safe ability catalog are healthy.</p><code id="guide-command">adversaryflow doctor --json</code><p class="next" id="guide-next"><strong>Do this now:</strong> Run the health check. Continue only after it passes.</p><button id="run-safe-check" onclick="runDoctor()">Run health check here</button><button class="secondary" id="guide-back" onclick="moveStep(-1)">Back</button><button id="guide-forward" onclick="moveStep(1)">Next: create a draft</button><pre id="safe-result" hidden></pre></section>
<section class="card" id="draft-helper"><h2>Create a reviewable offline draft</h2><p class="muted">This stores a locally generated, RoE-validated plan for review. It does not use a hosted provider and does not run an emulation.</p><p id="draft-context" class="notice">Loading the local RoE scope and safe catalog…</p><div class="layout"><div><label>Threat actor<input id="actor" value="APT29" maxlength="200"></label><label>Defensive objective<input id="objective" value="validate endpoint process visibility" maxlength="200"></label><label>RoE-approved target<input id="target" value="local-lab" maxlength="200"></label><button onclick="createDraft()">Create safe offline draft</button><button class="secondary" onclick="copyCommand()">Copy equivalent CLI command</button></div><div><h3 id="draft-heading">Your next step</h3><pre id="command">Complete the fields, then create a safe offline draft.</pre><p class="next" id="command-next"><strong>Then:</strong> Inspect the saved plan before any approval decision.</p></div></div></section>
<section class="card"><h2>Saved campaigns</h2><p class="muted">Inspect every plan before scheduling. You may record a rejection or cancellation here; the manager cannot approve or execute a campaign.</p><button onclick="loadCampaigns()">Refresh campaign list</button><label>Show status<select id="status-filter" onchange="loadCampaigns()"><option value="all">All campaigns</option><option value="awaiting-approval">Awaiting approval</option><option value="completed">Completed</option><option value="rejected">Rejected</option><option value="cancelled">Cancelled</option></select></label><div id="portfolio" class="muted">Loading local campaign summary…</div><div id="campaigns" class="muted">Loading local campaigns…</div><div id="campaign-detail" hidden></div></section>
<section class="card"><h2>What happens after review?</h2><div class="layout"><div><h3>Approve only when scheduled</h3><code>adversaryflow campaign --campaign-id campaign-... --approve --approver &lt;RoE-approver&gt;</code><p class="muted">The CLI verifies the draft, RoE, and ability catalog integrity before local synthetic emulation.</p></div><div><h3>Learn and retest</h3><p class="muted">Open a completed report, use detection gaps to define a new objective, and draft a new campaign instead of modifying an approved one.</p></div></div></section>
<section class="card"><h2>Common questions</h2><details><summary>My setup is not ready.</summary><p>Run <code>adversaryflow doctor --fix --json</code>. It only creates local artifact folders, then explains remaining problems.</p></details><details><summary>My provider is unavailable.</summary><p>The browser draft flow is always offline. For CLI help, run <code>adversaryflow provider diagnose</code> and use <code>--fallback-offline</code> for a safe rehearsal.</p></details><details><summary>I prefer the terminal.</summary><p>Run <code>adversaryflow guide --interactive</code> for the same step-by-step workflow.</p></details></section>
</main><script>
function q(id){return document.getElementById(id)}function esc(v){let d=document.createElement('div');d.textContent=String(v??'');return d.innerHTML}async function api(path,options={}){let r=await fetch(path,options),d=await r.json();if(!r.ok)throw new Error(d.error||'Request failed');return d}
const steps=[['Check your setup','Confirm the local environment, RoE, and safe ability catalog are healthy.','adversaryflow doctor --json','Run the health check. Continue only after it passes.','Next: create a draft'],['Create a reviewable offline draft','Describe a defensive objective and an RoE-approved target. This saves an offline plan for review; it does not run an emulation.','Use the draft helper below.','Create the local draft, then inspect its scope and selected abilities.','Next: review the draft'],['Review the saved plan','Inspect the campaign record for scope, selected abilities, telemetry, assumptions, and stop conditions.','Use Inspect in Saved campaigns.','Reject or cancel an inappropriate draft; do not edit an approval-bound plan.','Next: obtain approval'],['Obtain explicit approval','Only the approver named in the RoE can authorize local synthetic emulation. This action is deliberately CLI-only.','adversaryflow campaign --campaign-id campaign-... --approve --approver <RoE-approver>','Confirm schedule and scope, then use the CLI approval command.','Next: learn from results'],['Learn and retest','Open a completed report, review detection gaps, and create a focused new draft for any retest.','Open report in Saved campaigns.','Do not modify an approved campaign. Use its report to define a new defensive objective.','Finish walkthrough']];let currentStep=0;
function showStep(index){currentStep=Math.max(0,Math.min(steps.length-1,index));let s=steps[currentStep];q('guide-count').textContent='Guided walkthrough · step '+(currentStep+1)+' of 5';q('guide-title').textContent=s[0];q('guide-detail').textContent=s[1];q('guide-command').textContent=s[2];q('guide-next').innerHTML='<strong>Do this now:</strong> '+s[3];q('guide-back').disabled=currentStep===0;q('guide-forward').textContent=s[4];q('run-safe-check').hidden=currentStep!==0;document.querySelectorAll('.step').forEach((el,i)=>el.setAttribute('aria-current',i===currentStep?'step':'false'))}function moveStep(delta){showStep(currentStep+delta)}
async function runDoctor(){let b=q('run-safe-check'),o=q('safe-result');b.disabled=true;b.textContent='Checking…';try{let result=await api('/api/doctor',{method:'POST'});o.hidden=false;o.textContent=JSON.stringify(result,null,2);b.textContent=result.passed?'Health check passed':'Health check needs attention';q('guide-next').innerHTML=result.passed?'<strong>Ready:</strong> Your local checks passed. Continue to create a draft.':'<strong>Pause:</strong> Follow the remediation before creating a draft.'}catch(e){o.hidden=false;o.textContent='Health check failed: '+e.message;b.textContent='Try health check again'}finally{b.disabled=false}}
async function createDraft(){let b=event.currentTarget;b.disabled=true;b.textContent='Creating local draft…';try{let result=await api('/api/campaigns',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor:q('actor').value,objective:q('objective').value,target:q('target').value})});q('draft-heading').textContent='Draft '+result.campaign_id+' is ready for review';q('command').textContent=JSON.stringify(result,null,2);q('command-next').innerHTML='<strong>Next:</strong> Inspect this RoE-validated offline draft below. Browser approval and emulation are unavailable by design.';showStep(2);await loadCampaigns()}catch(e){q('command').textContent='Draft was not created: '+e.message;q('command-next').innerHTML='<strong>Pause:</strong> Correct the input or RoE configuration, then try again.'}finally{b.disabled=false;b.textContent='Create safe offline draft'}}
function copyCommand(){let text='adversaryflow campaign --actor "'+q('actor').value.replaceAll('"','')+'" --target "'+q('target').value.replaceAll('"','')+'" --objective "'+q('objective').value.replaceAll('"','')+'" --fallback-offline';navigator.clipboard.writeText(text);q('command').textContent=text;q('command-next').innerHTML='<strong>Copied:</strong> This CLI command creates a draft only; review it before approval.'}
async function loadContext(){try{let d=await api('/api/context'),r=d.roe;q('draft-context').innerHTML='<strong>Current local scope:</strong> '+esc(r.engagement_name)+' · environment '+esc(r.environment)+' · approved targets '+pills(r.approved_targets)+' · '+esc(d.catalog.ability_count)+' safe catalog abilities. Browser drafts are '+esc(d.mode)+'.'}catch(e){q('draft-context').textContent='Could not load local RoE context: '+e.message}}
function pills(items){return items.length?items.map(x=>'<span style="display:inline-block;padding:2px 8px;margin:3px;border:1px solid #31516e;border-radius:99px;font-size:.85rem">'+esc(x)+'</span>').join(''):'<span class="muted">None recorded</span>'}
function reportSummary(s){if(s.status!=='available')return '<p class="muted">'+esc(s.detail)+'</p>';let gaps=s.gaps.length?s.gaps.map(g=>'<li>'+esc(g.category)+': '+esc(g.description)+'</li>').join(''):'<li>No required telemetry gaps reported.</li>';return '<p><strong>Behavior:</strong> '+(s.behavior_success?'completed':'needs review')+'<br><strong>Telemetry:</strong> '+esc(s.telemetry_observed)+' observed of '+esc(s.telemetry_expected)+' expected<br><strong>Detection gaps:</strong> '+esc(s.detection_gap_count)+'</p><p class="muted">'+esc(s.assessment)+'</p><details><summary>Detection-gap findings</summary><ul>'+gaps+'</ul></details>'}
function timeline(items){return '<ol>'+items.map(i=>'<li><strong>'+esc(i.event)+'</strong><br><span class="muted">'+esc(i.at)+' · '+esc(i.detail)+'</span></li>').join('')+'</ol>'}
function readiness(r){return '<p style="color:'+(r.ready?'#8de0ac':'#f3cb72')+'"><strong>'+(r.ready?'Ready for CLI approval review':'Not ready for approval')+'</strong></p><ul>'+r.checks.map(c=>'<li>'+esc(c.passed?'Pass: ':'Needs attention: ')+esc(c.label)+'</li>').join('')+'</ul><p class="muted">'+esc(r.next)+'</p>'}
function copyTerminalNext(){navigator.clipboard.writeText(q('terminal-next-command').textContent);q('terminal-next-note').textContent='Copied. Paste this into your terminal when the stated safety conditions are met.'}
function renderDetail(d){let x=d.detail,verified=x.integrity.status==='verified',color=verified?'#8de0ac':x.integrity.status==='review-required'?'#f3cb72':'#ff9d9d',report=x.report_url?'<a href="'+esc(x.report_url)+'">Open report</a>':'';q('campaign-detail').innerHTML='<p class="eyebrow">Campaign review</p><h2>'+esc(d.metadata.campaign_id)+'</h2><p class="next" style="border-left-color:'+color+'"><strong>Next:</strong> '+esc(x.next_action)+'</p><div class="layout"><section class="card"><h3>Scope</h3><p><strong>Target:</strong> '+esc(x.scope.target)+'<br><strong>Objective:</strong> '+esc(x.scope.objective)+'<br><strong>Risk:</strong> '+esc(x.scope.risk_level)+'<br><strong>Mode:</strong> local synthetic simulation only</p></section><section class="card"><h3>Integrity</h3><p style="color:'+color+'"><strong>'+esc(x.integrity.status.replaceAll('-',' '))+'</strong></p><p class="muted">'+esc(x.integrity.detail)+'</p></section><section class="card"><h3>Rules of Engagement</h3><p><strong>Environment:</strong> '+esc(x.roe.environment)+'<br><strong>Approver:</strong> '+esc(x.roe.approver_name)+'<br><strong>Approved targets:</strong><br>'+pills(x.roe.approved_targets)+'</p></section><section class="card"><h3>Selected safe abilities</h3><p>'+x.abilities.map(a=>'<strong>'+esc(a.id)+'</strong> · '+esc(a.name)+'<br><span class="muted">'+esc(a.technique_id)+' · '+esc(a.network_scope)+' · '+esc(a.telemetry_count)+' expected telemetry signals</span>').join('<hr>')+'</p></section><section class="card"><h3>Stop conditions</h3><p>'+pills(x.stop_conditions)+'</p></section><section class="card"><h3>Report review</h3><p>'+esc(x.report_review)+' '+report+'</p>'+reportSummary(x.report_summary)+'</section></div><section class="card"><h3>Approval readiness</h3>'+readiness(x.approval_readiness)+'</section><section class="card"><h3>'+esc(x.terminal_next.label)+'</h3><code id="terminal-next-command">'+esc(x.terminal_next.command)+'</code><p id="terminal-next-note" class="muted">'+esc(x.terminal_next.detail)+'</p><button class="secondary" onclick="copyTerminalNext()">Copy command</button></section><section class="card"><h3>Decision timeline</h3>'+timeline(x.decision_timeline)+'</section><details><summary>Show raw campaign record</summary><pre>'+esc(JSON.stringify(d,null,2))+'</pre></details>'}
async function inspectCampaign(id){try{let d=await api('/api/campaigns/'+encodeURIComponent(id));q('campaign-detail').hidden=false;renderDetail(d);q('campaign-detail').scrollIntoView({behavior:'smooth',block:'nearest'})}catch(e){alert('Could not inspect campaign: '+e.message)}}
async function recordDecision(id,action){let reason=prompt(action==='reject'?'Why should this draft be rejected?':'Why should this draft be cancelled?');if(!reason)return;let body={reason};if(action==='reject'){body.approver=prompt('Enter the RoE approver name to record this rejection:')||'';if(!body.approver)return}if(!confirm('Record this '+action+' decision for '+id+'? This does not execute any campaign.'))return;try{await api('/api/campaigns/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await loadCampaigns();await inspectCampaign(id)}catch(e){alert('Could not record decision: '+e.message)}}
function portfolio(s){let known=['awaiting-approval','completed','rejected','cancelled'];return '<p><strong>'+esc(s.total)+' total</strong> · '+known.map(k=>esc(s.statuses[k])+' '+esc(k.replaceAll('-',' '))).join(' · ')+'</p>'}
async function loadCampaigns(){try{let d=await api('/api/campaigns'),filter=q('status-filter').value;q('portfolio').innerHTML=portfolio(d.summary);let campaigns=filter==='all'?d.campaigns:d.campaigns.filter(c=>c.status===filter);if(!campaigns.length){q('campaigns').textContent=filter==='all'?'No saved campaigns yet. Create an offline draft after step 1.':'No campaigns match this status.';return}q('campaigns').innerHTML='<table><tr><th>Campaign</th><th>Status</th><th>Provider</th><th>Safe next action</th></tr>'+campaigns.map(c=>'<tr><td>'+esc(c.campaign_id)+'</td><td>'+esc(c.status)+'</td><td>'+esc(c.provider)+'</td><td class="inline">'+actions(c)+'</td></tr>').join('')+'</table>'}catch(e){q('campaigns').textContent='Could not load campaigns: '+e.message}}
function actions(c){let id=encodeURIComponent(c.campaign_id),x='<button class="secondary" onclick="inspectCampaign(\''+id+'\')">Inspect</button>';if(c.status==='awaiting-approval')return x+'<button class="warn" onclick="recordDecision(\''+id+'\',\'reject\')">Reject</button><button class="warn" onclick="recordDecision(\''+id+'\',\'cancel\')">Cancel</button>';if(c.status==='completed'&&c.report_url)return x+'<a href="'+esc(c.report_url)+'">Open report</a>';return x+' Recorded decision; create a new draft if scope changes.'}
showStep(0);loadContext();loadCampaigns()
</script></body></html>"""


def _manager_roe(path: str) -> RulesOfEngagement:
    """Load the configured RoE, including the packaged default for installed use."""
    if not Path(path).exists() and path == "examples/roe.yaml":
        path = str(files("adversaryflow.resources").joinpath("roe.yaml"))
    with Path(path).open(encoding="utf-8") as handle:
        return RulesOfEngagement.from_mapping(yaml.safe_load(handle) or {})


def _input(data: dict[str, object], name: str, limit: int = 200) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not (cleaned := value.strip()):
        raise ValueError(f"{name} must be a non-empty string")
    if len(cleaned) > limit:
        raise ValueError(f"{name} must be at most {limit} characters")
    return cleaned


def _offline_draft(campaign_root: str, roe_path: str, catalog_path: str, data: dict[str, object]) -> dict[str, object]:
    """Create only a local, offline, RoE-validated draft; never an emulation."""
    roe = _manager_roe(roe_path)
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    draft = OfflinePlanner().draft(CampaignRequest(_input(data, "actor"), _input(data, "target"), _input(data, "objective")), abilities)
    validate_ai_draft(draft, roe, abilities)
    integrity = campaign_integrity_hashes(draft, roe, abilities)
    campaign_dir = save_campaign_draft(
        draft, integrity["plan_hash"], "offline", campaign_root,
        provider_metadata={"provider": "offline", "status": "browser-offline-draft"},
        roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"],
    )
    return {"success": True, "stage": "drafted", "campaign_id": campaign_dir.name, "provider": "offline", "plan_hash": integrity["plan_hash"], "approval_required": True, "next": "Inspect the draft. Approval and emulation remain CLI-only."}


def _report_summary(metadata: dict[str, object]) -> dict[str, object]:
    """Read a local synthetic telemetry summary without trusting arbitrary paths."""
    run_dir = metadata.get("run_dir")
    if not isinstance(run_dir, str):
        return {"status": "not-available", "detail": "No completed local synthetic run is recorded yet."}
    try:
        resolved = Path(run_dir).resolve()
        resolved.relative_to(Path.cwd().resolve())
    except ValueError:
        return {"status": "not-available", "detail": "The recorded run is outside this workspace and will not be opened."}
    gap_path = resolved / "telemetry-gap-report.json"
    if not gap_path.is_file():
        return {"status": "not-available", "detail": "No telemetry-gap summary is available for this run."}
    data = json.loads(gap_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Telemetry-gap summary must be a JSON object")
    gaps = data.get("gaps", [])
    if not isinstance(gaps, list):
        gaps = []
    return {
        "status": "available",
        "behavior_success": bool(data.get("behavior_success")),
        "telemetry_expected": data.get("telemetry_expected", 0),
        "telemetry_observed": data.get("telemetry_observed", 0),
        "detection_gap_count": data.get("detection_gap_count", len(gaps)),
        "gaps": [item for item in gaps[:10] if isinstance(item, dict)],
        "assessment": str(data.get("assessment", "Review the local report before planning a retest.")),
    }


def _decision_timeline(campaign_dir: str, metadata: dict[str, object]) -> list[dict[str, str]]:
    """Return only known local lifecycle records in chronological display order."""
    entries = [{"event": "Draft created", "at": str(metadata.get("created_at", "Unknown time")), "detail": "A reviewable campaign draft was saved locally."}]
    root = Path(campaign_dir)
    records = (
        ("approval.json", "Approval recorded", "approved_at", "approver", "decision"),
        ("rejection.json", "Rejection recorded", "rejected_at", "approver", "reason"),
        ("cancellation.json", "Cancellation recorded", "cancelled_at", "", "reason"),
    )
    for filename, event, timestamp, actor_key, detail_key in records:
        path = root / filename
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        actor = f" by {data[actor_key]}" if actor_key and data.get(actor_key) else ""
        detail = str(data.get(detail_key, "Recorded local lifecycle decision."))
        entries.append({"event": event + actor, "at": str(data.get(timestamp, "Unknown time")), "detail": detail})
    return sorted(entries, key=lambda entry: entry["at"])


def _portfolio_summary(campaigns: list[dict[str, object]]) -> dict[str, object]:
    """Return small, read-only lifecycle counts for the manager landing page."""
    counts = {"awaiting-approval": 0, "completed": 0, "rejected": 0, "cancelled": 0, "other": 0}
    for campaign in campaigns:
        status = campaign.get("status")
        if status in counts:
            counts[status] += 1
        else:
            counts["other"] += 1
    return {"total": len(campaigns), "statuses": counts}


def _manager_context(roe_path: str, catalog_path: str) -> dict[str, object]:
    """Expose only the local safety context needed to prepare a browser draft."""
    roe = _manager_roe(roe_path)
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    return {
        "mode": "offline-only",
        "roe": {
            "engagement_name": roe.engagement_name,
            "environment": roe.environment,
            "approved_targets": list(roe.approved_targets),
            "excluded_targets": list(roe.excluded_targets),
            "allowed_actions": list(roe.allowed_actions),
        },
        "catalog": {"ability_count": len(abilities), "technique_count": len({ability.technique_id for ability in abilities})},
    }


def _approval_readiness(status: str, draft, roe: RulesOfEngagement, abilities: list[object], integrity: dict[str, str]) -> dict[str, object]:
    """Explain readiness without granting approval or changing campaign state."""
    checks = [
        {"label": "Campaign is awaiting an approval decision", "passed": status == "awaiting-approval"},
        {"label": "Saved draft, RoE, and catalog integrity are verified", "passed": integrity["status"] == "verified"},
        {"label": "Target remains RoE-approved", "passed": roe.allows(draft.target)},
        {"label": "At least one safe catalog ability is selected", "passed": bool(abilities)},
    ]
    ready = all(check["passed"] for check in checks)
    return {
        "ready": ready,
        "checks": checks,
        "next": "The named RoE approver may use the CLI approval command after confirming schedule and scope." if ready else "Do not approve. Resolve the failed checks or create a new reviewed draft.",
    }


def _terminal_value(value: str) -> str:
    """Quote a displayed CLI argument without preserving command metacharacters."""
    return '"' + value.replace('"', "") + '"'


def _terminal_next_step(campaign_id: str, status: str, readiness: dict[str, object], approver: str) -> dict[str, str]:
    """Offer a copyable CLI instruction; the browser never invokes it."""
    inspect = f"adversaryflow campaign inspect --campaign-id {campaign_id}"
    if status == "awaiting-approval" and readiness["ready"]:
        return {"label": "Copy CLI approval command", "command": f"adversaryflow campaign --campaign-id {campaign_id} --approve --approver {_terminal_value(approver)}", "detail": "Copy this command only after the named RoE approver confirms schedule and scope."}
    if status == "awaiting-approval":
        return {"label": "Copy CLI inspection command", "command": inspect, "detail": "Review the campaign again after resolving the failed readiness checks."}
    return {"label": "Copy CLI inspection command", "command": inspect, "detail": "This is a read-only inspection command; create a new draft if scope needs to change."}


def _campaign_detail(campaign_root: str, campaign_id: str, roe_path: str, catalog_path: str) -> dict[str, object]:
    """Return a human-readable, read-only review summary for one saved campaign."""
    campaign = inspect_campaign(campaign_root, campaign_id)
    draft, metadata = load_campaign_draft(campaign["campaign_dir"])
    roe = _manager_roe(roe_path)
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    current_hashes = campaign_integrity_hashes(draft, roe, abilities)
    matches = [metadata.get(key) == value for key, value in current_hashes.items()]
    if all(matches):
        integrity = {"status": "verified", "detail": "Saved plan, RoE, and safe ability catalog match the current review inputs."}
    elif any(key not in metadata for key in current_hashes):
        integrity = {"status": "unavailable", "detail": "This older draft has incomplete integrity metadata; create a new draft before approval."}
    else:
        integrity = {"status": "review-required", "detail": "The saved plan, RoE, or ability catalog changed. Do not approve; create a new reviewed draft."}
    selected = [ability for ability in abilities if ability.id in draft.ability_ids]
    status = str(metadata.get("status", "unknown"))
    next_action = {
        "awaiting-approval": "Verify this summary, confirm the schedule, then use the CLI approval command only if the RoE approver authorizes it.",
        "completed": "Open the report, review detection gaps, and create a new focused draft for any retest.",
        "rejected": "The rejection is recorded. Create a new draft only if scope or scheduling changes.",
        "cancelled": "The cancellation is recorded. Inspect the reason and create a new draft if work should resume.",
    }.get(status, "Inspect the recorded campaign state before taking any further action.")
    report = Path(campaign["campaign_dir"]) / "campaign-report.html"
    readiness = _approval_readiness(status, draft, roe, selected, integrity)
    campaign["detail"] = {
        "scope": {"target": draft.target, "objective": draft.objective, "risk_level": draft.risk_level},
        "roe": {"environment": roe.environment, "approver_name": roe.approver_name, "approved_targets": list(roe.approved_targets), "excluded_targets": list(roe.excluded_targets), "allowed_actions": list(roe.allowed_actions)},
        "integrity": integrity,
        "abilities": [{"id": ability.id, "name": ability.name, "technique_id": ability.technique_id, "network_scope": ability.network_scope, "telemetry_count": len(ability.expected_telemetry)} for ability in selected],
        "stop_conditions": list(draft.stop_conditions),
        "next_action": next_action,
        "report_url": f"/api/campaigns/{campaign_id}/report" if report.is_file() else None,
        "report_review": "A report is available for review." if report.is_file() else "No report exists until a CLI-authorized local synthetic emulation completes.",
        "report_summary": _report_summary(metadata),
        "decision_timeline": _decision_timeline(campaign["campaign_dir"], metadata),
        "approval_readiness": readiness,
        "terminal_next": _terminal_next_step(campaign_id, status, readiness, roe.approver_name),
    }
    return campaign


def make_handler(campaign_root: str, roe_path: str = "examples/roe.yaml", catalog_path: str = "content/abilities/catalog.json"):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: object, content_type: str = "application/json") -> None:
            body = payload.encode() if isinstance(payload, str) else json.dumps(payload, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, object]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Content-Length must be an integer") from exc
            if length <= 0 or length > 4096:
                raise ValueError("JSON request body must be between 1 and 4096 bytes")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("JSON request body must be an object")
            return payload

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/": self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/api/health": self._send(200, {"ok": True, "mode": "local-guided-manager"})
            elif path == "/api/context": self._send(200, _manager_context(roe_path, catalog_path))
            elif path == "/api/campaigns":
                campaigns = list_campaigns(campaign_root)
                for campaign in campaigns:
                    report = Path(campaign_root) / campaign["campaign_id"] / "campaign-report.html"
                    campaign["report_url"] = f"/api/campaigns/{campaign['campaign_id']}/report" if report.exists() else None
                self._send(200, {"campaigns": campaigns, "summary": _portfolio_summary(campaigns)})
            elif path.startswith("/api/campaigns/"):
                try:
                    parts = path.split("/"); campaign_id = parts[3]
                    if len(parts) == 5 and parts[4] == "report":
                        report = Path(inspect_campaign(campaign_root, campaign_id)["campaign_dir"]) / "campaign-report.html"
                        if not report.is_file(): raise FileNotFoundError(f"Campaign report not found: {campaign_id}")
                        self._send(200, report.read_text(encoding="utf-8"), "text/html; charset=utf-8")
                    elif len(parts) == 4: self._send(200, _campaign_detail(campaign_root, campaign_id, roe_path, catalog_path))
                    else: self._send(404, {"error": "not found"})
                except (OSError, ValueError) as exc: self._send(404, {"error": str(exc)})
            else: self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                if path == "/api/doctor": self._send(200, run_doctor())
                elif path == "/api/campaigns": self._send(201, _offline_draft(campaign_root, roe_path, catalog_path, self._body()))
                elif path.startswith("/api/campaigns/"):
                    parts = path.split("/")
                    if len(parts) != 5 or parts[4] not in {"reject", "cancel"}: self._send(404, {"error": "not found"}); return
                    data = self._body(); campaign_id = parts[3]; reason = _input(data, "reason")
                    if parts[4] == "reject":
                        approver = _input(data, "approver")
                        if approver != _manager_roe(roe_path).approver_name: raise PermissionError("Only the RoE approver can record a rejection")
                        record = reject_campaign(campaign_root, campaign_id, approver, reason); status = "rejected"
                    else: record = cancel_campaign(campaign_root, campaign_id, reason); status = "cancelled"
                    self._send(200, {"success": True, "status": status, "record": str(record)})
                else: self._send(404, {"error": "not found"})
            except PermissionError as exc: self._send(403, {"error": str(exc)})
            except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc: self._send(400, {"error": str(exc)})

        def log_message(self, *_args) -> None: return
    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787, campaign_root: str = "artifacts/campaigns", open_browser: bool = False, roe_path: str = "examples/roe.yaml", catalog_path: str = "content/abilities/catalog.json") -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}: raise ValueError("Manager must bind to loopback only")
    server = ThreadingHTTPServer((host, port), make_handler(campaign_root, roe_path, catalog_path))
    url = f"http://{host}:{server.server_port}"; print(f"AdversaryFlow Campaign Guide listening on {url}")
    if open_browser: threading.Timer(0.2, webbrowser.open, args=(url,)).start()
    server.serve_forever()
