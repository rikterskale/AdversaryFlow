"""Loopback-only, simulation-only campaign manager and JSON API."""

import json
import threading
import webbrowser
from importlib.resources import files
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from .ai import CampaignRequest, OfflinePlanner, validate_ai_draft
from .doctor import run_doctor
from .support import create_support_bundle
from .provider import OpenAICompatiblePlanner, ProviderError, load_provider_config, provider_setup_instructions, validate_provider_config
from .profiles import activation_summary, allow_profile, list_profiles, policy_summary, remove_profile, save_profile, use_profile
from .intel import fetch_attack_bundle, find_technique
from .planner import build_plan
from .audit import AuditLog
from .emulation import default_catalog_path, load_catalog
from .adapters import adapter_readiness
from .lifecycle import cancel_campaign, inspect_campaign, list_campaigns, reject_campaign, reset_campaign
from .models import RulesOfEngagement
from .workflow import approve_draft, build_gap_report, campaign_integrity_hashes, load_campaign_draft, run_local_emulation, save_campaign_draft, verify_campaign_integrity
from .reports import write_campaign_reports
from .campaign_service import complete_saved_campaign
from .product_tools import export_executive_summary, read_roe_editor, save_roe_editor, search_campaign_archive, update_campaign_archive, update_campaign_tags
from .ctid import assess_fixture_evidence, create_fixture_bundle, fixtures as ctid_fixtures
from .actor_profiles import get_profile as get_actor_profile, list_profiles as list_actor_profiles, plan_profile as plan_actor_profile, run_profile as run_actor_profile, save_profile as save_actor_profile


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AdversaryFlow Campaign Guide</title><style>
:root{color-scheme:dark;--bg:#08111f;--panel:#112239;--line:#31516e;--text:#edf5fc;--muted:#b8c9db;--accent:#62d4e8;--safe:#8de0ac;--warn:#f3cb72}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#143a61 0,var(--bg) 40%);color:var(--text);font:16px/1.5 system-ui,sans-serif}main{max-width:1060px;margin:auto;padding:42px 20px 80px}h1{font-size:clamp(2.2rem,5vw,3.6rem);line-height:1.05;margin:.2rem 0}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:.78rem}.lede,.muted{color:var(--muted)}.notice,.card{background:linear-gradient(145deg,#142940,#0e1b2d);border:1px solid var(--line);border-radius:16px;padding:22px;margin-top:20px}.notice{border-color:#277291}.journey{display:grid;grid-template-columns:repeat(5,1fr);gap:9px;margin-top:24px}.step{margin:0;padding:13px;background:var(--panel);border:1px solid var(--line);border-radius:10px;color:var(--text);font:inherit;text-align:left;cursor:pointer}.step:hover,.step[aria-current="step"]{border-color:var(--accent);background:#123552}.step b{display:block;color:var(--accent);font-size:.8rem}.step span{display:block;font-weight:750;margin:4px 0}.step small{color:var(--muted)}.checklist{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 0}.check{padding:6px 10px;border:1px solid var(--line);border-radius:99px;color:var(--muted)}.check.done{border-color:var(--safe);color:var(--safe)}.layout{display:grid;grid-template-columns:1fr 1fr;gap:22px}.next{border-left:4px solid var(--safe);padding:12px 14px;background:#112f29;border-radius:0 8px 8px 0}code,pre{display:block;white-space:pre-wrap;overflow:auto;background:#07111e;padding:13px;border-radius:8px;color:#d9f4fa}button{margin:12px 8px 0 0;padding:11px 15px;background:var(--accent);border:0;border-radius:8px;color:#06212a;font:700 15px system-ui;cursor:pointer}button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent)}button.warn{background:transparent;color:var(--warn);border:1px solid var(--warn)}button:disabled{opacity:.45;cursor:not-allowed}label{display:block;margin-top:12px;font-weight:650}input,select{width:100%;margin-top:4px;padding:11px;background:#07111e;color:var(--text);border:1px solid #41647f;border-radius:8px;font:inherit}details{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-weight:650}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:10px 7px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}a{color:var(--accent)}.inline button{margin-top:4px;padding:6px 9px;font-size:.8rem}@media(max-width:760px){main{padding-top:28px}.journey,.layout{grid-template-columns:1fr}.step{min-height:auto}table{display:block;overflow:auto}}
</style></head><body><main>
<p class="eyebrow">Local-only campaign workspace</p><h1>Start a safe campaign in five clear steps.</h1><p class="lede">Follow one step at a time. This guide can run an allowlisted health check and create an offline draft. It never contacts an external target, creates an exploit, or bypasses approval.</p><div class="notice"><strong>Boundary:</strong> browser actions are limited to local drafts, inspection, rejection, and cancellation. The named RoE approver—not this page—authorizes local synthetic emulation in the CLI.</div>
<nav class="journey" aria-label="Campaign walkthrough"><button class="step" onclick="showStep(0)"><b>Step 1</b><span>Check</span><small>Verify setup.</small></button><button class="step" onclick="showStep(1)"><b>Step 2</b><span>Draft</span><small>Save offline plan.</small></button><button class="step" onclick="showStep(2)"><b>Step 3</b><span>Review</span><small>Inspect scope.</small></button><button class="step" onclick="showStep(3)"><b>Step 4</b><span>Approve</span><small>Use CLI.</small></button><button class="step" onclick="showStep(4)"><b>Step 5</b><span>Learn</span><small>Review report.</small></button></nav>
<section class="notice"><strong>Your setup checklist</strong><p class="muted">Saved in this browser only. Completed items help you resume without repeating setup.</p><div class="checklist" id="setup-checklist" aria-live="polite"></div></section>
<section class="card" id="walkthrough" aria-live="polite"><p class="eyebrow" id="guide-count">Guided walkthrough · step 1 of 5</p><h2 id="guide-title">Check your setup</h2><p id="guide-detail">Confirm the local environment, RoE, and safe ability catalog are healthy.</p><code id="guide-command">adversaryflow doctor --json</code><p class="next" id="guide-next"><strong>Do this now:</strong> Run the health check. Continue only after it passes.</p><button id="run-safe-check" onclick="runDoctor()">Run health check here</button><button class="secondary" id="guide-back" onclick="moveStep(-1)">Back</button><button id="guide-forward" onclick="moveStep(1)">Next: create a draft</button><div class="notice" id="safe-result" hidden></div></section>
<section class="card" id="draft-helper"><h2>Create a reviewable offline draft</h2><p class="muted">This stores a locally generated, RoE-validated plan for review. It does not use a hosted provider and does not run an emulation.</p><p id="draft-context" class="notice">Loading the local RoE scope and safe catalog…</p><div class="layout"><div><label>Threat actor<input id="actor" value="APT29" maxlength="200" oninput="updateDraftPreview()"></label><label>Defensive objective<input id="objective" value="validate endpoint process visibility" maxlength="200" oninput="updateDraftPreview()"></label><label>RoE-approved target<select id="target" disabled onchange="updateDraftPreview()"><option>Loading approved targets…</option></select></label><p class="muted">Targets come from the active local RoE; the server validates scope again before saving.</p><button id="create-draft" onclick="createDraft()" disabled>Create safe offline draft</button><button class="secondary" id="create-example" onclick="createSafeExample()" disabled>Create safe example draft</button><button class="secondary" onclick="copyCommand()">Copy equivalent CLI command</button></div><div><h3 id="draft-heading">Before you save</h3><pre id="command">Waiting for the active local RoE before a draft can be prepared.</pre><p class="next" id="command-next"><strong>This action creates:</strong> a local, offline review draft. It will not contact a target, run a command, use a hosted provider, approve a campaign, or start emulation.</p></div></div></section>
<section class="card"><h2>Saved campaigns</h2><p class="muted">Inspect every plan before scheduling. You may record a rejection or cancellation here; the manager cannot approve or execute a campaign.</p><button onclick="loadCampaigns()">Refresh campaign list</button><label>Show status<select id="status-filter" onchange="loadCampaigns()"><option value="all">All campaigns</option><option value="awaiting-approval">Awaiting approval</option><option value="completed">Completed</option><option value="rejected">Rejected</option><option value="cancelled">Cancelled</option></select></label><div id="portfolio" class="muted">Loading local campaign summary…</div><div id="campaigns" class="muted">Loading local campaigns…</div><div id="campaign-detail" hidden></div></section>
<section class="card"><h2>What happens after review?</h2><div class="layout"><div><h3>Approve only when scheduled</h3><code>adversaryflow campaign --campaign-id campaign-... --approve --approver &lt;RoE-approver&gt;</code><p class="muted">The CLI verifies the draft, RoE, and ability catalog integrity before local synthetic emulation.</p></div><div><h3>Learn and retest</h3><p class="muted">Open a completed report, use detection gaps to define a new objective, and draft a new campaign instead of modifying an approved one.</p></div></div></section>
<section class="card"><h2>Common questions</h2><details><summary>My setup is not ready.</summary><p>Run <code>adversaryflow doctor --fix --json</code>. It only creates local artifact folders, then explains remaining problems.</p></details><details><summary>My provider is unavailable.</summary><p>The browser draft flow is always offline. For CLI help, run <code>adversaryflow provider diagnose</code> and use <code>--fallback-offline</code> for a safe rehearsal.</p></details><details><summary>I prefer the terminal.</summary><p>Run <code>adversaryflow guide --interactive</code> for the same step-by-step workflow.</p></details></section>
</main><script>
function q(id){return document.getElementById(id)}function esc(v){let d=document.createElement('div');d.textContent=String(v??'');return d.innerHTML}async function api(path,options={}){let r=await fetch(path,options),d=await r.json();if(!r.ok)throw new Error(d.error||'Request failed');return d}
const steps=[['Check your setup','Confirm the local environment, RoE, and safe ability catalog are healthy.','adversaryflow doctor --json','Run the health check. Continue only after it passes.','Next: create a draft'],['Create a reviewable offline draft','Describe a defensive objective and an RoE-approved target. This saves an offline plan for review; it does not run an emulation.','Use the draft helper below.','Create the local draft, then inspect its scope and selected abilities.','Next: review the draft'],['Review the saved plan','Inspect the campaign record for scope, selected abilities, telemetry, assumptions, and stop conditions.','Use Inspect in Saved campaigns.','Reject or cancel an inappropriate draft; do not edit an approval-bound plan.','Next: obtain approval'],['Obtain explicit approval','Only the approver named in the RoE can authorize local synthetic emulation. This action is deliberately CLI-only.','adversaryflow campaign --campaign-id campaign-... --approve --approver <RoE-approver>','Confirm schedule and scope, then use the CLI approval command.','Next: learn from results'],['Learn and retest','Open a completed report, review detection gaps, and create a focused new draft for any retest.','Open report in Saved campaigns.','Do not modify an approved campaign. Use its report to define a new defensive objective.','Finish walkthrough']];let currentStep=0;
const checklistItems=[['scope','Scope loaded'],['health','Health check passed'],['draft','Draft saved'],['review','Campaign reviewed']];function checklist(){let done=JSON.parse(localStorage.getItem('adversaryflow-setup')||'{}');q('setup-checklist').innerHTML=checklistItems.map(([id,label])=>'<span class="check '+(done[id]?'done':'')+'">'+(done[id]?'✓ ':'○ ')+label+'</span>').join('')}function complete(id){let done=JSON.parse(localStorage.getItem('adversaryflow-setup')||'{}');done[id]=true;localStorage.setItem('adversaryflow-setup',JSON.stringify(done));checklist()}
function showStep(index){currentStep=Math.max(0,Math.min(steps.length-1,index));let s=steps[currentStep];q('guide-count').textContent='Guided walkthrough · step '+(currentStep+1)+' of 5';q('guide-title').textContent=s[0];q('guide-detail').textContent=s[1];q('guide-command').textContent=s[2];q('guide-next').innerHTML='<strong>Do this now:</strong> '+s[3];q('guide-back').disabled=currentStep===0;q('guide-forward').textContent=s[4];q('run-safe-check').hidden=currentStep!==0;document.querySelectorAll('.step').forEach((el,i)=>el.setAttribute('aria-current',i===currentStep?'step':'false'))}function moveStep(delta){showStep(currentStep+delta)}
function copyDoctorFix(command){navigator.clipboard.writeText(command);q('safe-result').insertAdjacentHTML('beforeend','<p class="muted">Copied: '+esc(command)+'</p>')}function doctorSummary(result){if(result.passed)return '<strong>Setup is ready.</strong><p class="muted">Your local safety checks passed. You can continue to create an offline draft.</p>';let fixes=result.guided_fixes||[];if(!fixes.length)return '<strong>Setup needs attention.</strong><p>Run <code>adversaryflow doctor --json</code> in your terminal for details.</p>';return '<strong>Setup needs attention.</strong><p>Work through these steps, then run the check again.</p><ol>'+fixes.map(f=>'<li><strong>'+esc(f.check)+':</strong> '+esc(f.problem)+'<br><code>'+esc(f.fix)+'</code><button class="secondary" onclick="copyDoctorFix(this.previousElementSibling.textContent)">Copy fix</button></li>').join('')+'</ol>'}async function runDoctor(){let b=q('run-safe-check'),o=q('safe-result');b.disabled=true;b.textContent='Checking…';try{let result=await api('/api/doctor',{method:'POST'});o.hidden=false;o.innerHTML=doctorSummary(result);b.textContent=result.passed?'Health check passed':'Health check needs attention';if(result.passed)complete('health');q('guide-next').innerHTML=result.passed?'<strong>Ready:</strong> Your local checks passed. Continue to create a draft.':'<strong>Pause:</strong> Use the copyable fix above, then run the check again.'}catch(e){o.hidden=false;o.textContent='Health check could not run: '+e.message+' Try adversaryflow doctor --json in your terminal.';b.textContent='Try health check again'}finally{b.disabled=false}}
function updateDraftPreview(){let target=q('target'),actor=q('actor').value.trim(),objective=q('objective').value.trim(),targetReady=!target.disabled&&Boolean(target.value),ready=targetReady&&Boolean(actor)&&Boolean(objective);q('create-draft').disabled=!ready;q('create-example').disabled=!targetReady;if(ready){q('draft-heading').textContent='Ready to create a local review draft';q('command').textContent='Target: '+target.value+'\\nActor: '+actor+'\\nObjective: '+objective;q('command-next').innerHTML='<strong>This action creates:</strong> one RoE-validated offline draft for review. It will not contact '+esc(target.value)+', run a command, use a hosted provider, approve a campaign, or start emulation.'}}
function createSafeExample(){createDraft({actor:'APT29',objective:'review a safe local telemetry example'})}
async function createDraft(example=null){let b=example?q('create-example'):q('create-draft'),payload={actor:q('actor').value,objective:q('objective').value,target:q('target').value};if(example)Object.assign(payload,example);b.disabled=true;b.textContent=example?'Creating safe example…':'Creating local draft…';try{let result=await api('/api/campaigns',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});complete('draft');q('draft-heading').textContent='Draft '+result.campaign_id+' is ready for review';q('command').textContent=JSON.stringify(result,null,2);q('command-next').innerHTML=example?'<strong>Example ready:</strong> Your form entries are unchanged. Inspect this RoE-validated example; browser approval and emulation are unavailable by design.':'<strong>Next:</strong> Inspect this RoE-validated offline draft below. Browser approval and emulation are unavailable by design.';showStep(2);await loadCampaigns()}catch(e){q('command').textContent='Draft was not created: '+e.message;q('command-next').innerHTML='<strong>Pause:</strong> Correct the input or RoE configuration, then try again.'}finally{b.textContent=example?'Create safe example draft':'Create safe offline draft';updateDraftPreview()}}
function copyCommand(){let text='adversaryflow campaign --actor "'+q('actor').value.replaceAll('"','')+'" --target "'+q('target').value.replaceAll('"','')+'" --objective "'+q('objective').value.replaceAll('"','')+'" --fallback-offline';navigator.clipboard.writeText(text);q('command').textContent=text;q('command-next').innerHTML='<strong>Copied:</strong> This CLI command creates a draft only; review it before approval.'}
async function loadContext(){try{let d=await api('/api/context'),r=d.roe,target=q('target');target.innerHTML=r.approved_targets.map(value=>'<option value="'+esc(value)+'">'+esc(value)+'</option>').join('');target.disabled=!r.approved_targets.length;complete('scope');q('draft-context').innerHTML='<strong>Current local scope:</strong> '+esc(r.engagement_name)+' · environment '+esc(r.environment)+' · approved targets '+pills(r.approved_targets)+' · '+esc(d.catalog.ability_count)+' safe catalog abilities. Browser drafts are '+esc(d.mode)+'.';updateDraftPreview()}catch(e){q('target').disabled=true;q('draft-context').textContent='Could not load local RoE context: '+e.message;updateDraftPreview()}}
function pills(items){return items.length?items.map(x=>'<span style="display:inline-block;padding:2px 8px;margin:3px;border:1px solid #31516e;border-radius:99px;font-size:.85rem">'+esc(x)+'</span>').join(''):'<span class="muted">None recorded</span>'}
function reportSummary(s){if(s.status!=='available')return '<p class="muted">'+esc(s.detail)+'</p>';let gaps=s.gaps.length?s.gaps.map(g=>'<li>'+esc(g.category)+': '+esc(g.description)+'</li>').join(''):'<li>No required telemetry gaps reported.</li>';return '<p><strong>Behavior:</strong> '+(s.behavior_success?'completed':'needs review')+'<br><strong>Telemetry:</strong> '+esc(s.telemetry_observed)+' observed of '+esc(s.telemetry_expected)+' expected<br><strong>Detection gaps:</strong> '+esc(s.detection_gap_count)+'</p><p class="muted">'+esc(s.assessment)+'</p><details><summary>Detection-gap findings</summary><ul>'+gaps+'</ul></details>'}
function timeline(items){return '<ol>'+items.map(i=>'<li><strong>'+esc(i.event)+'</strong><br><span class="muted">'+esc(i.at)+' · '+esc(i.detail)+'</span></li>').join('')+'</ol>'}
function readiness(r){return '<p style="color:'+(r.ready?'#8de0ac':'#f3cb72')+'"><strong>'+(r.ready?'Ready for CLI approval review':'Not ready for approval')+'</strong></p><ul>'+r.checks.map(c=>'<li>'+esc(c.passed?'Pass: ':'Needs attention: ')+esc(c.label)+'</li>').join('')+'</ul><p class="muted">'+esc(r.next)+'</p>'}
function plainReview(x){let actions=x.abilities.map(a=>esc(a.name)).join(', ')||'No reviewed abilities';return '<section class="card"><h3>Plain-language safety summary</h3><p><strong>What will happen:</strong> If the named RoE approver later uses the CLI approval command, AdversaryFlow will run these reviewed local simulations: '+actions+'.</p><p><strong>What will not happen:</strong> This draft cannot run an operator-supplied command, contact an external target, use a hosted provider, or bypass approval.</p><p><strong>Why it is permitted:</strong> The target is in the local RoE, the draft and catalog integrity are verified, and execution remains local synthetic simulation only.</p></section>'}
function copyTerminalNext(){navigator.clipboard.writeText(q('terminal-next-command').textContent);q('terminal-next-note').textContent='Copied. Paste this into your terminal when the stated safety conditions are met.'}
function renderDetail(d){let x=d.detail,verified=x.integrity.status==='verified',color=verified?'#8de0ac':x.integrity.status==='review-required'?'#f3cb72':'#ff9d9d',report=x.report_url?'<a href="'+esc(x.report_url)+'">Open report</a>':'';q('campaign-detail').innerHTML='<p class="eyebrow">Campaign review</p><h2>'+esc(d.metadata.campaign_id)+'</h2><p class="next" style="border-left-color:'+color+'"><strong>Next:</strong> '+esc(x.next_action)+'</p>'+plainReview(x)+'<div class="layout"><section class="card"><h3>Scope</h3><p><strong>Target:</strong> '+esc(x.scope.target)+'<br><strong>Objective:</strong> '+esc(x.scope.objective)+'<br><strong>Risk:</strong> '+esc(x.scope.risk_level)+'<br><strong>Mode:</strong> local synthetic simulation only</p></section><section class="card"><h3>Integrity</h3><p style="color:'+color+'"><strong>'+esc(x.integrity.status.replaceAll('-',' '))+'</strong></p><p class="muted">'+esc(x.integrity.detail)+'</p></section><section class="card"><h3>Rules of Engagement</h3><p><strong>Environment:</strong> '+esc(x.roe.environment)+'<br><strong>Approver:</strong> '+esc(x.roe.approver_name)+'<br><strong>Approved targets:</strong><br>'+pills(x.roe.approved_targets)+'</p></section><section class="card"><h3>Selected safe abilities</h3><p>'+x.abilities.map(a=>'<strong>'+esc(a.id)+'</strong> · '+esc(a.name)+'<br><span class="muted">'+esc(a.technique_id)+' · '+esc(a.network_scope)+' · '+esc(a.telemetry_count)+' expected telemetry signals</span>').join('<hr>')+'</p></section><section class="card"><h3>Stop conditions</h3><p>'+pills(x.stop_conditions)+'</p></section><section class="card"><h3>Report review</h3><p>'+esc(x.report_review)+' '+report+'</p>'+reportSummary(x.report_summary)+'</section></div><section class="card"><h3>Approval readiness</h3>'+readiness(x.approval_readiness)+'</section><section class="card"><h3>'+esc(x.terminal_next.label)+'</h3><code id="terminal-next-command">'+esc(x.terminal_next.command)+'</code><p id="terminal-next-note" class="muted">'+esc(x.terminal_next.detail)+'</p><button class="secondary" onclick="copyTerminalNext()">Copy command</button></section><section class="card"><h3>Decision timeline</h3>'+timeline(x.decision_timeline)+'</section><details><summary>Show raw campaign record</summary><pre>'+esc(JSON.stringify(d,null,2))+'</pre></details>'}
async function inspectCampaign(id){try{let d=await api('/api/campaigns/'+encodeURIComponent(id));complete('review');q('campaign-detail').hidden=false;renderDetail(d);q('campaign-detail').scrollIntoView({behavior:'smooth',block:'nearest'})}catch(e){alert('Could not inspect campaign: '+e.message)}}
async function recordDecision(id,action){let reason=prompt(action==='reject'?'Why should this draft be rejected?':'Why should this draft be cancelled?');if(!reason)return;let body={reason};if(action==='reject'){body.approver=prompt('Enter the RoE approver name to record this rejection:')||'';if(!body.approver)return}if(!confirm('Record this '+action+' decision for '+id+'? This does not execute any campaign.'))return;try{await api('/api/campaigns/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await loadCampaigns();await inspectCampaign(id)}catch(e){alert('Could not record decision: '+e.message)}}
function statusLabel(status){return ({'awaiting-approval':'Needs approval','completed':'Complete','rejected':'Rejected','cancelled':'Cancelled'})[status]||status.replaceAll('-',' ')}function portfolio(s){let known=['awaiting-approval','completed','rejected','cancelled'];return '<p><strong>'+esc(s.total)+' total</strong> · '+known.map(k=>esc(s.statuses[k])+' '+esc(statusLabel(k))).join(' · ')+'</p>'}
async function loadCampaigns(){try{let d=await api('/api/campaigns'),filter=q('status-filter').value;q('portfolio').innerHTML=portfolio(d.summary);let campaigns=filter==='all'?d.campaigns:d.campaigns.filter(c=>c.status===filter);if(!campaigns.length){q('campaigns').textContent=filter==='all'?'No saved campaigns yet. Create an offline draft after step 1.':'No campaigns match this status.';return}q('campaigns').innerHTML='<table><tr><th>Campaign</th><th>Status</th><th>Provider</th><th>Safe next action</th></tr>'+campaigns.map(c=>'<tr><td>'+esc(c.campaign_id)+'</td><td>'+esc(statusLabel(c.status))+'</td><td>'+esc(c.provider)+'</td><td class="inline">'+actions(c)+'</td></tr>').join('')+'</table>'}catch(e){q('campaigns').textContent='Could not load campaigns: '+e.message}}
function actions(c){let id=encodeURIComponent(c.campaign_id),x='<button class="secondary" onclick="inspectCampaign(&quot;'+id+'&quot;)">Inspect</button>';if(c.status==='awaiting-approval')return x+'<button class="warn" onclick="recordDecision(&quot;'+id+'&quot;,&quot;reject&quot;)">Reject</button><button class="warn" onclick="recordDecision(&quot;'+id+'&quot;,&quot;cancel&quot;)">Cancel</button>';if(c.status==='completed'&&c.report_url)return x+'<a href="'+esc(c.report_url)+'">Open report</a>';return x+' Recorded decision; create a new draft if scope changes.'}
checklist();showStep(0);loadContext();loadCampaigns()
</script><script>
document.querySelector('.lede').textContent='Follow one step at a time. This guide checks local readiness, creates reviewed drafts, and lets the named RoE approver run the fixed local-synthetic workflow after explicit confirmation.';
document.querySelector('.notice').innerHTML='<strong>Boundary:</strong> browser actions remain local and use only the reviewed fixed local-synthetic adapter. Approval requires the named RoE approver, typed campaign-specific confirmation, and integrity verification.';
steps[3]=['Obtain explicit approval','The RoE-named approver can authorize the reviewed local synthetic emulation here after every readiness check passes.','Inspect the campaign and use the approval panel.','Enter the named approver and the campaign-specific confirmation, then approve and run.','Next: learn from results'];showStep(currentStep);
function approvalPanel(d){let x=d.detail;if(d.metadata.status!=='awaiting-approval')return '';let disabled=x.approval_readiness.ready?'':' disabled';return '<section class="card"><h3>Approve and run local synthetic emulation</h3><p class="muted">This is available only to the RoE-named approver after every readiness check passes. It runs the fixed local-synthetic adapter; it cannot execute operator-supplied commands or contact an external target.</p><label>RoE approver<input id="gui-approver" value="'+esc(x.roe.approver_name)+'" maxlength="200"></label><label>Type APPROVE '+esc(d.metadata.campaign_id)+' to confirm<input id="gui-confirmation" autocomplete="off" maxlength="300" placeholder="APPROVE '+esc(d.metadata.campaign_id)+'"></label><button id="approve-run"'+disabled+' onclick="approveCampaign(&quot;'+esc(d.metadata.campaign_id)+'&quot;)">Approve and run local simulation</button><p id="approval-result" class="muted"></p></section>'}
async function approveCampaign(id){let button=q('approve-run'),result=q('approval-result');if(!confirm('Approve '+id+' and start its reviewed local synthetic emulation?'))return;button.disabled=true;result.textContent='Validating reviewed inputs and starting local synthetic emulation…';try{let response=await api('/api/campaigns/'+encodeURIComponent(id)+'/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({approver:q('gui-approver').value,confirmation:q('gui-confirmation').value})});result.textContent='Completed. Local run: '+response.run_dir;showStep(4);await loadCampaigns();await inspectCampaign(id)}catch(e){result.textContent='Approval or emulation did not complete: '+e.message;button.disabled=false}}
async function inspectCampaign(id){try{let d=await api('/api/campaigns/'+encodeURIComponent(id));complete('review');q('campaign-detail').hidden=false;renderDetail(d);q('campaign-detail').insertAdjacentHTML('beforeend',approvalPanel(d));q('campaign-detail').scrollIntoView({behavior:'smooth',block:'nearest'})}catch(e){alert('Could not inspect campaign: '+e.message)}}
document.querySelector('main').insertAdjacentHTML('beforeend','<section class="card"><h2>Provider setup and diagnostics</h2><p class="muted">Profiles contain only endpoint, model, and credential-variable names. Set the credential in your shell or secret manager; the browser never receives or saves it.</p><button onclick="providerRefresh()">Refresh provider readiness</button><pre id="provider-status">Loading provider readiness…</pre><details><summary>Create or update an approved provider profile</summary><label>Profile name<input id="profile-name" maxlength="64" placeholder="team-provider"></label><label>HTTPS endpoint<input id="profile-endpoint" maxlength="500" placeholder="https://provider.example/v1"></label><label>Model<input id="profile-model" maxlength="200" placeholder="model-name"></label><label>Credential environment variable<input id="profile-credential" maxlength="100" value="ADVERSARYFLOW_API_KEY"></label><button onclick="saveProviderProfile()">Save non-secret profile</button></details><label>Profile name to activate or allow<input id="profile-action-name" maxlength="64" placeholder="team-provider"></label><button class="secondary" onclick="useProviderProfile()">Activate profile</button><button class="secondary" onclick="allowProviderProfile()">Allow exact endpoint and model</button><p id="provider-result" class="muted"></p></section><section class="card"><h2>MITRE ATT&CK dry-run planner</h2><p class="muted">Fetches the official HTTPS ATT&CK bundle and produces a simulation-only plan. It does not create a campaign or execute anything.</p><label>Threat actor<input id="plan-actor" value="APT29" maxlength="200"></label><label>RoE-approved target<input id="plan-target" value="local-lab" maxlength="200"></label><label>ATT&CK technique ID<input id="plan-technique" value="T1059" maxlength="32"></label><button onclick="createMitrePlan()">Create dry-run plan</button><pre id="plan-result">No plan requested.</pre></section><section class="card"><h2>Support bundle</h2><p class="muted">Creates a redacted local diagnostics ZIP under artifacts/support for troubleshooting.</p><button class="secondary" onclick="createSupportBundle()">Create redacted support bundle</button><p id="support-result" class="muted"></p></section>');
async function providerRefresh(){try{let d=await api('/api/provider');q('provider-status').textContent=JSON.stringify(d,null,2)}catch(e){q('provider-status').textContent='Provider status could not be loaded: '+e.message}}
async function saveProviderProfile(){let result=q('provider-result');try{let d=await api('/api/provider/profiles',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:q('profile-name').value,endpoint:q('profile-endpoint').value,model:q('profile-model').value,credential_env:q('profile-credential').value})});result.textContent='Saved profile '+d.saved+'. Set its credential outside the browser, then activate and allow it.';providerRefresh()}catch(e){result.textContent='Profile was not saved: '+e.message}}
async function useProviderProfile(){let result=q('provider-result');try{let d=await api('/api/provider/use',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:q('profile-action-name').value})});result.textContent='Active profile: '+d.active+'. '+d.activation.next;providerRefresh()}catch(e){result.textContent='Profile was not activated: '+e.message}}
async function allowProviderProfile(){let result=q('provider-result');try{let d=await api('/api/provider/allow',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:q('profile-action-name').value})});result.textContent='Allowed exact settings for '+d.allowed+'.';providerRefresh()}catch(e){result.textContent='Profile was not allowed: '+e.message}}
async function createMitrePlan(){let out=q('plan-result');out.textContent='Fetching official ATT&CK data and creating a dry-run plan…';try{let d=await api('/api/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor:q('plan-actor').value,target:q('plan-target').value,technique:q('plan-technique').value})});out.textContent=JSON.stringify(d,null,2)}catch(e){out.textContent='Plan was not created: '+e.message}}
async function createSupportBundle(){let out=q('support-result');out.textContent='Creating redacted local diagnostics bundle…';try{let d=await api('/api/support-bundle',{method:'POST'});out.textContent='Created: '+d.bundle}catch(e){out.textContent='Support bundle was not created: '+e.message}}
document.querySelector('main').insertAdjacentHTML('beforeend','<section class="card"><h2>Operator controls</h2><p class="muted">Read-only readiness data is shown below. A provider test sends exactly one harmless planning request only after you confirm it.</p><button onclick="operatorReadiness()">Refresh RoE, capabilities, and adapter status</button><pre id="operator-readiness">Loading operator readiness…</pre><h3>Test active hosted provider</h3><p class="muted">This sends one planning request to the active approved provider. It does not save, approve, or execute a campaign.</p><label>Actor<input id="provider-test-actor" value="APT29" maxlength="200"></label><label>Target<input id="provider-test-target" value="local-lab" maxlength="200"></label><label>Objective<input id="provider-test-objective" value="validate endpoint process visibility" maxlength="200"></label><button class="secondary" onclick="testProvider()">Test hosted provider once</button><pre id="provider-test-result">No provider test sent.</pre></section>');
document.querySelector('main').insertAdjacentHTML('beforeend','<section class="card"><h2>Draft with the active provider</h2><p class="muted">Creates one RoE-validated review draft using the active provider. This can send a planning request, but it never approves or runs a campaign.</p><label>Threat actor<input id="hosted-draft-actor" value="APT29" maxlength="200"></label><label>RoE-approved target<input id="hosted-draft-target" value="local-lab" maxlength="200"></label><label>Defensive objective<input id="hosted-draft-objective" value="validate endpoint process visibility" maxlength="200"></label><label>Platform<select id="hosted-draft-platform"><option value="linux">Linux</option><option value="windows">Windows</option><option value="macos">macOS</option></select></label><label><input id="hosted-draft-fallback" type="checkbox" style="width:auto"> Fall back to an offline draft if the provider fails</label><button onclick="createProviderDraft()">Create provider-backed review draft</button><pre id="hosted-draft-result">No provider-backed draft created.</pre></section>');
document.querySelector('main').insertAdjacentHTML('beforeend','<section class="card"><h2>Local synthetic demo</h2><p class="muted">Runs the fixed local-synthetic demo with the RoE approver recorded automatically, just like the CLI demo command. It never contacts an external target and does not save a campaign draft.</p><label>Threat actor<input id="demo-actor" value="APT29" maxlength="200"></label><label>Defensive objective<input id="demo-objective" value="validate endpoint process visibility" maxlength="200"></label><label>Type RUN LOCAL DEMO to confirm<input id="demo-confirmation" maxlength="100" placeholder="RUN LOCAL DEMO"></label><button onclick="runDemo()">Run local synthetic demo</button><pre id="demo-result">No demo run.</pre></section>');
async function operatorReadiness(){try{let d=await api('/api/operator-readiness');q('operator-readiness').textContent=JSON.stringify(d,null,2)}catch(e){q('operator-readiness').textContent='Readiness could not be loaded: '+e.message}}
async function testProvider(){let out=q('provider-test-result');if(!confirm('Send one harmless planning request to the active hosted provider?'))return;out.textContent='Sending one planning request…';try{let d=await api('/api/provider/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor:q('provider-test-actor').value,target:q('provider-test-target').value,objective:q('provider-test-objective').value})});out.textContent=JSON.stringify(d,null,2)}catch(e){out.textContent='Provider test did not complete: '+e.message}}
async function createProviderDraft(){let out=q('hosted-draft-result');if(!confirm('Create a review draft using the active provider? This may send a planning request but cannot approve or execute a campaign.'))return;out.textContent='Creating review draft…';try{let d=await api('/api/campaigns/provider',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor:q('hosted-draft-actor').value,target:q('hosted-draft-target').value,objective:q('hosted-draft-objective').value,platform:q('hosted-draft-platform').value,fallback_offline:q('hosted-draft-fallback').checked})});out.textContent=JSON.stringify(d,null,2);await loadCampaigns();await inspectCampaign(d.campaign_id)}catch(e){out.textContent='Draft was not created: '+e.message}}
async function removeProviderProfile(){let name=q('profile-action-name').value.trim(),result=q('provider-result');if(!name)return;let confirmation=prompt('Type REMOVE '+name+' to remove this non-secret provider profile:')||'';if(!confirmation)return;try{let d=await api('/api/provider/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,confirmation})});result.textContent='Removed profile '+d.removed+'.';providerRefresh()}catch(e){result.textContent='Profile was not removed: '+e.message}}
async function runDemo(){let out=q('demo-result');if(!confirm('Run the fixed local synthetic demo now?'))return;out.textContent='Running local synthetic demo…';try{let d=await api('/api/demo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor:q('demo-actor').value,objective:q('demo-objective').value,confirmation:q('demo-confirmation').value})});out.textContent=JSON.stringify(d,null,2)}catch(e){out.textContent='Demo did not complete: '+e.message}}
async function resetCampaign(id){let confirmation=prompt('Type RESET '+id+' to permanently delete this saved campaign and its local records:')||'';if(!confirmation)return;try{await api('/api/campaigns/'+encodeURIComponent(id)+'/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})});q('campaign-detail').hidden=true;await loadCampaigns()}catch(e){alert('Campaign was not reset: '+e.message)}}
function resetPanel(id){return '<section class="card"><h3>Remove saved campaign</h3><p class="muted">This permanently deletes this campaign directory and its review records. Type the campaign-specific reset confirmation when prompted.</p><button class="warn" onclick="resetCampaign(&quot;'+esc(id)+'&quot;)">Reset saved campaign</button></section>'}
async function inspectCampaign(id){try{let d=await api('/api/campaigns/'+encodeURIComponent(id));complete('review');q('campaign-detail').hidden=false;renderDetail(d);q('campaign-detail').insertAdjacentHTML('beforeend',approvalPanel(d)+resetPanel(id));q('campaign-detail').scrollIntoView({behavior:'smooth',block:'nearest'})}catch(e){alert('Could not inspect campaign: '+e.message)}}
q('profile-action-name').insertAdjacentHTML('afterend','<button class="warn" onclick="removeProviderProfile()">Remove profile</button>');
operatorReadiness();
providerRefresh();
</script></body></html>"""

# The browser workspace is packaged as static assets rather than assembled from
# Python string literals. Keep the API server as the only dynamic boundary.
PAGE = files("adversaryflow.resources").joinpath("manager.html").read_text(encoding="utf-8")


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
    return {"success": True, "stage": "drafted", "campaign_id": campaign_dir.name, "provider": "offline", "plan_hash": integrity["plan_hash"], "approval_required": True, "next": "Inspect the draft, then obtain explicit RoE approval before local synthetic emulation."}


def _provider_draft(campaign_root: str, roe_path: str, catalog_path: str, data: dict[str, object]) -> dict[str, object]:
    """Create a reviewable draft with the active provider, optionally falling back offline."""
    roe = _manager_roe(roe_path)
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    request = CampaignRequest(_input(data, "actor"), _input(data, "target"), _input(data, "objective"), _input(data, "platform", 32))
    fallback_offline = data.get("fallback_offline") is True
    config = load_provider_config()
    provider_name = config.name
    try:
        if config.name == "offline":
            draft = OfflinePlanner().draft(request, abilities)
            provider_metadata = {"provider": "offline", "status": "offline"}
        elif config.name == "openai-compatible":
            planner = OpenAICompatiblePlanner(config)
            draft = planner.draft(request, abilities)
            provider_metadata = planner.last_request_metadata
            if config.profile_name:
                provider_metadata = {**provider_metadata, "profile": config.profile_name, "policy_version": policy_summary().get("version")}
        else:
            raise ProviderError(f"Unsupported provider '{config.name}'.")
        validate_ai_draft(draft, roe, abilities)
    except (ProviderError, ValueError) as exc:
        if not fallback_offline or config.name == "offline":
            raise ValueError(f"Provider draft could not be created: {exc}") from exc
        draft = OfflinePlanner().draft(request, abilities)
        validate_ai_draft(draft, roe, abilities)
        provider_name = "offline-fallback"
        provider_metadata = {"provider": config.name, "status": "fallback-offline", "error": str(exc)}
    integrity = campaign_integrity_hashes(draft, roe, abilities)
    campaign_dir = save_campaign_draft(draft, integrity["plan_hash"], provider_name, campaign_root, provider_metadata=provider_metadata, roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"])
    return {"success": True, "stage": "drafted", "campaign_id": campaign_dir.name, "provider": provider_name, "plan_hash": integrity["plan_hash"], "approval_required": True, "next": "Inspect the draft before any approval decision."}


def _provider_status() -> dict[str, object]:
    """Return only non-secret provider readiness data for the local UI."""
    config = load_provider_config()
    return {"configuration": config.as_dict(), "valid": not validate_provider_config(config), "errors": validate_provider_config(config), "profiles": list_profiles(), "activation": activation_summary(), "policy": policy_summary(), "setup": provider_setup_instructions()}


def _provider_compatibility() -> dict[str, object]:
    """Explain whether a provider can be tested without exposing a credential."""
    status = _provider_status(); config = status["configuration"]
    checks = [
        {"label": "An active provider profile is selected", "passed": config["provider"] == "openai-compatible"},
        {"label": "The endpoint uses HTTPS", "passed": not config["endpoint"] or str(config["endpoint"]).startswith("https://")},
        {"label": "A credential variable is configured in the local environment", "passed": bool(config["credential_configured"])},
        {"label": "The exact provider settings are policy-approved", "passed": not status["errors"]},
    ]
    return {"checks": checks, "ready": all(check["passed"] for check in checks), "next": "Run the one-request compatibility test." if all(check["passed"] for check in checks) else "Complete the failed setup steps; no request has been sent."}


def _learning_context(catalog_path: str, technique_id: str = "") -> dict[str, object]:
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    chosen = technique_id.strip().upper()
    abilities = [ability for ability in load_catalog(catalog_path) if not chosen or ability.technique_id == chosen or ability.technique_id.startswith(chosen + ".")]
    return {"technique": chosen or "all reviewed techniques", "abilities": [{"id": ability.id, "name": ability.name, "technique_id": ability.technique_id, "simulation_action": ability.simulation_action, "network_scope": ability.network_scope, "expected_telemetry": [item.description for item in ability.expected_telemetry], "interpretation": "Confirm each listed synthetic signal is present, then use any gap to define a narrower retest."} for ability in abilities], "boundary": "Reviewed abilities are local synthetic simulations only; they do not provide remote execution or target contact."}


def _detection_mappings(catalog_path: str, technique_id: str = "") -> dict[str, object]:
    learning = _learning_context(catalog_path, technique_id)
    mappings = [{"technique_id": ability["technique_id"], "ability": ability["name"], "telemetry": ability["expected_telemetry"], "recommendation": "Create or tune a detection rule for the listed synthetic telemetry, then rerun this local simulation and compare the report.", "rule_formats": ["Sigma concept", "SIEM correlation", "EDR analytic"]} for ability in learning["abilities"]]
    return {"mappings": mappings, "notice": "Recommendations are defensive validation guidance. Review platform-specific fields before implementing a detection rule."}


def _save_provider_profile(data: dict[str, object]) -> dict[str, object]:
    name = _input(data, "name", 64)
    path = save_profile(name, "openai-compatible", _input(data, "endpoint", 500), _input(data, "model", 200), _input(data, "credential_env", 100))
    return {"success": True, "saved": name, "file": str(path), "profiles": list_profiles(), "activation": activation_summary()}


def _use_provider_profile(data: dict[str, object]) -> dict[str, object]:
    name = _input(data, "name", 64)
    path = use_profile(name)
    return {"success": True, "active": name, "file": str(path), "activation": activation_summary(), "policy": policy_summary()}


def _allow_provider_profile(data: dict[str, object]) -> dict[str, object]:
    name = _input(data, "name", 64)
    path = allow_profile(name)
    return {"success": True, "allowed": name, "file": str(path), "policy": policy_summary()}


def _remove_provider_profile(data: dict[str, object]) -> dict[str, object]:
    name = _input(data, "name", 64)
    if _input(data, "confirmation", 100) != f"REMOVE {name}":
        raise PermissionError(f"Type 'REMOVE {name}' to remove this non-secret provider profile")
    remove_profile(name)
    return {"success": True, "removed": name, "profiles": list_profiles(), "activation": activation_summary()}


def _mitre_plan(roe_path: str, data: dict[str, object]) -> dict[str, object]:
    """Fetch the official ATT&CK bundle and create a dry-run plan only."""
    actor, target, technique_id = _input(data, "actor"), _input(data, "target"), _input(data, "technique", 32).upper()
    AuditLog("artifacts/audit.jsonl").record("plan_requested", actor=actor, target=target, technique=technique_id)
    technique = find_technique(fetch_attack_bundle(), technique_id)
    if not technique:
        raise ValueError(f"Technique not found in MITRE ATT&CK source: {technique_id}")
    plan = build_plan(_manager_roe(roe_path), actor, target, technique, "MITRE ATT&CK Enterprise STIX")
    return {"notice": "DRY RUN ONLY", "plan": {"actor": plan.actor, "target": plan.target, "source": plan.source, "steps": [step.__dict__ for step in plan.steps]}}


def _provider_test(roe_path: str, catalog_path: str, data: dict[str, object]) -> dict[str, object]:
    """Send the single harmless planning request exposed by the CLI provider test."""
    config = load_provider_config()
    if config.name != "openai-compatible":
        raise ValueError("Provider test requires an active openai-compatible profile.")
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    request = CampaignRequest(_input(data, "actor"), _input(data, "target"), _input(data, "objective"))
    try:
        draft = OpenAICompatiblePlanner(config).draft(request, abilities)
        validate_ai_draft(draft, _manager_roe(roe_path), abilities)
    except (ProviderError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    return {"success": True, "stage": "draft-validated", "draft": draft.as_dict(), "notice": "This sent one planning request only. No campaign was saved, approved, or executed."}


def _operator_readiness(roe_path: str, catalog_path: str) -> dict[str, object]:
    """Combine read-only RoE, capability, and adapter information for the operator UI."""
    context = _manager_context(roe_path, catalog_path)
    active_catalog = catalog_path if Path(catalog_path).exists() or catalog_path != "content/abilities/catalog.json" else str(default_catalog_path())
    capabilities = json.loads(files("adversaryflow.resources").joinpath("capabilities.json").read_text(encoding="utf-8"))
    return {"roe": context["roe"], "capabilities": capabilities, "adapter": adapter_readiness(load_catalog(active_catalog))}


def _reset_saved_campaign(campaign_root: str, campaign_id: str, data: dict[str, object]) -> dict[str, object]:
    if _input(data, "confirmation", 300) != f"RESET {campaign_id}":
        raise PermissionError(f"Type 'RESET {campaign_id}' to permanently remove this saved campaign")
    reset_campaign(campaign_root, campaign_id, True)
    return {"success": True, "status": "reset", "campaign_id": campaign_id}


def _run_demo(roe_path: str, catalog_path: str, data: dict[str, object]) -> dict[str, object]:
    """Run the same explicit, fixed local-synthetic demo available from the CLI."""
    if _input(data, "confirmation", 100) != "RUN LOCAL DEMO":
        raise PermissionError("Type 'RUN LOCAL DEMO' to start the local synthetic demonstration")
    roe = _manager_roe(roe_path)
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    draft = OfflinePlanner().draft(CampaignRequest(_input(data, "actor"), "local-lab", _input(data, "objective"), "linux"), abilities)
    validate_ai_draft(draft, roe, abilities)
    plan_hash = campaign_integrity_hashes(draft, roe, abilities)["plan_hash"]
    approval = approve_draft(draft, roe, abilities, roe.approver_name, plan_hash)
    run_dir = run_local_emulation(draft, abilities, approval, "artifacts/runs")
    return {"success": True, "stage": "completed", "draft": draft.as_dict(), "approval": approval.__dict__, "run_dir": str(run_dir), "telemetry_gap_report": build_gap_report(run_dir), "notice": "Local synthetic demo complete. No campaign draft was saved."}


def _approve_and_run(campaign_root: str, roe_path: str, catalog_path: str, campaign_id: str, data: dict[str, object]) -> dict[str, object]:
    """Approve and run one reviewed campaign through the fixed local-synthetic adapter."""
    approver = _input(data, "approver")
    confirmation = _input(data, "confirmation")
    if confirmation != f"APPROVE {campaign_id}":
        raise PermissionError(f"Type 'APPROVE {campaign_id}' to confirm approval and local synthetic emulation")
    roe = _manager_roe(roe_path)
    if not Path(catalog_path).exists() and catalog_path == "content/abilities/catalog.json":
        catalog_path = str(default_catalog_path())
    abilities = load_catalog(catalog_path)
    return {"success": True, **complete_saved_campaign(campaign_root, campaign_id, roe, abilities, approver, "artifacts/runs")}


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
        "next": "The named RoE approver may approve and run this reviewed local synthetic workflow after confirming schedule and scope." if ready else "Do not approve. Resolve the failed checks or create a new reviewed draft.",
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
        "awaiting-approval": "Verify this summary, confirm the schedule, then the RoE approver may approve and run the reviewed local synthetic workflow.",
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
        "report_review": "A report is available for review." if report.is_file() else "No report exists until a RoE-approved local synthetic emulation completes.",
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
            parsed = urlparse(self.path); path = parsed.path; query = parse_qs(parsed.query)
            if path == "/": self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/assets/manager.css": self._send(200, files("adversaryflow.resources").joinpath("manager.css").read_text(encoding="utf-8"), "text/css; charset=utf-8")
            elif path == "/assets/manager.js": self._send(200, files("adversaryflow.resources").joinpath("manager.js").read_text(encoding="utf-8"), "application/javascript; charset=utf-8")
            elif path == "/api/health": self._send(200, {"ok": True, "mode": "local-guided-manager"})
            elif path == "/api/context": self._send(200, _manager_context(roe_path, catalog_path))
            elif path == "/api/provider": self._send(200, _provider_status())
            elif path == "/api/provider/compatibility": self._send(200, _provider_compatibility())
            elif path == "/api/operator-readiness": self._send(200, _operator_readiness(roe_path, catalog_path))
            elif path == "/api/learning": self._send(200, _learning_context(catalog_path, query.get("technique", [""])[0]))
            elif path == "/api/detection-mappings": self._send(200, _detection_mappings(catalog_path, query.get("technique", [""])[0]))
            elif path == "/api/ctid-fixtures": self._send(200, ctid_fixtures())
            elif path == "/api/actor-profiles": self._send(200, {"profiles": list_actor_profiles()})
            elif path.startswith("/api/actor-profiles/"):
                name = path.removeprefix("/api/actor-profiles/")
                if path.endswith("/plan"): self._send(200, plan_actor_profile(name.removesuffix("/plan")))
                else: self._send(200, get_actor_profile(name))
            elif path == "/api/archive": self._send(200, {"campaigns": search_campaign_archive(campaign_root, query.get("q", [""])[0], query.get("tag", [""])[0])})
            elif path == "/api/roe": self._send(200, read_roe_editor(roe_path))
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
                elif path == "/api/doctor/fix": self._send(200, run_doctor(fix=True))
                elif path == "/api/support-bundle": self._send(201, {"success": True, "bundle": str(create_support_bundle("artifacts/support", roe_path))})
                elif path == "/api/demo": self._send(200, _run_demo(roe_path, catalog_path, self._body()))
                elif path == "/api/plan": self._send(200, _mitre_plan(roe_path, self._body()))
                elif path == "/api/provider/profiles": self._send(201, _save_provider_profile(self._body()))
                elif path == "/api/provider/use": self._send(200, _use_provider_profile(self._body()))
                elif path == "/api/provider/allow": self._send(200, _allow_provider_profile(self._body()))
                elif path == "/api/provider/remove": self._send(200, _remove_provider_profile(self._body()))
                elif path == "/api/provider/test": self._send(200, _provider_test(roe_path, catalog_path, self._body()))
                elif path == "/api/roe":
                    data = self._body()
                    self._send(200, save_roe_editor(roe_path, data, _input(data, "editor", 100)))
                elif path == "/api/archive/tags":
                    data = self._body()
                    self._send(200, update_campaign_tags(campaign_root, _input(data, "campaign_id", 100), data.get("tags", [])))
                elif path == "/api/archive/controls":
                    data = self._body()
                    self._send(200, update_campaign_archive(campaign_root, _input(data, "campaign_id", 100), _input(data, "owner", 100), data.get("retention_days")))
                elif path == "/api/exports/executive-summary":
                    data = self._body()
                    self._send(201, export_executive_summary(campaign_root, _input(data, "campaign_id", 100)))
                elif path == "/api/ctid-fixtures":
                    data = self._body()
                    retest_of = data.get("retest_of")
                    if retest_of is not None and (not isinstance(retest_of, str) or len(retest_of) > 100): raise ValueError("retest_of must be a short run ID")
                    self._send(201, create_fixture_bundle(retest_of=retest_of))
                elif path == "/api/ctid-fixtures/assess":
                    data = self._body(); observed = data.get("observed_fixture_ids", [])
                    if not isinstance(observed, list) or not all(isinstance(item, str) and len(item) <= 100 for item in observed): raise ValueError("observed_fixture_ids must be a list of fixture IDs")
                    self._send(200, assess_fixture_evidence(_input(data, "bundle", 1000), observed))
                elif path == "/api/actor-profiles": self._send(201, save_actor_profile(self._body()))
                elif path.startswith("/api/actor-profiles/") and path.endswith("/run"):
                    data = self._body(); name = path.removeprefix("/api/actor-profiles/").removesuffix("/run").rstrip("/")
                    retest_of = data.get("retest_of")
                    if retest_of is not None and (not isinstance(retest_of, str) or len(retest_of) > 100): raise ValueError("retest_of must be a short run ID")
                    self._send(201, run_actor_profile(name, retest_of))
                elif path == "/api/campaigns/provider": self._send(201, _provider_draft(campaign_root, roe_path, catalog_path, self._body()))
                elif path == "/api/campaigns": self._send(201, _offline_draft(campaign_root, roe_path, catalog_path, self._body()))
                elif path.startswith("/api/campaigns/"):
                    parts = path.split("/")
                    if len(parts) != 5 or parts[4] not in {"approve", "reject", "cancel", "reset"}: self._send(404, {"error": "not found"}); return
                    data = self._body(); campaign_id = parts[3]
                    if parts[4] == "approve":
                        self._send(200, _approve_and_run(campaign_root, roe_path, catalog_path, campaign_id, data))
                        return
                    elif parts[4] == "reset":
                        self._send(200, _reset_saved_campaign(campaign_root, campaign_id, data))
                        return
                    elif parts[4] == "reject":
                        reason = _input(data, "reason")
                        approver = _input(data, "approver")
                        if approver != _manager_roe(roe_path).approver_name: raise PermissionError("Only the RoE approver can record a rejection")
                        record = reject_campaign(campaign_root, campaign_id, approver, reason); status = "rejected"
                    else:
                        reason = _input(data, "reason")
                        record = cancel_campaign(campaign_root, campaign_id, reason); status = "cancelled"
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
