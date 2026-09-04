/* ============================================================
   AdversaryFlow — guided wizard controller
   ============================================================ */

const PRE_TACTICS = ["reconnaissance", "resource-development"];

const TACTIC_META = {
  "reconnaissance": "Researching the target from the outside.",
  "resource-development": "Building or acquiring adversary infrastructure.",
  "initial-access": "Getting the first foothold in the environment.",
  "execution": "Running adversary-controlled code.",
  "persistence": "Keeping access across reboots and logoffs.",
  "privilege-escalation": "Gaining higher-level permissions.",
  "stealth": "Avoiding detection while operating.",
  "defense-impairment": "Weakening or disabling defenses.",
  "defense-evasion": "Avoiding detection and defenses.",
  "credential-access": "Stealing account names and secrets.",
  "discovery": "Learning about the environment.",
  "lateral-movement": "Moving through the environment.",
  "collection": "Gathering data of interest.",
  "command-and-control": "Communicating with compromised systems.",
  "exfiltration": "Stealing data out of the network.",
  "impact": "Manipulating, interrupting, or destroying systems/data.",
};
// Authoritative kill-chain order is taken from the workflow response
// (workflow.kill_chain); this is only the initial default for step 2 chips.
let TACTIC_ORDER = Object.keys(TACTIC_META);
function killChainOrder() {
  return (state.workflow && state.workflow.kill_chain)
    ? state.workflow.kill_chain.map(k => k.tactic) : TACTIC_ORDER;
}
function tacticTitle(tactic) {
  if (state.workflow && state.workflow.kill_chain) {
    const k = state.workflow.kill_chain.find(x => x.tactic === tactic);
    if (k) return k.title;
  }
  return titleCase(tactic);
}

const FEATURED = ["G0016", "G0032", "G0007", "G0046", "G1017", "G0096", "G0008", "G1006"];

const state = {
  actors: [], filtered: [], selectedId: null, selectedActor: null,
  workflow: null,
  domains: ["enterprise"], dataVersion: "unknown",
  scope: { cmdPlatform: "windows", tactics: new Set(TACTIC_ORDER), includePre: true, curatedOnly: false, allowNetwork: false, allowAdmin: false, allowHighRisk: false },
  run: new Set(),
  records: {},
  recordContext: { operator: "", target: "" },
  csrf: "",
  apiToken: sessionStorage.getItem("af_api_token") || "",
  step: 0, stage: 0, maxStep: 0,
  typeFilter: "all", sort: "name",
};

const el = (id) => document.getElementById(id);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/* ---------- tactic color across the kill chain ---------- */
function tacticColor(tactic) {
  const order = killChainOrder();
  const i = Math.max(0, order.indexOf(tactic));
  const hue = 250 - (i / Math.max(1, order.length - 1)) * 250; // indigo -> red
  return `hsl(${Math.round(hue)}, 70%, 62%)`;
}
function titleCase(t) { return (t || "").split("-").map(w => w[0].toUpperCase() + w.slice(1)).join(" "); }

/* ============================================================
   BOOT
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  boot();

  el("startBtn").addEventListener("click", () => goTo(1));
  el("brandHome").addEventListener("click", restart);
  el("refreshBtn").addEventListener("click", refreshFeed);
  el("backBtn").addEventListener("click", () => goTo(state.step - 1));
  el("nextBtn").addEventListener("click", onNext);
  el("restartBtn").addEventListener("click", restart);
  el("importPlan").addEventListener("change", importPlan);

  // Stepper
  $$("#stepper .stepper__item").forEach(b =>
    b.addEventListener("click", () => { const t = +b.dataset.goto; if (!b.disabled) goTo(t); }));

  // Step 1 controls
  el("actorSearch").addEventListener("input", onSearch);
  el("searchClear").addEventListener("click", () => { el("actorSearch").value = ""; onSearch(); el("actorSearch").focus(); });
  $$("#typeFilter .segmented__btn").forEach(b =>
    b.addEventListener("click", () => { state.typeFilter = b.dataset.type; setOn("#typeFilter", b); applyFilter(); }));
  $$("#domainFilter .segmented__btn").forEach(b =>
    b.addEventListener("click", () => toggleDomain(b.dataset.domain)));
  el("sortSel").addEventListener("change", e => { state.sort = e.target.value; applyFilter(); });

  // Step 2 controls
  $$("#cmdPlatform .segmented__btn").forEach(b =>
    b.addEventListener("click", () => {
      state.scope.cmdPlatform = b.dataset.plat;
      setOn("#cmdPlatform", b);
      loadRunState();
      renderScope();
    }));
  el("optPre").addEventListener("change", e => { state.scope.includePre = e.target.checked; syncTacticChips(); renderScope(); });
  el("optCurated").addEventListener("change", e => { state.scope.curatedOnly = e.target.checked; renderScope(); });
  el("optNetwork").addEventListener("change", e => { state.scope.allowNetwork = e.target.checked; renderScope(); });
  el("optAdmin").addEventListener("change", e => { state.scope.allowAdmin = e.target.checked; renderScope(); });
  el("optHighRisk").addEventListener("change", e => { state.scope.allowHighRisk = e.target.checked; renderScope(); });
  el("stagesAll").addEventListener("click", toggleAllStages);
  ["recordOperator", "recordTarget"].forEach(id => el(id).addEventListener("input", updateRecordContext));

  // Export
  $$("[data-export]").forEach(b => b.addEventListener("click", () => exportPlan(b.dataset.export)));

  // Keyboard: Enter advances when possible
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.target.matches("input,select,textarea,button,a") && !el("nextBtn").disabled && state.step >= 1 && state.step <= 3)
      onNext();
  });
});

async function boot() {
  showLoader("Preparing AdversaryFlow…", "Checking the local service and ATT&CK cache.");
  try {
    let session;
    try {
      session = await apiJson("/api/session");
    } catch (error) {
      if (!/bearer token/i.test(error.message || "")) throw error;
      const token = window.prompt("This AdversaryFlow service requires an API token.");
      if (!token) throw new Error("An API token is required to use this remote service");
      state.apiToken = token;
      sessionStorage.setItem("af_api_token", token);
      session = await apiJson("/api/session");
    }
    state.csrf = session.csrf_token;
    await waitForBootstrap();
    await loadActors(true);
  } catch (e) {
    showLoadFailure(e);
  } finally {
    hideLoader();
  }
}

async function waitForBootstrap() {
  let status = await fetch("/api/bootstrap", { headers: authHeaders() });
  if (status.status === 503) {
    status = await fetch("/api/bootstrap", { method: "POST", headers: csrfHeaders() });
  }
  for (;;) {
    const data = await status.json();
    if (data.runtime && data.runtime.ready) return;
    if (data.runtime && data.runtime.phase === "failed") throw new Error(data.runtime.error || "ATT&CK data could not be prepared");
    const cache = data.cache && data.cache.domains && data.cache.domains.enterprise;
    const event = cache && cache.metadata;
    const progress = event && event.bytes_received ? ` Downloaded ${(event.bytes_received / 1048576).toFixed(1)} MB${event.content_length ? ` of ${(event.content_length / 1048576).toFixed(1)} MB` : ""}.` : "";
    showLoader("Preparing MITRE ATT&CK data…", `The first run downloads and validates the enterprise bundle.${progress} You can leave this tab open.`);
    await new Promise(resolve => setTimeout(resolve, 750));
    status = await fetch("/api/bootstrap", { headers: authHeaders() });
  }
}

function authHeaders(extra = {}) {
  return state.apiToken ? { ...extra, Authorization: `Bearer ${state.apiToken}` } : { ...extra };
}
function csrfHeaders(extra = {}) { return authHeaders({ ...extra, "X-AdversaryFlow-CSRF": state.csrf }); }

function showLoadFailure(error) {
  setStatus("setup needs attention", "err");
  const grid = el("actorGrid");
  grid.innerHTML = `<div class="emptystate"><p>${escapeHtml(error.message || "Couldn't prepare ATT&CK data")}</p><button type="button" class="btn" id="retryLoad">Retry setup</button></div>`;
  const retry = el("retryLoad");
  if (retry) retry.addEventListener("click", boot);
}

/* ============================================================
   DATA
   ============================================================ */
async function loadActors(throwOnError = false) {
  setStatus("loading ATT&CK…", "");
  try {
    const data = await apiJson(`/api/actors?${domainQuery()}`);
    if (!Array.isArray(data.actors)) throw new Error("Actor response is missing its actors array");
    state.actors = data.actors;
    state.dataVersion = data.data_version || "unknown";
    renderFeatured();
    applyFilter();
    setStatus(`${data.actors.length} actors · ${state.domains.map(titleCase).join(" + ")}`, "ok");
  } catch (e) {
    setStatus("backend offline", "err");
    showLoadFailure(e);
    if (throwOnError) throw e;
  }
}
async function refreshFeed() {
  if (state.workflow && !window.confirm("Refreshing can change technique mappings and will rebuild the current plan. Continue?")) return;
  showLoader("Re-downloading the live ATT&CK STIX feed…");
  try {
    await apiJson(`/api/refresh?${domainQuery()}`, { method: "POST", headers: csrfHeaders() });
    const selected = state.selectedId;
    state.workflow = null; state.records = {}; state.run = new Set(); state.stage = 0; state.maxStep = 1;
    await loadActors(true);
    state.selectedActor = state.actors.find(actor => actor.stix_id === selected) || null;
    state.selectedId = state.selectedActor ? selected : null;
    if (state.step > 1) goTo(1);
    renderActorGrid(); updateStepper(); updateActionBar();
    toast("ATT&CK feed refreshed; the plan was rebuilt", "success");
  }
  catch (e) { setStatus("refresh failed", "err"); toast(e.message || "Refresh failed", "error"); }
  finally { hideLoader(); }
}
async function apiJson(url, options) {
  const requestOptions = { ...(options || {}), headers: authHeaders((options && options.headers) || {}) };
  const res = await fetch(url, requestOptions);
  let data;
  try { data = await res.json(); }
  catch { throw new Error(`Backend returned an unreadable response (${res.status})`); }
  if (!res.ok) throw new Error(data.message || data.error || `Request failed (${res.status})`);
  return data;
}
function domainQuery() {
  return new URLSearchParams({ domains: state.domains.join(",") }).toString();
}
function toggleDomain(domain) {
  const next = new Set(state.domains);
  if (next.has(domain)) next.delete(domain); else next.add(domain);
  if (!next.size) { toast("Keep at least one ATT&CK domain selected"); return; }
  const order = ["enterprise", "ics", "mobile"];
  state.domains = order.filter(item => next.has(item));
  $$("#domainFilter .segmented__btn").forEach(button => {
    const on = state.domains.includes(button.dataset.domain);
    button.classList.toggle("is-on", on);
    button.setAttribute("aria-pressed", String(on));
  });
  state.selectedId = null; state.selectedActor = null; state.workflow = null;
  state.run = new Set(); state.maxStep = 1; state.stage = 0;
  state.actors = []; state.filtered = []; state.dataVersion = "unknown";
  renderFeatured(); renderActorGrid(); updateStepper(); updateActionBar();
  loadActors();
}
function setStatus(text, cls) {
  const s = el("dataStatus");
  s.textContent = text;
  s.className = "chip " + (cls === "ok" ? "chip--ok" : cls === "err" ? "chip--err" : "chip--muted");
}

/* ============================================================
   NAVIGATION
   ============================================================ */
function goTo(step) {
  if (step < 0) step = 0;
  // Guards
  if (step >= 2 && !state.selectedId) { goTo(1); return; }
  if (step >= 2 && !state.workflow) { loadWorkflowThen(() => goTo(step)); return; }
  state.step = step;
  state.maxStep = Math.max(state.maxStep, step);

  $$(".screen").forEach(s => s.classList.toggle("is-active", +s.dataset.screen === step));
  el("stage").scrollTop = 0;
  updateStepper();
  updateActionBar();

  if (step === 2) renderScope();
  if (step === 3) enterPlan();
  if (step === 4) renderExport();
  requestAnimationFrame(() => {
    const heading = document.querySelector(`.screen[data-screen="${step}"] h1, .screen[data-screen="${step}"] h2`);
    if (heading) heading.focus({ preventScroll: true });
  });
}

function onNext() {
  if (state.step === 1) { if (!state.selectedId) return; goTo(2); }
  else if (state.step === 2) { if (filteredPlan().runnable === 0) return; goTo(3); }
  else if (state.step === 3) { goTo(4); }
}

function updateStepper() {
  $$("#stepper .stepper__item").forEach(item => {
    const n = +item.dataset.goto;
    item.classList.toggle("is-active", n === state.step);
    item.classList.toggle("is-done", n < state.step && state.step > 0);
    // allow jumping to any step already reached this session
    item.disabled = n > Math.max(state.maxStep, state.selectedId ? 1 : 0);
    if (n === state.step) item.setAttribute("aria-current", "step"); else item.removeAttribute("aria-current");
  });
}

function updateActionBar() {
  const bar = el("actionbar");
  if (state.step === 0) { bar.hidden = true; return; }
  bar.hidden = false;
  el("backBtn").style.visibility = state.step <= 1 ? "hidden" : "visible";
  const next = el("nextBtn");
  const ctx = el("actionbarCtx");

  if (state.step === 1) {
    next.hidden = false;
    next.disabled = !state.selectedId;
    next.innerHTML = 'Continue <svg class="icon"><use href="#i-arrow-r"/></svg>';
    ctx.innerHTML = state.selectedActor ? `Selected: <b>${escapeHtml(state.selectedActor.name)}</b>` : "Select a threat actor to continue";
  } else if (state.step === 2) {
    const p = filteredPlan();
    next.hidden = false;
    next.disabled = p.runnable === 0;
    next.innerHTML = 'Build plan <svg class="icon"><use href="#i-arrow-r"/></svg>';
    ctx.innerHTML = p.total ? `<b>${p.runnable}</b> runnable · <b>${p.unsupported}</b> unsupported across <b>${p.stages.length}</b> stages` : "No techniques in scope — enable a stage";
  } else if (state.step === 3) {
    next.hidden = false;
    next.disabled = false;
    next.innerHTML = 'Finish & export <svg class="icon"><use href="#i-arrow-r"/></svg>';
    const p = filteredPlan();
    const done = [...state.run].filter(id => p.runnableIds.has(id)).length;
    ctx.innerHTML = `<b>${done}</b> / ${p.runnable} runnable techniques marked run`;
  } else if (state.step === 4) {
    next.hidden = true;
    ctx.innerHTML = "Plan complete ✓";
  }
}

function restart() {
  state.selectedId = null; state.selectedActor = null; state.workflow = null;
  state.run = new Set();
  state.records = {};
  state.maxStep = 0; state.stage = 0;
  state.scope = { cmdPlatform: "windows", tactics: new Set(TACTIC_ORDER), includePre: true, curatedOnly: false, allowNetwork: false, allowAdmin: false, allowHighRisk: false };
  el("actorSearch").value = "";
  $$(".actorcard").forEach(c => c.classList.remove("is-selected"));
  applyFilter();
  goTo(0);
}

async function importPlan(event) {
  const file = event.target.files && event.target.files[0];
  event.target.value = "";
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) { toast("Plan file is larger than 5 MB", "error"); return; }
  try {
    const data = JSON.parse(await file.text());
    validateImportedPlan(data);
    state.domains = data.domains;
    state.selectedActor = data.actor;
    state.selectedId = data.actor.stix_id;
    state.dataVersion = data.data_version;
    state.scope = {
      cmdPlatform: data.scope.command_platform, tactics: new Set(data.scope.stages),
      includePre: data.scope.include_pre, curatedOnly: data.scope.curated_only,
      allowNetwork: data.scope.allow_network, allowAdmin: data.scope.allow_admin,
      allowHighRisk: data.scope.allow_high_risk,
    };
    state.recordContext = data.execution_context || { operator: "", target: "" };
    state.records = {};
    data.stages.forEach(stage => stage.techniques.forEach(technique => {
      state.records[technique.id] = technique.execution || { outcome: technique.run ? "passed" : "not_run" };
    }));
    state.run = new Set(Object.entries(state.records).filter(([, record]) => record.outcome !== "not_run").map(([id]) => id));
    state.workflow = {
      actor: data.actor,
      kill_chain: data.stages.map(stage => ({ tactic: stage.tactic, title: stage.title })),
      stages: data.stages.map(stage => ({ ...stage, techniques: stage.techniques.map(technique => ({
        attack_id: technique.id, name: technique.name, url: technique.url, platforms: technique.platforms,
        description: "Imported plan record", is_subtechnique: technique.id.includes("."),
        command_source: technique.command_source, commands: [normalizeImportedCommand(technique.command)], tactics: [stage.tactic],
      })) })),
      metadata: { version: data.tool_version, data_version: data.data_version, domains: data.domains },
    };
    TACTIC_ORDER = state.workflow.kill_chain.map(item => item.tactic);
    state.maxStep = 4; state.stage = 0;
    saveRunState();
    syncStaticScopeControls();
    goTo(3);
    toast("Plan imported; verify its data version before execution");
  } catch (error) {
    toast(error.message || "Plan import failed", "error");
  }
}

function validateImportedPlan(data) {
  const allowedDomains = ["enterprise", "ics", "mobile"];
  if (!data || data.schema_version !== "2.0" || !data.actor || typeof data.actor.stix_id !== "string" || typeof data.actor.technique_count !== "number") throw new Error("This is not an AdversaryFlow 2.0 plan export");
  if (!Array.isArray(data.domains) || !data.domains.length || data.domains.some(domain => !allowedDomains.includes(domain))) throw new Error("Plan contains an invalid ATT&CK domain");
  if (!data.scope || !["windows", "linux", "macos"].includes(data.scope.command_platform) || !Array.isArray(data.scope.stages) || ["allow_network", "allow_admin", "allow_high_risk"].some(key => typeof data.scope[key] !== "boolean")) throw new Error("Plan scope is invalid");
  if (!Array.isArray(data.stages) || data.stages.length > 32) throw new Error("Plan stage count is invalid");
  let techniqueCount = 0;
  data.stages.forEach(stage => {
    if (!stage || typeof stage.tactic !== "string" || !Array.isArray(stage.techniques)) throw new Error("Plan contains an invalid stage");
    techniqueCount += stage.techniques.length;
    stage.techniques.forEach(technique => {
      if (!technique || typeof technique.id !== "string" || !technique.command || typeof technique.command.command !== "string" || technique.command.command.length > 10000) throw new Error("Plan contains an invalid command record");
    });
  });
  if (techniqueCount > 2000) throw new Error("Plan contains too many technique records");
}

function normalizeImportedCommand(command) {
  return {
    platform: typeof command.platform === "string" ? command.platform : "unknown",
    command: command.command,
    note: `Imported plan — verify before use. ${command.note || ""}`,
    cleanup: typeof command.cleanup === "string" ? command.cleanup : "Review and reverse every imported command change manually.",
    risk: "high",
    side_effects: Array.isArray(command.side_effects) ? command.side_effects : ["imported_untrusted_command"],
    requires_admin: Boolean(command.requires_admin),
    requires_network: Boolean(command.requires_network),
    network_targets: Array.isArray(command.network_targets) ? command.network_targets : [],
    prerequisites: Array.isArray(command.prerequisites) ? command.prerequisites : ["Validate the command in an isolated lab"],
    expected_telemetry: typeof command.expected_telemetry === "string" ? command.expected_telemetry : "Treat imported commands as untrusted and verify relevant process, command-line, and target telemetry.",
    expected_output: typeof command.expected_output === "string" ? command.expected_output : "Varies; validate before execution.",
    timeout_seconds: Number.isInteger(command.timeout_seconds) ? command.timeout_seconds : 60,
    rollback: typeof command.rollback === "string" ? command.rollback : "Restore the target from a known-good snapshot if cleanup cannot be verified.",
    cleanup_required: command.cleanup_required !== false,
    acknowledgment_required: true,
  };
}

function syncStaticScopeControls() {
  $$("#domainFilter .segmented__btn").forEach(button => {
    const on = state.domains.includes(button.dataset.domain); button.classList.toggle("is-on", on); button.setAttribute("aria-pressed", String(on));
  });
  $$("#cmdPlatform .segmented__btn").forEach(button => {
    const on = button.dataset.plat === state.scope.cmdPlatform; button.classList.toggle("is-on", on); button.setAttribute("aria-pressed", String(on));
  });
}

/* ============================================================
   STEP 1 — ACTOR SELECTION
   ============================================================ */
function onSearch() {
  el("searchClear").hidden = !el("actorSearch").value;
  applyFilter();
}
function applyFilter() {
  const q = el("actorSearch").value.toLowerCase().trim();
  let list = state.actors.filter(a => {
    if (state.typeFilter !== "all" && a.type !== state.typeFilter) return false;
    if (!q) return true;
    return (a.name + " " + a.attack_id + " " + a.aliases.join(" ")).toLowerCase().includes(q);
  });
  list.sort(state.sort === "ttps" ? (a, b) => b.technique_count - a.technique_count : (a, b) => a.name.localeCompare(b.name));
  state.filtered = list;
  renderActorGrid();
}
function renderFeatured() {
  const wrap = el("featuredChips");
  const chips = FEATURED.map(id => state.actors.find(a => a.attack_id === id)).filter(Boolean);
  wrap.innerHTML = chips.map(a => `<button type="button" class="fchip" data-id="${a.stix_id}">${escapeHtml(a.name)}</button>`).join("");
  $$(".fchip", wrap).forEach(c => c.addEventListener("click", () => { selectActor(c.dataset.id); }));
}
function renderActorGrid() {
  const grid = el("actorGrid");
  el("actorEmpty").hidden = state.filtered.length > 0;
  grid.innerHTML = state.filtered.map(a => `
    <button type="button" class="actorcard ${state.selectedId === a.stix_id ? "is-selected" : ""}" data-id="${a.stix_id}" aria-pressed="${state.selectedId === a.stix_id}">
      <div class="actorcard__top">
        <div>
          <div class="actorcard__name">${escapeHtml(a.name)}</div>
          <div class="actorcard__id">${a.attack_id}</div>
        </div>
        <span class="tag tag--${a.type}">${a.type}</span>
      </div>
      ${a.aliases.length ? `<div class="actorcard__aka">aka ${escapeHtml(a.aliases.slice(0, 4).join(", "))}</div>` : ""}
      <div class="actorcard__desc">${escapeHtml(a.description || "No description available.")}</div>
      <div class="actorcard__foot">
        <span class="ttpcount">${a.technique_count} <span>TTPs</span></span>
        <span class="actorcard__pick">${state.selectedId === a.stix_id ? '<svg class="icon"><use href="#i-check"/></svg> Selected' : "Select"}</span>
      </div>
    </button>`).join("");
  $$(".actorcard", grid).forEach(c => c.addEventListener("click", () => selectActor(c.dataset.id)));
}
function selectActor(id) {
  const changed = state.selectedId !== id;
  state.selectedId = id;
  state.selectedActor = state.actors.find(a => a.stix_id === id);
  if (changed) { state.workflow = null; state.stage = 0; state.maxStep = 1; } // re-flow for the new actor
  renderActorGrid();
  updateStepper();
  updateActionBar();
  if (state.step === 0) goTo(1);
  // Smooth scroll the selected card into view when chosen via chip
  const card = document.querySelector(`.actorcard[data-id="${CSS.escape(id)}"]`);
  if (card && state.step === 1) card.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function loadWorkflowThen(cb) {
  showLoader(`Pulling ${state.selectedActor.name}'s TTPs from MITRE ATT&CK…`);
  try {
    const data = await apiJson(`/api/workflow/${encodeURIComponent(state.selectedId)}?${domainQuery()}`);
    if (!Array.isArray(data.stages) || !data.metadata) throw new Error("Workflow response is incomplete");
    state.workflow = data;
    state.dataVersion = data.metadata.data_version || state.dataVersion;
    TACTIC_ORDER = data.kill_chain.map(item => item.tactic);
    state.scope.tactics = new Set(TACTIC_ORDER);
    loadRunState();
    cb && cb();
  } catch (e) { toast(e.message || "Failed to build workflow"); }
  finally { hideLoader(); }
}

/* ============================================================
   SCOPE ENGINE
   ============================================================ */
function filteredPlan() {
  const wf = state.workflow;
  if (!wf) return { stages: [], total: 0, runnable: 0, unsupported: 0, curated: 0, fallback: 0, ids: new Set(), runnableIds: new Set() };
  const sc = state.scope;
  const stages = [];
  // Unique-technique accounting (a technique can serve several tactics).
  const ids = new Set(), runnableIds = new Set(), curatedIds = new Set();
  wf.stages.forEach(stage => {
    if (!sc.tactics.has(stage.tactic)) return;
    if (!sc.includePre && PRE_TACTICS.includes(stage.tactic)) return;
    const techs = [];
    stage.techniques.forEach(t => {
      if (sc.curatedOnly && t.command_source === "fallback") return;
      const selected = { ...t, _cmd: pickCommand(t, sc.cmdPlatform) };
      techs.push(selected);
      ids.add(t.attack_id);
      if (!selected._cmd.unsupported) runnableIds.add(t.attack_id);
      if (t.command_source === "curated") curatedIds.add(t.attack_id);
    });
    if (techs.length) stages.push({ ...stage, techniques: techs });
  });
  return {
    stages, total: ids.size, runnable: runnableIds.size, unsupported: ids.size - runnableIds.size,
    curated: curatedIds.size, fallback: ids.size - curatedIds.size, ids, runnableIds,
  };
}
function pickCommand(t, plat) {
  const list = t.commands || [];
  const exact = list.find(c => c.platform === plat);
  if (exact) {
    const restrictions = [];
    if (exact.requires_network && !state.scope.allowNetwork) restrictions.push("network-active commands are disabled");
    if (exact.requires_admin && !state.scope.allowAdmin) restrictions.push("administrator commands are disabled");
    if (exact.risk === "high" && !state.scope.allowHighRisk) restrictions.push("high-risk commands are disabled");
    if (!restrictions.length) return exact;
    return { ...exact, command: `Restricted by scope: ${restrictions.join("; ")}.`, note: "Enable the corresponding safety option in Scope after reviewing the risk.", unsupported: true, restricted: true };
  }
  return {
      platform: plat,
      command: `No ${titleCase(plat)} test is available for this technique.`,
      note: "Choose another platform or contribute an exact-platform test.",
      cleanup: "",
      risk: "none", side_effects: [], requires_admin: false, requires_network: false,
      network_targets: [], prerequisites: [], expected_telemetry: "", expected_output: "",
      timeout_seconds: 0, rollback: "", cleanup_required: false, acknowledgment_required: false,
      unsupported: true,
    };
}

function renderScope() {
  buildTacticGrid();
  const p = filteredPlan();
  const sc = state.scope;
  el("recordOperator").value = state.recordContext.operator;
  el("recordTarget").value = state.recordContext.target;
  el("optNetwork").checked = state.scope.allowNetwork;
  el("optAdmin").checked = state.scope.allowAdmin;
  el("optHighRisk").checked = state.scope.allowHighRisk;
  el("scopeSummary").innerHTML = `
    <h4>Plan preview</h4>
    <div class="sumrow"><span class="k">Actor</span><span class="v">${escapeHtml(state.selectedActor.name)}</span></div>
    <div class="sumrow"><span class="k">Techniques</span><span class="v big">${p.total}</span></div>
    <div class="sumrow"><span class="k">Runnable on ${titleCase(sc.cmdPlatform)}</span><span class="v">${p.runnable}</span></div>
    <div class="sumrow"><span class="k">Unsupported</span><span class="v">${p.unsupported}</span></div>
    <div class="sumrow"><span class="k">Kill-chain stages</span><span class="v">${p.stages.length}</span></div>
    <div class="sumrow"><span class="k">Command target</span><span class="v">${titleCase(sc.cmdPlatform)}</span></div>
    <div class="sumbar">
      <span class="sumbar__seg" style="width:${p.total ? p.curated / p.total * 100 : 0}%;background:var(--success)"></span>
      <span class="sumbar__seg" style="width:${p.total ? p.fallback / p.total * 100 : 0}%;background:var(--warn)"></span>
    </div>
    <div class="sumrow" style="border:0"><span class="k" style="color:var(--success)">${p.curated} curated</span><span class="k" style="color:var(--warn)">${p.fallback} fallback</span></div>`;
  updateActionBar();
}
function buildTacticGrid() {
  const grid = el("tacticGrid");
  const wf = state.workflow;
  const present = wf.stages.map(s => s.tactic);
  grid.innerHTML = killChainOrder().filter(t => present.includes(t)).map(t => {
    const stage = wf.stages.find(s => s.tactic === t);
    const on = state.scope.tactics.has(t);
    const disabled = !state.scope.includePre && PRE_TACTICS.includes(t);
    return `<button type="button" class="tacticchip ${on && !disabled ? "is-on" : "is-off"}" data-tactic="${t}" aria-pressed="${on && !disabled}" ${disabled ? "disabled" : ""}>
      <span class="tacticchip__dot" style="background:${tacticColor(t)}"></span>
      <span class="tacticchip__name">${escapeHtml(tacticTitle(t))}</span>
      <span class="tacticchip__n">${stage.techniques.length}</span>
      <span class="tacticchip__check"><svg class="icon"><use href="#i-check"/></svg></span>
    </button>`;
  }).join("");
  $$(".tacticchip", grid).forEach(c => c.addEventListener("click", () => {
    const t = c.dataset.tactic;
    if (state.scope.tactics.has(t)) state.scope.tactics.delete(t); else state.scope.tactics.add(t);
    renderScope();
  }));
}
function syncTacticChips() { /* re-render handled by renderScope */ }
function toggleAllStages() {
  const present = state.workflow.stages.map(s => s.tactic)
    .filter(t => state.scope.includePre || !PRE_TACTICS.includes(t));
  const allOn = present.every(t => state.scope.tactics.has(t));
  present.forEach(t => allOn ? state.scope.tactics.delete(t) : state.scope.tactics.add(t));
  el("stagesAll").textContent = allOn ? "Select all" : "Clear all";
  renderScope();
}

/* ---------- small utilities ---------- */
function setOn(sel, btn) {
  $$(`${sel} .segmented__btn`).forEach(b => {
    const on = b === btn;
    b.classList.toggle("is-on", on);
    b.setAttribute("aria-pressed", String(on));
  });
}
function escapeHtml(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
function stripMd(s) { return String(s || "").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/<[^>]+>/g, ""); }
function runbookSafe(s) { return String(s || "").replace(/[\r\n&|<>^]+/g, " ").trim(); }
function toast(msg, kind = "success") { const t = el("toast"); t.innerHTML = `<svg class="icon"><use href="#${kind === "error" ? "i-x" : "i-check"}"/></svg>${escapeHtml(msg)}`; t.hidden = false; requestAnimationFrame(() => t.classList.add("is-show")); clearTimeout(t._t); t._t = setTimeout(() => { t.classList.remove("is-show"); t.hidden = true; }, 2600); }
function showLoader(txt, detail = "") { el("loaderText").textContent = txt || "Working…"; el("loaderDetail").textContent = detail; el("loader").hidden = false; }
function hideLoader() { el("loader").hidden = true; }
function updateRecordContext() {
  state.recordContext.operator = el("recordOperator").value.trim();
  state.recordContext.target = el("recordTarget").value.trim();
  saveRunState();
}

/* ============================================================
   STEP 3 — GUIDED PLAN RUN-THROUGH
   ============================================================ */
function runKey() {
  const identity = [state.selectedId || "", state.domains.join("+"), state.dataVersion, state.scope.cmdPlatform].join("|");
  return "af_run_v3_" + encodeURIComponent(identity);
}
function loadRunState() {
  try {
    const stored = JSON.parse(localStorage.getItem(runKey()) || "{}");
    if (Array.isArray(stored)) {
      state.records = Object.fromEntries(stored.filter(item => typeof item === "string").map(id => [id, { outcome: "passed", updated_at: new Date().toISOString() }]));
    } else {
      state.records = stored.records && typeof stored.records === "object" ? stored.records : {};
      state.recordContext = stored.context && typeof stored.context === "object" ? stored.context : { operator: "", target: "" };
    }
    state.run = new Set(Object.entries(state.records).filter(([, record]) => record.outcome && record.outcome !== "not_run").map(([id]) => id));
  }
  catch { state.run = new Set(); state.records = {}; }
}
function saveRunState() {
  try { localStorage.setItem(runKey(), JSON.stringify({ records: state.records, context: state.recordContext })); } catch {}
}

function enterPlan() {
  const a = state.selectedActor;
  el("planActorName").textContent = `${a.name} · ${a.attack_id}`;
  el("planActorMeta").innerHTML = (a.aliases.length ? `aka ${escapeHtml(a.aliases.slice(0, 3).join(", "))} · ` : "") +
    `development-lab emulation plan · commands target <b>${titleCase(state.scope.cmdPlatform)}</b>`;
  if (state.stage >= filteredPlan().stages.length) state.stage = 0;
  renderRail();
  renderStage();
  updateProgress();
}
function renderRail() {
  const p = filteredPlan();
  const rail = el("stageRail");
  rail.innerHTML = p.stages.map((s, i) => {
    const runnable = s.techniques.filter(t => !t._cmd.unsupported);
    const done = runnable.length > 0 && runnable.every(t => state.run.has(t.attack_id));
    return `<button type="button" class="railitem ${i === state.stage ? "is-active" : ""}" data-i="${i}" aria-current="${i === state.stage ? "step" : "false"}">
      <span class="railitem__num" style="background:${tacticColor(s.tactic)}">${i + 1}</span>
      <span class="railitem__name">${escapeHtml(s.title)}</span>
      ${done ? '<span class="railitem__done"><svg class="icon"><use href="#i-check"/></svg></span>' : `<span class="railitem__meta">${s.techniques.length}</span>`}
    </button>`;
  }).join("");
  $$(".railitem", rail).forEach(b => b.addEventListener("click", () => { state.stage = +b.dataset.i; renderRail(); renderStage(); }));
}
function renderStage() {
  const p = filteredPlan();
  const s = p.stages[state.stage];
  const body = el("stageBody");
  if (!s) { body.innerHTML = `<div class="emptystate">No techniques in scope.</div>`; return; }
  const color = tacticColor(s.tactic);
  body.innerHTML = `
    <div class="stagepanel__head">
      <span class="stagepanel__badge" style="background:${color}">${state.stage + 1}</span>
      <h3>${escapeHtml(s.title)}</h3>
    </div>
    <p class="stagepanel__desc">${escapeHtml(TACTIC_META[s.tactic] || "")} · ${s.techniques.length} technique${s.techniques.length !== 1 ? "s" : ""}</p>
    <div class="techlist">${s.techniques.map(renderTech).join("")}</div>
    <div class="stagenav">
      <button type="button" class="btn btn--ghost" ${state.stage === 0 ? "disabled" : ""} id="prevStage"><svg class="icon"><use href="#i-arrow-l"/></svg> Previous stage</button>
      <button type="button" class="btn" ${state.stage >= p.stages.length - 1 ? "disabled" : ""} id="nextStage">Next stage <svg class="icon"><use href="#i-arrow-r"/></svg></button>
    </div>`;

  $$(".techcard__check", body).forEach(c => c.addEventListener("click", () => toggleRun(c.dataset.id)));
  $$(".copybtn", body).forEach(b => b.addEventListener("click", () => copyCmd(b)));
  $$(".evidence__outcome", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { outcome: control.value })));
  $$(".evidence__note", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { notes: control.value.trim() })));
  $$(".evidence__cleanup", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { cleanup_completed: control.checked })));
  const prev = el("prevStage"), next = el("nextStage");
  if (prev) prev.addEventListener("click", () => { if (state.stage > 0) { state.stage--; renderRail(); renderStage(); scrollPlanTop(); } });
  if (next) next.addEventListener("click", () => { if (state.stage < p.stages.length - 1) { state.stage++; renderRail(); renderStage(); scrollPlanTop(); } });
}
function scrollPlanTop() { el("stage").scrollTo({ top: 0, behavior: "smooth" }); }

function renderTech(t) {
  const c = t._cmd;
  const run = state.run.has(t.attack_id);
  const record = state.records[t.attack_id] || {};
  const unsupported = Boolean(c.unsupported);
  const source = unsupported ? "unsupported" : t.command_source;
  const effects = (c.side_effects || []).map(titleCase).join(", ");
  const risk = c.risk || "unknown";
  return `
  <div class="techcard ${run ? "is-run" : ""}" data-tid="${t.attack_id}">
    <div class="techcard__main">
      <button type="button" class="techcard__check" data-id="${t.attack_id}" title="${unsupported ? "No test available for this platform" : "Mark as run"}" aria-label="${unsupported ? "No test available for this platform" : `Mark ${escapeHtml(t.attack_id)} as run`}" aria-pressed="${run}" ${unsupported ? "disabled" : ""}><svg class="icon"><use href="#i-check"/></svg></button>
      <div class="techcard__info">
        <div class="techcard__row">
          <a class="techcard__id" href="${safeUrl(t.url)}" target="_blank" rel="noopener">${t.attack_id} <svg class="icon"><use href="#i-external"/></svg></a>
          <span class="techcard__name">${escapeHtml(t.name)}</span>
          ${t.is_subtechnique ? '<span class="techcard__sub">sub-technique</span>' : ""}
        </div>
        <p class="techcard__desc">${escapeHtml(stripMd(t.description || ""))}</p>
        ${(t.platforms || []).length ? `<div class="techcard__plats">${t.platforms.slice(0, 5).map(p => `<span class="plat">${escapeHtml(p)}</span>`).join("")}</div>` : ""}
      </div>
    </div>
    <div class="command ${unsupported ? "cmd--unsupported" : ""}">
      <div class="command__bar">
        <span class="command__label">Lab command</span>
        <span class="srcbadge srcbadge--${source}">${source}</span>
      </div>
      ${unsupported ? "" : `<div class="safety safety--${risk}">
        <div class="safety__badges"><span class="riskbadge riskbadge--${risk}">${escapeHtml(risk)} risk</span>${c.requires_admin ? '<span class="riskbadge">admin</span>' : ''}${c.requires_network ? '<span class="riskbadge">network</span>' : ''}${c.cleanup_required ? '<span class="riskbadge">cleanup required</span>' : ''}</div>
        <div><b>Effects:</b> ${escapeHtml(effects || "Not classified")} · <b>Expected:</b> ${escapeHtml(c.expected_telemetry || "Verify relevant telemetry")}</div>
        ${(c.network_targets || []).length ? `<div><b>Network targets:</b> ${escapeHtml(c.network_targets.join(", "))}</div>` : ""}
      </div>`}
      <div class="cmd">
        <div class="cmd__head">
          <span class="cmd__plat">${escapeHtml(c.platform)}</span>
          <button type="button" class="copybtn" data-cmd="${escapeHtml(c.command)}" data-risk="${escapeHtml(risk)}" data-ack="${Boolean(c.acknowledgment_required)}" ${unsupported ? "disabled" : ""}><svg class="icon"><use href="#i-copy"/></svg> Copy command</button>
        </div>
        <pre class="cmd__code">${escapeHtml(c.command)}</pre>
        ${c.note ? `<p class="cmd__note">${escapeHtml(c.note)}</p>` : ""}
        ${c.cleanup ? `<p class="cmd__cleanup"><b>cleanup</b> <code>${escapeHtml(c.cleanup)}</code> <button type="button" class="copybtn" data-cmd="${escapeHtml(c.cleanup)}" data-risk="low" data-ack="false"><svg class="icon"><use href="#i-copy"/></svg> Copy cleanup</button></p>` : ""}
      </div>
      ${unsupported ? "" : `<div class="evidence">
        <select class="evidence__outcome" data-id="${t.attack_id}" aria-label="Outcome for ${t.attack_id}">
          ${[["not_run","Not run"],["passed","Passed"],["failed","Failed"],["skipped","Skipped"]].map(([value,label]) => `<option value="${value}" ${record.outcome === value || (!record.outcome && value === "not_run") ? "selected" : ""}>${label}</option>`).join("")}
        </select>
        <input class="evidence__note" data-id="${t.attack_id}" maxlength="500" value="${escapeHtml(record.notes || "")}" placeholder="Evidence or observation (no secrets)" aria-label="Evidence note for ${t.attack_id}" />
        <label class="cleanupcheck"><input type="checkbox" class="evidence__cleanup" data-id="${t.attack_id}" ${record.cleanup_completed ? "checked" : ""} ${c.cleanup ? "" : "disabled"}/> cleanup verified</label>
      </div>`}
    </div>
  </div>`;
}
function toggleRun(tid) {
  if (!filteredPlan().runnableIds.has(tid)) return;
  const outcome = state.run.has(tid) ? "not_run" : "passed";
  updateEvidence(tid, { outcome }, false);
  saveRunState();
  const card = document.querySelector(`.techcard[data-tid="${CSS.escape(tid)}"]`);
  if (card) card.classList.toggle("is-run", state.run.has(tid));
  const control = card && card.querySelector(".techcard__check");
  if (control) control.setAttribute("aria-pressed", String(state.run.has(tid)));
  updateProgress();
  renderRail();
}
function updateEvidence(tid, changes, rerender = true) {
  const previous = state.records[tid] || {};
  const next = { ...previous, ...changes, updated_at: new Date().toISOString(), operator: state.recordContext.operator, target: state.recordContext.target };
  if (!next.outcome || next.outcome === "not_run") {
    next.outcome = "not_run";
    state.run.delete(tid);
  } else state.run.add(tid);
  state.records[tid] = next;
  saveRunState();
  updateProgress();
  renderRail();
  if (rerender) renderStage();
}
function copyCmd(btn) {
  if (btn.dataset.ack === "true" && !window.confirm(`This is a ${btn.dataset.risk} risk lab command. Review prerequisites, side effects, and cleanup before copying. Continue?`)) return;
  const originalLabel = btn.innerHTML;
  navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
    btn.classList.add("is-copied");
    btn.innerHTML = '<svg class="icon"><use href="#i-check"/></svg> Copied';
    toast("Command copied to clipboard");
    setTimeout(() => { btn.classList.remove("is-copied"); btn.innerHTML = originalLabel; }, 1600);
  }).catch(() => toast("Clipboard access was denied", "error"));
}
function safeUrl(value) {
  try { const url = new URL(value); return url.protocol === "https:" ? escapeHtml(url.href) : "#"; }
  catch { return "#"; }
}
function updateProgress() {
  const p = filteredPlan();
  const done = [...state.run].filter(id => p.runnableIds.has(id)).length;
  const pct = p.runnable ? Math.round(done / p.runnable * 100) : 0;
  const ring = el("progressRing");
  ring.style.setProperty("--pct", pct);
  ring.setAttribute("aria-valuenow", String(pct));
  ring.setAttribute("aria-valuetext", `${done} of ${p.runnable} runnable techniques`);
  el("progressPct").textContent = pct + "%";
  el("progressCount").textContent = `${done} / ${p.runnable}`;
  updateActionBar();
}

/* ============================================================
   STEP 4 — EXPORT
   ============================================================ */
function renderExport() {
  const p = filteredPlan();
  const done = [...state.run].filter(id => p.runnableIds.has(id)).length;
  el("exportSummary").innerHTML = `
    <div class="statsrow">
      <div class="statbox brand"><div class="n">${p.total}</div><div class="l">Techniques</div></div>
      <div class="statbox"><div class="n">${p.stages.length}</div><div class="l">Stages</div></div>
      <div class="statbox success"><div class="n">${p.runnable}</div><div class="l">Runnable tests</div></div>
      <div class="statbox"><div class="n">${done}</div><div class="l">Marked run</div></div>
    </div>`;
}

function exportPlan(format) {
  const p = filteredPlan();
  const a = state.selectedActor;
  const slug = a.attack_id + "_" + a.name.replace(/[^a-z0-9]+/gi, "_");
  let content, filename, mime;
  if (format === "json") { content = JSON.stringify(buildExportObj(p), null, 2); filename = `AdversaryFlow_${slug}.json`; mime = "application/json"; }
  else if (format === "markdown") { content = toMarkdown(p); filename = `AdversaryFlow_${slug}.md`; mime = "text/markdown"; }
  else {
    content = toRunbook(p);
    const shell = state.scope.cmdPlatform === "windows" ? "cmd" : "sh";
    filename = `AdversaryFlow_${slug}_runbook.${shell}.txt`;
    mime = "text/plain";
  }
  download(content, filename, mime);
  toast(`Exported ${filename}`);
}
function buildExportObj(p) {
  return {
    schema_version: "2.0",
    tool: "AdversaryFlow", tool_version: state.workflow.metadata.version,
    data_version: state.workflow.metadata.data_version,
    domains: state.workflow.metadata.domains,
    generated: new Date().toISOString(),
    actor: state.selectedActor,
    scope: { command_platform: state.scope.cmdPlatform, include_pre: state.scope.includePre, curated_only: state.scope.curatedOnly, allow_network: state.scope.allowNetwork, allow_admin: state.scope.allowAdmin, allow_high_risk: state.scope.allowHighRisk, stages: [...state.scope.tactics] },
    execution_context: state.recordContext,
    summary: {
      techniques: p.total, runnable: p.runnable, unsupported: p.unsupported,
      stages: p.stages.length, curated: p.curated, fallback: p.fallback,
      marked_run: [...state.run].filter(id => p.runnableIds.has(id)),
    },
    stages: p.stages.map(s => ({ tactic: s.tactic, title: s.title, techniques: s.techniques.map(t => ({
      id: t.attack_id, name: t.name, url: t.url, platforms: t.platforms, command_source: t.command_source,
      supported: !t._cmd.unsupported, command: t._cmd, run: !t._cmd.unsupported && state.run.has(t.attack_id),
      execution: state.records[t.attack_id] || { outcome: "not_run" },
    })) })),
  };
}
function toMarkdown(p) {
  const a = state.selectedActor;
  let md = `# AdversaryFlow — ${a.name} (${a.attack_id})\n\n`;
  md += `> Development-lab emulation plan. AdversaryFlow generated this plan but did not execute it.\n\n`;
  if (state.recordContext.operator || state.recordContext.target) md += `**Execution context:** operator ${state.recordContext.operator || "not recorded"} · target ${state.recordContext.target || "not recorded"}\n\n`;
  if (a.aliases.length) md += `*Aliases: ${a.aliases.join(", ")}*\n\n`;
  md += `${a.description || ""}\n\n`;
  md += `**${p.total} techniques · ${p.runnable} runnable · ${p.unsupported} unsupported · ${p.stages.length} stages · commands target ${titleCase(state.scope.cmdPlatform)}** (${p.curated} curated / ${p.fallback} fallback)\n\n`;
  p.stages.forEach((s, i) => {
    md += `## ${i + 1}. ${s.title}\n\n_${TACTIC_META[s.tactic] || ""}_\n\n`;
    s.techniques.forEach(t => {
      const c = t._cmd;
      md += `### ${t.attack_id} — ${t.name}${state.run.has(t.attack_id) ? " ✅" : ""}\n\n`;
      const record = state.records[t.attack_id] || { outcome: "not_run" };
      md += `**Outcome:** ${record.outcome}${record.updated_at ? ` · ${record.updated_at}` : ""}${record.notes ? ` · ${record.notes}` : ""}\n\n`;
      if (t.description) md += `${stripMd(t.description)}\n\n`;
      if (c.unsupported) {
        md += `**Unsupported on ${titleCase(state.scope.cmdPlatform)}.** ${c.note}\n\n`;
        return;
      }
      md += `**[${c.platform}] lab command:**\n\n\`\`\`\n${c.command}\n\`\`\`\n`;
      if (c.note) md += `_${c.note}_\n`;
      if (c.cleanup) md += `_cleanup: \`${c.cleanup}\`_\n`;
      md += `\n`;
    });
  });
  return md;
}
function toRunbook(p) {
  const a = state.selectedActor;
  const comment = state.scope.cmdPlatform === "windows" ? "REM" : "#";
  let out = `${comment} AdversaryFlow runbook — ${runbookSafe(a.name)} (${runbookSafe(a.attack_id)})\n`;
  out += `${comment} DEVELOPMENT-LAB EMULATION RUNBOOK.\n`;
  out += `${comment} Command platform: ${titleCase(state.scope.cmdPlatform)}\n`;
  out += `${comment} Data version: ${runbookSafe(state.workflow.metadata.data_version)}\n`;
  out += `${comment} Operator: ${runbookSafe(state.recordContext.operator) || "not recorded"}\n${comment} Target: ${runbookSafe(state.recordContext.target) || "not recorded"}\n`;
  p.stages.forEach((s, i) => {
    out += `\n${comment} ===== ${i + 1}. ${s.title.toUpperCase()} =====\n`;
    s.techniques.forEach(t => {
      const c = t._cmd;
      out += `\n${comment} ${t.attack_id} ${t.name} [${c.platform}]${state.run.has(t.attack_id) ? " (run)" : ""}\n`;
      const record = state.records[t.attack_id] || { outcome: "not_run" };
      out += `${comment} Outcome: ${record.outcome}${record.updated_at ? ` at ${record.updated_at}` : ""}\n`;
      if (record.notes) out += `${comment} Evidence: ${runbookSafe(record.notes)}\n`;
      if (c.unsupported) {
        out += `${comment} UNSUPPORTED: ${c.note}\n`;
        return;
      }
      if (c.note) out += `${comment}   ${c.note}\n`;
      out += `${c.command}\n`;
      if (c.cleanup) out += `${comment} MANUAL CLEANUP: ${c.cleanup}\n`;
    });
  });
  return out;
}
function download(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = filename;
  document.body.appendChild(link); link.click(); link.remove();
  URL.revokeObjectURL(url);
}
