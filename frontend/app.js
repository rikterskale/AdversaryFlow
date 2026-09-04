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
  scope: { cmdPlatform: "windows", tactics: new Set(TACTIC_ORDER), includePre: true, curatedOnly: false },
  run: new Set(),
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
  loadActors();

  el("startBtn").addEventListener("click", () => goTo(1));
  el("brandHome").addEventListener("click", restart);
  el("brandHome").addEventListener("keydown", (e) => { if (e.key === "Enter") restart(); });
  el("refreshBtn").addEventListener("click", refreshFeed);
  el("backBtn").addEventListener("click", () => goTo(state.step - 1));
  el("nextBtn").addEventListener("click", onNext);
  el("restartBtn").addEventListener("click", restart);

  // Stepper
  $$("#stepper .stepper__item").forEach(b =>
    b.addEventListener("click", () => { const t = +b.dataset.goto; if (!b.disabled) goTo(t); }));

  // Step 1 controls
  el("actorSearch").addEventListener("input", onSearch);
  el("searchClear").addEventListener("click", () => { el("actorSearch").value = ""; onSearch(); el("actorSearch").focus(); });
  $$("#typeFilter .segmented__btn").forEach(b =>
    b.addEventListener("click", () => { state.typeFilter = b.dataset.type; setOn("#typeFilter", b); applyFilter(); }));
  el("sortSel").addEventListener("change", e => { state.sort = e.target.value; applyFilter(); });

  // Step 2 controls
  $$("#cmdPlatform .segmented__btn").forEach(b =>
    b.addEventListener("click", () => { state.scope.cmdPlatform = b.dataset.plat; setOn("#cmdPlatform", b); renderScope(); }));
  el("optPre").addEventListener("change", e => { state.scope.includePre = e.target.checked; syncTacticChips(); renderScope(); });
  el("optCurated").addEventListener("change", e => { state.scope.curatedOnly = e.target.checked; renderScope(); });
  el("stagesAll").addEventListener("click", toggleAllStages);

  // Export
  $$("[data-export]").forEach(b => b.addEventListener("click", () => exportPlan(b.dataset.export)));

  // Keyboard: Enter advances when possible
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.target.matches("input,select,textarea,button,a") && !el("nextBtn").disabled && state.step >= 1 && state.step <= 3)
      onNext();
  });
});

/* ============================================================
   DATA
   ============================================================ */
async function loadActors() {
  setStatus("loading ATT&CK…", "");
  try {
    const res = await fetch("/api/actors");
    const data = await res.json();
    state.actors = data.actors;
    renderFeatured();
    applyFilter();
    setStatus(`${data.actors.length} actors · ATT&CK live`, "ok");
  } catch (e) {
    setStatus("backend offline", "err");
    el("actorGrid").innerHTML = `<div class="emptystate">Couldn't reach the backend. Is <code>app.py</code> running?</div>`;
  }
}
async function refreshFeed() {
  showLoader("Re-downloading the live ATT&CK STIX feed…");
  try { await fetch("/api/refresh", { method: "POST" }); await loadActors(); toast("ATT&CK feed refreshed"); }
  catch { setStatus("refresh failed", "err"); }
  finally { hideLoader(); }
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
}

function onNext() {
  if (state.step === 1) { if (!state.selectedId) return; goTo(2); }
  else if (state.step === 2) { if (filteredPlan().total === 0) return; goTo(3); }
  else if (state.step === 3) { goTo(4); }
}

function updateStepper() {
  $$("#stepper .stepper__item").forEach(item => {
    const n = +item.dataset.goto;
    item.classList.toggle("is-active", n === state.step);
    item.classList.toggle("is-done", n < state.step && state.step > 0);
    // allow jumping to any step already reached this session
    item.disabled = n > Math.max(state.maxStep, state.selectedId ? 1 : 0);
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
    next.disabled = p.total === 0;
    next.innerHTML = 'Build plan <svg class="icon"><use href="#i-arrow-r"/></svg>';
    ctx.innerHTML = p.total ? `<b>${p.total}</b> techniques across <b>${p.stages.length}</b> stages` : "No techniques in scope — enable a stage";
  } else if (state.step === 3) {
    next.hidden = false;
    next.disabled = false;
    next.innerHTML = 'Finish & export <svg class="icon"><use href="#i-arrow-r"/></svg>';
    const p = filteredPlan();
    ctx.innerHTML = `<b>${state.run.size}</b> / ${p.total} techniques marked run`;
  } else if (state.step === 4) {
    next.hidden = true;
    ctx.innerHTML = "Plan complete ✓";
  }
}

function restart() {
  state.selectedId = null; state.selectedActor = null; state.workflow = null;
  state.run = new Set();
  state.maxStep = 0; state.stage = 0;
  state.scope = { cmdPlatform: "windows", tactics: new Set(TACTIC_ORDER), includePre: true, curatedOnly: false };
  el("actorSearch").value = "";
  $$(".actorcard").forEach(c => c.classList.remove("is-selected"));
  applyFilter();
  goTo(0);
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
  wrap.innerHTML = chips.map(a => `<button class="fchip" data-id="${a.stix_id}">${escapeHtml(a.name)}</button>`).join("");
  $$(".fchip", wrap).forEach(c => c.addEventListener("click", () => { selectActor(c.dataset.id); }));
}
function renderActorGrid() {
  const grid = el("actorGrid");
  el("actorEmpty").hidden = state.filtered.length > 0;
  grid.innerHTML = state.filtered.map(a => `
    <button class="actorcard ${state.selectedId === a.stix_id ? "is-selected" : ""}" data-id="${a.stix_id}">
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
    const res = await fetch(`/api/workflow/${state.selectedId}`);
    state.workflow = await res.json();
    loadRunState();
    cb && cb();
  } catch (e) { toast("Failed to build workflow"); }
  finally { hideLoader(); }
}

/* ============================================================
   SCOPE ENGINE
   ============================================================ */
function filteredPlan() {
  const wf = state.workflow;
  if (!wf) return { stages: [], total: 0, curated: 0, fallback: 0, ids: new Set() };
  const sc = state.scope;
  const stages = [];
  // Unique-technique accounting (a technique can serve several tactics).
  const ids = new Set(), curatedIds = new Set();
  wf.stages.forEach(stage => {
    if (!sc.tactics.has(stage.tactic)) return;
    if (!sc.includePre && PRE_TACTICS.includes(stage.tactic)) return;
    const techs = [];
    stage.techniques.forEach(t => {
      if (sc.curatedOnly && t.benign_source === "fallback") return;
      techs.push({ ...t, _cmd: pickCommand(t, sc.cmdPlatform) });
      ids.add(t.attack_id);
      if (t.benign_source === "curated") curatedIds.add(t.attack_id);
    });
    if (techs.length) stages.push({ ...stage, techniques: techs });
  });
  return { stages, total: ids.size, curated: curatedIds.size, fallback: ids.size - curatedIds.size, ids };
}
function pickCommand(t, plat) {
  const list = t.benign || [];
  return list.find(c => c.platform === plat)
    || list.find(c => c.platform === "pre")
    || list.find(c => c.platform === "windows")
    || list[0] || { platform: "n/a", command: "(no command)", note: "", cleanup: "" };
}

function renderScope() {
  buildTacticGrid();
  const p = filteredPlan();
  const sc = state.scope;
  el("scopeSummary").innerHTML = `
    <h4>Plan preview</h4>
    <div class="sumrow"><span class="k">Actor</span><span class="v">${escapeHtml(state.selectedActor.name)}</span></div>
    <div class="sumrow"><span class="k">Techniques</span><span class="v big">${p.total}</span></div>
    <div class="sumrow"><span class="k">Kill-chain stages</span><span class="v">${p.stages.length}</span></div>
    <div class="sumrow"><span class="k">Command target</span><span class="v">${titleCase(sc.cmdPlatform)}</span></div>
    <div class="sumbar">
      <span class="sumbar__seg" style="width:${p.total ? p.curated / p.total * 100 : 0}%;background:var(--safe)"></span>
      <span class="sumbar__seg" style="width:${p.total ? p.fallback / p.total * 100 : 0}%;background:var(--warn)"></span>
    </div>
    <div class="sumrow" style="border:0"><span class="k" style="color:var(--safe)">${p.curated} curated</span><span class="k" style="color:var(--warn)">${p.fallback} fallback</span></div>`;
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
    return `<div class="tacticchip ${on && !disabled ? "is-on" : "is-off"}" data-tactic="${t}" ${disabled ? 'style="pointer-events:none"' : ""}>
      <span class="tacticchip__dot" style="background:${tacticColor(t)}"></span>
      <span class="tacticchip__name">${escapeHtml(tacticTitle(t))}</span>
      <span class="tacticchip__n">${stage.techniques.length}</span>
      <span class="tacticchip__check"><svg class="icon"><use href="#i-check"/></svg></span>
    </div>`;
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
function setOn(sel, btn) { $$(`${sel} .segmented__btn`).forEach(b => b.classList.toggle("is-on", b === btn)); }
function escapeHtml(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
function stripMd(s) { return String(s || "").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/<[^>]+>/g, ""); }
function toast(msg) { const t = el("toast"); t.innerHTML = `<svg class="icon"><use href="#i-check"/></svg>${escapeHtml(msg)}`; t.hidden = false; requestAnimationFrame(() => t.classList.add("is-show")); clearTimeout(t._t); t._t = setTimeout(() => { t.classList.remove("is-show"); }, 1900); }
function showLoader(txt) { el("loaderText").textContent = txt || "Working…"; el("loader").hidden = false; }
function hideLoader() { el("loader").hidden = true; }

/* ============================================================
   STEP 3 — GUIDED PLAN RUN-THROUGH
   ============================================================ */
function runKey() { return "af_run_" + (state.selectedId || ""); }
function loadRunState() {
  try { state.run = new Set(JSON.parse(localStorage.getItem(runKey()) || "[]")); }
  catch { state.run = new Set(); }
}
function saveRunState() {
  try { localStorage.setItem(runKey(), JSON.stringify([...state.run])); } catch {}
}

function enterPlan() {
  const a = state.selectedActor;
  el("planActorName").textContent = `${a.name} · ${a.attack_id}`;
  el("planActorMeta").innerHTML = (a.aliases.length ? `aka ${escapeHtml(a.aliases.slice(0, 3).join(", "))} · ` : "") +
    `benign detection-validation plan · commands target <b>${titleCase(state.scope.cmdPlatform)}</b>`;
  if (state.stage >= filteredPlan().stages.length) state.stage = 0;
  renderRail();
  renderStage();
  updateProgress();
}
function renderRail() {
  const p = filteredPlan();
  const rail = el("stageRail");
  rail.innerHTML = p.stages.map((s, i) => {
    const done = s.techniques.every(t => state.run.has(t.attack_id));
    return `<button class="railitem ${i === state.stage ? "is-active" : ""}" data-i="${i}">
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
      <button class="btn btn--ghost" ${state.stage === 0 ? "disabled" : ""} id="prevStage"><svg class="icon"><use href="#i-arrow-l"/></svg> Previous stage</button>
      <button class="btn" ${state.stage >= p.stages.length - 1 ? "disabled" : ""} id="nextStage">Next stage <svg class="icon"><use href="#i-arrow-r"/></svg></button>
    </div>`;

  $$(".techcard__check", body).forEach(c => c.addEventListener("click", () => toggleRun(c.dataset.id)));
  $$(".copybtn", body).forEach(b => b.addEventListener("click", () => copyCmd(b)));
  const prev = el("prevStage"), next = el("nextStage");
  if (prev) prev.addEventListener("click", () => { if (state.stage > 0) { state.stage--; renderRail(); renderStage(); scrollPlanTop(); } });
  if (next) next.addEventListener("click", () => { if (state.stage < p.stages.length - 1) { state.stage++; renderRail(); renderStage(); scrollPlanTop(); } });
}
function scrollPlanTop() { el("stage").scrollTo({ top: 0, behavior: "smooth" }); }

function renderTech(t) {
  const c = t._cmd;
  const run = state.run.has(t.attack_id);
  return `
  <div class="techcard ${run ? "is-run" : ""}" data-tid="${t.attack_id}">
    <div class="techcard__main">
      <button class="techcard__check" data-id="${t.attack_id}" title="Mark as run"><svg class="icon"><use href="#i-check"/></svg></button>
      <div class="techcard__info">
        <div class="techcard__row">
          <a class="techcard__id" href="${t.url || "#"}" target="_blank" rel="noopener">${t.attack_id} <svg class="icon"><use href="#i-external"/></svg></a>
          <span class="techcard__name">${escapeHtml(t.name)}</span>
          ${t.is_subtechnique ? '<span class="techcard__sub">sub-technique</span>' : ""}
        </div>
        <p class="techcard__desc">${escapeHtml(stripMd(t.description || ""))}</p>
        ${(t.platforms || []).length ? `<div class="techcard__plats">${t.platforms.slice(0, 5).map(p => `<span class="plat">${escapeHtml(p)}</span>`).join("")}</div>` : ""}
      </div>
    </div>
    <div class="benign">
      <div class="benign__bar">
        <span class="benign__label">Benign test</span>
        <span class="srcbadge srcbadge--${t.benign_source}">${t.benign_source}</span>
      </div>
      <div class="cmd">
        <div class="cmd__head">
          <span class="cmd__plat">${escapeHtml(c.platform)}</span>
          <button class="copybtn" data-cmd="${escapeHtml(c.command)}"><svg class="icon"><use href="#i-copy"/></svg> Copy</button>
        </div>
        <pre class="cmd__code">${escapeHtml(c.command)}</pre>
        ${c.note ? `<p class="cmd__note">${escapeHtml(c.note)}</p>` : ""}
        ${c.cleanup ? `<p class="cmd__cleanup"><b>cleanup</b> ${escapeHtml(c.cleanup)}</p>` : ""}
      </div>
    </div>
  </div>`;
}
function toggleRun(tid) {
  if (state.run.has(tid)) state.run.delete(tid); else state.run.add(tid);
  saveRunState();
  const card = document.querySelector(`.techcard[data-tid="${CSS.escape(tid)}"]`);
  if (card) card.classList.toggle("is-run", state.run.has(tid));
  updateProgress();
  renderRail();
}
function copyCmd(btn) {
  navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
    btn.classList.add("is-copied");
    btn.innerHTML = '<svg class="icon"><use href="#i-check"/></svg> Copied';
    toast("Command copied to clipboard");
    setTimeout(() => { btn.classList.remove("is-copied"); btn.innerHTML = '<svg class="icon"><use href="#i-copy"/></svg> Copy'; }, 1600);
  });
}
function updateProgress() {
  const p = filteredPlan();
  const done = [...state.run].filter(id => p.ids.has(id)).length;
  const pct = p.total ? Math.round(done / p.total * 100) : 0;
  const ring = el("progressRing");
  ring.style.setProperty("--pct", pct);
  el("progressPct").textContent = pct + "%";
  el("progressCount").textContent = `${done} / ${p.total}`;
  updateActionBar();
}

/* ============================================================
   STEP 4 — EXPORT
   ============================================================ */
function renderExport() {
  const p = filteredPlan();
  const done = [...state.run].filter(id => p.ids.has(id)).length;
  el("exportSummary").innerHTML = `
    <div class="statsrow">
      <div class="statbox brand"><div class="n">${p.total}</div><div class="l">Techniques</div></div>
      <div class="statbox"><div class="n">${p.stages.length}</div><div class="l">Stages</div></div>
      <div class="statbox safe"><div class="n">${p.curated}</div><div class="l">Curated tests</div></div>
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
  else { content = toRunbook(p); filename = `AdversaryFlow_${slug}_runbook.txt`; mime = "text/plain"; }
  download(content, filename, mime);
  toast(`Exported ${filename}`);
}
function buildExportObj(p) {
  return {
    tool: "AdversaryFlow", generated: new Date().toISOString(),
    actor: state.selectedActor,
    scope: { command_platform: state.scope.cmdPlatform, include_pre: state.scope.includePre, curated_only: state.scope.curatedOnly, stages: [...state.scope.tactics] },
    summary: { techniques: p.total, stages: p.stages.length, curated: p.curated, fallback: p.fallback, marked_run: [...state.run] },
    stages: p.stages.map(s => ({ tactic: s.tactic, title: s.title, techniques: s.techniques.map(t => ({
      id: t.attack_id, name: t.name, url: t.url, platforms: t.platforms, benign_source: t.benign_source,
      benign_command: t._cmd, run: state.run.has(t.attack_id),
    })) })),
  };
}
function toMarkdown(p) {
  const a = state.selectedActor;
  let md = `# AdversaryFlow — ${a.name} (${a.attack_id})\n\n`;
  md += `> **Authorized purple-team use only.** Every command is a benign detection-validation proxy — review before running.\n\n`;
  if (a.aliases.length) md += `*Aliases: ${a.aliases.join(", ")}*\n\n`;
  md += `${a.description || ""}\n\n`;
  md += `**${p.total} techniques · ${p.stages.length} stages · commands target ${titleCase(state.scope.cmdPlatform)}** (${p.curated} curated / ${p.fallback} fallback)\n\n`;
  p.stages.forEach((s, i) => {
    md += `## ${i + 1}. ${s.title}\n\n_${TACTIC_META[s.tactic] || ""}_\n\n`;
    s.techniques.forEach(t => {
      const c = t._cmd;
      md += `### ${t.attack_id} — ${t.name}${state.run.has(t.attack_id) ? " ✅" : ""}\n\n`;
      if (t.description) md += `${stripMd(t.description)}\n\n`;
      md += `**[${c.platform}] benign test:**\n\n\`\`\`\n${c.command}\n\`\`\`\n`;
      if (c.note) md += `_${c.note}_\n`;
      if (c.cleanup) md += `_cleanup: \`${c.cleanup}\`_\n`;
      md += `\n`;
    });
  });
  return md;
}
function toRunbook(p) {
  const a = state.selectedActor;
  let out = `:: AdversaryFlow runbook — ${a.name} (${a.attack_id})\n`;
  out += `:: AUTHORIZED PURPLE-TEAM USE ONLY. Benign detection-validation commands. Review every line.\n`;
  out += `:: Command platform: ${titleCase(state.scope.cmdPlatform)}\n`;
  p.stages.forEach((s, i) => {
    out += `\n:: ===== ${i + 1}. ${s.title.toUpperCase()} =====\n`;
    s.techniques.forEach(t => {
      const c = t._cmd;
      out += `\n:: ${t.attack_id} ${t.name} [${c.platform}]${state.run.has(t.attack_id) ? " (run)" : ""}\n`;
      if (c.note) out += `::   ${c.note}\n`;
      out += `${c.command}\n`;
      if (c.cleanup) out += `:: cleanup: ${c.cleanup}\n`;
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
