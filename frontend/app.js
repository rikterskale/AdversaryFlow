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
const ACTOR_PAGE_SIZE = 24;
const SESSION_KEY = "af_session_v1";
const FIDELITY_VALUES = ["direct", "bounded_synthetic", "lab_proxy"];
const DETECTION_RESULTS = ["not_assessed", "alerted", "silent", "blocked", "not_instrumented"];
const DETECTION_LABELS = {
  not_assessed: "Not assessed",
  alerted: "Alerted",
  silent: "Silent",
  blocked: "Blocked",
  not_instrumented: "Not instrumented",
};

// Upper bound on the first-run bundle download so a wedged bootstrap surfaces
// an actionable error instead of spinning forever.
const BOOTSTRAP_TIMEOUT_MS = 15 * 60 * 1000;

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
  toolVersion: "",
  focusedTech: 0,
  step: 0, stage: 0, maxStep: 0,
  typeFilter: "all", sort: "name",
  actorShowAll: false,
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
  el("recommendedBtn").addEventListener("click", startRecommended);
  el("brandHome").addEventListener("click", () => restart());
  el("refreshBtn").addEventListener("click", refreshFeed);
  el("helpBtn").addEventListener("click", openHelp);
  el("helpClose").addEventListener("click", () => el("helpDialog").close());
  el("retryLoad").addEventListener("click", boot);
  el("actorShowAll").addEventListener("click", () => { state.actorShowAll = true; renderActorGrid(); });
  el("backBtn").addEventListener("click", () => goTo(state.step - 1));
  el("nextBtn").addEventListener("click", onNext);
  el("restartBtn").addEventListener("click", () => restart());
  el("resumeSessionBtn").addEventListener("click", resumeSession);
  el("resumeJsonBtn").addEventListener("click", () => el("importPlan").click());
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
  el("optPre").addEventListener("change", e => { state.scope.includePre = e.target.checked; renderScope(); });
  el("optCurated").addEventListener("change", e => { state.scope.curatedOnly = e.target.checked; renderScope(); });
  el("optNetwork").addEventListener("change", e => { state.scope.allowNetwork = e.target.checked; renderScope(); });
  el("optAdmin").addEventListener("change", e => { state.scope.allowAdmin = e.target.checked; renderScope(); });
  el("optHighRisk").addEventListener("change", e => { state.scope.allowHighRisk = e.target.checked; renderScope(); });
  el("stagesAll").addEventListener("click", toggleAllStages);
  ["recordOperator", "recordTarget"].forEach(id => el(id).addEventListener("input", updateRecordContext));

  // Export
  $$("[data-export]").forEach(b => b.addEventListener("click", () => exportPlan(b.dataset.export)));

  // Keyboard: Enter advances when possible; j/k/c operate the plan.
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input,select,textarea,a,[contenteditable]")) return;
    if ((e.key === "?" || e.key === "F1") && !e.altKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      if (el("helpDialog").open) el("helpDialog").close();
      else if (!el("confirmDialog").open && !el("authDialog").open) openHelp();
      return;
    }
    if (e.key === "Enter" && !e.target.matches("button") && !el("nextBtn").disabled && state.step >= 1 && state.step <= 3)
      onNext();
    if (state.step === 3) handlePlanKeys(e);
  });
});

async function boot() {
  showLoader("Preparing AdversaryFlow…", "Checking the local service and ATT&CK cache.");
  try {
    hideSetupError();
    const session = await establishSession();
    state.csrf = session.csrf_token;
    state.toolVersion = session.version || "";
    if (state.toolVersion) {
      el("buildVersion").hidden = false;
      el("buildVersion").textContent = state.toolVersion;
    }
    await waitForBootstrap();
    await loadActors(true);
    renderWelcomeActions();
  } catch (e) {
    showLoadFailure(e);
  } finally {
    hideLoader();
  }
}

function openHelp() {
  const dialog = el("helpDialog");
  if (dialog && !dialog.open) dialog.showModal();
}

async function establishSession() {
  let message = "";
  for (;;) {
    try {
      return await apiJson("/api/session");
    } catch (error) {
      if (!/bearer token/i.test(error.message || "")) throw error;
      state.apiToken = "";
      sessionStorage.removeItem("af_api_token");
      const token = await requestApiToken(message);
      state.apiToken = token;
      sessionStorage.setItem("af_api_token", token);
      message = "That token was not accepted. Check it and try again.";
    }
  }
}

function requestApiToken(message = "") {
  const dialog = el("authDialog");
  const form = el("authForm");
  const token = el("authToken");
  const error = el("authError");
  error.textContent = message;
  error.hidden = !message;
  token.value = "";
  hideLoader();

  return new Promise((resolve, reject) => {
    const cleanup = () => {
      form.removeEventListener("submit", submit);
      el("authCancel").removeEventListener("click", cancel);
      dialog.removeEventListener("cancel", cancel);
    };
    const submit = event => {
      event.preventDefault();
      const value = token.value.trim();
      if (!value) {
        error.textContent = "Enter the API token to continue.";
        error.hidden = false;
        token.focus();
        return;
      }
      cleanup();
      dialog.close();
      showLoader("Connecting securely…", "Validating access to the AdversaryFlow service.");
      resolve(value);
    };
    const cancel = event => {
      event.preventDefault();
      cleanup();
      dialog.close();
      reject(new Error("An API token is required to use this remote service"));
    };
    form.addEventListener("submit", submit);
    el("authCancel").addEventListener("click", cancel);
    dialog.addEventListener("cancel", cancel);
    dialog.showModal();
    token.focus();
  });
}

function confirmAction({ title, description, detail = "", acceptLabel = "Continue", danger = false } = {}) {
  const dialog = el("confirmDialog");
  const form = el("confirmForm");
  const detailEl = el("confirmDetail");
  el("confirmTitle").textContent = title || "Confirm";
  el("confirmDescription").textContent = description || "";
  detailEl.textContent = detail || "";
  detailEl.hidden = !detail;
  el("confirmAccept").textContent = acceptLabel;
  el("confirmAccept").classList.toggle("btn--danger", Boolean(danger));
  return new Promise(resolve => {
    const cleanup = () => {
      form.removeEventListener("submit", accept);
      el("confirmCancel").removeEventListener("click", cancel);
      dialog.removeEventListener("cancel", cancel);
    };
    const accept = event => {
      event.preventDefault();
      cleanup();
      dialog.close();
      resolve(true);
    };
    const cancel = event => {
      event.preventDefault();
      cleanup();
      dialog.close();
      resolve(false);
    };
    form.addEventListener("submit", accept);
    el("confirmCancel").addEventListener("click", cancel);
    dialog.addEventListener("cancel", cancel);
    dialog.showModal();
    el("confirmAccept").focus();
  });
}

async function waitForBootstrap() {
  const deadline = Date.now() + BOOTSTRAP_TIMEOUT_MS;
  let status = await fetch("/api/bootstrap", { headers: authHeaders() });
  if (status.status === 503) {
    status = await fetch("/api/bootstrap", { method: "POST", headers: csrfHeaders() });
    // A rejected start (401/403) never produces progress, so fail loudly here
    // instead of polling a bootstrap that was never scheduled.
    if (!status.ok) {
      const body = await status.json().catch(() => ({}));
      throw new Error(body.message || body.error || `ATT&CK setup could not be started (${status.status})`);
    }
  }
  for (;;) {
    const data = await status.json();
    if (data.runtime && data.runtime.ready) return;
    if (data.runtime && data.runtime.phase === "failed") throw new Error(data.runtime.error || "ATT&CK data could not be prepared");
    if (Date.now() >= deadline) throw new Error("Preparing ATT&CK data timed out. Check the service log, then retry setup.");
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

function hideSetupError() {
  el("setupError").hidden = true;
}
function showLoadFailure(error) {
  setStatus("setup needs attention", "err");
  el("setupErrorText").textContent = error.message || "Could not prepare ATT&CK data";
  el("setupError").hidden = false;
  const rec = el("recommendedBtn");
  if (rec) rec.hidden = true;
}

/* ============================================================
   DATA
   ============================================================ */
async function loadActors(throwOnError = false, { busy = false } = {}) {
  if (busy) showLoader("Loading ATT&CK domain data…", "Downloading and validating the selected bundles. You can leave this tab open.");
  setStatus("loading ATT&CK…", "");
  try {
    const data = await apiJson(`/api/actors?${domainQuery()}`);
    if (!Array.isArray(data.actors)) throw new Error("Actor response is missing its actors array");
    state.actors = data.actors;
    state.dataVersion = data.data_version || "unknown";
    renderFeatured();
    applyFilter();
    const count = data.actors.length;
    setStatus(`${count} actor${count === 1 ? "" : "s"} · ${state.domains.map(titleCase).join(" + ")}`, "ok");
    hideSetupError();
    renderWelcomeActions();
  } catch (e) {
    setStatus("backend offline", "err");
    showLoadFailure(e);
    if (throwOnError) throw e;
  } finally {
    if (busy) hideLoader();
  }
}
async function refreshFeed() {
  if (state.workflow && !await confirmAction({
    title: "Refresh the ATT&CK feed?",
    description: "Refreshing can change technique mappings and will rebuild the current plan.",
    acceptLabel: "Refresh feed",
  })) return;
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
  loadActors(false, { busy: true });
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

  if (step === 0) renderWelcomeActions();
  if (step === 2) renderScope();
  if (step === 3) enterPlan();
  if (step === 4) renderExport();
  persistSession();
  requestAnimationFrame(() => {
    const heading = document.querySelector(`.screen[data-screen="${step}"] h1, .screen[data-screen="${step}"] h2`);
    if (heading) heading.focus({ preventScroll: true });
  });
}

function firstRunnableStage() {
  const p = filteredPlan();
  const index = p.stages.findIndex(stage => stage.techniques.some(technique => !technique._cmd.unsupported));
  return index < 0 ? 0 : index;
}
function onNext() {
  if (state.step === 1) { if (!state.selectedId) return; goTo(2); }
  else if (state.step === 2) {
    if (filteredPlan().runnable === 0) return;
    state.stage = firstRunnableStage();
    goTo(3);
  }
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
    ctx.innerHTML = "Plan complete";
  }
}

async function restart() {
  if ((state.step > 0 || state.selectedId) && !await confirmAction({
    title: "Start a new plan?",
    description: "This clears the current actor, scope, and unsaved evidence in this browser. Exported files are not affected.",
    acceptLabel: "Start new plan",
    danger: true,
  })) return;
  clearSession();
  const domainsWereChanged = state.domains.length !== 1 || state.domains[0] !== "enterprise";
  state.selectedId = null; state.selectedActor = null; state.workflow = null;
  state.run = new Set();
  state.records = {};
  state.recordContext = { operator: "", target: "" };
  state.maxStep = 0; state.stage = 0;
  state.typeFilter = "all"; state.sort = "name";
  state.actorShowAll = false;
  state.domains = ["enterprise"];
  state.scope = { cmdPlatform: "windows", tactics: new Set(TACTIC_ORDER), includePre: true, curatedOnly: false, allowNetwork: false, allowAdmin: false, allowHighRisk: false };
  el("actorSearch").value = "";
  el("searchClear").hidden = true;
  el("sortSel").value = "name";
  $$("#typeFilter .segmented__btn").forEach(button => {
    const on = button.dataset.type === "all";
    button.classList.toggle("is-on", on);
    button.setAttribute("aria-pressed", String(on));
  });
  syncStaticScopeControls();
  $$(".actorcard").forEach(c => c.classList.remove("is-selected"));
  if (domainsWereChanged) {
    state.actors = []; state.filtered = []; state.dataVersion = "unknown";
    renderFeatured(); renderActorGrid();
    loadActors();
  } else applyFilter();
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
      // Every imported command is re-classified as high risk below, so honouring
      // the file's own allow_high_risk flag would restrict the whole plan and
      // hide the very records the operator is resuming. The enforced control for
      // untrusted commands stays acknowledgment-on-copy, not the scope filter.
      allowHighRisk: true,
    };
    state.recordContext = { operator: data.execution_context.operator, target: data.execution_context.target };
    state.records = {};
    data.stages.forEach(stage => stage.techniques.forEach(technique => {
      state.records[technique.id] = technique.execution || { outcome: technique.run ? "passed" : "not_run" };
    }));
    state.run = new Set(Object.entries(state.records).filter(([, record]) => record.outcome !== "not_run").map(([id]) => id));
    state.workflow = {
      actor: data.actor,
      kill_chain: data.stages.map(stage => ({ tactic: stage.tactic, title: stage.title })),
      stages: data.stages.map(stage => ({ ...stage, techniques: stage.techniques.map(technique => ({
        attack_id: technique.id, name: technique.name, url: technique.url, platforms: technique.platforms || [],
        description: "Imported plan record", is_subtechnique: technique.id.includes("."),
        data_sources: Array.isArray(technique.data_sources) ? technique.data_sources : [],
        detection: typeof technique.detection === "string" ? technique.detection : "",
        command_source: technique.command_source === "fallback" ? "fallback" : "curated",
        commands: [normalizeImportedCommand(technique.command)], tactics: [stage.tactic],
      })) })),
      metadata: { version: data.tool_version, data_version: data.data_version, domains: data.domains },
    };
    TACTIC_ORDER = state.workflow.kill_chain.map(item => item.tactic);
    state.maxStep = 4; state.stage = 0;
    saveRunState();
    syncStaticScopeControls();
    goTo(3);
    toast("Plan imported as high-risk; verify its data version before execution");
  } catch (error) {
    toast(error.message || "Plan import failed", "error");
  }
}

function nonEmptyString(value) { return typeof value === "string" && value.length > 0; }
function plainObject(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function onlyKeys(value, required, optional = []) {
  if (!plainObject(value) || required.some(key => !Object.prototype.hasOwnProperty.call(value, key))) return false;
  const allowed = new Set([...required, ...optional]);
  return Object.keys(value).every(key => allowed.has(key));
}
function uniqueStrings(value, { nonEmpty = false } = {}) {
  return Array.isArray(value)
    && value.every(item => typeof item === "string" && (!nonEmpty || item.length > 0))
    && new Set(value).size === value.length;
}
function stringArray(value) { return Array.isArray(value) && value.every(item => typeof item === "string"); }
function nonNegativeInteger(value) { return Number.isInteger(value) && value >= 0; }
function dateTime(value) { return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value) && !Number.isNaN(Date.parse(value)); }
function uriOrNull(value) {
  if (value === null) return true;
  if (typeof value !== "string") return false;
  try { return Boolean(new URL(value).protocol); } catch { return false; }
}

function validateImportedPlan(data) {
  const allowedDomains = ["enterprise", "ics", "mobile"];
  const rootKeys = ["schema_version", "tool", "tool_version", "data_version", "domains", "generated", "actor", "scope", "execution_context", "summary", "stages"];
  if (!plainObject(data) || data.schema_version !== "2.0" || data.tool !== "AdversaryFlow") throw new Error("This is not an AdversaryFlow 2.0 plan export");
  if (!onlyKeys(data, rootKeys)) throw new Error("Plan contains unknown or missing top-level fields");
  if (!nonEmptyString(data.tool_version) || !nonEmptyString(data.data_version)) throw new Error("Plan is missing its tool or ATT&CK data version");
  if (!dateTime(data.generated)) throw new Error("Plan generated timestamp is invalid");
  // The actor drives every later screen and export, so enforce the same shape
  // the checked-in plan schema requires rather than trusting a partial record.
  const actor = data.actor;
  if (!onlyKeys(actor, ["stix_id", "attack_id", "name", "type", "aliases", "description", "technique_count"])
    || !nonEmptyString(actor.stix_id) || !nonEmptyString(actor.attack_id) || !nonEmptyString(actor.name)
    || !["group", "campaign"].includes(actor.type)
    || !stringArray(actor.aliases)
    || typeof actor.description !== "string"
    || !nonNegativeInteger(actor.technique_count)) throw new Error("Plan actor record is invalid");
  if (!uniqueStrings(data.domains) || !data.domains.length || data.domains.some(domain => !allowedDomains.includes(domain))) throw new Error("Plan contains an invalid ATT&CK domain");
  const scopeKeys = ["command_platform", "include_pre", "curated_only", "allow_network", "allow_admin", "allow_high_risk", "stages"];
  if (!onlyKeys(data.scope, scopeKeys) || !["windows", "linux", "macos"].includes(data.scope.command_platform)
    || !uniqueStrings(data.scope.stages) || ["include_pre", "curated_only", "allow_network", "allow_admin", "allow_high_risk"].some(key => typeof data.scope[key] !== "boolean")) throw new Error("Plan scope is invalid");
  const context = data.execution_context;
  if (!onlyKeys(context, ["operator", "target"]) || typeof context.operator !== "string" || context.operator.length > 120
    || typeof context.target !== "string" || context.target.length > 200) throw new Error("Plan execution context is invalid");
  const summaryKeys = ["techniques", "runnable", "unsupported", "stages", "curated", "fallback", "marked_run"];
  if (!onlyKeys(data.summary, summaryKeys)
    || summaryKeys.slice(0, 6).some(key => !nonNegativeInteger(data.summary[key]))
    || !uniqueStrings(data.summary.marked_run)) throw new Error("Plan summary is invalid");
  if (!Array.isArray(data.stages) || data.stages.length > 32) throw new Error("Plan stage count is invalid");
  data.stages.forEach(stage => {
    if (plainObject(stage) && Array.isArray(stage.techniques) && stage.techniques.length > 2000) throw new Error("Plan contains too many technique records");
    if (!onlyKeys(stage, ["tactic", "title", "techniques"]) || !nonEmptyString(stage.tactic)
      || !nonEmptyString(stage.title) || !Array.isArray(stage.techniques)) throw new Error("Plan contains an invalid stage");
    stage.techniques.forEach(technique => {
      const techniqueKeys = ["id", "name", "url", "platforms", "command_source", "supported", "command", "run", "execution"];
      if (!onlyKeys(technique, techniqueKeys, ["data_sources", "detection"]) || !nonEmptyString(technique.id) || !nonEmptyString(technique.name)
        || !uriOrNull(technique.url) || !stringArray(technique.platforms)
        || !["curated", "fallback"].includes(technique.command_source)
        || typeof technique.supported !== "boolean" || typeof technique.run !== "boolean"
        || (technique.data_sources !== undefined && !stringArray(technique.data_sources))
        || (technique.detection !== undefined && typeof technique.detection !== "string")) throw new Error("Plan contains an invalid technique record");
      const command = technique.command;
      const commandKeys = ["platform", "command", "note", "cleanup", "risk", "side_effects", "requires_admin", "requires_network", "network_targets", "prerequisites", "expected_telemetry", "expected_output", "timeout_seconds", "rollback", "cleanup_required", "acknowledgment_required"];
      if (!onlyKeys(command, commandKeys, ["unsupported", "restricted", "exercise_kind", "fidelity", "evidence_source", "telemetry_acceptance"])
        || !["platform", "command", "note", "cleanup", "expected_telemetry", "expected_output", "rollback"].every(key => typeof command[key] === "string")
        || command.command.length > 10000 || !["none", "low", "medium", "high"].includes(command.risk)
        || !uniqueStrings(command.side_effects) || !uniqueStrings(command.network_targets) || !stringArray(command.prerequisites)
        || !["requires_admin", "requires_network", "cleanup_required", "acknowledgment_required"].every(key => typeof command[key] === "boolean")
        || (command.unsupported !== undefined && typeof command.unsupported !== "boolean")
        || (command.restricted !== undefined && typeof command.restricted !== "boolean")
        || (command.exercise_kind !== undefined && command.exercise_kind !== "technique_relevant_bounded")
        || (command.fidelity !== undefined && !FIDELITY_VALUES.includes(command.fidelity))
        || (command.evidence_source !== undefined && command.evidence_source !== "self_reported_receipt")
        || (command.telemetry_acceptance !== undefined && (!plainObject(command.telemetry_acceptance)
          || !onlyKeys(command.telemetry_acceptance, ["technique_id", "scenario", "activity_event_types", "minimum_activity_events", "requirements", "limitation"])
          || command.telemetry_acceptance.technique_id !== technique.id
          || !nonEmptyString(command.telemetry_acceptance.scenario)
          || !uniqueStrings(command.telemetry_acceptance.activity_event_types, { nonEmpty: true })
          || !nonNegativeInteger(command.telemetry_acceptance.minimum_activity_events) || command.telemetry_acceptance.minimum_activity_events < 1
          || !uniqueStrings(command.telemetry_acceptance.requirements, { nonEmpty: true })
          || !nonEmptyString(command.telemetry_acceptance.limitation)))
        || !Number.isInteger(command.timeout_seconds) || command.timeout_seconds < 0 || command.timeout_seconds > 3600) throw new Error("Plan contains an invalid command record");
      const execution = technique.execution;
      if (!onlyKeys(execution, ["outcome"], ["updated_at", "operator", "target", "notes", "cleanup_completed", "run_id", "started_at", "completed_at", "exit_code", "stdout_sha256", "stderr_sha256", "receipt_sha256", "receipt_verified", "telemetry_refs", "evidence_source", "detection_result"])
        || !["not_run", "passed", "failed", "skipped"].includes(execution.outcome)
        || (execution.detection_result !== undefined && !DETECTION_RESULTS.includes(execution.detection_result))
        || (execution.updated_at !== undefined && !dateTime(execution.updated_at))
        || (execution.operator !== undefined && (typeof execution.operator !== "string" || execution.operator.length > 120))
        || (execution.target !== undefined && (typeof execution.target !== "string" || execution.target.length > 200))
        || (execution.notes !== undefined && (typeof execution.notes !== "string" || execution.notes.length > 500))
        || (execution.cleanup_completed !== undefined && typeof execution.cleanup_completed !== "boolean")
        || (execution.run_id !== undefined && (typeof execution.run_id !== "string" || !execution.run_id.length || execution.run_id.length > 128))
        || (execution.started_at !== undefined && !dateTime(execution.started_at))
        || (execution.completed_at !== undefined && !dateTime(execution.completed_at))
        || (execution.exit_code !== undefined && (!Number.isInteger(execution.exit_code) || execution.exit_code < -255 || execution.exit_code > 65535))
        || ["stdout_sha256", "stderr_sha256", "receipt_sha256"].some(key => execution[key] !== undefined && (typeof execution[key] !== "string" || !/^[a-fA-F0-9]{64}$/.test(execution[key])))
        || (execution.receipt_verified !== undefined && typeof execution.receipt_verified !== "boolean")
        || (execution.telemetry_refs !== undefined && (!uniqueStrings(execution.telemetry_refs, { nonEmpty: true }) || execution.telemetry_refs.length > 20 || execution.telemetry_refs.some(ref => ref.length > 500)))
        || (execution.evidence_source !== undefined && !["operator_supplied", "exercise_receipt", "endpoint_verified", "siem_verified"].includes(execution.evidence_source))) throw new Error("Plan execution record is invalid");
    });
  });
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
    ...(command.exercise_kind ? { exercise_kind: command.exercise_kind } : {}),
    ...(command.fidelity ? { fidelity: command.fidelity } : {}),
    ...(command.evidence_source ? { evidence_source: command.evidence_source } : {}),
    ...(command.telemetry_acceptance ? { telemetry_acceptance: command.telemetry_acceptance } : {}),
  };
}

function syncStaticScopeControls() {
  $$("#domainFilter .segmented__btn").forEach(button => {
    const on = state.domains.includes(button.dataset.domain); button.classList.toggle("is-on", on); button.setAttribute("aria-pressed", String(on));
  });
  $$("#cmdPlatform .segmented__btn").forEach(button => {
    const on = button.dataset.plat === state.scope.cmdPlatform; button.classList.toggle("is-on", on); button.setAttribute("aria-pressed", String(on));
  });
  el("optPre").checked = state.scope.includePre;
  el("optCurated").checked = state.scope.curatedOnly;
  el("optNetwork").checked = state.scope.allowNetwork;
  el("optAdmin").checked = state.scope.allowAdmin;
  el("optHighRisk").checked = state.scope.allowHighRisk;
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
  if (list.length <= ACTOR_PAGE_SIZE) state.actorShowAll = false;
  renderActorGrid();
}
function renderFeatured() {
  const wrap = el("featuredChips");
  const chips = FEATURED.map(id => state.actors.find(a => a.attack_id === id)).filter(Boolean);
  wrap.innerHTML = chips.map(a => `<button type="button" class="fchip" data-id="${escapeHtml(a.stix_id)}">${escapeHtml(a.name)}</button>`).join("");
  $$(".fchip", wrap).forEach(c => c.addEventListener("click", () => { selectActor(c.dataset.id); }));
  el("featured").classList.toggle("is-empty", chips.length === 0);
}
function renderActorGrid() {
  const grid = el("actorGrid");
  const visible = state.actorShowAll || state.filtered.length <= ACTOR_PAGE_SIZE
    ? state.filtered
    : state.filtered.slice(0, ACTOR_PAGE_SIZE);
  el("actorEmpty").hidden = state.filtered.length > 0;
  el("actorResults").textContent = `${state.filtered.length} ${state.filtered.length === 1 ? "result" : "results"}`;
  const more = el("actorMore");
  more.hidden = state.filtered.length <= ACTOR_PAGE_SIZE || state.actorShowAll;
  el("actorShowAll").textContent = `Show all ${state.filtered.length} actors`;
  grid.innerHTML = visible.map(a => `
    <button type="button" class="actorcard ${state.selectedId === a.stix_id ? "is-selected" : ""}" data-id="${escapeHtml(a.stix_id)}" aria-label="Select ${escapeHtml(a.name)}, ${escapeHtml(a.attack_id)}, ${a.technique_count} techniques" aria-pressed="${state.selectedId === a.stix_id}">
      <div class="actorcard__top">
        <div>
          <div class="actorcard__name">${escapeHtml(a.name)}</div>
          <div class="actorcard__id">${escapeHtml(a.attack_id)}</div>
        </div>
        <span class="tag tag--${escapeHtml(a.type)}">${escapeHtml(a.type)}</span>
      </div>
      ${a.aliases.length ? `<div class="actorcard__aka">aka ${escapeHtml(a.aliases.slice(0, 4).join(", "))}</div>` : ""}
      <div class="actorcard__desc">${escapeHtml(cleanDescription(a.description) || "No description available.")}</div>
      <div class="actorcard__foot">
        <span class="ttpcount">${a.technique_count} <span>techniques</span></span>
        <span class="actorcard__pick">${state.selectedId === a.stix_id ? '<svg class="icon"><use href="#i-check"/></svg> Selected' : "Select"}</span>
      </div>
    </button>`).join("");
  $$(".actorcard", grid).forEach(c => {
    c.addEventListener("click", () => selectActor(c.dataset.id));
    c.addEventListener("dblclick", () => {
      selectActor(c.dataset.id);
      if (state.selectedId) goTo(2);
    });
  });
}
function recommendedActor() {
  for (const id of FEATURED) {
    const actor = state.actors.find(a => a.attack_id === id);
    if (actor) return actor;
  }
  return state.actors[0] || null;
}
function startRecommended() {
  if (!el("setupError").hidden) return;
  const actor = recommendedActor();
  if (!actor) { toast("No actors are loaded yet", "error"); return; }
  const changed = state.selectedId !== actor.stix_id;
  state.selectedId = actor.stix_id;
  state.selectedActor = actor;
  if (changed) { state.workflow = null; state.stage = 0; state.maxStep = 1; }
  persistSession();
  goTo(2);
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
  persistSession();
  // Smooth scroll the selected card into view when chosen via chip
  const card = document.querySelector(`.actorcard[data-id="${CSS.escape(id)}"]`);
  if (card && state.step === 1) card.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function loadWorkflowThen(cb, { keepScope = false } = {}) {
  showLoader(`Building ${state.selectedActor.name}'s lab plan…`, "Resolving mapped techniques from the live ATT&CK catalog.");
  try {
    const data = await apiJson(`/api/workflow/${encodeURIComponent(state.selectedId)}?${domainQuery()}`);
    if (!Array.isArray(data.stages) || !data.metadata) throw new Error("Workflow response is incomplete");
    state.workflow = data;
    state.dataVersion = data.metadata.data_version || state.dataVersion;
    TACTIC_ORDER = data.kill_chain.map(item => item.tactic);
    if (!keepScope) state.scope.tactics = new Set(TACTIC_ORDER);
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

function guessPlatform() {
  const ua = (navigator.userAgent || "").toLowerCase();
  const plat = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "").toLowerCase();
  if (/mac/.test(plat) || /mac os/.test(ua)) return "macos";
  if (/win/.test(plat) || /windows/.test(ua)) return "windows";
  if (/linux/.test(plat) || /linux/.test(ua) || /cros/.test(ua)) return "linux";
  return "";
}
function renderPlatformHint() {
  const hint = el("platformHint");
  if (!hint) return;
  const guessed = guessPlatform();
  if (!guessed || guessed === state.scope.cmdPlatform) { hint.hidden = true; hint.textContent = ""; return; }
  hint.hidden = false;
  hint.innerHTML = `This browser looks like <b>${titleCase(guessed)}</b>. Commands currently target <b>${titleCase(state.scope.cmdPlatform)}</b> — switch only if that is the lab OS you will type on. <button type="button" class="linkbtn" id="useGuessedPlat">Use ${titleCase(guessed)}</button>`;
  el("useGuessedPlat").addEventListener("click", () => {
    state.scope.cmdPlatform = guessed;
    $$("#cmdPlatform .segmented__btn").forEach(button => {
      const on = button.dataset.plat === guessed;
      button.classList.toggle("is-on", on);
      button.setAttribute("aria-pressed", String(on));
    });
    loadRunState();
    renderScope();
  });
}
function renderScope() {
  buildTacticGrid();
  renderPlatformHint();
  const p = filteredPlan();
  const sc = state.scope;
  el("recordOperator").value = state.recordContext.operator;
  el("recordTarget").value = state.recordContext.target;
  el("optNetwork").checked = state.scope.allowNetwork;
  el("optAdmin").checked = state.scope.allowAdmin;
  el("optHighRisk").checked = state.scope.allowHighRisk;
  el("scopeSummary").innerHTML = `
    <h4>Plan preview</h4>
    <p class="panel__desc" style="margin-bottom:12px">${p.runnable ? `${p.runnable} lab tests ready on ${titleCase(sc.cmdPlatform)}.` : "No runnable tests with this scope — switch platform or enable a safety option."}</p>
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
  persistSession();
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
  const selectable = selectableStages();
  el("stagesAll").textContent =
    selectable.length && selectable.every(t => state.scope.tactics.has(t)) ? "Clear all" : "Select all";
}
function selectableStages() {
  if (!state.workflow) return [];
  return state.workflow.stages.map(s => s.tactic)
    .filter(t => state.scope.includePre || !PRE_TACTICS.includes(t));
}
function toggleAllStages() {
  const present = selectableStages();
  const allOn = present.length > 0 && present.every(t => state.scope.tactics.has(t));
  present.forEach(t => allOn ? state.scope.tactics.delete(t) : state.scope.tactics.add(t));
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
function cleanDescription(s) {
  return stripMd(s)
    .replace(/\[([^\]]+)\]\([^)]*$/g, "$1")
    .replace(/\(Citation:[^)]+\)/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}
function runbookSafe(s) { return String(s || "").replace(/[\r\n&|<>^]+/g, " ").trim(); }
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function toast(msg, kind = "success") { const t = el("toast"); t.innerHTML = `<svg class="icon"><use href="#${kind === "error" ? "i-x" : "i-check"}"/></svg>${escapeHtml(msg)}`; t.hidden = false; requestAnimationFrame(() => t.classList.add("is-show")); clearTimeout(t._t); t._t = setTimeout(() => { t.classList.remove("is-show"); t.hidden = true; }, kind === "error" ? 5200 : 2800); }
function showLoader(txt, detail = "") { el("loaderText").textContent = txt || "Working"; el("loaderDetail").textContent = detail; el("loader").hidden = false; }
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
let runStateWarned = false;
function sessionSnapshot() {
  if (!state.selectedId || state.step < 1) return null;
  return {
    selectedId: state.selectedId,
    selectedActor: state.selectedActor,
    domains: state.domains,
    dataVersion: state.dataVersion,
    step: state.step,
    stage: state.stage,
    maxStep: state.maxStep,
    scope: {
      cmdPlatform: state.scope.cmdPlatform,
      tactics: [...state.scope.tactics],
      includePre: state.scope.includePre,
      curatedOnly: state.scope.curatedOnly,
      allowNetwork: state.scope.allowNetwork,
      allowAdmin: state.scope.allowAdmin,
      allowHighRisk: state.scope.allowHighRisk,
    },
    typeFilter: state.typeFilter,
    sort: state.sort,
  };
}
function readSession() {
  try {
    const stored = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    if (!plainObject(stored) || !nonEmptyString(stored.selectedId) || !plainObject(stored.selectedActor)) return null;
    if (!nonEmptyString(stored.selectedActor.name) || !nonEmptyString(stored.selectedActor.attack_id)) return null;
    return stored;
  } catch { return null; }
}
function persistSession() {
  try {
    const snapshot = sessionSnapshot();
    if (!snapshot) return;
    localStorage.setItem(SESSION_KEY, JSON.stringify(snapshot));
  } catch { /* run-state saver already warns when storage is unavailable */ }
}
function clearSession() {
  try { localStorage.removeItem(SESSION_KEY); } catch { /* ignore */ }
  renderWelcomeActions();
}
function renderWelcomeActions() {
  const button = el("resumeSessionBtn");
  const session = readSession();
  if (button) {
    if (!session) button.hidden = true;
    else {
      button.hidden = false;
      button.textContent = `Resume ${session.selectedActor.name} plan`;
    }
  }
  const rec = el("recommendedBtn");
  if (!rec) return;
  const actor = recommendedActor();
  rec.hidden = !actor || !el("setupError").hidden;
  rec.textContent = actor ? `Start with ${actor.name}` : "Start with a recommended actor";
}
function restoreScopeFromSession(session) {
  const scope = session.scope || {};
  state.scope.cmdPlatform = ["windows", "linux", "macos"].includes(scope.cmdPlatform) ? scope.cmdPlatform : "windows";
  state.scope.includePre = Boolean(scope.includePre);
  state.scope.curatedOnly = Boolean(scope.curatedOnly);
  state.scope.allowNetwork = Boolean(scope.allowNetwork);
  state.scope.allowAdmin = Boolean(scope.allowAdmin);
  state.scope.allowHighRisk = Boolean(scope.allowHighRisk);
  const allowed = new Set(killChainOrder());
  const saved = Array.isArray(scope.tactics) ? scope.tactics.filter(item => allowed.has(item)) : [...allowed];
  state.scope.tactics = new Set(saved.length ? saved : allowed);
  syncStaticScopeControls();
}
async function resumeSession() {
  const session = readSession();
  if (!session) { toast("No saved plan was found in this browser", "error"); return; }
  state.domains = Array.isArray(session.domains) && session.domains.length ? session.domains : ["enterprise"];
  state.typeFilter = session.typeFilter || "all";
  state.sort = session.sort || "name";
  state.stage = Number.isInteger(session.stage) ? session.stage : 0;
  state.maxStep = Number.isInteger(session.maxStep) ? session.maxStep : 1;
  restoreScopeFromSession(session);
  $$("#typeFilter .segmented__btn").forEach(button => {
    const on = button.dataset.type === state.typeFilter;
    button.classList.toggle("is-on", on);
    button.setAttribute("aria-pressed", String(on));
  });
  el("sortSel").value = state.sort;
  showLoader(`Resuming ${session.selectedActor.name}…`, "Reloading ATT&CK data and restoring this browser's evidence.");
  try {
    await loadActors(true);
    const actor = state.actors.find(item => item.stix_id === session.selectedId);
    if (!actor) {
      clearSession();
      throw new Error("The saved actor is not in the current ATT&CK data");
    }
    state.selectedId = actor.stix_id;
    state.selectedActor = actor;
    const targetStep = Math.min(Math.max(session.step || 1, 1), 4);
    if (targetStep >= 2) {
      await loadWorkflowThen(() => {
        restoreScopeFromSession(session);
        loadRunState();
        state.maxStep = Math.max(session.maxStep || targetStep, targetStep);
        state.stage = session.stage || 0;
        goTo(targetStep);
        if (session.dataVersion && session.dataVersion !== state.dataVersion) {
          toast("ATT&CK data version changed since this plan was saved; review commands before use");
        } else {
          toast(`Resumed ${actor.name}`);
        }
      }, { keepScope: true });
    } else {
      applyFilter();
      goTo(1);
      toast(`Resumed ${actor.name}`);
    }
  } catch (error) {
    toast(error.message || "The saved plan could not be resumed", "error");
  } finally {
    hideLoader();
  }
}
function markSaveStatus(kind) {
  const chip = el("saveStatus");
  if (!chip) return;
  chip.classList.toggle("is-saving", kind === "saving");
  chip.classList.toggle("is-error", kind === "error");
  if (kind === "error") chip.textContent = "Not saved in this browser";
  else if (kind === "saving") chip.textContent = "Saving";
  else chip.textContent = "Saved in this browser";
}
function saveRunState() {
  persistSession();
  markSaveStatus("saving");
  try {
    localStorage.setItem(runKey(), JSON.stringify({ records: state.records, context: state.recordContext }));
    markSaveStatus("saved");
  } catch {
    // Private-browsing modes and full quotas make local storage unavailable.
    // Saving is best-effort, but the operator must know their evidence is not
    // being retained rather than discover it after closing the tab.
    markSaveStatus("error");
    if (runStateWarned) return;
    runStateWarned = true;
    toast("Progress can't be saved in this browser — export the plan to keep your records", "error");
  }
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
    const doneCount = runnable.filter(t => state.run.has(t.attack_id)).length;
    const done = runnable.length > 0 && doneCount === runnable.length;
    return `<button type="button" class="railitem ${i === state.stage ? "is-active" : ""}" data-i="${i}" aria-current="${i === state.stage ? "step" : "false"}">
      <span class="railitem__num" style="background:${tacticColor(s.tactic)}">${i + 1}</span>
      <span class="railitem__name">${escapeHtml(s.title)}</span>
      <span class="railitem__meta">${runnable.length ? `${doneCount}/${runnable.length}` : s.techniques.length}</span>
      ${done ? '<span class="railitem__done"><svg class="icon"><use href="#i-check"/></svg></span>' : ""}
    </button>`;
  }).join("");
  $$(".railitem", rail).forEach(b => b.addEventListener("click", () => { state.stage = +b.dataset.i; state.focusedTech = 0; renderRail(); renderStage(); }));
}
function stageTechniques(stage) {
  return [...stage.techniques].sort((a, b) => Number(Boolean(a._cmd.unsupported)) - Number(Boolean(b._cmd.unsupported)));
}
function renderStage() {
  const p = filteredPlan();
  const s = p.stages[state.stage];
  const body = el("stageBody");
  if (!s) { body.innerHTML = `<div class="emptystate">No techniques in scope.</div>`; return; }
  const techniques = stageTechniques(s);
  const color = tacticColor(s.tactic);
  body.innerHTML = `
    <div class="stagepanel__head">
      <span class="stagepanel__badge" style="background:${color}">${state.stage + 1}</span>
      <h3>${escapeHtml(s.title)}</h3>
    </div>
    <p class="stagepanel__desc">${escapeHtml(TACTIC_META[s.tactic] || "")} · ${s.techniques.length} technique${s.techniques.length !== 1 ? "s" : ""}</p>
    <p class="kbdhint">On this stage: copy a command, run it on your lab host, then record the result. j / k move · c copies.</p>
    <div class="techlist">${techniques.map(renderTech).join("")}</div>
    <div class="stagenav">
      <button type="button" class="btn btn--ghost" ${state.stage === 0 ? "disabled" : ""} id="prevStage"><svg class="icon"><use href="#i-arrow-l"/></svg> Previous stage</button>
      <button type="button" class="btn" ${state.stage >= p.stages.length - 1 ? "disabled" : ""} id="nextStage">Next stage <svg class="icon"><use href="#i-arrow-r"/></svg></button>
    </div>`;

  $$(".techcard__check", body).forEach(c => c.addEventListener("click", () => toggleRun(c.dataset.id)));
  $$(".copybtn", body).forEach(b => b.addEventListener("click", () => copyCmd(b)));
  $$(".techcard", body).forEach((card, index) => card.addEventListener("click", () => setPlanFocus(index)));
  $$(".evidence__outcome", body).forEach(control => control.addEventListener("change", () => {
    updateEvidence(control.dataset.id, { outcome: control.value }, false);
    syncCardRunState(control.dataset.id);
  }));
  $$(".evidence__detection", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { detection_result: control.value }, false)));
  $$(".evidence__note", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { notes: control.value.trim() }, false)));
  $$(".evidence__cleanup", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { cleanup_completed: control.checked }, false)));
  $$(".evidence__field", body).forEach(control => control.addEventListener("change", () => {
    let value = control.value.trim();
    if (control.dataset.key === "exit_code") value = value === "" ? undefined : Number(value);
    if (control.dataset.key === "telemetry_refs") value = [...new Set(value.split(/[,\n]/).map(item => item.trim()).filter(Boolean))];
    if (["started_at", "completed_at"].includes(control.dataset.key) && value && !dateTime(value)) { toast("Use a valid ISO 8601 timestamp", "error"); return; }
    if (["stdout_sha256", "stderr_sha256"].includes(control.dataset.key) && value && !/^[a-fA-F0-9]{64}$/.test(value)) { toast("SHA-256 values must contain 64 hexadecimal characters", "error"); return; }
    if (value === "" && control.dataset.key !== "telemetry_refs") value = undefined;
    updateEvidence(control.dataset.id, { [control.dataset.key]: value }, false);
  }));
  $$(".evidence__source", body).forEach(control => control.addEventListener("change", () => updateEvidence(control.dataset.id, { evidence_source: control.value }, false)));
  $$(".receipt__import", body).forEach(button => button.addEventListener("click", async () => {
    const receipt = button.closest(".evidenceproof").querySelector(".receipt__json").value;
    await importExerciseReceipt(button.dataset.id, receipt);
  }));
  const prev = el("prevStage"), next = el("nextStage");
  if (prev) prev.addEventListener("click", () => { if (state.stage > 0) { state.stage--; state.focusedTech = 0; renderRail(); renderStage(); scrollPlanTop(); } });
  if (next) next.addEventListener("click", () => { if (state.stage < p.stages.length - 1) { state.stage++; state.focusedTech = 0; renderRail(); renderStage(); scrollPlanTop(); } });
  setPlanFocus(Math.min(state.focusedTech, Math.max(0, techniques.length - 1)));
}
function scrollPlanTop() { el("stage").scrollTo({ top: 0, behavior: "smooth" }); }

function renderTech(t) {
  const c = t._cmd;
  const run = state.run.has(t.attack_id);
  const record = state.records[t.attack_id] || {};
  const unsupported = Boolean(c.unsupported);
  const source = unsupported ? "unsupported" : t.command_source;
  const fidelity = fidelityMeta(c, unsupported);
  const effects = (c.side_effects || []).map(titleCase).join(", ");
  const risk = c.risk || "unknown";
  const tid = escapeHtml(t.attack_id);
  return `
  <div class="techcard ${run ? "is-run" : ""}" data-tid="${tid}">
    <div class="techcard__main">
      <button type="button" class="techcard__check" data-id="${tid}" title="${unsupported ? "No test available for this platform" : "Mark as run"}" aria-label="${unsupported ? `No ${tid} test available for this platform` : `Mark ${tid} as run`}" aria-pressed="${run}" ${unsupported ? "disabled" : ""}><svg class="icon"><use href="#i-check"/></svg></button>
      <div class="techcard__info">
        <div class="techcard__row">
          <a class="techcard__id" href="${safeUrl(t.url)}" target="_blank" rel="noopener">${tid} <svg class="icon"><use href="#i-external"/></svg></a>
          <span class="techcard__name">${escapeHtml(t.name)}</span>
          ${t.is_subtechnique ? '<span class="techcard__sub">sub-technique</span>' : ""}
        </div>
        ${(t.platforms || []).length ? `<div class="techcard__plats">${t.platforms.slice(0, 5).map(p => `<span class="plat">${escapeHtml(p)}</span>`).join("")}</div>` : ""}
      </div>
    </div>
    <div class="command ${unsupported ? "cmd--unsupported" : ""}">
      <div class="command__bar">
        <span class="command__label">Lab command</span>
        <span class="srcbadge srcbadge--${fidelity.cls}">${fidelity.label}</span>
        ${source === "fallback" ? '<span class="srcbadge srcbadge--fallback">fallback</span>' : ""}
      </div>
      <div class="cmd">
        <div class="cmd__head">
          <span class="cmd__plat">${escapeHtml(c.platform)}</span>
          <button type="button" class="copybtn" data-cmd="${escapeHtml(c.command)}" data-risk="${escapeHtml(risk)}" data-ack="${Boolean(c.acknowledgment_required)}" ${unsupported ? "disabled" : ""}><svg class="icon"><use href="#i-copy"/></svg> Copy command</button>
        </div>
        <pre class="cmd__code">${escapeHtml(c.command)}</pre>
        ${c.note ? `<p class="cmd__note">${escapeHtml(c.note)}</p>` : ""}
        ${c.cleanup ? `<p class="cmd__cleanup"><b>cleanup</b> <code>${escapeHtml(c.cleanup)}</code> <button type="button" class="copybtn" data-cmd="${escapeHtml(c.cleanup)}" data-risk="low" data-ack="false" ${unsupported ? "disabled" : ""}><svg class="icon"><use href="#i-copy"/></svg> Copy cleanup</button></p>` : ""}
      </div>
      ${unsupported ? "" : `<div class="safety safety--${risk}">
        <div class="safety__badges"><span class="riskbadge riskbadge--${risk}">${escapeHtml(risk)} risk</span>${c.requires_admin ? '<span class="riskbadge">admin</span>' : ''}${c.requires_network ? '<span class="riskbadge">network</span>' : ''}${c.cleanup_required ? '<span class="riskbadge">cleanup required</span>' : ''}</div>
        <div class="safety__grid">
        <div><b>Effects:</b> ${escapeHtml(effects || "Not classified")} · <b>Expected:</b> ${escapeHtml(c.expected_telemetry || "Verify relevant telemetry")}</div>
        ${c.fidelity === "bounded_synthetic" ? `<div>Bounded synthetic exercise — a safe analogue, not the full ATT&amp;CK behaviour. The JSON receipt is self-reported; correlate it with endpoint or SIEM telemetry.</div>` : ""}
        ${c.fidelity === "lab_proxy" ? `<div>Lab proxy — locates, echoes, or approximates related telemetry rather than reproducing the full technique.</div>` : ""}
        ${c.telemetry_acceptance ? `<div><b>Independent pass gate:</b> marker + ${c.telemetry_acceptance.minimum_activity_events} ${escapeHtml(c.telemetry_acceptance.activity_event_types.join(" or "))} event(s) on the same host and receipt time window.</div>` : ""}
        ${(c.network_targets || []).length ? `<div><b>Network targets:</b> ${escapeHtml(c.network_targets.join(", "))}</div>` : ""}
        ${(c.prerequisites || []).length ? `<div><b>Prerequisites:</b> ${escapeHtml(c.prerequisites.join("; "))}</div>` : ""}
        ${c.expected_output ? `<div><b>Expected output:</b> ${escapeHtml(c.expected_output)}</div>` : ""}
        ${c.timeout_seconds ? `<div><b>Timeout:</b> ${c.timeout_seconds}s</div>` : ""}
        ${c.rollback ? `<div><b>Rollback:</b> ${escapeHtml(c.rollback)}</div>` : ""}
        </div>
      </div>`}
      ${unsupported ? "" : `<div class="evidence">
        <label class="evidence__pair">Command
          <select class="evidence__outcome" data-id="${t.attack_id}" aria-label="Outcome for ${t.attack_id}">
            ${[["not_run","Not run"],["passed","Ran"],["failed","Failed"],["skipped","Skipped"]].map(([value,label]) => `<option value="${value}" ${record.outcome === value || (!record.outcome && value === "not_run") ? "selected" : ""}>${label}</option>`).join("")}
          </select>
        </label>
        <label class="evidence__pair">Detection
          <select class="evidence__detection" data-id="${t.attack_id}" aria-label="Detection for ${t.attack_id}">
            ${DETECTION_RESULTS.map(value => `<option value="${value}" ${(record.detection_result || "not_assessed") === value ? "selected" : ""}>${DETECTION_LABELS[value]}</option>`).join("")}
          </select>
        </label>
        <input class="evidence__note" data-id="${t.attack_id}" maxlength="500" value="${escapeHtml(record.notes || "")}" placeholder="Evidence or observation (no secrets)" aria-label="Evidence note for ${t.attack_id}" />
        <label class="cleanupcheck"><input type="checkbox" class="evidence__cleanup" data-id="${t.attack_id}" ${record.cleanup_completed ? "checked" : ""} ${c.cleanup ? "" : "disabled"}/> cleanup verified</label>
      </div>
      ${(t.description || (t.data_sources || []).length || t.detection) ? `<details class="techcard__more"><summary>ATT&amp;CK context</summary>
        ${t.description ? `<p class="techcard__desc">${escapeHtml(cleanDescription(t.description))}</p>` : ""}
        ${(t.data_sources || []).length ? `<div class="techcard__plats">${t.data_sources.slice(0, 8).map(item => `<span class="plat plat--source">${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        ${t.detection ? `<p class="techcard__detect"><b>ATT&amp;CK detection:</b> ${escapeHtml(cleanDescription(t.detection))}</p>` : ""}
      </details>` : ""}
      <details class="evidenceproof">
        <summary>Execution proof ${record.receipt_verified ? '<span class="proofbadge">receipt digest verified (self-reported)</span>' : ""}</summary>
        <p>A receipt proves this runner produced the recorded events. Correlate its run ID and timestamps with endpoint or SIEM telemetry for independent proof.</p>
        <div class="evidenceproof__grid">
          <label>Run ID<input class="evidence__field" data-id="${t.attack_id}" data-key="run_id" maxlength="128" value="${escapeHtml(record.run_id || "")}" /></label>
          <label>Exit code<input class="evidence__field" data-id="${t.attack_id}" data-key="exit_code" type="number" min="-255" max="65535" value="${record.exit_code ?? ""}" /></label>
          <label>Started (ISO 8601)<input class="evidence__field" data-id="${t.attack_id}" data-key="started_at" value="${escapeHtml(record.started_at || "")}" /></label>
          <label>Completed (ISO 8601)<input class="evidence__field" data-id="${t.attack_id}" data-key="completed_at" value="${escapeHtml(record.completed_at || "")}" /></label>
          <label>stdout SHA-256<input class="evidence__field" data-id="${t.attack_id}" data-key="stdout_sha256" maxlength="64" value="${escapeHtml(record.stdout_sha256 || "")}" /></label>
          <label>stderr SHA-256<input class="evidence__field" data-id="${t.attack_id}" data-key="stderr_sha256" maxlength="64" value="${escapeHtml(record.stderr_sha256 || "")}" /></label>
          <label>Evidence source<select class="evidence__source" data-id="${t.attack_id}" aria-label="Evidence source for ${t.attack_id}">${[["operator_supplied","Operator supplied"],["exercise_receipt","Exercise receipt"],["endpoint_verified","Endpoint verified"],["siem_verified","SIEM verified"]].map(([value,label]) => `<option value="${value}" ${record.evidence_source === value ? "selected" : ""}>${label}</option>`).join("")}</select></label>
          <label>Telemetry references<textarea class="evidence__field" data-id="${t.attack_id}" data-key="telemetry_refs" maxlength="10000" placeholder="SIEM event IDs or endpoint links, one per line">${escapeHtml((record.telemetry_refs || []).join("\n"))}</textarea></label>
        </div>
        ${c.exercise_kind === "technique_relevant_bounded" ? `<label class="receiptlabel">Exercise receipt JSON<textarea class="receipt__json" aria-label="Exercise receipt for ${t.attack_id}" placeholder="Paste the JSON emitted by the lab command"></textarea></label><button type="button" class="btn btn--ghost receipt__import" data-id="${t.attack_id}">Verify and import receipt</button>` : ""}
      </details>`}
    </div>
  </div>`;
}
function planCard(tid) {
  return document.querySelector(`.techcard[data-tid="${CSS.escape(tid)}"]`);
}
function syncCardRunState(tid) {
  const card = planCard(tid);
  if (!card) return;
  const run = state.run.has(tid);
  const record = state.records[tid] || {};
  card.classList.toggle("is-run", run);
  const check = card.querySelector(".techcard__check");
  if (check) check.setAttribute("aria-pressed", String(run));
  const outcome = card.querySelector(".evidence__outcome");
  if (outcome) outcome.value = record.outcome || "not_run";
}
function syncCardEvidence(tid) {
  const card = planCard(tid);
  if (!card) return;
  syncCardRunState(tid);
  const record = state.records[tid] || {};
  const detection = card.querySelector(".evidence__detection");
  if (detection) detection.value = record.detection_result || "not_assessed";
  const notes = card.querySelector(".evidence__note");
  if (notes && document.activeElement !== notes) notes.value = record.notes || "";
  const cleanup = card.querySelector(".evidence__cleanup");
  if (cleanup) cleanup.checked = Boolean(record.cleanup_completed);
  card.querySelectorAll(".evidence__field").forEach(field => {
    if (document.activeElement === field) return;
    const key = field.dataset.key;
    let value = record[key];
    if (key === "telemetry_refs") value = Array.isArray(value) ? value.join("\n") : "";
    else if (value === undefined || value === null) value = "";
    field.value = value;
  });
  const source = card.querySelector(".evidence__source");
  if (source && record.evidence_source) source.value = record.evidence_source;
  const summary = card.querySelector(".evidenceproof > summary");
  if (summary && record.receipt_verified && !summary.querySelector(".proofbadge")) {
    const badge = document.createElement("span");
    badge.className = "proofbadge";
    badge.textContent = "receipt digest verified (self-reported)";
    summary.appendChild(badge);
  }
}
function setPlanFocus(index) {
  const cards = $$(".techcard", el("stageBody"));
  if (!cards.length) { state.focusedTech = 0; return; }
  state.focusedTech = Math.max(0, Math.min(index, cards.length - 1));
  cards.forEach((card, i) => card.classList.toggle("is-focused", i === state.focusedTech));
}
function handlePlanKeys(e) {
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  if (el("confirmDialog")?.open || el("authDialog")?.open || el("helpDialog")?.open) return;
  if (e.target.matches("input,select,textarea,a,[contenteditable]")) return;
  const cards = $$(".techcard", el("stageBody"));
  if (!cards.length) return;
  if (e.key === "j" || e.key === "J") {
    e.preventDefault();
    setPlanFocus(state.focusedTech + 1);
    cards[state.focusedTech]?.scrollIntoView({ block: "nearest" });
  } else if (e.key === "k" || e.key === "K") {
    e.preventDefault();
    setPlanFocus(state.focusedTech - 1);
    cards[state.focusedTech]?.scrollIntoView({ block: "nearest" });
  } else if (e.key === "c" || e.key === "C") {
    const button = cards[state.focusedTech]?.querySelector(".cmd__head .copybtn:not(:disabled)");
    if (button) { e.preventDefault(); copyCmd(button); }
  }
}
function toggleRun(tid) {
  if (!filteredPlan().runnableIds.has(tid)) return;
  updateEvidence(tid, { outcome: state.run.has(tid) ? "not_run" : "passed" }, false);
  syncCardRunState(tid);
}
function updateEvidence(tid, changes, rerender = false) {
  const previous = state.records[tid] || {};
  const next = { ...previous, ...changes, updated_at: new Date().toISOString(), operator: state.recordContext.operator, target: state.recordContext.target };
  Object.entries(changes).forEach(([key, value]) => { if (value === undefined) delete next[key]; });
  if (!next.outcome || next.outcome === "not_run") {
    next.outcome = "not_run";
    state.run.delete(tid);
  } else state.run.add(tid);
  if (!DETECTION_RESULTS.includes(next.detection_result)) next.detection_result = "not_assessed";
  state.records[tid] = next;
  saveRunState();
  updateProgress();
  renderRail();
  if (rerender) renderStage();
}
async function importExerciseReceipt(tid, source) {
  try {
    const receipt = JSON.parse(source);
    if (!plainObject(receipt) || receipt.technique_id !== tid || typeof receipt.receipt_sha256 !== "string") throw new Error(`Receipt must be for ${tid}`);
    if (!nonEmptyString(receipt.run_id) || !dateTime(receipt.started_at) || !dateTime(receipt.completed_at)
      || !Number.isInteger(receipt.exit_code) || typeof receipt.cleanup_verified !== "boolean"
      || !["passed", "failed"].includes(receipt.status) || !Array.isArray(receipt.events)) throw new Error("Receipt fields are incomplete or invalid");
    const claimed = receipt.receipt_sha256.toLowerCase();
    const unsigned = { ...receipt };
    delete unsigned.receipt_sha256;
    if (!/^[a-f0-9]{64}$/.test(claimed) || await sha256Hex(canonicalJson(unsigned)) !== claimed) throw new Error("Receipt digest does not match its contents");
    updateEvidence(tid, {
      outcome: receipt.status,
      run_id: receipt.run_id,
      started_at: receipt.started_at,
      completed_at: receipt.completed_at,
      exit_code: receipt.exit_code,
      cleanup_completed: receipt.cleanup_verified,
      receipt_sha256: claimed,
      receipt_verified: true,
      evidence_source: "exercise_receipt",
    }, false);
    syncCardEvidence(tid);
    toast(`Verified and imported ${tid} receipt`);
  } catch (error) {
    toast(error.message || "Receipt import failed", "error");
  }
}
function fidelityMeta(command, unsupported) {
  if (unsupported) return { cls: "unsupported", label: "unsupported" };
  if (command.fidelity === "bounded_synthetic") return { cls: "bounded", label: "bounded synthetic" };
  if (command.fidelity === "lab_proxy") return { cls: "proxy", label: "lab proxy" };
  return { cls: "direct", label: "direct" };
}
async function copyCmd(btn) {
  if (btn.dataset.ack === "true" && !await confirmAction({
    title: `Copy this ${btn.dataset.risk} risk lab command?`,
    description: "Review prerequisites, side effects, and cleanup before copying. AdversaryFlow does not execute the command.",
    detail: btn.dataset.cmd,
    acceptLabel: "Copy command",
    danger: btn.dataset.risk === "high",
  })) return;
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
  const kit = el("executionKitExport");
  const supported = ["windows", "linux", "macos"].includes(state.scope.cmdPlatform);
  kit.disabled = !supported;
  el("executionKitTitle").textContent = `Download ${titleCase(state.scope.cmdPlatform)} execution kit`;
  const hasBounded = p.stages.some(stage => stage.techniques.some(item => item._cmd.fidelity === "bounded_synthetic" && !item._cmd.unsupported));
  const runner = state.scope.cmdPlatform === "windows" ? "PowerShell" : "Bash";
  el("executionKitDescription").textContent = hasBounded
    ? `One ZIP containing the operator CSV, a self-contained ${runner} runner, and a portable exercise script. Direct steps need no extra runtime; bounded synthetic steps need Python 3.10+ beside the kit.`
    : `One ZIP containing the operator CSV and a self-contained ${runner} runner. Direct commands need no AdversaryFlow installation, Python, or network on the destination.`;
}

async function exportPlan(format) {
  const p = filteredPlan();
  const a = state.selectedActor;
  const slug = a.attack_id + "_" + a.name.replace(/[^a-z0-9]+/gi, "_");
  let content, filename, mime;
  if (format === "kit") {
    await exportExecutionKit(p);
    return;
  }
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
async function exportExecutionKit(p) {
  const button = el("executionKitExport");
  const original = button.innerHTML;
  button.disabled = true;
  button.classList.add("is-loading");
  button.innerHTML = '<span class="expcard__ico"><svg class="icon"><use href="#i-refresh"/></svg></span><b>Building verified execution kit…</b><span>Preparing the CSV, portable runner, integrity binding, and evidence workflow.</span>';
  try {
    const response = await fetch("/api/execution-kit", {
      method: "POST",
      headers: csrfHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(buildExportObj(p)),
    });
    if (!response.ok) {
      let message = `Execution kit could not be generated (${response.status})`;
      try { const body = await response.json(); message = body.message || body.error || message; } catch { /* retain readable fallback */ }
      throw new Error(message);
    }
    const disposition = response.headers.get("Content-Disposition") || "";
    const matched = disposition.match(/filename\*?=(?:UTF-8''|\")?([^\";]+)/i);
    const filename = matched ? decodeURIComponent(matched[1].replace(/^\"|\"$/g, "")) : "AdversaryFlow_execution_kit.zip";
    downloadBlob(await response.blob(), filename);
    toast(`Execution kit ready: ${filename}`);
  } catch (error) {
    toast(error.message || "Execution kit generation failed", "error");
  } finally {
    button.innerHTML = original;
    button.classList.remove("is-loading");
    button.disabled = !["windows", "linux", "macos"].includes(state.scope.cmdPlatform);
  }
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
      data_sources: Array.isArray(t.data_sources) ? t.data_sources : [],
      detection: typeof t.detection === "string" ? t.detection : "",
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
      md += `**Detection:** ${record.detection_result || "not_assessed"}\n\n`;
      if (record.run_id) md += `**Execution proof:** run ID \`${record.run_id}\`${record.started_at ? ` · started ${record.started_at}` : ""}${record.completed_at ? ` · completed ${record.completed_at}` : ""}${record.exit_code !== undefined ? ` · exit ${record.exit_code}` : ""}\n\n`;
      if (record.receipt_sha256) md += `**Receipt SHA-256:** \`${record.receipt_sha256}\` (${record.receipt_verified ? "digest verified; self-reported" : "not verified"})\n\n`;
      if (record.stdout_sha256 || record.stderr_sha256) md += `**Captured output hashes:** stdout \`${record.stdout_sha256 || "not recorded"}\` · stderr \`${record.stderr_sha256 || "not recorded"}\`\n\n`;
      if ((record.telemetry_refs || []).length) md += `**Independent telemetry:** ${record.telemetry_refs.join(", ")}\n\n`;
      if ((t.data_sources || []).length) md += `**ATT&CK data sources:** ${t.data_sources.join(", ")}\n\n`;
      if (t.detection) md += `**ATT&CK detection:** ${stripMd(t.detection)}\n\n`;
      if (t.description) md += `${stripMd(t.description)}\n\n`;
      if (c.unsupported) {
        md += `**Unsupported on ${titleCase(state.scope.cmdPlatform)}.** ${c.note}\n\n`;
        return;
      }
      md += `**Fidelity:** ${c.fidelity === "bounded_synthetic" ? "bounded synthetic" : c.fidelity === "lab_proxy" ? "lab proxy" : "direct"}\n\n`;
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
      out += `${comment} Fidelity: ${c.fidelity === "bounded_synthetic" ? "bounded synthetic" : c.fidelity === "lab_proxy" ? "lab proxy" : "direct"}\n`;
      const record = state.records[t.attack_id] || { outcome: "not_run" };
      out += `${comment} Outcome: ${record.outcome}${record.updated_at ? ` at ${record.updated_at}` : ""}\n`;
      out += `${comment} Detection: ${record.detection_result || "not_assessed"}\n`;
      if (record.notes) out += `${comment} Evidence: ${runbookSafe(record.notes)}\n`;
      if (record.run_id) out += `${comment} Run ID: ${runbookSafe(record.run_id)}\n`;
      if (record.receipt_sha256) out += `${comment} Receipt SHA-256: ${runbookSafe(record.receipt_sha256)} (${record.receipt_verified ? "digest verified; self-reported" : "not verified"})\n`;
      (record.telemetry_refs || []).forEach(ref => { out += `${comment} Telemetry: ${runbookSafe(ref)}\n`; });
      if (c.unsupported) {
        out += `${comment} UNSUPPORTED: ${c.note}\n`;
        return;
      }
      if (c.note) out += `${comment}   ${c.note}\n`;
      out += `${comment} COMMAND: ${runbookSafe(c.command)}\n`;
      if (c.cleanup) out += `${comment} MANUAL CLEANUP: ${c.cleanup}\n`;
    });
  });
  return out;
}
function download(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  downloadBlob(blob, filename);
}
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = filename;
  document.body.appendChild(link); link.click(); link.remove();
  URL.revokeObjectURL(url);
}
