/*
 * User acceptance tests — browser rows of the journey map in
 * docs/USER_JOURNEY.md. One test per journey id, named with that id so a
 * failure names the accepted behaviour it broke.
 */
const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const Ajv2020 = require("ajv/dist/2020");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

test.use({ permissions: ["clipboard-read", "clipboard-write"] });

const lowRisk = {
  platform: "windows", command: "whoami", note: "Read-only identity check.",
  cleanup: "", risk: "low", side_effects: ["read_only_or_process_telemetry"],
  requires_admin: false, requires_network: false, network_targets: [],
  prerequisites: ["windows command environment", "authorized disposable lab"],
  expected_telemetry: "Process and command-line telemetry.",
  expected_output: "Current user identity.", timeout_seconds: 60, rollback: "",
  cleanup_required: false, acknowledgment_required: false,
};

const highRisk = {
  ...lowRisk,
  command: "schtasks /Create /TN AFLab /TR cmd.exe /SC ONCE /ST 23:59 /F",
  note: "Creates a lab scheduled task.",
  cleanup: "schtasks /Delete /TN AFLab /F",
  rollback: "schtasks /Delete /TN AFLab /F",
  risk: "high", side_effects: ["changes_local_state"],
  cleanup_required: true, acknowledgment_required: true,
};

const ACTORS = [
  { stix_id: "intrusion-set--uat", attack_id: "G0001", name: "UAT Actor", type: "group", aliases: ["Example"], description: "Fixture actor", technique_count: 2 },
  { stix_id: "intrusion-set--other", attack_id: "G0002", name: "Second Actor", type: "campaign", aliases: [], description: "Second fixture", technique_count: 1 },
];

function technique(id, name, tactic, commands) {
  return {
    stix_id: `attack-pattern--${id}`, attack_id: id, name,
    description: "Fixture technique", tactics: [tactic], platforms: ["Windows"],
    is_subtechnique: id.includes("."), url: `https://attack.mitre.org/techniques/${id}/`,
    commands, command_source: "curated",
  };
}

function workflow(commands = [lowRisk], multiStage = false) {
  const stages = [
    { tactic: "execution", title: "Execution", techniques: [technique("T1059.001", "PowerShell", "execution", commands)] },
  ];
  const killChain = [{ tactic: "execution", title: "Execution" }];
  if (multiStage) {
    stages.push({ tactic: "persistence", title: "Persistence", techniques: [technique("T1547", "Boot or Logon Autostart Execution", "persistence", commands)] });
    stages.push({ tactic: "impact", title: "Impact", techniques: [technique("T1486", "Data Encrypted for Impact", "impact", commands)] });
    killChain.push({ tactic: "persistence", title: "Persistence" }, { tactic: "impact", title: "Impact" });
  }
  const total = stages.length;
  return {
    actor: { stix_id: "intrusion-set--uat", attack_id: "G0001", name: "UAT Actor", type: "group", aliases: ["Example"], description: "Fixture actor" },
    summary: { total_techniques: total, unique_stages: total, curated_commands: total, fallback_commands: 0 },
    kill_chain: killChain, stages,
    metadata: { domains: ["enterprise"], data_version: "enterprise:bundle--uat", version: "0.3.0" },
  };
}

async function interceptApi(page, { commands = [lowRisk], multiStage = false, actors = ACTORS } = {}) {
  await page.route("**/api/session", r => r.fulfill({ json: { csrf_token: "uat-token", version: "0.3.0" } }));
  await page.route("**/api/bootstrap", r => r.fulfill({ json: { status: "ready", runtime: { ready: true, phase: "ready" }, cache: { domains: {} } } }));
  await page.route("**/api/actors?*", r => r.fulfill({ json: { actors, domains: ["enterprise"], data_version: "enterprise:bundle--uat", version: "0.3.0" } }));
  await page.route("**/api/workflow/**", r => r.fulfill({ json: workflow(commands, multiStage) }));
}

async function toScope(page, options) {
  await interceptApi(page, options);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /UAT Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Scope the engagement" })).toBeVisible();
}

function planFile(plan) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "af-uat-")), "plan.json");
  fs.writeFileSync(file, JSON.stringify(plan), "utf-8");
  return file;
}

function validPlan(overrides = {}) {
  return {
    schema_version: "2.0", tool: "AdversaryFlow", tool_version: "0.3.0",
    data_version: "enterprise:bundle--uat", domains: ["enterprise"],
    generated: "2026-09-04T00:00:00.000Z",
    actor: { stix_id: "intrusion-set--uat", attack_id: "G0001", name: "UAT Actor", type: "group", aliases: ["Example"], description: "Fixture actor", technique_count: 1 },
    scope: { command_platform: "windows", include_pre: true, curated_only: false, allow_network: false, allow_admin: false, allow_high_risk: false, stages: ["execution"] },
    execution_context: { operator: "Purple Team", target: "lab-host-01" },
    summary: { techniques: 1, runnable: 1, unsupported: 0, stages: 1, curated: 1, fallback: 0, marked_run: ["T1059.001"] },
    stages: [{ tactic: "execution", title: "Execution", techniques: [{
      id: "T1059.001", name: "PowerShell", url: "https://attack.mitre.org/techniques/T1059/001/",
      platforms: ["Windows"], command_source: "curated", supported: true, command: lowRisk, run: true,
      execution: { outcome: "passed", notes: "Script block logging fired" },
    }] }],
    ...overrides,
  };
}

/* ---------------------------------------------------------------- */

test("J10 — the welcome screen invites the operator to start", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Begin emulation plan/ })).toBeEnabled();
  await expect(page.getByText("AdversaryFlow creates plans; it does not execute commands.")).toBeVisible();
});

test("J11 — the header reports how much ATT&CK data loaded", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await expect(page.locator("#dataStatus")).toHaveText(/^\d+ actors · Enterprise$/);
});

test("J13 — selecting an actor enables the next step", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await expect(page.locator("#actionbarCtx")).toHaveText("Select a threat actor to continue");
  await page.getByRole("button", { name: /UAT Actor/ }).click();
  await expect(page.locator("#actionbarCtx")).toHaveText("Selected: UAT Actor");
  await expect(page.getByRole("button", { name: /^Continue/ })).toBeEnabled();
});

test("J14 — search narrows the actor gallery", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await expect(page.locator(".actorcard")).toHaveCount(2);
  await page.locator("#actorSearch").fill("Second");
  await expect(page.locator(".actorcard")).toHaveCount(1);
  await expect(page.locator("#searchClear")).toBeVisible();
  await page.locator("#searchClear").click();
  await expect(page.locator(".actorcard")).toHaveCount(2);
});

test("J15 — a search matching nothing shows the empty state", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.locator("#actorSearch").fill("zzzzzz-no-such-actor");
  await expect(page.getByText("No actors match your search.")).toBeVisible();
  await expect(page.locator(".actorcard")).toHaveCount(0);
});

test("J17 — the scope screen previews the plan", async ({ page }) => {
  await toScope(page);
  await expect(page.locator("#scopeSummary")).toContainText("UAT Actor");
  await expect(page.locator("#actionbarCtx")).toHaveText("1 runnable · 0 unsupported across 1 stages");
});

test("J18 — switching platform never substitutes another OS", async ({ page }) => {
  await toScope(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator("pre.cmd__code")).toHaveText("whoami");

  await page.getByRole("button", { name: /^Back/ }).click();
  await page.getByRole("button", { name: "Linux", exact: true }).click();
  await expect(page.locator("#scopeSummary")).toContainText("Runnable on Linux");
  await expect(page.locator("#actionbarCtx")).toHaveText("0 runnable · 1 unsupported across 1 stages");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeDisabled();

  await page.locator(".stepper__item", { hasText: "Emulation plan" }).click();
  await expect(page.locator("pre.cmd__code")).toHaveText("No Linux test is available for this technique.");
  await expect(page.getByRole("button", { name: /Copy command/ })).toBeDisabled();
});

test("J19 — clearing every stage empties the plan", async ({ page }) => {
  await toScope(page);
  await expect(page.locator("#stagesAll")).toHaveText("Clear all");
  await page.locator("#stagesAll").click();
  await expect(page.locator("#stagesAll")).toHaveText("Select all");
  await expect(page.locator("#actionbarCtx")).toHaveText("No techniques in scope — enable a stage");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeDisabled();
});

test("J20 — a command above the chosen risk scope is withheld", async ({ page }) => {
  await toScope(page, { commands: [highRisk] });
  await expect(page.locator("#actionbarCtx")).toHaveText("0 runnable · 1 unsupported across 1 stages");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeDisabled();

  // Reach the plan with the risk allowed, then withdraw the allowance.
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /^Back/ }).click();
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await page.locator(".stepper__item", { hasText: "Emulation plan" }).click();

  await expect(page.locator("pre.cmd__code")).toHaveText("Restricted by scope: high-risk commands are disabled.");
  await expect(page.getByRole("button", { name: /Copy command/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Copy cleanup/ })).toBeDisabled();
});

test("J21 — allowing the risk restores the command", async ({ page }) => {
  await toScope(page, { commands: [highRisk] });
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await expect(page.locator("#actionbarCtx")).toHaveText("1 runnable · 0 unsupported across 1 stages");
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator("pre.cmd__code")).toContainText("schtasks /Create /TN AFLab");
});

test("J22 — the plan opens on the first kill-chain stage", async ({ page }) => {
  await toScope(page, { multiStage: true });
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.getByRole("heading", { name: "UAT Actor · G0001" })).toBeVisible();
  await expect(page.locator(".railitem")).toHaveCount(3);
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Execution");
  await expect(page.locator("pre.cmd__code")).toHaveText("whoami");
});

test("J23 — every supported command shows its safety classification", async ({ page }) => {
  await toScope(page, { commands: [highRisk] });
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator(".riskbadge--high")).toHaveText("high risk");
  await expect(page.locator(".safety")).toContainText("Effects:");
  await expect(page.locator(".safety")).toContainText("Expected:");
  await expect(page.locator(".safety")).toContainText("cleanup required");
});

test("J24 — the operator can walk stages forwards and backwards", async ({ page }) => {
  await toScope(page, { multiStage: true });
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.getByRole("button", { name: /Previous stage/ })).toBeDisabled();
  await page.getByRole("button", { name: /Next stage/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Persistence");
  await page.getByRole("button", { name: /Next stage/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Impact");
  await expect(page.getByRole("button", { name: /Next stage/ })).toBeDisabled();
  await page.getByRole("button", { name: /Previous stage/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Persistence");
  await page.locator(".railitem").first().click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Execution");
});

test("J25 — copying a risky command requires acknowledgement", async ({ page }) => {
  const dialogs = [];
  page.on("dialog", d => { dialogs.push(d.message()); d.accept(); });
  await toScope(page, { commands: [highRisk] });
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Copy command/ }).click();
  expect(dialogs.join("")).toContain("This is a high risk lab command.");
  await expect(page.getByRole("status").filter({ hasText: "Command copied to clipboard" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText()))
    .toBe("schtasks /Create /TN AFLab /TR cmd.exe /SC ONCE /ST 23:59 /F");
});

test("J26 — recording an outcome advances the progress indicator", async ({ page }) => {
  await toScope(page, { multiStage: true });
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator("#progressCount")).toHaveText("0 / 3");
  await expect(page.locator("#progressPct")).toHaveText("0%");
  await page.getByLabel("Outcome for T1059.001").selectOption("passed");
  await page.getByLabel("Evidence note for T1059.001").fill("Script block logging fired");
  await expect(page.locator("#progressCount")).toHaveText("1 / 3");
  await expect(page.locator("#progressPct")).toHaveText("33%");
  await expect(page.locator("#actionbarCtx")).toContainText("1 / 3 runnable techniques marked run");
});

test("J27 — unavailable local storage is reported, not swallowed", async ({ page }) => {
  await page.addInitScript(() => {
    Storage.prototype.setItem = () => { throw new Error("storage unavailable"); };
  });
  await toScope(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1059.001").selectOption("passed");
  await expect(page.getByRole("status").filter({ hasText: "Progress can't be saved in this browser" })).toBeVisible();
});

test("J28 — the export screen summarises the finished plan", async ({ page }) => {
  await toScope(page, { multiStage: true });
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1059.001").selectOption("passed");
  await page.getByRole("button", { name: /Finish & export/ }).click();
  await expect(page.getByRole("heading", { name: "Your emulation plan is ready" })).toBeVisible();
  const stats = page.locator(".statbox");
  await expect(stats).toHaveCount(4);
  await expect(stats.nth(0)).toContainText("Techniques");
  await expect(stats.nth(1)).toContainText("Stages");
  await expect(stats.nth(2)).toContainText("Runnable tests");
  await expect(stats.nth(3)).toContainText("Marked run");
  await expect(page.locator("#actionbarCtx")).toHaveText("Plan complete ✓");
});

async function exportAndRead(page, name) {
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name }).click();
  const artifact = await download;
  return { artifact, text: fs.readFileSync(await artifact.path(), "utf-8") };
}

test("J29 — the JSON export validates against the published schema", async ({ page }) => {
  await toScope(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1059.001").selectOption("passed");
  await page.getByLabel("Evidence note for T1059.001").fill("Observed");
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const { artifact, text } = await exportAndRead(page, /JSON/);
  expect(artifact.suggestedFilename()).toBe("AdversaryFlow_G0001_UAT_Actor.json");
  const exported = JSON.parse(text);
  const schema = JSON.parse(fs.readFileSync(path.resolve("schemas/adversaryflow-plan.schema.json"), "utf-8"));
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(schema);
  expect(validate(exported), JSON.stringify(validate.errors)).toBeTruthy();
  expect(exported.stages[0].techniques[0].execution.outcome).toBe("passed");
  expect(exported.stages[0].techniques[0].execution.notes).toBe("Observed");
});

test("J30 — the Markdown export is a readable report", async ({ page }) => {
  await toScope(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1059.001").selectOption("failed");
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const { artifact, text } = await exportAndRead(page, /Markdown report/);
  expect(artifact.suggestedFilename()).toBe("AdversaryFlow_G0001_UAT_Actor.md");
  expect(text).toContain("# AdversaryFlow — UAT Actor (G0001)");
  expect(text).toContain("### T1059.001 — PowerShell");
  expect(text).toContain("**Outcome:** failed");
  expect(text).toContain("whoami");
});

test("J31 — the runbook export contains review metadata and command lines", async ({ page }) => {
  await toScope(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const { artifact, text } = await exportAndRead(page, /Runbook/);
  expect(artifact.suggestedFilename()).toBe("AdversaryFlow_G0001_UAT_Actor_runbook.cmd.txt");
  expect(text).toContain("REM AdversaryFlow runbook — UAT Actor (G0001)");
  expect(text).toContain("REM ===== 1. EXECUTION =====");
  expect(text).toContain("REM Outcome: not_run");
  expect(text.split(/\r?\n/)).toContain("whoami");
});

test("J32 — a saved plan is restored with its evidence", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.setInputFiles("#importPlan", planFile(validPlan()));
  await expect(page.getByRole("status").filter({ hasText: "Plan imported as high-risk" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "UAT Actor · G0001" })).toBeVisible();
  await expect(page.getByLabel("Outcome for T1059.001")).toHaveValue("passed");
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Script block logging fired");
});

test("J33 — a default-scope export round-trips into a runnable plan", async ({ page }) => {
  await toScope(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /JSON/ }).click();
  const exportedPath = await (await download).path();
  expect(JSON.parse(fs.readFileSync(exportedPath, "utf-8")).scope.allow_high_risk).toBe(false);

  await page.goto("/");
  await page.setInputFiles("#importPlan", exportedPath);
  await expect(page.getByRole("heading", { name: "UAT Actor · G0001" })).toBeVisible();
  await expect(page.locator("pre.cmd__code")).toHaveText("whoami");
  await expect(page.locator("pre.cmd__code")).not.toContainText("Restricted by scope");
  await expect(page.locator("#actionbarCtx")).toContainText("/ 1 runnable");
});

test("J34 — an incomplete actor record is refused", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.setInputFiles("#importPlan", planFile(validPlan({ actor: { stix_id: "intrusion-set--uat", technique_count: 1 } })));
  await expect(page.getByRole("status").filter({ hasText: "Plan actor record is invalid" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
});

test("J35 — a plan from another schema version is refused", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.setInputFiles("#importPlan", planFile(validPlan({ schema_version: "1.0" })));
  await expect(page.getByRole("status").filter({ hasText: "This is not an AdversaryFlow 2.0 plan export" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
});

test("J36 — planning another actor resets the picker", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: "ICS / OT" }).click();
  // "UAT Actor" is a group, so filter to Groups to keep it selectable.
  await page.getByRole("button", { name: "Groups", exact: true }).click();
  await page.locator("#sortSel").selectOption("ttps");
  await expect(page.locator(".actorcard")).toHaveCount(1);
  await page.getByRole("button", { name: /UAT Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  await page.getByRole("button", { name: /Plan another actor/ }).click();
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();

  await expect(page.getByRole("button", { name: "Enterprise" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "ICS / OT" })).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#sortSel")).toHaveValue("name");
  await expect(page.locator("#actionbarCtx")).toHaveText("Select a threat actor to continue");
});

test("J37 — a different actor starts with a clean execution record", async ({ page }) => {
  await toScope(page);
  await page.getByLabel("Operator").fill("Purple Team");
  await page.getByLabel("Target").fill("lab-host-01");
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  await page.getByRole("button", { name: /Plan another actor/ }).click();
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Second Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByLabel("Operator")).toHaveValue("");
  await expect(page.getByLabel("Target")).toHaveValue("");
});

test("J38 — a failed setup is reported with a retry", async ({ page }) => {
  let fail = true;
  await page.route("**/api/session", route => fail
    ? route.fulfill({ status: 500, json: { error: "request failed", message: "ATT&CK cache is unreadable", version: "0.3.0" } })
    : route.fulfill({ json: { csrf_token: "uat-token", version: "0.3.0" } }));
  await page.route("**/api/bootstrap", r => r.fulfill({ json: { status: "ready", runtime: { ready: true, phase: "ready" }, cache: { domains: {} } } }));
  await page.route("**/api/actors?*", r => r.fulfill({ json: { actors: ACTORS, domains: ["enterprise"], data_version: "enterprise:bundle--uat", version: "0.3.0" } }));

  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await expect(page.getByText("ATT&CK cache is unreadable")).toBeVisible();
  await expect(page.locator("#dataStatus")).toHaveText("setup needs attention");
  await expect(page.getByRole("button", { name: "Retry setup" })).toBeVisible();

  // J39 — the same session recovers once the fault clears.
  fail = false;
  await page.getByRole("button", { name: "Retry setup" }).click();
  await expect(page.getByRole("button", { name: /UAT Actor/ })).toBeVisible();
  await expect(page.locator("#dataStatus")).toHaveText(/^\d+ actors · Enterprise$/);
});

/* Boundary inputs accepted or refused by the plan-import contract. Driven
 * against the shipped validator in the loaded page, one case per limit. */
test("J34/J35 boundaries — the import contract holds at every documented limit", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");

  const results = await page.evaluate(() => {
    const cmd = { platform: "windows", command: "whoami", note: "", cleanup: "", risk: "low",
      side_effects: [], requires_admin: false, requires_network: false, network_targets: [],
      prerequisites: [], expected_telemetry: "", expected_output: "", timeout_seconds: 60,
      rollback: "", cleanup_required: false, acknowledgment_required: false };
    const actor = { stix_id: "intrusion-set--x", attack_id: "G0001", name: "A", type: "group",
      aliases: [], description: "d", technique_count: 1 };
    const tech = (id = "T1059.001") => ({ id, name: "n", url: null, platforms: [],
      command_source: "curated", supported: true, command: cmd, run: false,
      execution: { outcome: "not_run" } });
    const base = (o = {}) => ({ schema_version: "2.0", tool: "AdversaryFlow", tool_version: "0.3.0",
      data_version: "v", domains: ["enterprise"], generated: "2026-09-04T00:00:00.000Z", actor,
      scope: { command_platform: "windows", include_pre: true, curated_only: false,
        allow_network: false, allow_admin: false, allow_high_risk: false, stages: ["execution"] },
      execution_context: { operator: "", target: "" },
      summary: { techniques: 1, runnable: 1, unsupported: 0, stages: 1, curated: 1, fallback: 0, marked_run: [] },
      stages: [{ tactic: "execution", title: "Execution", techniques: [tech()] }], ...o });
    const manyStages = n => Array.from({ length: n }, (_, i) => ({ tactic: `t${i}`, title: `T${i}`, techniques: [tech()] }));
    const manyTechniques = n => [{ tactic: "execution", title: "Execution",
      techniques: Array.from({ length: n }, (_, i) => tech(`T${1000 + i}`)) }];
    const scope = extra => ({ ...base().scope, ...extra });

    const cases = [
      ["valid plan", base(), null],
      ["schema_version 1.0", base({ schema_version: "1.0" }), "This is not an AdversaryFlow 2.0 plan export"],
      ["foreign tool", base({ tool: "AnotherTool" }), "This is not an AdversaryFlow 2.0 plan export"],
      ["empty tool_version", base({ tool_version: "" }), "Plan is missing its tool or ATT&CK data version"],
      ["empty data_version", base({ data_version: "" }), "Plan is missing its tool or ATT&CK data version"],
      ["invalid generated timestamp", base({ generated: "today" }), "Plan generated timestamp is invalid"],
      ["unknown top-level field", { ...base(), surprise: true }, "Plan contains unknown or missing top-level fields"],
      ["actor without aliases", base({ actor: { ...actor, aliases: undefined } }), "Plan actor record is invalid"],
      ["actor of an unknown type", base({ actor: { ...actor, type: "threat" } }), "Plan actor record is invalid"],
      ["negative technique_count", base({ actor: { ...actor, technique_count: -1 } }), "Plan actor record is invalid"],
      ["actor with unknown field", base({ actor: { ...actor, surprise: true } }), "Plan actor record is invalid"],
      ["unknown domain", base({ domains: ["galaxy"] }), "Plan contains an invalid ATT&CK domain"],
      ["empty domain list", base({ domains: [] }), "Plan contains an invalid ATT&CK domain"],
      ["duplicate domains", base({ domains: ["enterprise", "enterprise"] }), "Plan contains an invalid ATT&CK domain"],
      ["unknown platform", base({ scope: scope({ command_platform: "plan9" }) }), "Plan scope is invalid"],
      ["non-boolean safety flag", base({ scope: scope({ allow_high_risk: "yes" }) }), "Plan scope is invalid"],
      ["duplicate scope stages", base({ scope: scope({ stages: ["execution", "execution"] }) }), "Plan scope is invalid"],
      ["missing execution context", base({ execution_context: undefined }), "Plan execution context is invalid"],
      ["non-string execution context", base({ execution_context: { operator: 1, target: 2 } }), "Plan execution context is invalid"],
      ["operator over 120 chars", base({ execution_context: { operator: "x".repeat(121), target: "" } }), "Plan execution context is invalid"],
      ["negative summary count", base({ summary: { ...base().summary, runnable: -1 } }), "Plan summary is invalid"],
      ["32 stages (limit)", base({ stages: manyStages(32) }), null],
      ["33 stages (over)", base({ stages: manyStages(33) }), "Plan stage count is invalid"],
      ["stage without a title", base({ stages: [{ tactic: "execution", techniques: [tech()] }] }), "Plan contains an invalid stage"],
      ["technique without a name", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), name: "" }] }] }), "Plan contains an invalid technique record"],
      ["platforms not an array", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), platforms: "Windows" }] }] }), "Plan contains an invalid technique record"],
      ["invalid technique URL", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), url: "not a uri" }] }] }), "Plan contains an invalid technique record"],
      ["command of 10000 chars (limit)", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), command: { ...cmd, command: "x".repeat(10000) } }] }] }), null],
      ["command of 10001 chars (over)", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), command: { ...cmd, command: "x".repeat(10001) } }] }] }), "Plan contains an invalid command record"],
      ["command without risk", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), command: { ...cmd, risk: undefined } }] }] }), "Plan contains an invalid command record"],
      ["invalid execution outcome", base({ stages: [{ tactic: "execution", title: "E", techniques: [{ ...tech(), execution: { outcome: "maybe" } }] }] }), "Plan execution record is invalid"],
      ["2000 techniques (limit)", base({ stages: manyTechniques(2000) }), null],
      ["2001 techniques (over)", base({ stages: manyTechniques(2001) }), "Plan contains too many technique records"],
    ];

    return cases.map(([name, plan, expected]) => {
      let actual = null;
      try { validateImportedPlan(plan); } catch (error) { actual = error.message; }
      return { name, expected, actual };
    });
  });

  expect(results).toHaveLength(33);
  for (const { name, expected, actual } of results) {
    expect(actual, `boundary case: ${name}`).toBe(expected);
  }
});

test("J55 — the entry screen has no serious accessibility violations", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter(v => ["serious", "critical"].includes(v.impact))).toEqual([]);
});
