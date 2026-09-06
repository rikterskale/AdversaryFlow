const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

test.use({ permissions: ["clipboard-read", "clipboard-write"] });
const Ajv2020 = require("ajv/dist/2020");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const command = {
  platform: "windows",
  command: "whoami",
  note: "Read-only identity check.",
  cleanup: "",
  risk: "low",
  side_effects: ["read_only_or_process_telemetry"],
  requires_admin: false,
  requires_network: false,
  network_targets: [],
  prerequisites: ["windows command environment", "authorized disposable lab"],
  expected_telemetry: "Process and command-line telemetry.",
  expected_output: "Current user identity.",
  timeout_seconds: 60,
  rollback: "",
  cleanup_required: false,
  acknowledgment_required: false,
};

const highRiskCommand = {
  ...command,
  command: "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com -UseBasicParsing\"",
  note: "Lab HTTPS request as a C2 proxy.",
  cleanup: "",
  risk: "high",
  side_effects: ["network_activity"],
  requires_network: true,
  network_targets: ["example.com"],
  acknowledgment_required: true,
};

const cleanupCommand = {
  ...highRiskCommand,
  command: "schtasks /Create /TN AFLab /TR cmd.exe /SC ONCE /ST 23:59 /F",
  cleanup: "schtasks /Delete /TN AFLab /F",
  rollback: "schtasks /Delete /TN AFLab /F",
  cleanup_required: true,
  requires_network: false,
  network_targets: [],
};

function multiStageWorkflow() {
  const technique = (id, name, tactic) => ({
    stix_id: `attack-pattern--${id}`, attack_id: id, name,
    description: "Fixture technique", tactics: [tactic], platforms: ["Windows"],
    is_subtechnique: false, url: `https://attack.mitre.org/techniques/${id}/`,
    commands: [command], command_source: "curated",
  });
  return {
    actor: { stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "Fixture actor" },
    summary: { total_techniques: 3, unique_stages: 3, curated_commands: 3, fallback_commands: 0 },
    kill_chain: [{ tactic: "execution", title: "Execution" }, { tactic: "persistence", title: "Persistence" }, { tactic: "impact", title: "Impact" }],
    stages: [
      { tactic: "execution", title: "Execution", techniques: [technique("T1033", "System Owner/User Discovery", "execution")] },
      { tactic: "persistence", title: "Persistence", techniques: [technique("T1547", "Boot or Logon Autostart Execution", "persistence")] },
      { tactic: "impact", title: "Impact", techniques: [technique("T1486", "Data Encrypted for Impact", "impact")] },
    ],
    metadata: { domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0" },
  };
}

function workflowBody(commands = [command]) {
  return {
    actor: { stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "Fixture actor" },
    summary: { total_techniques: 1, unique_stages: 1, curated_commands: 1, fallback_commands: 0 },
    kill_chain: [{ tactic: "execution", title: "Execution" }],
    stages: [{ tactic: "execution", title: "Execution", techniques: [{
      stix_id: "attack-pattern--test", attack_id: "T1033", name: "System Owner/User Discovery",
      description: "Fixture technique", tactics: ["execution"], platforms: ["Windows"],
      is_subtechnique: false, url: "https://attack.mitre.org/techniques/T1033/",
      commands, command_source: "curated",
    }] }],
    metadata: { domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0" },
  };
}

function planFixture(overrides = {}) {
  return {
    schema_version: "2.0", tool: "AdversaryFlow", tool_version: "0.3.0",
    data_version: "enterprise:bundle--test", domains: ["enterprise"],
    generated: "2026-09-04T00:00:00.000Z",
    actor: { stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "Fixture actor", technique_count: 1 },
    scope: { command_platform: "windows", include_pre: true, curated_only: false, allow_network: false, allow_admin: false, allow_high_risk: false, stages: ["execution"] },
    execution_context: { operator: "Purple Team", target: "lab-host-01" },
    summary: { techniques: 1, runnable: 1, unsupported: 0, stages: 1, curated: 1, fallback: 0, marked_run: ["T1033"] },
    stages: [{ tactic: "execution", title: "Execution", techniques: [{
      id: "T1033", name: "System Owner/User Discovery", url: "https://attack.mitre.org/techniques/T1033/",
      platforms: ["Windows"], command_source: "curated", supported: true, command, run: true,
      execution: { outcome: "passed", notes: "Imported evidence" },
    }] }],
    ...overrides,
  };
}

function writePlan(plan) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "af-plan-")), "plan.json");
  fs.writeFileSync(file, JSON.stringify(plan), "utf-8");
  return file;
}

async function interceptApi(page, commands = [command]) {
  await page.route("**/api/session", route => route.fulfill({ json: { csrf_token: "test-token", version: "0.3.0" } }));
  await page.route("**/api/bootstrap", route => route.fulfill({ json: { status: "ready", runtime: { ready: true, phase: "ready" }, cache: { domains: {} } } }));
  await page.route("**/api/actors?*", route => route.fulfill({ json: {
    actors: [{ stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "[Test Actor](https://attack.mitre.org/groups/G0001/) fixture. (Citation: Test source)", technique_count: 1 }],
    domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0",
  } }));
  await page.route("**/api/workflow/**", route => route.fulfill({ json: workflowBody(commands) }));
  await page.route("**/api/execution-kit", route => route.fulfill({
    status: 200,
    contentType: "application/zip",
    headers: { "Content-Disposition": 'attachment; filename="AdversaryFlow_G0001_Test_Actor_Windows.zip"' },
    body: Buffer.from("fixture execution kit"),
  }));
}

async function buildPlan(page) {
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Test Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Scope the engagement" })).toBeVisible();
}

test("guided workflow records evidence and exports JSON", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Test Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Scope the engagement" })).toBeVisible();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator(".techcard__name")).toHaveText("System Owner/User Discovery");
  await expect(page.locator("#firstLabHint")).toContainText("T1033");
  await page.getByLabel("Evidence note for T1033").fill("Expected process event observed");
  await page.getByLabel("Outcome for T1033").selectOption("passed");
  await page.getByLabel("Detection for T1033").selectOption("silent");
  await expect(page.getByLabel("Evidence note for T1033")).toHaveValue("Expected process event observed");
  await expect(page.locator("#saveStatus")).toHaveText("Saved in this browser");
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /JSON/ }).click();
  const artifact = await download;
  expect(artifact.suggestedFilename()).toMatch(/AdversaryFlow_G0001/);
  const exported = JSON.parse(fs.readFileSync(await artifact.path(), "utf-8"));
  const schema = JSON.parse(fs.readFileSync(path.resolve("schemas/adversaryflow-plan.schema.json"), "utf-8"));
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(schema);
  expect(validate(exported), JSON.stringify(validate.errors)).toBeTruthy();
  expect(exported.stages[0].techniques[0].execution.outcome).toBe("passed");
  expect(exported.stages[0].techniques[0].execution.detection_result).toBe("silent");
  expect(exported.stages[0].techniques[0].execution.notes).toBe("Expected process event observed");
});

test("welcome screen has no serious accessibility violations", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter(item => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("mobile screens never create page-level horizontal scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await interceptApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.getByRole("button", { name: /Select Test Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Scope the engagement" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.getByRole("button", { name: /Build plan/ }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  await page.getByRole("button", { name: /Finish & export/ }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
});

test("actor cards present clean copy and concise accessible names", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  const card = page.locator(".actorcard").first();
  await expect(card).toHaveAttribute("aria-label", /Select Test Actor, G0001, 1 techniques/);
  await expect(card.locator(".actorcard__desc")).not.toContainText("[Test Actor](https://");
});

test("remote access uses an accessible in-app token dialog", async ({ page }) => {
  await page.route("**/api/session", route => {
    const authorization = route.request().headers().authorization;
    if (authorization === "Bearer fixture-token") return route.fulfill({ json: { csrf_token: "test-token", version: "0.3.0" } });
    return route.fulfill({ status: 401, json: { error: "unauthorized", message: "A valid bearer token is required for remote API access" } });
  });
  await page.route("**/api/bootstrap", route => route.fulfill({ json: { status: "ready", runtime: { ready: true, phase: "ready" }, cache: { domains: {} } } }));
  await page.route("**/api/actors?*", route => route.fulfill({ json: { actors: [], domains: ["enterprise"], data_version: "enterprise:fixture", version: "0.3.0" } }));
  await page.goto("/");

  const dialog = page.getByRole("dialog", { name: "Connect to this AdversaryFlow service" });
  await expect(dialog).toBeVisible();
  await page.getByLabel("API token").fill("fixture-token");
  await page.getByRole("button", { name: "Connect securely" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("af_api_token"))).toBe("fixture-token");
});

test("markdown export carries the scope, outcome and command", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1033").selectOption("failed");
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /Markdown report/ }).click();
  const artifact = await download;
  expect(artifact.suggestedFilename()).toBe("AdversaryFlow_G0001_Test_Actor.md");
  const markdown = fs.readFileSync(await artifact.path(), "utf-8");
  expect(markdown).toContain("# AdversaryFlow — Test Actor (G0001)");
  expect(markdown).toContain("### T1033 — System Owner/User Discovery");
  expect(markdown).toContain("**Outcome:** failed");
  expect(markdown).toContain("**Detection:** not_assessed");
  expect(markdown).toContain("whoami");
});

test("runbook export is a commented, non-executable artifact", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /Runbook/ }).click();
  const artifact = await download;
  expect(artifact.suggestedFilename()).toBe("AdversaryFlow_G0001_Test_Actor_runbook.cmd.txt");
  const runbook = fs.readFileSync(await artifact.path(), "utf-8");
  expect(runbook).toContain("REM AdversaryFlow runbook — Test Actor (G0001)");
  expect(runbook).toContain("REM ===== 1. EXECUTION =====");
  expect(runbook).toContain("REM Outcome: not_run");
  expect(runbook).toContain("REM Detection: not_assessed");
  expect(runbook).toContain("REM COMMAND: whoami");
  expect(runbook.split(/\r?\n/)).not.toContain("whoami");
});

test("operator execution kit is a one-click portable download", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /Download Windows execution kit/ }).click();
  const artifact = await download;
  expect(artifact.suggestedFilename()).toBe("AdversaryFlow_G0001_Test_Actor_Windows.zip");
});

test("a bounded exercise receipt is digest-verified and exported as execution proof", async ({ page }) => {
  const exercise = { ...command, command: "python -m backend.lab_exercises T1033", exercise_kind: "technique_relevant_bounded", fidelity: "bounded_synthetic", evidence_source: "self_reported_receipt" };
  await interceptApi(page, [exercise]);
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator(".srcbadge--bounded")).toHaveText("bounded synthetic");
  const receipt = {
    attestation: "self-reported",
    cleanup_verified: true,
    completed_at: "2026-09-04T12:00:01+00:00",
    duration_ms: 1000,
    error: null,
    events: [{ event: "identity_probe", technique_id: "T1033" }],
    exercise_summary: "Synthetic identity probe.",
    exit_code: 0,
    expected_telemetry: "Process telemetry.",
    run_id: "550e8400-e29b-41d4-a716-446655440000",
    scenario: "identity_probe",
    schema_version: "1.0",
    started_at: "2026-09-04T12:00:00+00:00",
    status: "passed",
    technique_id: "T1033",
  };
  receipt.receipt_sha256 = crypto.createHash("sha256").update(JSON.stringify(receipt)).digest("hex");
  await page.getByText("Execution proof").click();
  await page.getByLabel("Exercise receipt for T1033").fill(JSON.stringify(receipt));
  await page.getByRole("button", { name: "Verify and import receipt" }).click();
  await expect(page.getByText("receipt digest verified (self-reported)")).toBeVisible();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /JSON/ }).click();
  const exported = JSON.parse(fs.readFileSync(await (await download).path(), "utf-8"));
  const evidence = exported.stages[0].techniques[0].execution;
  expect(evidence).toMatchObject({ run_id: receipt.run_id, exit_code: 0, receipt_sha256: receipt.receipt_sha256, receipt_verified: true, cleanup_completed: true, evidence_source: "exercise_receipt" });
});

test("a browser session can be resumed after reload", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Select Test Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.getByRole("heading", { name: /Test Actor · G0001/ })).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: /Resume Test Actor plan/ }).click();
  await expect(page.getByRole("heading", { name: /Test Actor · G0001/ })).toBeVisible();
  await expect(page.locator("pre.cmd__code")).toHaveText("whoami");
});

test("a saved plan can be resumed from the welcome screen", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  await page.setInputFiles("#importPlan", writePlan(planFixture()));
  await expect(page.getByRole("status").filter({ hasText: "Plan imported as high-risk" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Test Actor · G0001/ })).toBeVisible();
  await expect(page.getByText("System Owner/User Discovery")).toBeVisible();
  await expect(page.getByLabel("Outcome for T1033")).toHaveValue("passed");
  await expect(page.getByLabel("Evidence note for T1033")).toHaveValue("Imported evidence");
  // Imported commands are re-classified as untrusted high-risk content.
  await expect(page.getByText("high risk")).toBeVisible();
});

test("a resumed plan re-exports against the published schema", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.setInputFiles("#importPlan", writePlan(planFixture()));
  await expect(page.getByRole("heading", { name: /Test Actor · G0001/ })).toBeVisible();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /JSON/ }).click();
  const exported = JSON.parse(fs.readFileSync(await (await download).path(), "utf-8"));
  const schema = JSON.parse(fs.readFileSync(path.resolve("schemas/adversaryflow-plan.schema.json"), "utf-8"));
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(schema);
  expect(validate(exported), JSON.stringify(validate.errors)).toBeTruthy();
  expect(exported.execution_context).toEqual({ operator: "Purple Team", target: "lab-host-01" });
});

test("an incomplete actor record is rejected instead of corrupting the session", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  const broken = planFixture({ actor: { stix_id: "intrusion-set--test", technique_count: 1 } });
  await page.setInputFiles("#importPlan", writePlan(broken));
  await expect(page.getByRole("status").filter({ hasText: "Plan actor record is invalid" })).toBeVisible();
  // The welcome screen is still usable and no half-imported plan is exposed.
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
});

test("a plan from another tool version is rejected", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.setInputFiles("#importPlan", writePlan(planFixture({ schema_version: "1.0" })));
  await expect(page.getByRole("status").filter({ hasText: "not an AdversaryFlow 2.0 plan export" })).toBeVisible();
});

test("switching the command platform marks techniques unsupported", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await page.getByRole("button", { name: "Linux", exact: true }).click();
  const summary = page.locator("#scopeSummary");
  await expect(summary).toContainText("Runnable on Linux");
  await expect(page.locator("#actionbarCtx")).toContainText("0 runnable");
  await expect(page.locator("#actionbarCtx")).toContainText("1 unsupported");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeDisabled();
});

test("safety scope blocks a network high-risk command until it is allowed", async ({ page }) => {
  await interceptApi(page, [highRiskCommand]);
  await buildPlan(page);
  await expect(page.locator("#actionbarCtx")).toContainText("0 runnable");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeDisabled();

  await page.locator("label.toggle", { hasText: "Allow network-active commands" }).click();
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await expect(page.locator("#actionbarCtx")).toContainText("1 runnable");
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator("pre.cmd__code")).toContainText("Invoke-WebRequest https://example.com");
  await expect(page.getByText("high risk")).toBeVisible();
});

test("deselecting every kill-chain stage empties the plan", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await expect(page.locator("#stagesAll")).toHaveText("Clear all");
  await page.locator("#stagesAll").click();
  await expect(page.locator("#stagesAll")).toHaveText("Select all");
  await expect(page.locator("#actionbarCtx")).toContainText("No techniques in scope");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeDisabled();
  await page.locator("#stagesAll").click();
  await expect(page.locator("#actionbarCtx")).toContainText("1 runnable");
});

test("a plan exported with the default scope resumes as a runnable plan", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /JSON/ }).click();
  const exportedPath = await (await download).path();
  const exported = JSON.parse(fs.readFileSync(exportedPath, "utf-8"));
  expect(exported.scope.allow_high_risk).toBe(false);

  await page.goto("/");
  await page.setInputFiles("#importPlan", exportedPath);
  await expect(page.getByRole("heading", { name: /Test Actor · G0001/ })).toBeVisible();
  await expect(page.locator("pre.cmd__code")).toContainText("whoami");
  await expect(page.locator("pre.cmd__code")).not.toContainText("Restricted by scope");
  await expect(page.getByLabel("Outcome for T1033")).toBeVisible();
  await expect(page.locator("#actionbarCtx")).toContainText("/ 1 runnable");
});

test("a scope-restricted command exposes no copyable cleanup", async ({ page }) => {
  await interceptApi(page, [cleanupCommand]);
  await buildPlan(page);
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.getByRole("button", { name: /Copy cleanup/ })).toBeEnabled();

  await page.getByRole("button", { name: /^Back/ }).click();
  await page.locator("label.toggle", { hasText: "Allow high-risk commands" }).click();
  await expect(page.locator("#actionbarCtx")).toContainText("0 runnable");
  await page.locator(".stepper__item", { hasText: "Emulation plan" }).click();
  await expect(page.locator("pre.cmd__code")).toContainText("Restricted by scope");
  await expect(page.getByRole("button", { name: /Copy command/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Copy cleanup/ })).toBeDisabled();
});

test("planning another actor resets the picker filters", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();

  await page.getByRole("button", { name: "ICS / OT" }).click();
  await page.getByRole("button", { name: "Groups", exact: true }).click();
  await page.locator("#sortSel").selectOption("ttps");
  await page.getByRole("button", { name: /Test Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();

  await page.getByRole("button", { name: /Plan another actor/ }).click();
  await page.getByRole("dialog", { name: "Start a new plan?" }).getByRole("button", { name: "Start new plan" }).click();
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();

  await expect(page.getByRole("button", { name: "Enterprise" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "ICS / OT" })).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#sortSel")).toHaveValue("name");
  await expect(page.locator("#actionbarCtx")).toContainText("Select a threat actor");
});

test("a new actor starts with an empty execution context", async ({ page }) => {
  await interceptApi(page);
  await buildPlan(page);
  await page.getByLabel("Operator").fill("Purple Team");
  await page.getByLabel("Target").fill("lab-host-01");
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: /Finish & export/ }).click();
  await page.getByRole("button", { name: /Plan another actor/ }).click();
  await page.getByRole("dialog", { name: "Start a new plan?" }).getByRole("button", { name: "Start new plan" }).click();

  // Saved progress is keyed by actor, data version, domains and platform, so a
  // different key must start clean rather than inherit the previous operator.
  await page.route("**/api/actors?*", route => route.fulfill({ json: {
    actors: [{ stix_id: "intrusion-set--other", attack_id: "G0002", name: "Other Actor", type: "group", aliases: [], description: "Second fixture", technique_count: 1 }],
    domains: ["enterprise"], data_version: "enterprise:bundle--other", version: "0.3.0",
  } }));
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: "ICS / OT" }).click();
  await page.getByRole("button", { name: /Other Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByLabel("Operator")).toHaveValue("");
  await expect(page.getByLabel("Target")).toHaveValue("");
});

test("unavailable local storage is reported instead of silently losing evidence", async ({ page }) => {
  await page.addInitScript(() => {
    Storage.prototype.setItem = () => { throw new Error("storage is unavailable"); };
  });
  await interceptApi(page);
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1033").selectOption("passed");
  await expect(page.getByRole("status").filter({ hasText: "Progress can't be saved" })).toBeVisible();
});

test("a failed setup shows an actionable error and can be retried", async ({ page }) => {
  let failNext = true;
  await page.route("**/api/session", route => {
    if (failNext) {
      failNext = false;
      return route.fulfill({ status: 500, json: { error: "request failed", message: "ATT&CK cache is unreadable", version: "0.3.0" } });
    }
    return route.fulfill({ json: { csrf_token: "test-token", version: "0.3.0" } });
  });
  await page.route("**/api/bootstrap", route => route.fulfill({ json: { status: "ready", runtime: { ready: true, phase: "ready" }, cache: { domains: {} } } }));
  await page.route("**/api/actors?*", route => route.fulfill({ json: {
    actors: [{ stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "Fixture actor", technique_count: 1 },
    ], domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0",
  } }));

  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await expect(page.getByText("ATT&CK cache is unreadable")).toBeVisible();
  await expect(page.locator("#dataStatus")).toHaveText("setup needs attention");

  await page.getByRole("button", { name: "Retry setup" }).click();
  await expect(page.getByRole("button", { name: /Test Actor/ })).toBeVisible();
  await expect(page.locator("#dataStatus")).toContainText("1 actor");
});

test("a multi-stage plan can be walked stage by stage", async ({ page }) => {
  await interceptApi(page);
  await page.route("**/api/workflow/**", route => route.fulfill({ json: multiStageWorkflow() }));
  await buildPlan(page);
  await expect(page.locator("#actionbarCtx")).toContainText("3 runnable");
  await page.getByRole("button", { name: /Build plan/ }).click();

  await expect(page.locator(".stagepanel__head h3")).toHaveText("Execution");
  await expect(page.getByRole("button", { name: /Previous stage/ })).toBeDisabled();
  await page.getByRole("button", { name: /Next stage/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Persistence");
  await page.getByRole("button", { name: /Next stage/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Impact");
  await expect(page.getByRole("button", { name: /Next stage/ })).toBeDisabled();
  await page.getByRole("button", { name: /Previous stage/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Persistence");

  // The rail jumps directly to any stage and progress is tracked across them.
  await page.locator(".railitem").first().click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Execution");
  await page.locator(".techcard__check").click();
  await expect(page.locator("#progressCount")).toHaveText("1 / 3");
  await expect(page.locator("#progressPct")).toHaveText("33%");
});

test("plan keyboard shortcuts move focus and copy the command", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const second = {
    stix_id: "attack-pattern--t1059", attack_id: "T1059", name: "Command and Scripting Interpreter",
    description: "Fixture technique", tactics: ["execution"], platforms: ["Windows"],
    is_subtechnique: false, url: "https://attack.mitre.org/techniques/T1059/",
    commands: [command], command_source: "curated",
  };
  const body = workflowBody();
  body.summary.total_techniques = 2;
  body.summary.curated_commands = 2;
  body.stages[0].techniques.push(second);
  await interceptApi(page);
  await page.route("**/api/workflow/**", route => route.fulfill({ json: body }));
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  const cards = page.locator(".techcard");
  await expect(cards).toHaveCount(2);
  await expect(cards.nth(0)).toHaveClass(/is-focused/);
  await page.keyboard.press("j");
  await expect(cards.nth(1)).toHaveClass(/is-focused/);
  await page.keyboard.press("k");
  await expect(cards.nth(0)).toHaveClass(/is-focused/);
  await page.keyboard.press("c");
  await expect(page.getByRole("status").filter({ hasText: "Command copied to clipboard" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("whoami");
});

test("the plan opens on the first stage that has a runnable command", async ({ page }) => {
  const linuxOnly = { ...command, platform: "linux", command: "id" };
  const recon = {
    stix_id: "attack-pattern--recon", attack_id: "T1595", name: "Active Scanning",
    description: "Fixture technique", tactics: ["reconnaissance"], platforms: ["Linux"],
    is_subtechnique: false, url: "https://attack.mitre.org/techniques/T1595/",
    commands: [linuxOnly], command_source: "curated",
  };
  const body = workflowBody();
  body.summary.total_techniques = 2;
  body.summary.unique_stages = 2;
  body.summary.curated_commands = 2;
  body.kill_chain = [{ tactic: "reconnaissance", title: "Reconnaissance" }, { tactic: "execution", title: "Execution" }];
  body.stages = [
    { tactic: "reconnaissance", title: "Reconnaissance", techniques: [recon] },
    body.stages[0],
  ];
  await interceptApi(page);
  await page.route("**/api/workflow/**", route => route.fulfill({ json: body }));
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Execution");
  await expect(page.locator("pre.cmd__code")).toHaveText("whoami");
});

test("the plan skips bounded-synthetic stages and marks the first lab command", async ({ page }) => {
  const bounded = {
    ...command,
    command: "python -m backend.lab_exercises T1595",
    fidelity: "bounded_synthetic",
    exercise_kind: "technique_relevant_bounded",
    note: "Technique-relevant bounded exercise.",
  };
  const recon = {
    stix_id: "attack-pattern--recon", attack_id: "T1595", name: "Active Scanning",
    description: "Fixture technique", tactics: ["reconnaissance"], platforms: ["Windows"],
    is_subtechnique: false, url: "https://attack.mitre.org/techniques/T1595/",
    commands: [bounded], command_source: "curated",
  };
  const body = workflowBody();
  body.summary.total_techniques = 2;
  body.summary.unique_stages = 2;
  body.summary.curated_commands = 2;
  body.kill_chain = [{ tactic: "reconnaissance", title: "Reconnaissance" }, { tactic: "execution", title: "Execution" }];
  body.stages = [
    { tactic: "reconnaissance", title: "Reconnaissance", techniques: [recon] },
    body.stages[0],
  ];
  await interceptApi(page);
  await page.route("**/api/workflow/**", route => route.fulfill({ json: body }));
  await buildPlan(page);
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.locator(".stagepanel__head h3")).toHaveText("Execution");
  await expect(page.locator("#firstLabHint")).toContainText("T1033");
  await expect(page.locator(".firstlabbadge")).toHaveText("Try this first");
  await expect(page.locator(".techcard").first()).toContainText("whoami");
  await expect(page.locator(".techcard").first()).toHaveClass(/is-firstlab/);
});

test.describe("linux browser first run", () => {
  test.use({
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  });

  test("command platform starts as Linux and copies the Linux lab command", async ({ page }) => {
    const linuxCmd = { ...command, platform: "linux", command: "id" };
    await interceptApi(page, [command, linuxCmd]);
    await buildPlan(page);
    await expect(page.locator("#cmdPlatform .is-on")).toHaveText("Linux");
    await expect(page.locator("#scopeSummary")).toContainText("Runnable on Linux");
    await expect(page.locator("#platformHint")).toBeHidden();
    await page.getByRole("button", { name: /Build plan/ }).click();
    await expect(page.locator("pre.cmd__code").first()).toHaveText("id");
    await expect(page.locator("#planActorMeta")).toContainText("Linux");
  });
});

test("the operator chooses any actor from the full gallery", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await expect(page.getByRole("button", { name: /Start with / })).toHaveCount(0);
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await expect(page.getByRole("heading", { name: "Choose a threat actor" })).toBeVisible();
  await page.getByRole("button", { name: /Test Actor/ }).click();
  await expect(page.locator("#actionbarCtx")).toHaveText("Selected: Test Actor");
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Scope the engagement" })).toBeVisible();
  await expect(page.locator("#scopeSummary")).toContainText("Test Actor");
  await expect(page.getByRole("button", { name: /Build plan/ })).toBeEnabled();
});

test("setup failures are visible on the welcome screen with a retry", async ({ page }) => {
  await page.route("**/api/session", route => route.fulfill({
    status: 500, json: { error: "request failed", message: "ATT&CK cache is unreadable", version: "0.3.0" },
  }));
  await page.goto("/");
  await expect(page.getByText("ATT&CK cache is unreadable")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry setup" })).toBeVisible();
  await expect(page.locator("#dataStatus")).toHaveText("setup needs attention");
});

test("help explains the four-step path", async ({ page }) => {
  await interceptApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: "How to use AdversaryFlow" }).click();
  const dialog = page.getByRole("dialog", { name: "How to use AdversaryFlow" });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("Pick any threat actor");
  await expect(dialog).toContainText("never executes catalog commands");
  await dialog.getByRole("button", { name: "Got it" }).click();
  await expect(dialog).toBeHidden();
});

test("the actor gallery lists every loaded actor", async ({ page }) => {
  const actors = Array.from({ length: 30 }, (_, i) => ({
    stix_id: `intrusion-set--${i}`, attack_id: `G${String(i).padStart(4, "0")}`,
    name: `Actor ${String(i).padStart(2, "0")}`, type: "group", aliases: [],
    description: "Fixture actor", technique_count: 1,
  }));
  await interceptApi(page);
  await page.route("**/api/actors?*", route => route.fulfill({
    json: { actors, domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0" },
  }));
  await page.goto("/");
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await expect(page.locator(".actorcard")).toHaveCount(30);
  await expect(page.locator("#actorResults")).toHaveText("30 results");
  await expect(page.getByRole("button", { name: /Show all/ })).toHaveCount(0);
});
