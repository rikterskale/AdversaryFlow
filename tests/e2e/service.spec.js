const { test, expect } = require("@playwright/test");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const Ajv2020 = require("ajv/dist/2020");
const AxeBuilder = require("@axe-core/playwright").default;

const localPython = path.resolve(process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const python = process.env.ADVERSARYFLOW_TEST_PYTHON || (fs.existsSync(localPython) ? localPython : "python");
let server;
let baseURL;
test.setTimeout(60_000);

test.beforeAll(async () => {
  server = spawn(python, ["-u", "-m", "tests.e2e.real_server"], { cwd: path.resolve("."), stdio: ["ignore", "pipe", "pipe"] });
  baseURL = await new Promise((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`Fixture service did not start: ${output}`)), 20_000);
    server.on("error", error => { clearTimeout(timer); reject(error); });
    server.on("exit", code => { clearTimeout(timer); reject(new Error(`Fixture service exited (${code}): ${output}`)); });
    server.stderr.on("data", chunk => { output += chunk.toString(); });
    server.stdout.on("data", chunk => {
      output += chunk.toString();
      const match = output.match(/READY (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
});
test.afterAll(async () => {
  if (server && server.exitCode === null) {
    const exited = new Promise(resolve => server.once("exit", resolve));
    server.kill();
    await exited;
  }
});
test.beforeEach(async ({ request }) => {
  expect((await request.post(`${baseURL}/test-control`, { data: { action: "reset" } })).ok()).toBe(true);
});

async function connect(page) {
  // Firefox can occasionally stall before committing the document even
  // though the fixture service is responsive. Retry that bounded navigation
  // once so a transient browser stall does not make the whole suite flaky.
  const navigate = () => page.goto(baseURL, { waitUntil: "commit", timeout: 20_000 });
  try {
    await navigate();
  } catch (error) {
    const browserName = page.context().browser()?.browserType().name();
    if (browserName !== "firefox" || !String(error?.message ?? error).includes("Timeout")) throw error;
    await page.goto("about:blank", { waitUntil: "commit", timeout: 5_000 });
    await navigate();
  }
  await page.getByLabel("API token").fill("browser-fixture-token");
  await page.getByRole("button", { name: "Connect securely" }).click();
}
async function reviewPlan(page) {
  await connect(page);
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Zeta Group/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1059.001").selectOption("passed");
  await page.getByLabel("Evidence note for T1059.001").fill("Windows evidence preserved");
}
async function download(page, name) {
  const result = page.waitForEvent("download");
  await page.getByRole("button", { name }).click();
  return (await result).path();
}
async function savePlan(page) {
  return JSON.parse(fs.readFileSync(await download(page, "Save JSON plan"), "utf8"));
}

async function capabilityPlan(page, platform) {
  await connect(page);
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Capability Group/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await page.getByRole("button", { name: platform, exact: true }).click();
}

test("cloud, planning and container blocks expose execution requirements and survive Linux kit export", async ({ page }) => {
  await capabilityPlan(page, "Linux");
  await page.locator("label.toggle", { hasText: "Allow network-active commands" }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  const cloud = page.getByRole("region", { name: "What this will touch" }).filter({ hasText: "Azure CLI authenticated" });
  await expect(cloud).toContainText("Cloud");
  await expect(cloud).toContainText("Prerequisites Unverified");
  await expect(cloud).toContainText("Environment Validation");
  await expect(page.getByRole("region", { name: "What this will touch" }).filter({ hasText: "Linux container context" })).toContainText("Container");
  await expect(page.getByText("This is a planning step. Its outcome does not establish endpoint detection coverage.")).toBeVisible();
  await page.getByRole("button", { name: "Finish & export" }).click();
  const plan = await savePlan(page);
  const commands = plan.stages.flatMap(s => s.techniques).map(t => t.command);
  expect(commands.find(c => c.environment === "cloud")).toMatchObject({ platform: "linux", required_tools: ["az"], availability_status: "prerequisites_unverified" });
  const kit = await download(page, /Download Linux execution kit/);
  const rows = JSON.parse(execFileSync(python, ["-c", "import csv,io,json,sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); n=next(n for n in z.namelist() if n.endswith('.csv')); print(json.dumps(list(csv.DictReader(io.StringIO(z.read(n).decode('utf-8-sig'))))))", kit], { encoding: "utf8" }));
  const cloudRow = rows.find(r => r.technique_id === "T1059.009");
  expect(cloudRow.environment).toBe("cloud");
  expect(cloudRow.command_id).toBe(commands.find(c => c.environment === "cloud").command_id);
  expect(cloudRow.required_tools).toBe("az");
});

test("explicit same-OS variants archive earlier evidence and persist through local recovery", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await capabilityPlan(page, "Windows");
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByLabel("Outcome for T1001", { exact: true }).selectOption("passed");
  await page.getByLabel("Evidence note for T1001", { exact: true }).fill("Original variant evidence");
  const selector = page.getByLabel("Command variant for T1001", { exact: true });
  const options = await selector.locator("option").evaluateAll(items => items.map(i => i.value));
  expect(options).toHaveLength(2);
  const bounds = await selector.boundingBox();
  expect(bounds.x).toBeGreaterThanOrEqual(0);
  expect(bounds.x + bounds.width).toBeLessThanOrEqual(390);
  await selector.selectOption(options[1]);
  await page.getByRole("button", { name: "Change command variant", exact: true }).click();
  await expect(page.getByLabel("Evidence note for T1001", { exact: true })).toHaveValue("");
  await page.reload();
  await page.getByRole("button", { name: "Resume Capability Group plan" }).click();
  await expect(page.getByLabel("Command variant for T1001", { exact: true })).toHaveValue(options[1]);
  await page.getByRole("button", { name: "Finish & export" }).click();
  const plan = await savePlan(page);
  expect(plan.scope.command_selections.T1001).toBe(options[1]);
  expect(plan.stages.flatMap(s => s.techniques).find(t => t.id === "T1001").command.fidelity).toBe("bounded_synthetic");
});

test("Home keeps the active engagement while opening saved records and intelligence tools", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  await page.getByRole("button", { name: "Save engagement", exact: true }).click();
  await expect(page.getByRole("button", { name: "Save new revision" })).toBeEnabled();
  await page.getByRole("button", { name: "Return to workspace home" }).click();
  await expect(page.getByRole("button", { name: "Browse saved engagements" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Import and compare" })).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.getByRole("button", { name: "Resume Zeta Group plan" }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
  await page.getByRole("button", { name: "Finish & export" }).click();
  await expect(page.getByRole("button", { name: "Save new revision" })).toBeEnabled();
  const plan = await savePlan(page);
  expect(plan.stages.flatMap(stage => stage.techniques).find(technique => technique.id === "T1059.001").execution.notes).toBe("Windows evidence preserved");
});

test("a missing service token still permits saved-plan review and local JSON backup", async ({ page, request }) => {
  await reviewPlan(page);
  await request.post(`${baseURL}/test-control`, { data: { action: "token" } });
  await page.reload();
  await page.getByRole("button", { name: "Continue with saved work" }).click();
  await page.getByRole("button", { name: "Resume Zeta Group plan" }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
  await page.getByRole("button", { name: "Finish & export" }).click();
  const plan = await savePlan(page);
  expect(plan.stages.flatMap(stage => stage.techniques).find(technique => technique.id === "T1059.001").execution.notes).toBe("Windows evidence preserved");
  await page.getByRole("button", { name: "Connect to service" }).click();
  await page.getByLabel("API token").fill("rotated-fixture-token");
  await page.getByRole("button", { name: "Connect securely" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Save engagement", exact: true })).toBeEnabled();
});

test("real service Atomic export persists editable backlog ownership", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  const zip = await download(page, "Atomic Red Team draft + gap backlog");
  const manifest = JSON.parse(execFileSync(python, ["-c",
    "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); print(z.read('adversaryflow-atomic-manifest.json').decode())", zip], { encoding: "utf8" }));
  expect(manifest.summary.gaps).toBeGreaterThan(0);
  await page.getByRole("button", { name: "Manage ability backlog" }).click();
  const item = page.locator(".ability-backlog__item").first();
  await item.getByLabel("Owner").fill("E2E team");
  await item.getByLabel("Status").selectOption("in_progress");
  await item.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: /saved|updated/i })).toBeVisible();
  await page.getByRole("button", { name: "Hide ability backlog" }).click();
  await page.getByRole("button", { name: "Manage ability backlog" }).click();
  const saved = page.locator(".ability-backlog__item").filter({ has: page.locator('input[value="E2E team"]') });
  await expect(saved.getByLabel("Owner")).toHaveValue("E2E team");
  await expect(saved.getByLabel("Status")).toHaveValue("in_progress");
  const response = await page.request.get(`${baseURL}/api/audit-events`, { headers: { Authorization: "Bearer browser-fixture-token" } });
  expect(response.status()).toBe(200);
  expect((await response.json()).chain_valid).toBe(true);
});

test("real intelligence review preserves accepted procedures through schema 3 exports and save", async ({ page }) => {
  await connect(page);
  await page.getByRole("button", { name: "Import and compare" }).click();
  await page.getByLabel("Compare against actor or campaign").selectOption("intrusion-set--zeta");
  await page.getByLabel("Structured source").setInputFiles({ name: "review.csv", mimeType: "text/csv",
    buffer: Buffer.from("technique_id,procedure,evidence_quote\nT1059.001,Reviewed procedure,Reviewed quotation\nT9999,Unknown technique,Unknown quotation\n") });
  await page.getByRole("button", { name: "Compare mappings" }).click();
  await expect(page.locator(".intelligence-candidate")).toHaveCount(2);
  await page.getByLabel("Reviewer name").fill("E2E reviewer");
  await page.locator(".intelligence-candidate").filter({ hasText: "T1059.001" }).getByRole("button", { name: "Accept mapping" }).click();
  const unknown = page.locator(".intelligence-candidate").filter({ hasText: "T9999" });
  await expect(unknown.getByRole("button", { name: "Accept mapping" })).toBeDisabled();
  await unknown.getByRole("button", { name: "Reject", exact: true }).click();
  const reviewed = JSON.parse(fs.readFileSync(await download(page, "Download reviewed mapping record"), "utf8"));
  expect(reviewed.candidates.map(candidate => candidate.review_status).sort()).toEqual(["accepted", "rejected"]);
  await page.getByRole("button", { name: "Attach accepted procedures to planning workspace" }).click();
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Zeta Group/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await page.getByRole("button", { name: "Finish & export" }).click();
  const plan = await savePlan(page);
  expect(plan.schema_version).toBe("3.0");
  expect(plan.procedures).toHaveLength(1);
  expect(plan.procedures[0].reviewed_by).toBe("E2E reviewer");
  const validator = new Ajv2020({ strict: false, validateFormats: false });
  for (const schema of ["adversaryflow-plan.schema.json", "adversaryflow-receipt.schema.json"]) {
    validator.addSchema(JSON.parse(fs.readFileSync(`schemas/${schema}`, "utf8")));
  }
  const validate = validator.compile(JSON.parse(fs.readFileSync("schemas/adversaryflow-plan-v3.schema.json", "utf8")));
  expect(validate(plan), JSON.stringify(validate.errors)).toBe(true);
  await page.getByRole("button", { name: "Generate report", exact: true }).click();
  await expect(page.frameLocator("iframe").getByRole("heading", { name: /Zeta Group/ })).toBeVisible();
  await page.getByRole("button", { name: "Save engagement", exact: true }).click();
  await expect(page.getByText("Server engagement · revision 1", { exact: true })).toBeVisible();
  const evidence = JSON.parse(fs.readFileSync(await download(page, "Download Schema-versioned JSON"), "utf8"));
  expect(evidence.procedures).toEqual(plan.procedures);
});

test("real service exports reports and keeps imported high-risk steps withheld", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  const plan = await savePlan(page);
  expect(plan.scope.allow_high_risk).toBe(false);
  await page.goto(baseURL);
  await page.locator("#importPlan").setInputFiles({ name: "plan.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(plan)) });
  await page.getByRole("button", { name: "Replace and restore" }).click();
  await page.getByRole("button", { name: "Finish & export" }).click();
  const zipPath = await download(page, /Download Windows execution kit/);
  const rows = JSON.parse(execFileSync(python, ["-c", "import csv,io,json,sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); n=next(n for n in z.namelist() if n.endswith('.csv')); print(json.dumps(list(csv.DictReader(io.StringIO(z.read(n).decode('utf-8-sig'))))))", zipPath], { encoding: "utf8" }));
  expect(rows.find(row => row.technique_id === "T1053.005").supported).toBe("false");
  expect(rows.find(row => row.technique_id === "T1059.001").interpreter).toBe("cmd");
  await page.getByRole("button", { name: "Generate report", exact: true }).click();
  await expect(page.frameLocator("iframe").getByRole("heading", { name: /Zeta Group/ })).toBeVisible();
  expect(fs.readFileSync(await download(page, "Download PDF engagement report")).subarray(0, 5).toString()).toBe("%PDF-");
  const exported = JSON.parse(fs.readFileSync(await download(page, "Download Schema-versioned JSON"), "utf8"));
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(JSON.parse(fs.readFileSync("schemas/adversaryflow-plan.schema.json", "utf8")));
  expect(validate(exported), JSON.stringify(validate.errors)).toBe(true);
  expect(exported.scope.allow_high_risk).toBe(false);
  expect(exported.stages.flatMap(stage => stage.techniques).find(t => t.id === "T1059.001").execution.notes).toBe("Windows evidence preserved");
});

test("platform changes cannot relabel evidence through the Export stepper", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  await page.getByRole("button", { name: "Scope engagement", exact: true }).click();
  await page.getByRole("button", { name: "Linux", exact: true }).click();
  await page.getByRole("button", { name: "Export kit", exact: true }).click();
  const linux = await savePlan(page);
  expect(linux.scope.command_platform).toBe("linux");
  expect(linux.stages.flatMap(stage => stage.techniques).every(t => t.execution.outcome === "not_run")).toBe(true);
  await page.getByRole("button", { name: "Scope engagement", exact: true }).click();
  await page.getByRole("button", { name: "Windows", exact: true }).click();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
});

test("changed ATT&CK data preserves a restorable evidence snapshot", async ({ page, request }, testInfo) => {
  await reviewPlan(page);
  await request.post(`${baseURL}/test-control`, { data: { action: "version" } });
  await page.reload();
  await page.getByRole("button", { name: "Resume Zeta Group plan" }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("");
  await page.getByText(/Saved evidence from other platforms or data versions/).click();
  const snapshot = JSON.parse(fs.readFileSync(await download(page, "Download snapshot"), "utf8"));
  expect(snapshot.stages.flatMap(stage => stage.techniques).find(t => t.id === "T1059.001").execution.notes).toBe("Windows evidence preserved");
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.getByRole("button", { name: "Restore snapshot" })).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze()).violations).toEqual([]);
    await page.screenshot({ path: testInfo.outputPath(`evidence-recovery-${width}.png`) });
  }
  await page.getByRole("button", { name: "Restore snapshot" }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
});

test("a failed real feed refresh preserves the current scope and evidence", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Refresh the live ATT&CK feed" }).click();
  const response = page.waitForResponse(r => r.url().includes("/api/refresh") && r.request().method() === "POST");
  await page.getByRole("dialog").getByRole("button", { name: /Refresh/ }).click();
  const failed = await response;
  expect(failed.status()).toBe(503);
  expect((await failed.json()).error).toBe("refresh_failed");
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
});

test("token and CSRF rotation recover without losing the current plan", async ({ page, request }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  await page.getByRole("button", { name: "Generate report", exact: true }).click();
  await expect(page.getByRole("button", { name: "Regenerate report" })).toBeVisible();
  const statuses = [];
  page.on("response", response => { if (response.url().endsWith("/api/report/pdf")) statuses.push(response.status()); });
  await request.post(`${baseURL}/test-control`, { data: { action: "csrf" } });
  await download(page, "Download PDF engagement report");
  expect(statuses).toEqual([403, 200]);
  await request.post(`${baseURL}/test-control`, { data: { action: "token" } });
  await page.getByRole("button", { name: "Regenerate report" }).click();
  await page.getByLabel("API token").fill("rotated-fixture-token");
  await page.getByRole("button", { name: "Connect securely" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.getByRole("button", { name: "Retry report generation" }).click();
  await expect(page.getByRole("button", { name: "Regenerate report" })).toBeVisible();
  expect((await savePlan(page)).summary.marked_run).toContain("T1059.001");
});

test("saved and imported plans remain usable when bootstrap fails", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  const original = await savePlan(page);
  await page.route("**/api/bootstrap", route => route.fulfill({ status: 503, json: { error: "unavailable", message: "Fixture cache unavailable" } }));
  await page.reload();
  await expect(page.getByText("Could not prepare ATT&CK data")).toBeVisible();
  await page.getByRole("button", { name: "Resume Zeta Group plan" }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
  await page.getByRole("button", { name: "Finish & export" }).click();
  expect((await savePlan(page)).summary.marked_run).toEqual(original.summary.marked_run);
  await page.reload();
  await page.locator("#importPlan").setInputFiles({ name: "plan.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(original)) });
  await page.getByRole("button", { name: "Replace and restore" }).click();
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
});

test("engagement saves retain their server identity across browser reloads", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  await page.getByRole("button", { name: "Save engagement", exact: true }).click();
  await expect(page.getByText("Server engagement · revision 1", { exact: true })).toBeVisible();
  const key = await page.evaluate(() => JSON.parse(localStorage.getItem("adversaryflow-wizard-v3")).state.engagementId);
  await page.reload();
  await page.getByRole("button", { name: "Resume Zeta Group plan" }).click();
  await page.getByRole("button", { name: "Finish & export" }).click();
  await page.getByRole("button", { name: "Save new revision", exact: true }).click();
  await expect(page.getByText("Server engagement · revision 2", { exact: true })).toBeVisible();
  const response = await page.request.get(`${baseURL}/api/engagements/${key}`, {
    headers: { Authorization: "Bearer browser-fixture-token" },
  });
  expect(response.status()).toBe(200);
  const engagement = await response.json();
  expect(engagement.revisions.map(item => item.revision)).toEqual([2, 1]);
  expect(engagement.latest_plan.stages.flatMap(stage => stage.techniques)
    .find(item => item.id === "T1059.001").execution.notes).toBe("Windows evidence preserved");
});
