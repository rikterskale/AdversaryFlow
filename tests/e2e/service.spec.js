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
  // The token dialog is the readiness boundary; Firefox can delay the window
  // load notification even after this client-rendered form is interactive.
  await page.goto(baseURL, { waitUntil: "domcontentloaded" });
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

test("real service exports reports and keeps imported high-risk steps withheld", async ({ page }) => {
  await reviewPlan(page);
  await page.getByRole("button", { name: "Finish & export" }).click();
  const plan = await savePlan(page);
  expect(plan.scope.allow_high_risk).toBe(false);
  await page.goto(baseURL);
  await page.locator("#importPlan").setInputFiles({ name: "plan.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(plan)) });
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
  await expect(page.getByLabel("Evidence note for T1059.001")).toHaveValue("Windows evidence preserved");
});
