const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const Ajv2020 = require("ajv/dist/2020");
const fs = require("node:fs");
const path = require("node:path");

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

async function stubApi(page) {
  await page.route("**/api/session", route => route.fulfill({ json: { csrf_token: "test-token", version: "0.3.0" } }));
  await page.route("**/api/bootstrap", route => route.fulfill({ json: { status: "ready", runtime: { ready: true, phase: "ready" }, cache: { domains: {} } } }));
  await page.route("**/api/actors?*", route => route.fulfill({ json: {
    actors: [{ stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "Fixture actor", technique_count: 1 }],
    domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0",
  } }));
  await page.route("**/api/workflow/**", route => route.fulfill({ json: {
    actor: { stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: ["Example"], description: "Fixture actor" },
    summary: { total_techniques: 1, unique_stages: 1, curated_commands: 1, fallback_commands: 0 },
    kill_chain: [{ tactic: "execution", title: "Execution" }],
    stages: [{ tactic: "execution", title: "Execution", techniques: [{
      stix_id: "attack-pattern--test", attack_id: "T1033", name: "System Owner/User Discovery",
      description: "Fixture technique", tactics: ["execution"], platforms: ["Windows"],
      is_subtechnique: false, url: "https://attack.mitre.org/techniques/T1033/",
      commands: [command], command_source: "curated",
    }] }],
    unmapped: [], metadata: { domains: ["enterprise"], data_version: "enterprise:bundle--test", version: "0.3.0" },
  } }));
}

test("guided workflow records evidence and exports JSON", async ({ page }) => {
  await stubApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Turn a threat actor/ })).toBeVisible();
  await page.getByRole("button", { name: /Begin emulation plan/ }).click();
  await page.getByRole("button", { name: /Test Actor/ }).click();
  await page.getByRole("button", { name: /^Continue/ }).click();
  await expect(page.getByRole("heading", { name: "Scope the engagement" })).toBeVisible();
  await page.getByRole("button", { name: /Build plan/ }).click();
  await expect(page.getByText("System Owner/User Discovery")).toBeVisible();
  await page.getByLabel("Outcome for T1033").selectOption("passed");
  await page.getByLabel("Evidence note for T1033").fill("Expected process event observed");
  await page.getByRole("button", { name: /Finish & export/ }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /JSON/ }).click();
  const artifact = await download;
  expect(artifact.suggestedFilename()).toMatch(/AdversaryFlow_G0001/);
  const exported = JSON.parse(fs.readFileSync(await artifact.path(), "utf-8"));
  const schema = JSON.parse(fs.readFileSync(path.resolve("schemas/adversaryflow-plan.schema.json"), "utf-8"));
  const validate = new Ajv2020({ strict: false, validateFormats: false }).compile(schema);
  expect(validate(exported), JSON.stringify(validate.errors)).toBeTruthy();
});

test("welcome screen has no serious accessibility violations", async ({ page }) => {
  await stubApi(page);
  await page.goto("/");
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter(item => ["serious", "critical"].includes(item.impact))).toEqual([]);
});
