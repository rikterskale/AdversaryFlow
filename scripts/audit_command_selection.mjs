// Compare the actual UI resolver against every backend scope/variant decision,
// and round-trip every catalog block through the actual browser plan contract.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";

const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "adversaryflow-ui-audit-"));
globalThis.window = {};
try {
  const load = async (name, source) => {
    const target = path.join(temporary, `${name}.mjs`);
    execFileSync(process.execPath, ["node_modules/rolldown/bin/cli.mjs", source, "--file", target, "--format", "esm"], { stdio: "pipe" });
    return import(pathToFileURL(target).href);
  };
  const { resolveCommand } = await load("scope", "frontend/src/features/scope/scopeModel.ts");
  const { buildExportBundle } = await load("export", "frontend/src/features/export/exportModel.ts");
  const { validateImportedPlan, scopeFromImportedPlan, workflowFromImportedPlan } = await load("contract", "frontend/src/features/export/planContract.ts");
  const techniques = new Map(input.techniques.map(t => [t.attack_id, t]));
  const scopeFor = c => ({ commandPlatform: c.platform, commandSelections: c.selected_id ? { [c.technique_id]: c.selected_id } : {},
    tactics: ["discovery"], includePre: true, curatedOnly: false, allowNetwork: c.allow_network, allowAdmin: c.allow_admin,
    allowHighRisk: c.allow_high_risk, operator: "Audit fixture", target: "Disposable fixture" });
  for (const c of input.cases) {
    const command = resolveCommand(techniques.get(c.technique_id), scopeFor(c));
    assert.equal(command.command_id ?? null, c.command_id, JSON.stringify(c));
    assert.equal(command.availability_status, c.status, JSON.stringify(c));
  }
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  for (const name of fs.readdirSync("schemas").filter(n => n.endsWith(".schema.json"))) ajv.addSchema(JSON.parse(fs.readFileSync(path.join("schemas", name), "utf8")));
  const base = "https://github.com/rikterskale/AdversaryFlow/schemas/";
  const validators = [ajv.getSchema(`${base}adversaryflow-plan.schema.json`), ajv.getSchema(`${base}adversaryflow-plan-v3.schema.json`)];
  const actor = { stix_id: "intrusion-set--audit", attack_id: "G0001", name: "Audit fixture", type: "group", aliases: [], description: "Offline audit", technique_count: 1 };
  let exports = 0;
  for (const technique of techniques.values()) for (const command of technique.commands) {
    const scope = scopeFor({ technique_id: technique.attack_id, platform: command.platform, selected_id: command.command_id,
      allow_network: true, allow_admin: true, allow_high_risk: true });
    const workflow = { actor: {}, summary: {}, kill_chain: [{ tactic: "discovery", title: "Discovery" }],
      stages: [{ tactic: "discovery", title: "Discovery", techniques: [technique] }],
      metadata: { domains: ["enterprise"], data_version: "offline-audit", version: "0.5.3" } };
    const { plan } = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]);
    for (let version = 0; version < 2; version++) {
      const candidate = version ? { ...plan, schema_version: "3.0", procedures: [] } : plan;
      assert.ok(validators[version](candidate), JSON.stringify(validators[version].errors));
      validateImportedPlan(candidate);
      const restored = workflowFromImportedPlan(candidate).stages[0].techniques[0].commands[0];
      for (const key of ["command_id", "environment", "execution_role", "required_tools", "required_credentials", "fidelity"])
        assert.deepEqual(restored[key], command[key], `${technique.attack_id}/${key}`);
      assert.deepEqual(scopeFromImportedPlan(candidate).commandSelections, scope.commandSelections);
      exports++;
    }
  }
  console.log(JSON.stringify({ selection_cases_passed: input.cases.length, schema_2_3_exports_round_tripped: exports }, null, 2));
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
