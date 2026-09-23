import { describe, expect, it } from "vitest";

import type { Actor, Command, WorkflowResponse } from "../../api/contract";
import type { ExecutionEvidence } from "../review/evidence";
import type { ScopeSettings } from "../scope/scopeModel";
import { buildExportBundle, summarizeExportReadiness } from "./exportModel";
import { scopeFromImportedPlan, validateImportedPlan, workflowFromImportedPlan } from "./planContract";

const actor: Actor = { stix_id: "intrusion-set--test", attack_id: "G0001", name: "Test Actor", type: "group", aliases: [], description: "Fixture", technique_count: 2 };
const command: Command = { platform: "windows", command: "whoami", note: "Identity check", cleanup: "", risk: "low", side_effects: [], requires_admin: false, requires_network: false, network_targets: [], prerequisites: ["Authorized lab"], expected_telemetry: "Process telemetry", expected_output: "Identity", timeout_seconds: 60, rollback: "", cleanup_required: false, acknowledgment_required: false };
const technique = (id: string) => ({ attack_id: id, name: `${id} fixture`, commands: [command], command_source: "curated" as const, tactics: ["execution"], platforms: ["Windows"] });
const workflow: WorkflowResponse = {
  actor: {}, summary: {},
  kill_chain: [{ tactic: "reconnaissance", title: "Reconnaissance" }, { tactic: "execution", title: "Execution" }],
  stages: [
    { tactic: "reconnaissance", title: "Reconnaissance", techniques: [technique("T1595")] },
    { tactic: "execution", title: "Execution", techniques: [technique("T1033")] },
  ],
  metadata: { domains: ["enterprise"], data_version: "enterprise:fixture", version: "1.0.0" },
};
const scope: ScopeSettings = { commandPlatform: "windows", tactics: ["reconnaissance", "execution"], includePre: false, curatedOnly: false, allowNetwork: false, allowAdmin: false, allowHighRisk: false, operator: "Purple Team", target: "lab-01" };

describe("exportModel", () => {
  it("preserves imported guardrails while requiring review of untrusted command text", () => {
    const original = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    const importedScope = scopeFromImportedPlan(original);
    expect(importedScope.allowHighRisk).toBe(false);
    const importedWorkflow = workflowFromImportedPlan(original);
    const imported = importedWorkflow.stages[0]?.techniques[0]?.commands[0];
    expect(imported).toMatchObject({ risk: "low", acknowledgment_required: true, untrusted: true });
    const roundTrip = buildExportBundle(actor, importedWorkflow, importedScope, {}, ["enterprise"]);
    expect(roundTrip.plan.scope.allow_high_risk).toBe(false);
    expect(roundTrip.preview.runnable).toBe(1);
    expect(() => validateImportedPlan(roundTrip.plan)).not.toThrow();
  });
  it("exports only effective stages and validates the generated schema 2.0 plan", () => {
    const records: Record<string, ExecutionEvidence> = {
      T1033: { outcome: "passed", detection_result: "alerted", telemetry_refs: ["x".repeat(501), ...Array.from({ length: 25 }, (_, index) => `event-${index}`)] },
    };
    const bundle = buildExportBundle(actor, workflow, scope, records, ["enterprise"]);
    expect(bundle.plan.scope.stages).toEqual(["execution"]);
    expect(bundle.plan.stages.map((stage) => stage.tactic)).toEqual(["execution"]);
    expect(bundle.plan.stages[0]?.techniques[0]?.execution.telemetry_refs).toHaveLength(20);
    expect(() => validateImportedPlan(bundle.plan)).not.toThrow();
  });

  it("deduplicates readiness statistics for techniques mapped to multiple tactics", () => {
    const bundle = buildExportBundle(actor, workflow, { ...scope, includePre: true }, { T1033: { outcome: "passed", detection_result: "silent" } }, ["enterprise"]);
    const duplicate = bundle.plan.stages[1]?.techniques[0];
    if (!duplicate) throw new Error("Fixture technique is missing");
    bundle.plan.stages[0]?.techniques.push({ ...duplicate, command_source: "fallback" });
    expect(summarizeExportReadiness(bundle.plan)).toEqual({ techniques: 2, detectionAssessed: 1, coverageGaps: 1 });
  });
});
