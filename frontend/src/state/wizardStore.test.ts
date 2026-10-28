import { beforeEach, describe, expect, it } from "vitest";

import type { Actor, WorkflowResponse } from "../api/contract";
import { defaultScope } from "../features/scope/scopeModel";
import { evidenceIdentity, useWizardStore } from "./wizardStore";

const actor: Actor = {
  stix_id: "intrusion-set--test",
  attack_id: "G0001",
  name: "Test Actor",
  type: "group",
  aliases: ["Example"],
  description: "Fixture actor",
  technique_count: 4,
};

describe("wizardStore", () => {
  beforeEach(() => {
    useWizardStore.getState().restart();
  });

  it("archives evidence when the chosen command changes and restores the original variant", () => {
    const base = { platform: "windows", command: "whoami", note: "Identity", cleanup: "", risk: "low" as const,
      requires_admin: false, requires_network: false, network_targets: [], side_effects: [], prerequisites: [],
      expected_telemetry: "Process", expected_output: "Identity", timeout_seconds: 60, rollback: "",
      cleanup_required: false, acknowledgment_required: false, command_id: "a".repeat(64) };
    const workflow: WorkflowResponse = { actor: {}, summary: {}, kill_chain: [], metadata: { domains: ["enterprise"], data_version: "same", version: "0.5.3" },
      stages: [{ tactic: "discovery", title: "Discovery", techniques: [{ attack_id: "T1033", name: "Identity", command_source: "curated",
        commands: [base, { ...base, command: "hostname", command_id: "b".repeat(64) }] }] }] };
    const store = useWizardStore.getState();
    store.selectActor(actor);
    store.updateScope({ commandPlatform: "windows" });
    const key = evidenceIdentity(actor.stix_id, workflow, "windows", undefined, useWizardStore.getState().scope);
    store.ensureEvidenceKey(key, workflow);
    store.updateEvidence("T1033", { outcome: "passed", notes: "Original command" });
    store.updateScope({ commandSelections: { T1033: "b".repeat(64) } });
    expect(useWizardStore.getState().records).toEqual({});
    expect(useWizardStore.getState().evidenceArchive[key]?.records.T1033?.notes).toBe("Original command");
    store.updateScope({ commandSelections: {} });
    expect(useWizardStore.getState().records.T1033?.notes).toBe("Original command");
    const revised = structuredClone(workflow);
    revised.stages[0]!.techniques[0]!.commands[0]!.command_id = "c".repeat(64);
    expect(evidenceIdentity(actor.stix_id, revised, "windows")).not.toBe(key);
    workflow.stages[0]!.techniques[0]!.commands[0]!.requires_network = true;
    const scope = { ...defaultScope(), commandPlatform: "windows" as const };
    expect(evidenceIdentity(actor.stix_id, workflow, "windows", undefined, scope))
      .not.toBe(evidenceIdentity(actor.stix_id, workflow, "windows", undefined, { ...scope, allowNetwork: true }));
  });

  it("partitions evidence before leaving Scope and restores it when returning to a platform", () => {
    const workflow: WorkflowResponse = { actor: {}, summary: {}, kill_chain: [], stages: [], metadata: { domains: ["enterprise"], data_version: "old", version: "0.5.3" } };
    const store = useWizardStore.getState();
    store.selectActor(actor);
    store.updateScope({ commandPlatform: "windows" });
    const windowsKey = evidenceIdentity(actor.stix_id, workflow, "windows");
    store.ensureEvidenceKey(windowsKey, workflow);
    store.updateEvidence("T1033", { outcome: "passed", notes: "Windows evidence" });
    store.updateScope({ commandPlatform: "linux" });
    expect(useWizardStore.getState().records).toEqual({});
    expect(useWizardStore.getState().evidenceArchive[windowsKey]?.records.T1033?.notes).toBe("Windows evidence");
    store.setStep(4);
    expect(useWizardStore.getState().records).toEqual({});
    store.updateEvidence("T1033", { outcome: "failed", notes: "Linux evidence" });
    store.updateScope({ commandPlatform: "windows" });
    expect(useWizardStore.getState().records.T1033?.notes).toBe("Windows evidence");
    store.updateScope({ commandPlatform: "linux" });
    expect(useWizardStore.getState().records.T1033?.notes).toBe("Linux evidence");
  });

  it("keeps the old workflow and evidence when ATT&CK data changes", () => {
    const oldWorkflow: WorkflowResponse = { actor: {}, summary: {}, kill_chain: [], stages: [], metadata: { domains: ["enterprise"], data_version: "old", version: "0.5.3" } };
    const newWorkflow = { ...oldWorkflow, metadata: { ...oldWorkflow.metadata, data_version: "new" } };
    const store = useWizardStore.getState();
    store.selectActor(actor);
    store.updateScope({ commandPlatform: "windows" });
    const oldKey = evidenceIdentity(actor.stix_id, oldWorkflow, "windows");
    store.ensureEvidenceKey(oldKey, oldWorkflow);
    store.updateEvidence("T1033", { outcome: "passed", notes: "Previous version" });
    store.ensureEvidenceKey(evidenceIdentity(actor.stix_id, newWorkflow, "windows"), newWorkflow);
    expect(useWizardStore.getState().records).toEqual({});
    expect(useWizardStore.getState().evidenceArchive[oldKey]?.workflow?.metadata.data_version).toBe("old");
    store.restoreEvidence(oldKey);
    expect(useWizardStore.getState().importedWorkflow?.metadata.data_version).toBe("old");
    expect(useWizardStore.getState().records.T1033?.notes).toBe("Previous version");
  });

  it("tracks the furthest reached guided step", () => {
    useWizardStore.getState().setStep(1);
    useWizardStore.getState().selectActor(actor);
    useWizardStore.getState().setStep(2);
    useWizardStore.getState().setStep(1);

    expect(useWizardStore.getState()).toMatchObject({ currentStep: 1, maxStep: 2, selectedActor: actor });
  });

  it("clears the selected actor when ATT&CK domains change", () => {
    useWizardStore.getState().selectActor(actor);
    useWizardStore.getState().setDomains(["enterprise", "ics"]);

    expect(useWizardStore.getState()).toMatchObject({
      currentStep: 1,
      maxStep: 1,
      domains: ["enterprise", "ics"],
      selectedActor: null,
    });
  });

  it("returns to the guided actor step when an in-progress plan changes actors", () => {
    useWizardStore.getState().selectActor(actor);
    useWizardStore.getState().setStep(3);
    useWizardStore.getState().updateEvidence("T1033", { outcome: "passed" });

    useWizardStore.getState().selectActor({ ...actor, stix_id: "intrusion-set--other", attack_id: "G0002", name: "Other Actor" });

    expect(useWizardStore.getState()).toMatchObject({
      currentStep: 1,
      maxStep: 1,
      records: {},
      scopeInitializedFor: null,
    });
  });

  it("clears stale receipt verification when an operator edits run evidence", () => {
    const store = useWizardStore.getState();
    store.updateEvidence("T1033", { outcome: "passed", run_id: "receipt-run", receipt_sha256: "a".repeat(64),
      receipt_verified: true, receipt_payload: { run_id: "receipt-run" }, evidence_source: "exercise_receipt" });
    store.updateEvidence("T1033", { notes: "Correlated with endpoint logs", detection_result: "alerted" });
    expect(useWizardStore.getState().records.T1033?.receipt_verified).toBe(true);
    store.updateEvidence("T1033", { run_id: "operator-run" });
    expect(useWizardStore.getState().records.T1033).toMatchObject({ run_id: "operator-run", receipt_verified: false, evidence_source: "operator_supplied" });
    expect(useWizardStore.getState().records.T1033?.receipt_payload).toBeUndefined();
    expect(useWizardStore.getState().records.T1033?.receipt_sha256).toBeUndefined();
  });
});
