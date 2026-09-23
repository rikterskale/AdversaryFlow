import { beforeEach, describe, expect, it } from "vitest";

import type { Actor, WorkflowResponse } from "../api/contract";
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
});
