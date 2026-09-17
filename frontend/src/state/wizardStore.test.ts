import { beforeEach, describe, expect, it } from "vitest";

import type { Actor } from "../api/contract";
import { useWizardStore } from "./wizardStore";

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
});
