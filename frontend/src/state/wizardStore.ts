import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { Actor, AttackDomain } from "../api/contract";

export type WizardStep = 0 | 1 | 2 | 3 | 4;

interface WizardState {
  currentStep: WizardStep;
  maxStep: WizardStep;
  domains: AttackDomain[];
  selectedActor: Actor | null;
  setStep: (step: WizardStep) => void;
  setDomains: (domains: AttackDomain[]) => void;
  selectActor: (actor: Actor | null) => void;
  restart: () => void;
}

const initialState = {
  currentStep: 0 as WizardStep,
  maxStep: 0 as WizardStep,
  domains: ["enterprise"] as AttackDomain[],
  selectedActor: null as Actor | null,
};

export const useWizardStore = create<WizardState>()(
  persist(
    (set) => ({
      ...initialState,
      setStep: (step) => set((state) => ({ currentStep: step, maxStep: Math.max(state.maxStep, step) as WizardStep })),
      setDomains: (domains) => set({ domains, selectedActor: null, currentStep: 1, maxStep: 1 }),
      selectActor: (actor) => set({ selectedActor: actor }),
      restart: () => set(initialState),
    }),
    {
      name: "adversaryflow-wizard-v3",
      partialize: (state) => ({
        currentStep: state.currentStep,
        maxStep: state.maxStep,
        domains: state.domains,
        selectedActor: state.selectedActor,
      }),
    },
  ),
);
