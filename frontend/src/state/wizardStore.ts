import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { Actor, AttackDomain } from "../api/contract";
import { defaultScope, type ScopeSettings } from "../features/scope/scopeModel";

export type WizardStep = 0 | 1 | 2 | 3 | 4;

interface WizardState {
  currentStep: WizardStep;
  maxStep: WizardStep;
  domains: AttackDomain[];
  selectedActor: Actor | null;
  scope: ScopeSettings;
  scopeInitializedFor: string | null;
  setStep: (step: WizardStep) => void;
  setDomains: (domains: AttackDomain[]) => void;
  selectActor: (actor: Actor | null) => void;
  initializeScope: (actorId: string, tactics: string[]) => void;
  updateScope: (patch: Partial<ScopeSettings>) => void;
  restart: () => void;
}

function initialState(): Pick<WizardState, "currentStep" | "maxStep" | "domains" | "selectedActor" | "scope" | "scopeInitializedFor"> {
  return {
    currentStep: 0,
    maxStep: 0,
    domains: ["enterprise"],
    selectedActor: null,
    scope: defaultScope(),
    scopeInitializedFor: null,
  };
}

export const useWizardStore = create<WizardState>()(
  persist(
    (set) => ({
      ...initialState(),
      setStep: (step) => set((state) => ({ currentStep: step, maxStep: Math.max(state.maxStep, step) as WizardStep })),
      setDomains: (domains) => set({ domains, selectedActor: null, scope: defaultScope(), scopeInitializedFor: null, currentStep: 1, maxStep: 1 }),
      selectActor: (actor) => set((state) => ({
        selectedActor: actor,
        ...(actor?.stix_id !== state.selectedActor?.stix_id ? { scope: defaultScope(), scopeInitializedFor: null } : {}),
      })),
      initializeScope: (actorId, tactics) => set((state) => state.scopeInitializedFor === actorId
        ? state
        : { scope: { ...state.scope, tactics }, scopeInitializedFor: actorId }),
      updateScope: (patch) => set((state) => ({ scope: { ...state.scope, ...patch } })),
      restart: () => set(initialState()),
    }),
    {
      name: "adversaryflow-wizard-v3",
      partialize: (state) => ({
        currentStep: state.currentStep,
        maxStep: state.maxStep,
        domains: state.domains,
        selectedActor: state.selectedActor,
        scope: state.scope,
        scopeInitializedFor: state.scopeInitializedFor,
      }),
    },
  ),
);
