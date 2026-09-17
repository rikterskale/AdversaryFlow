import { create } from "zustand";
import { createJSONStorage, persist, type StateStorage } from "zustand/middleware";

import type { Actor, AttackDomain } from "../api/contract";
import { defaultScope, type ScopeSettings } from "../features/scope/scopeModel";
import type { ExecutionEvidence } from "../features/review/evidence";

export type WizardStep = 0 | 1 | 2 | 3 | 4;

interface WizardState {
  currentStep: WizardStep;
  maxStep: WizardStep;
  domains: AttackDomain[];
  selectedActor: Actor | null;
  scope: ScopeSettings;
  scopeInitializedFor: string | null;
  evidenceKey: string | null;
  records: Record<string, ExecutionEvidence>;
  setStep: (step: WizardStep) => void;
  setDomains: (domains: AttackDomain[]) => void;
  selectActor: (actor: Actor | null) => void;
  initializeScope: (actorId: string, tactics: string[]) => void;
  updateScope: (patch: Partial<ScopeSettings>) => void;
  ensureEvidenceKey: (key: string) => void;
  updateEvidence: (techniqueId: string, patch: Partial<ExecutionEvidence>) => void;
  restart: () => void;
}

let storageWriteFailed = false;

const resilientStorage: StateStorage = {
  getItem: (name) => {
    try { return localStorage.getItem(name); } catch { return null; }
  },
  setItem: (name, value) => {
    try { localStorage.setItem(name, value); } catch { storageWriteFailed = true; }
  },
  removeItem: (name) => {
    try { localStorage.removeItem(name); } catch { storageWriteFailed = true; }
  },
};

export function consumeStorageWriteFailure(): boolean {
  const failed = storageWriteFailed;
  storageWriteFailed = false;
  return failed;
}

function initialState(): Pick<WizardState, "currentStep" | "maxStep" | "domains" | "selectedActor" | "scope" | "scopeInitializedFor" | "evidenceKey" | "records"> {
  return {
    currentStep: 0,
    maxStep: 0,
    domains: ["enterprise"],
    selectedActor: null,
    scope: defaultScope(),
    scopeInitializedFor: null,
    evidenceKey: null,
    records: {},
  };
}

export const useWizardStore = create<WizardState>()(
  persist(
    (set) => ({
      ...initialState(),
      setStep: (step) => set((state) => ({ currentStep: step, maxStep: Math.max(state.maxStep, step) as WizardStep })),
      setDomains: (domains) => set({ domains, selectedActor: null, scope: defaultScope(), scopeInitializedFor: null, evidenceKey: null, records: {}, currentStep: 1, maxStep: 1 }),
      selectActor: (actor) => set((state) => ({
        selectedActor: actor,
        ...(actor?.stix_id !== state.selectedActor?.stix_id ? { scope: defaultScope(), scopeInitializedFor: null, evidenceKey: null, records: {} } : {}),
      })),
      initializeScope: (actorId, tactics) => set((state) => state.scopeInitializedFor === actorId
        ? state
        : { scope: { ...state.scope, tactics }, scopeInitializedFor: actorId }),
      updateScope: (patch) => set((state) => ({ scope: { ...state.scope, ...patch } })),
      ensureEvidenceKey: (key) => set((state) => state.evidenceKey === key ? state : { evidenceKey: key, records: {} }),
      updateEvidence: (techniqueId, patch) => set((state) => {
        const previous = state.records[techniqueId] ?? { outcome: "not_run" };
        const next: ExecutionEvidence = {
          ...previous,
          ...patch,
          outcome: patch.outcome ?? previous.outcome,
          detection_result: patch.detection_result ?? previous.detection_result ?? "not_assessed",
          updated_at: new Date().toISOString(),
          operator: state.scope.operator,
          target: state.scope.target,
        };
        return { records: { ...state.records, [techniqueId]: next } };
      }),
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
        evidenceKey: state.evidenceKey,
        records: state.records,
      }),
      storage: createJSONStorage(() => resilientStorage),
    },
  ),
);
