import { create } from "zustand";
import { createJSONStorage, persist, type StateStorage } from "zustand/middleware";

import type { Actor, AttackDomain, WorkflowResponse } from "../api/contract";
import { evidenceFromImportedPlan, scopeFromImportedPlan, workflowFromImportedPlan, type PlanExport } from "../features/export/planContract";
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
  importedWorkflow: WorkflowResponse | null;
  setStep: (step: WizardStep) => void;
  setDomains: (domains: AttackDomain[]) => void;
  selectActor: (actor: Actor | null) => void;
  initializeScope: (actorId: string, tactics: string[]) => void;
  updateScope: (patch: Partial<ScopeSettings>) => void;
  ensureEvidenceKey: (key: string) => void;
  updateEvidence: (techniqueId: string, patch: Partial<ExecutionEvidence>) => void;
  importPlan: (plan: PlanExport) => void;
  resetAfterRefresh: () => void;
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

function initialState(): Pick<WizardState, "currentStep" | "maxStep" | "domains" | "selectedActor" | "scope" | "scopeInitializedFor" | "evidenceKey" | "records" | "importedWorkflow"> {
  return {
    currentStep: 0,
    maxStep: 0,
    domains: ["enterprise"],
    selectedActor: null,
    scope: defaultScope(),
    scopeInitializedFor: null,
    evidenceKey: null,
    records: {},
    importedWorkflow: null,
  };
}

export const useWizardStore = create<WizardState>()(
  persist(
    (set) => ({
      ...initialState(),
      setStep: (step) => set((state) => ({ currentStep: step, maxStep: Math.max(state.maxStep, step) as WizardStep })),
      setDomains: (domains) => set({ domains, selectedActor: null, scope: defaultScope(), scopeInitializedFor: null, evidenceKey: null, records: {}, importedWorkflow: null, currentStep: 1, maxStep: 1 }),
      selectActor: (actor) => set((state) => ({
        selectedActor: actor,
        ...(actor?.stix_id !== state.selectedActor?.stix_id ? { scope: defaultScope(), scopeInitializedFor: null, evidenceKey: null, records: {}, importedWorkflow: null } : {}),
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
      importPlan: (plan) => {
        const scope = scopeFromImportedPlan(plan);
        set({
          currentStep: 3,
          maxStep: 4,
          domains: [...plan.domains],
          selectedActor: { ...plan.actor, aliases: [...plan.actor.aliases] },
          scope,
          scopeInitializedFor: plan.actor.stix_id,
          evidenceKey: [plan.actor.stix_id, plan.domains.join("+"), plan.data_version, scope.commandPlatform].join("|"),
          records: evidenceFromImportedPlan(plan),
          importedWorkflow: workflowFromImportedPlan(plan),
        });
      },
      resetAfterRefresh: () => set((state) => ({
        currentStep: 1,
        maxStep: 1,
        selectedActor: state.selectedActor,
        scope: defaultScope(),
        scopeInitializedFor: null,
        evidenceKey: null,
        records: {},
        importedWorkflow: null,
      })),
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
        importedWorkflow: state.importedWorkflow,
      }),
      storage: createJSONStorage(() => resilientStorage),
    },
  ),
);
