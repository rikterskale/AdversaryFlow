import { create } from "zustand";
import { createJSONStorage, persist, type StateStorage } from "zustand/middleware";

import type { Actor, AttackDomain, WorkflowResponse } from "../api/contract";
import { evidenceFromImportedPlan, scopeFromImportedPlan, workflowFromImportedPlan, type PlanExport } from "../features/export/planContract";
import { defaultScope, type ScopeSettings } from "../features/scope/scopeModel";
import type { ExecutionEvidence } from "../features/review/evidence";

export type WizardStep = 0 | 1 | 2 | 3 | 4;

export interface EvidenceSnapshot {
  actor: Actor | null;
  domains: AttackDomain[];
  scope: ScopeSettings;
  workflow: WorkflowResponse | null;
  records: Record<string, ExecutionEvidence>;
}

export function evidenceIdentity(actorId: string, workflow: WorkflowResponse, platform: string): string {
  return [actorId, workflow.metadata.domains.join("+"), workflow.metadata.data_version, platform].join("|");
}

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
  savedWorkflow: WorkflowResponse | null;
  evidenceArchive: Record<string, EvidenceSnapshot>;
  setStep: (step: WizardStep) => void;
  setDomains: (domains: AttackDomain[]) => void;
  selectActor: (actor: Actor | null) => void;
  initializeScope: (actorId: string, tactics: string[]) => void;
  updateScope: (patch: Partial<ScopeSettings>) => void;
  ensureEvidenceKey: (key: string, workflow?: WorkflowResponse) => void;
  restoreEvidence: (key: string) => void;
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

function initialState(): Pick<WizardState, "currentStep" | "maxStep" | "domains" | "selectedActor" | "scope" | "scopeInitializedFor" | "evidenceKey" | "records" | "importedWorkflow" | "savedWorkflow" | "evidenceArchive"> {
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
    savedWorkflow: null,
    evidenceArchive: {},
  };
}

function archiveEvidence(state: WizardState): Record<string, EvidenceSnapshot> {
  if (!state.evidenceKey || !Object.keys(state.records).length) return state.evidenceArchive;
  return { ...state.evidenceArchive, [state.evidenceKey]: {
    actor: state.selectedActor, domains: state.domains, scope: state.scope,
    workflow: state.savedWorkflow ?? state.importedWorkflow, records: state.records,
  } };
}

function switchEvidence(state: WizardState, key: string): Partial<WizardState> {
  if (state.evidenceKey === key) return {};
  const evidenceArchive = archiveEvidence(state);
  return { evidenceArchive, evidenceKey: key, records: evidenceArchive[key]?.records ?? {} };
}

export const useWizardStore = create<WizardState>()(
  persist(
    (set) => ({
      ...initialState(),
      setStep: (step) => set((state) => ({ currentStep: step, maxStep: Math.max(state.maxStep, step) as WizardStep })),
      setDomains: (domains) => set({ ...initialState(), domains, currentStep: 1, maxStep: 1 }),
      selectActor: (actor) => set((state) => ({
        selectedActor: actor,
        ...(actor?.stix_id !== state.selectedActor?.stix_id ? {
          currentStep: 1,
          maxStep: 1,
          scope: defaultScope(),
          scopeInitializedFor: null,
          evidenceKey: null,
          records: {},
          importedWorkflow: null,
          savedWorkflow: null,
          evidenceArchive: {},
        } : {}),
      })),
      initializeScope: (actorId, tactics) => set((state) => state.scopeInitializedFor === actorId
        ? state
        : { scope: { ...state.scope, tactics }, scopeInitializedFor: actorId }),
      updateScope: (patch) => set((state) => {
        const scope = { ...state.scope, ...patch };
        const key = state.evidenceKey && scope.commandPlatform !== state.scope.commandPlatform
          ? [...state.evidenceKey.split("|").slice(0, -1), scope.commandPlatform].join("|") : null;
        return { ...(key ? switchEvidence(state, key) : {}), scope };
      }),
      ensureEvidenceKey: (key, workflow) => set((state) => {
        if (state.evidenceKey === key && (!workflow || state.savedWorkflow === workflow)) return state;
        return { ...switchEvidence(state, key), ...(workflow ? { savedWorkflow: workflow } : {}) };
      }),
      restoreEvidence: (key) => set((state) => {
        const snapshot = state.evidenceArchive[key];
        if (!snapshot?.workflow || !snapshot.actor) return state;
        return {
          ...switchEvidence(state, key), selectedActor: snapshot.actor, domains: snapshot.domains,
          scope: snapshot.scope, scopeInitializedFor: snapshot.actor.stix_id,
          importedWorkflow: snapshot.workflow, savedWorkflow: snapshot.workflow, currentStep: 3, maxStep: 4,
        };
      }),
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
          savedWorkflow: workflowFromImportedPlan(plan),
          evidenceArchive: {},
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
        savedWorkflow: null,
        evidenceArchive: {},
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
        savedWorkflow: state.savedWorkflow,
        evidenceArchive: state.evidenceArchive,
      }),
      storage: createJSONStorage(() => resilientStorage),
    },
  ),
);
