import { create } from "zustand";
import { createJSONStorage, persist, type StateStorage } from "zustand/middleware";

import type { Actor, AttackDomain, ProcedureEvidence, WorkflowResponse } from "../api/contract";
import { evidenceFromImportedPlan, scopeFromImportedPlan, workflowFromImportedPlan, type PlanExport } from "../features/export/planContract";
import { defaultScope, resolveCommand, type ScopeSettings } from "../features/scope/scopeModel";
import type { ExecutionEvidence } from "../features/review/evidence";

export type WizardStep = 0 | 1 | 2 | 3 | 4;
export const WIZARD_STORAGE_KEY = "adversaryflow-wizard-v3";

export interface EvidenceSnapshot {
  actor: Actor | null;
  domains: AttackDomain[];
  scope: ScopeSettings;
  workflow: WorkflowResponse | null;
  records: Record<string, ExecutionEvidence>;
  procedureEvidence?: ProcedureEvidence[];
}

export function evidenceIdentity(actorId: string, workflow: WorkflowResponse, platform: string, selections?: Record<string, string>, scope?: ScopeSettings): string {
  const choices = Object.entries(selections ?? {}).sort(([left], [right]) => left.localeCompare(right));
  const effectiveScope = scope ?? { commandPlatform: platform as ScopeSettings["commandPlatform"], commandSelections: selections,
    allowNetwork: false, allowAdmin: false, allowHighRisk: false, tactics: [], includePre: true, curatedOnly: false, operator: "", target: "" };
  const selectedIds = [...new Set(workflow.stages.flatMap((stage) => stage.techniques.map((technique) => {
    const selected = resolveCommand(technique, effectiveScope);
    return selected.command_id ? `${technique.attack_id}:${selected.command_id}` : "";
  })))].filter(Boolean).sort();
  return [actorId, workflow.metadata.domains.join("+"), workflow.metadata.data_version,
    ...(choices.length ? [`choices:${choices.map(([id, value]) => `${id}:${value}`).join(";")}`] : []),
    ...(selectedIds.length ? [`commands:${selectedIds.join(";")}`] : []), platform].join("|");
}

export interface WizardState {
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
  engagementId: string | null;
  engagementRevision: number | null;
  procedureEvidence: ProcedureEvidence[];
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
  setEngagementRecord: (id: string | null, revision: number | null) => void;
  attachProcedureEvidence: (procedures: ProcedureEvidence[]) => void;
  revokeProcedures: (actorId: string, sourceHash: string, candidateIds: string[]) => void;
  importWorkspace: (workspace: WorkspaceState) => void;
  reloadCatalog: (workflow: WorkflowResponse) => void;
  workspaceGeneration: number;
}

export const useStorageHealth = create<{ status: "unknown" | "saved" | "failed"; message: string }>(() => ({ status: "unknown", message: "" }));
function storageFailed(): void {
  useStorageHealth.setState({ status: "failed", message: "This workspace is not saved in this browser. Storage may be full or denied. Keep this tab open and download a workspace recovery copy now." });
}

const resilientStorage: StateStorage = {
  getItem: (name) => {
    try {
      const value = localStorage.getItem(name);
      if (value) useStorageHealth.setState({ status: "saved", message: "" });
      return value;
    } catch { storageFailed(); return null; }
  },
  setItem: (name, value) => {
    try { localStorage.setItem(name, value); useStorageHealth.setState({ status: "saved", message: "" }); } catch { storageFailed(); }
  },
  removeItem: (name) => {
    try { localStorage.removeItem(name); } catch { storageFailed(); }
  },
};

export type WorkspaceState = Pick<WizardState, "currentStep" | "maxStep" | "domains" | "selectedActor" | "scope" | "scopeInitializedFor" | "evidenceKey" | "records" | "importedWorkflow" | "savedWorkflow" | "evidenceArchive" | "engagementId" | "engagementRevision" | "procedureEvidence">;
function initialState(): WorkspaceState {
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
    engagementId: null,
    engagementRevision: null,
    procedureEvidence: [],
  };
}

function archiveEvidence(state: WizardState): Record<string, EvidenceSnapshot> {
  if (!state.evidenceKey || (!Object.keys(state.records).length && !state.procedureEvidence.some((item) => item.actor_stix_id === state.selectedActor?.stix_id))) return state.evidenceArchive;
  return { ...state.evidenceArchive, [state.evidenceKey]: {
    actor: state.selectedActor, domains: state.domains, scope: state.scope,
    workflow: state.savedWorkflow ?? state.importedWorkflow, records: state.records,
    procedureEvidence: state.procedureEvidence.filter((item) => item.actor_stix_id === state.selectedActor?.stix_id),
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
      workspaceGeneration: 0,
      setStep: (step) => set((state) => ({ currentStep: step, maxStep: Math.max(state.maxStep, step) as WizardStep })),
      setDomains: (domains) => set((state) => ({ ...initialState(), domains, currentStep: 1, maxStep: 1, procedureEvidence: state.procedureEvidence, workspaceGeneration: state.workspaceGeneration + 1 })),
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
          engagementId: null,
          engagementRevision: null,
          workspaceGeneration: state.workspaceGeneration + 1,
        } : {}),
      })),
      initializeScope: (actorId, tactics) => set((state) => state.scopeInitializedFor === actorId
        ? state
        : { scope: { ...state.scope, tactics }, scopeInitializedFor: actorId }),
      updateScope: (patch) => set((state) => {
        const scope = { ...state.scope, ...patch };
        const workflow = state.savedWorkflow ?? state.importedWorkflow;
        const key = state.evidenceKey && workflow && state.selectedActor
          ? evidenceIdentity(state.selectedActor.stix_id, workflow, scope.commandPlatform, scope.commandSelections, scope)
          : state.evidenceKey && scope.commandPlatform !== state.scope.commandPlatform
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
          procedureEvidence: snapshot.procedureEvidence ?? [],
          engagementId: null, engagementRevision: null,
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
          operator: patch.operator ?? previous.operator ?? (state.records[techniqueId] ? undefined : state.scope.operator),
          target: patch.target ?? previous.target ?? (state.records[techniqueId] ? undefined : state.scope.target),
        };
        const receiptFields = ["outcome", "run_id", "started_at", "completed_at", "exit_code", "cleanup_completed"] as const;
        if (previous.receipt_verified && patch.receipt_payload === undefined
            && receiptFields.some((field) => Object.prototype.hasOwnProperty.call(patch, field) && patch[field] !== previous[field])) {
          next.receipt_verified = false;
          delete next.receipt_payload;
          delete next.receipt_sha256;
          if (next.evidence_source === "exercise_receipt") next.evidence_source = "operator_supplied";
        }
        return { records: { ...state.records, [techniqueId]: next } };
      }),
      importPlan: (plan) => {
        const scope = scopeFromImportedPlan(plan);
        set((state) => ({
          currentStep: 3,
          maxStep: 4,
          domains: [...plan.domains],
          selectedActor: { ...plan.actor, aliases: [...plan.actor.aliases] },
          scope,
          scopeInitializedFor: plan.actor.stix_id,
          evidenceKey: evidenceIdentity(plan.actor.stix_id, workflowFromImportedPlan(plan), scope.commandPlatform, scope.commandSelections, scope),
          records: evidenceFromImportedPlan(plan),
          importedWorkflow: workflowFromImportedPlan(plan),
          savedWorkflow: workflowFromImportedPlan(plan),
          evidenceArchive: {},
          engagementId: null,
          engagementRevision: null,
          procedureEvidence: [...(plan.procedures ?? [])],
          workspaceGeneration: state.workspaceGeneration + 1,
        }));
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
        engagementId: null,
        engagementRevision: null,
        procedureEvidence: state.procedureEvidence,
        workspaceGeneration: state.workspaceGeneration + 1,
      })),
      restart: () => set((state) => ({ ...initialState(), workspaceGeneration: state.workspaceGeneration + 1 })),
      setEngagementRecord: (engagementId, engagementRevision) => set({ engagementId, engagementRevision }),
      attachProcedureEvidence: (procedures) => set((state) => {
        const key = (item: ProcedureEvidence): string => JSON.stringify([item.actor_stix_id, item.candidate_id]);
        const byId = new Map(state.procedureEvidence.map((item) => [key(item), item]));
        procedures.forEach((item) => byId.set(key(item), item));
        return { procedureEvidence: [...byId.values()] };
      }),
      revokeProcedures: (actorId, sourceHash, candidateIds) => set((state) => {
        const keep = (item: ProcedureEvidence): boolean => !(item.actor_stix_id === actorId && item.source_sha256 === sourceHash && candidateIds.includes(item.candidate_id));
        return {
          procedureEvidence: state.procedureEvidence.filter(keep),
          evidenceArchive: Object.fromEntries(Object.entries(state.evidenceArchive).map(([key, snapshot]) => [key, {
            ...snapshot, procedureEvidence: snapshot.procedureEvidence?.filter(keep),
          }])),
        };
      }),
      importWorkspace: (workspace) => set((state) => ({ ...workspace, workspaceGeneration: state.workspaceGeneration + 1 })),
      reloadCatalog: (workflow) => set((state) => {
        if (!state.selectedActor || workflow.actor.stix_id !== state.selectedActor.stix_id
            || workflow.metadata.domains.join("+") !== state.domains.join("+")) throw new Error("Catalog identity does not match this workspace.");
        // Keep the imported snapshot even if it has no execution records.
        const archived = { ...state.evidenceArchive };
        if (state.evidenceKey) archived[`${state.evidenceKey}|imported`] = {
          actor: state.selectedActor, domains: state.domains, scope: state.scope,
          workflow: state.importedWorkflow ?? state.savedWorkflow, records: state.records,
          procedureEvidence: state.procedureEvidence.filter((item) => item.actor_stix_id === state.selectedActor?.stix_id),
        };
        const key = evidenceIdentity(state.selectedActor.stix_id, workflow, state.scope.commandPlatform, state.scope.commandSelections, state.scope);
        return { evidenceArchive: archived, evidenceKey: key,
          records: key === state.evidenceKey ? state.records : archived[key]?.records ?? {},
          importedWorkflow: workflow, savedWorkflow: workflow, workspaceGeneration: state.workspaceGeneration + 1 };
      }),
    }),
    {
      name: WIZARD_STORAGE_KEY,
      partialize: workspaceSnapshot,
      storage: createJSONStorage(() => resilientStorage),
    },
  ),
);

export function workspaceSnapshot(state: WizardState): WorkspaceState {
  return {
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
        engagementId: state.engagementId,
        engagementRevision: state.engagementRevision,
        procedureEvidence: state.procedureEvidence,
  };
}
