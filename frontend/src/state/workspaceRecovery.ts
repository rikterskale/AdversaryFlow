import { isRecord, parseWorkflow } from "../api/guards";
import { validCommandSelections } from "../api/executionMetadata";
import type { ProcedureEvidence, WorkflowResponse } from "../api/contract";
import { validateActor, validateCommand, validateExecution, validateImportedPlan, verifyImportedPlanReceipts, type PlanExport } from "../features/export/planContract";
import { validDateTime, validReceiptFields, verifyReceiptDigest } from "../features/review/evidence";
import type { ScopeSettings } from "../features/scope/scopeModel";
import { boundedJson, downloadJson, PLAN_MAX_BYTES, requireByteLimit, WORKSPACE_MAX_BYTES } from "./workspaceIO";
import { useWizardStore, workspaceSnapshot, type EvidenceSnapshot, type WorkspaceState } from "./wizardStore";

export interface WorkspaceRecovery {
  recovery_version: "1.0";
  tool: "AdversaryFlow";
  captured_at: string;
  workspace: WorkspaceState;
}

function unsafeKeys(value: unknown, depth = 0): void {
  if (depth > 64) throw new Error("Recovery contains excessively nested data.");
  if (Array.isArray(value)) value.forEach((child) => unsafeKeys(child, depth + 1));
  else if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (["__proto__", "prototype", "constructor"].includes(key)) throw new Error("Recovery contains unsafe object keys.");
      unsafeKeys(child, depth + 1);
    }
  }
}

function scope(value: unknown): asserts value is ScopeSettings {
  const keys = ["commandPlatform", "tactics", "includePre", "curatedOnly", "allowNetwork", "allowAdmin", "allowHighRisk", "operator", "target", "commandSelections"];
  if (!isRecord(value) || Object.keys(value).some((key) => !keys.includes(key))
    || !["windows", "linux", "macos"].includes(String(value.commandPlatform))
    || (value.commandSelections !== undefined && !validCommandSelections(value.commandSelections))
    || !Array.isArray(value.tactics) || !value.tactics.every((item) => typeof item === "string")
    || !["includePre", "curatedOnly", "allowNetwork", "allowAdmin", "allowHighRisk"].every((key) => typeof value[key] === "boolean")
    || typeof value.operator !== "string" || value.operator.length > 120
    || typeof value.target !== "string" || value.target.length > 200) throw new Error("Recovery scope settings are invalid.");
}

function domains(value: unknown): asserts value is WorkspaceState["domains"] {
  if (!Array.isArray(value) || !value.length || new Set(value).size !== value.length
    || value.some((item) => !["enterprise", "ics", "mobile"].includes(String(item)))) throw new Error("Recovery domains are invalid.");
}

async function records(value: unknown): Promise<void> {
  if (!isRecord(value) || Object.keys(value).length > 4000) throw new Error("Recovery evidence records are invalid.");
  for (const [id, record] of Object.entries(value)) {
    if (!/^T[0-9]{4}(?:\.[0-9]{3})?$/.test(id) || !isRecord(record)) throw new Error("Recovery technique identity is invalid.");
    const { receipt_payload, telemetry_refs_draft, telemetry_refs, ...execution } = record;
    validateExecution(execution);
    // Invalid reference drafts are deliberately recoverable, never silently discarded.
    if (telemetry_refs_draft !== undefined && typeof telemetry_refs_draft !== "string") throw new Error("Recovery reference draft is invalid.");
    if (telemetry_refs !== undefined && (!Array.isArray(telemetry_refs) || !telemetry_refs.every((item) => typeof item === "string"))) throw new Error("Recovery references are invalid.");
    if (receipt_payload !== undefined && (!validReceiptFields(receipt_payload, id) || !await verifyReceiptDigest(receipt_payload)
      || record.run_id !== receipt_payload.run_id || record.receipt_sha256 !== receipt_payload.receipt_sha256)) throw new Error(`Recovery receipt for ${id} is invalid.`);
  }
}

function procedures(value: unknown): asserts value is ProcedureEvidence[] {
  if (!Array.isArray(value)) throw new Error("Recovery procedure collection is invalid.");
  const identities = new Set<string>();
  for (const item of value) {
    if (!isRecord(item) || typeof item.actor_stix_id !== "string" || !item.actor_stix_id
      || typeof item.candidate_id !== "string" || !item.candidate_id || item.candidate_id.length > 128
      || typeof item.source_sha256 !== "string" || !/^[a-fA-F0-9]{64}$/.test(item.source_sha256)
      || item.review_status !== "accepted") throw new Error("Recovery procedure attribution is invalid.");
    const key = JSON.stringify([item.actor_stix_id, item.candidate_id]);
    if (identities.has(key)) throw new Error("Recovery contains duplicate actor/candidate identities.");
    identities.add(key);
    // Reuse the published procedure contract, independently of the active actor.
    validateImportedPlan({
      schema_version: "3.0", tool: "AdversaryFlow", tool_version: "recovery", data_version: "recovery",
      domains: ["enterprise"], generated: new Date(0).toISOString(),
      actor: { stix_id: item.actor_stix_id, attack_id: "G0000", name: "Recovery", type: "group", aliases: [], description: "", technique_count: 1 },
      scope: { command_platform: "windows", include_pre: false, curated_only: false, allow_network: false, allow_admin: false, allow_high_risk: false, stages: ["execution"] },
      execution_context: { operator: "", target: "" },
      summary: { techniques: 1, runnable: 0, unsupported: 1, stages: 1, curated: 0, fallback: 1, marked_run: [] },
      stages: [{ tactic: "execution", title: "Recovery", techniques: [{
        id: "T0000", name: "Recovery", url: null, platforms: [], command_source: "fallback", supported: false, run: false, execution: { outcome: "not_run" },
        command: { platform: "windows", command: "", note: "", cleanup: "", risk: "none", side_effects: [], requires_admin: false, requires_network: false,
          network_targets: [], prerequisites: [], expected_telemetry: "", expected_output: "", timeout_seconds: 0, rollback: "", cleanup_required: false, acknowledgment_required: true, unsupported: true },
      }] }], procedures: [item],
    });
  }
}

function workflow(value: unknown): WorkflowResponse | null {
  if (value === null) return null;
  const result = parseWorkflow(value);
  domains(result.metadata.domains);
  if (result.stages.length > 32 || result.stages.reduce((sum, stage) => sum + stage.techniques.length, 0) > 4000) throw new Error("Recovery workflow exceeds the technique limit.");
  for (const stage of result.stages) {
    for (const item of stage.techniques) {
      if (!/^T[0-9]{4}(?:\.[0-9]{3})?$/.test(item.attack_id)) throw new Error("Recovery workflow technique identity is invalid.");
      for (const command of item.commands) {
        const { untrusted, ...savedCommand } = command;
        if (untrusted !== undefined && typeof untrusted !== "boolean") throw new Error("Recovery command trust flag is invalid.");
        validateCommand(savedCommand, item.attack_id);
      }
    }
  }
  return { ...result, stages: result.stages.map((stage) => ({ ...stage, techniques: stage.techniques.map((item) => ({
    ...item, commands: item.commands.map((command) => ({ ...command, untrusted: true, acknowledgment_required: true })),
  })) })) };
}

export async function validateWorkspace(value: unknown): Promise<WorkspaceState> {
  unsafeKeys(value);
  const keys = ["currentStep", "maxStep", "domains", "selectedActor", "scope", "scopeInitializedFor", "evidenceKey", "records", "importedWorkflow", "savedWorkflow", "evidenceArchive", "engagementId", "engagementRevision", "procedureEvidence"];
  if (!isRecord(value) || Object.keys(value).some((key) => !keys.includes(key)) || !keys.slice(0, 12).every((key) => key in value)
    || !Number.isInteger(value.currentStep) || Number(value.currentStep) < 0 || Number(value.currentStep) > 4
    || !Number.isInteger(value.maxStep) || Number(value.maxStep) < Number(value.currentStep) || Number(value.maxStep) > 4) throw new Error("Recovery workspace fields are invalid.");
  domains(value.domains);
  scope(value.scope);
  if (value.selectedActor !== null) validateActor(value.selectedActor);
  for (const key of ["scopeInitializedFor", "evidenceKey", "engagementId"]) {
    if (value[key] !== undefined && value[key] !== null && typeof value[key] !== "string") throw new Error(`Recovery ${key} is invalid.`);
  }
  if (value.engagementRevision !== undefined && value.engagementRevision !== null
    && (!Number.isInteger(value.engagementRevision) || Number(value.engagementRevision) < 1)) throw new Error("Recovery engagement revision is invalid.");
  await records(value.records);
  procedures(value.procedureEvidence ?? []);
  if (!isRecord(value.evidenceArchive)) throw new Error("Recovery archive is invalid.");
  const archive: Record<string, EvidenceSnapshot> = {};
  for (const [key, snapshot] of Object.entries(value.evidenceArchive)) {
    if (!isRecord(snapshot) || Object.keys(snapshot).some((name) => !["actor", "domains", "scope", "workflow", "records", "procedureEvidence"].includes(name))) throw new Error("Recovery snapshot is invalid.");
    if (snapshot.actor !== null) validateActor(snapshot.actor);
    const snapshotProcedures = snapshot.procedureEvidence ?? [];
    domains(snapshot.domains); scope(snapshot.scope); await records(snapshot.records); procedures(snapshotProcedures);
    archive[key] = { actor: snapshot.actor, domains: snapshot.domains, scope: snapshot.scope,
      workflow: workflow(snapshot.workflow), records: snapshot.records as WorkspaceState["records"], procedureEvidence: snapshotProcedures };
  }
  const accepted = value.procedureEvidence ?? [];
  procedures(accepted);
  const engagementId = value.engagementId ?? null;
  const engagementRevision = value.engagementRevision ?? null;
  if ((engagementId !== null && typeof engagementId !== "string") || (engagementRevision !== null && typeof engagementRevision !== "number")) throw new Error("Recovery engagement identity is invalid.");
  return { ...(value as unknown as WorkspaceState), importedWorkflow: workflow(value.importedWorkflow),
    savedWorkflow: workflow(value.savedWorkflow), evidenceArchive: archive, procedureEvidence: accepted, engagementId, engagementRevision };
}

export function createRecoveryCopy(): string {
  const recovery: WorkspaceRecovery = { recovery_version: "1.0", tool: "AdversaryFlow", captured_at: new Date().toISOString(), workspace: workspaceSnapshot(useWizardStore.getState()) };
  return boundedJson(recovery, WORKSPACE_MAX_BYTES);
}

export function downloadWorkspace(): void {
  downloadJson(createRecoveryCopy(), "AdversaryFlow_workspace_recovery.json");
}

export async function parseWorkspaceFile(text: string): Promise<{ kind: "workspace"; workspace: WorkspaceState } | { kind: "plan"; plan: PlanExport }> {
  requireByteLimit(text, WORKSPACE_MAX_BYTES, "Workspace recovery");
  let value: unknown;
  try { value = JSON.parse(text) as unknown; } catch { throw new Error("The file is not valid JSON. Choose an AdversaryFlow plan or workspace recovery copy."); }
  unsafeKeys(value);
  if (isRecord(value) && value.recovery_version === "1.0" && value.tool === "AdversaryFlow") {
    if (!validDateTime(value.captured_at) || Object.keys(value).some((key) => !["recovery_version", "tool", "captured_at", "workspace"].includes(key))) throw new Error("Recovery version 1.0 metadata is invalid.");
    return { kind: "workspace", workspace: await validateWorkspace(value.workspace) };
  }
  if (isRecord(value) && "saved_workspace" in value) {
    if (!validDateTime(value.captured_at) || Object.keys(value).some((key) => !["saved_workspace", "captured_at"].includes(key))) throw new Error("Original recovery metadata is invalid.");
    if (typeof value.saved_workspace !== "string") throw new Error("The original recovery copy contains no saved workspace.");
    let saved: unknown;
    try { saved = JSON.parse(value.saved_workspace) as unknown; } catch { throw new Error("The original recovery workspace is malformed."); }
    if (!isRecord(saved) || (saved.version !== undefined && saved.version !== 0)) throw new Error("The recovery persistence version is unsupported.");
    return { kind: "workspace", workspace: await validateWorkspace(saved.state) };
  }
  requireByteLimit(text, PLAN_MAX_BYTES, "Plan");
  validateImportedPlan(value);
  await verifyImportedPlanReceipts(value);
  return { kind: "plan", plan: value };
}
