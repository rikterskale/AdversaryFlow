import type { Actor, AttackDomain, Command, WorkflowResponse } from "../../api/contract";
import type { ExecutionEvidence } from "../review/evidence";
import type { ScopeSettings } from "../scope/scopeModel";

export interface PlanScope {
  command_platform: "windows" | "linux" | "macos";
  include_pre: boolean;
  curated_only: boolean;
  allow_network: boolean;
  allow_admin: boolean;
  allow_high_risk: boolean;
  stages: string[];
}

export interface PlanSummary {
  techniques: number;
  runnable: number;
  unsupported: number;
  stages: number;
  curated: number;
  fallback: number;
  marked_run: string[];
}

export interface PlanTechnique {
  id: string;
  name: string;
  url: string | null;
  platforms: string[];
  command_source: "curated" | "fallback";
  supported: boolean;
  command: Command;
  run: boolean;
  execution: ExecutionEvidence;
  data_sources?: string[];
  detection?: string;
}

export interface PlanStage {
  tactic: string;
  title: string;
  techniques: PlanTechnique[];
}

export interface PlanExport {
  schema_version: "2.0";
  tool: "AdversaryFlow";
  tool_version: string;
  data_version: string;
  domains: AttackDomain[];
  generated: string;
  actor: Actor;
  scope: PlanScope;
  execution_context: { operator: string; target: string };
  summary: PlanSummary;
  stages: PlanStage[];
}

const MAX_PLAN_STEPS = 4_000;
const fidelityValues = new Set(["direct", "bounded_synthetic", "lab_proxy"]);
const detectionResults = new Set(["not_assessed", "alerted", "silent", "blocked", "not_instrumented"]);
const evidenceSources = new Set(["operator_supplied", "exercise_receipt", "endpoint_verified", "siem_verified"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function onlyKeys(value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> {
  if (!isRecord(value) || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) return false;
  const allowed = new Set([...required, ...optional]);
  return Object.keys(value).every((key) => allowed.has(key));
}

function uniqueStrings(value: unknown, nonEmpty = false): value is string[] {
  return Array.isArray(value)
    && value.every((item) => typeof item === "string" && (!nonEmpty || item.length > 0))
    && new Set(value).size === value.length;
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function dateTime(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value) && !Number.isNaN(Date.parse(value));
}

function uriOrNull(value: unknown): value is string | null {
  if (value === null) return true;
  if (typeof value !== "string") return false;
  try { return Boolean(new URL(value).protocol); } catch { return false; }
}

function validateActor(value: unknown): void {
  if (!onlyKeys(value, ["stix_id", "attack_id", "name", "type", "aliases", "description", "technique_count"])
    || !nonEmptyString(value.stix_id) || !nonEmptyString(value.attack_id) || !nonEmptyString(value.name)
    || (value.type !== "group" && value.type !== "campaign")
    || !stringArray(value.aliases) || typeof value.description !== "string"
    || !nonNegativeInteger(value.technique_count)) throw new Error("Plan actor record is invalid");
}

function validateCommand(value: unknown, techniqueId: string): void {
  const commandKeys = ["platform", "command", "note", "cleanup", "risk", "side_effects", "requires_admin", "requires_network", "network_targets", "prerequisites", "expected_telemetry", "expected_output", "timeout_seconds", "rollback", "cleanup_required", "acknowledgment_required"];
  if (!onlyKeys(value, commandKeys, ["unsupported", "restricted", "exercise_kind", "fidelity", "evidence_source", "telemetry_acceptance", "interpreter"])
    || !["platform", "command", "note", "cleanup", "expected_telemetry", "expected_output", "rollback"].every((key) => typeof value[key] === "string")
    || (value.command as string).length > 10_000
    || !["none", "low", "medium", "high"].includes(String(value.risk))
    || !uniqueStrings(value.side_effects) || !uniqueStrings(value.network_targets) || !stringArray(value.prerequisites)
    || !["requires_admin", "requires_network", "cleanup_required", "acknowledgment_required"].every((key) => typeof value[key] === "boolean")
    || (value.unsupported !== undefined && typeof value.unsupported !== "boolean")
    || (value.restricted !== undefined && typeof value.restricted !== "boolean")
    || (value.interpreter !== undefined && !(value.platform === "windows" ? ["cmd", "powershell"] : ["bash"]).includes(String(value.interpreter)))
    || (value.exercise_kind !== undefined && value.exercise_kind !== "technique_relevant_bounded")
    || (value.fidelity !== undefined && (typeof value.fidelity !== "string" || !fidelityValues.has(value.fidelity)))
    || (value.evidence_source !== undefined && value.evidence_source !== "self_reported_receipt")
    || !Number.isInteger(value.timeout_seconds) || Number(value.timeout_seconds) < 0 || Number(value.timeout_seconds) > 3_600) {
    throw new Error("Plan contains an invalid command record");
  }
  if (value.telemetry_acceptance !== undefined) {
    const acceptance = value.telemetry_acceptance;
    if (!onlyKeys(acceptance, ["technique_id", "scenario", "activity_event_types", "minimum_activity_events", "requirements", "limitation"])
      || acceptance.technique_id !== techniqueId || !nonEmptyString(acceptance.scenario)
      || !uniqueStrings(acceptance.activity_event_types, true)
      || !nonNegativeInteger(acceptance.minimum_activity_events) || acceptance.minimum_activity_events < 1
      || !uniqueStrings(acceptance.requirements, true) || !nonEmptyString(acceptance.limitation)) {
      throw new Error("Plan contains an invalid command record");
    }
  }
}

function validateExecution(value: unknown): void {
  if (!onlyKeys(value, ["outcome"], ["updated_at", "operator", "target", "notes", "cleanup_completed", "run_id", "started_at", "completed_at", "exit_code", "stdout_sha256", "stderr_sha256", "receipt_sha256", "receipt_verified", "telemetry_refs", "evidence_source", "detection_result"])
    || !["not_run", "passed", "failed", "skipped"].includes(String(value.outcome))
    || (value.detection_result !== undefined && (typeof value.detection_result !== "string" || !detectionResults.has(value.detection_result)))
    || (value.updated_at !== undefined && !dateTime(value.updated_at))
    || (value.operator !== undefined && (typeof value.operator !== "string" || value.operator.length > 120))
    || (value.target !== undefined && (typeof value.target !== "string" || value.target.length > 200))
    || (value.notes !== undefined && (typeof value.notes !== "string" || value.notes.length > 500))
    || (value.cleanup_completed !== undefined && typeof value.cleanup_completed !== "boolean")
    || (value.run_id !== undefined && (typeof value.run_id !== "string" || !value.run_id.length || value.run_id.length > 128))
    || (value.started_at !== undefined && !dateTime(value.started_at))
    || (value.completed_at !== undefined && !dateTime(value.completed_at))
    || (value.exit_code !== undefined && (!Number.isInteger(value.exit_code) || Number(value.exit_code) < -255 || Number(value.exit_code) > 65_535))
    || ["stdout_sha256", "stderr_sha256", "receipt_sha256"].some((key) => value[key] !== undefined && (typeof value[key] !== "string" || !/^[a-fA-F0-9]{64}$/.test(value[key] as string)))
    || (value.receipt_verified !== undefined && typeof value.receipt_verified !== "boolean")
    || (value.telemetry_refs !== undefined && (!uniqueStrings(value.telemetry_refs, true) || value.telemetry_refs.length > 20 || value.telemetry_refs.some((reference) => reference.length > 500)))
    || (value.evidence_source !== undefined && (typeof value.evidence_source !== "string" || !evidenceSources.has(value.evidence_source)))) {
    throw new Error("Plan execution record is invalid");
  }
}

export function validateImportedPlan(data: unknown): asserts data is PlanExport {
  const rootKeys = ["schema_version", "tool", "tool_version", "data_version", "domains", "generated", "actor", "scope", "execution_context", "summary", "stages"];
  if (!isRecord(data) || data.schema_version !== "2.0" || data.tool !== "AdversaryFlow") throw new Error("This is not an AdversaryFlow 2.0 plan export");
  if (!onlyKeys(data, rootKeys)) throw new Error("Plan contains unknown or missing top-level fields");
  if (!nonEmptyString(data.tool_version) || !nonEmptyString(data.data_version)) throw new Error("Plan is missing its tool or ATT&CK data version");
  if (!dateTime(data.generated)) throw new Error("Plan generated timestamp is invalid");
  validateActor(data.actor);
  const allowedDomains = new Set(["enterprise", "ics", "mobile"]);
  if (!uniqueStrings(data.domains) || !data.domains.length || data.domains.some((domain) => !allowedDomains.has(domain))) throw new Error("Plan contains an invalid ATT&CK domain");

  const scopeKeys = ["command_platform", "include_pre", "curated_only", "allow_network", "allow_admin", "allow_high_risk", "stages"];
  const scope = data.scope;
  if (!onlyKeys(scope, scopeKeys) || !["windows", "linux", "macos"].includes(String(scope.command_platform))
    || !uniqueStrings(scope.stages)
    || ["include_pre", "curated_only", "allow_network", "allow_admin", "allow_high_risk"].some((key) => typeof scope[key] !== "boolean")) throw new Error("Plan scope is invalid");

  if (!onlyKeys(data.execution_context, ["operator", "target"])
    || typeof data.execution_context.operator !== "string" || data.execution_context.operator.length > 120
    || typeof data.execution_context.target !== "string" || data.execution_context.target.length > 200) throw new Error("Plan execution context is invalid");

  const summaryKeys = ["techniques", "runnable", "unsupported", "stages", "curated", "fallback", "marked_run"];
  const summary = data.summary;
  if (!onlyKeys(summary, summaryKeys)
    || summaryKeys.slice(0, 6).some((key) => !nonNegativeInteger(summary[key]))
    || !uniqueStrings(summary.marked_run)) throw new Error("Plan summary is invalid");

  if (!Array.isArray(data.stages) || !data.stages.length || data.stages.length > 32) throw new Error("Plan stage count is invalid");
  let totalTechniqueRecords = 0;
  data.stages.forEach((stage) => {
    if (isRecord(stage) && Array.isArray(stage.techniques) && stage.techniques.length > 2_000) throw new Error("Plan contains too many technique records");
    if (!onlyKeys(stage, ["tactic", "title", "techniques"]) || !nonEmptyString(stage.tactic)
      || !nonEmptyString(stage.title) || !Array.isArray(stage.techniques) || !stage.techniques.length) throw new Error("Plan contains an invalid stage");
    totalTechniqueRecords += stage.techniques.length;
    if (totalTechniqueRecords > MAX_PLAN_STEPS) throw new Error(`Plan exceeds the ${MAX_PLAN_STEPS}-technique limit`);
    stage.techniques.forEach((technique) => {
      const techniqueKeys = ["id", "name", "url", "platforms", "command_source", "supported", "command", "run", "execution"];
      if (!onlyKeys(technique, techniqueKeys, ["data_sources", "detection"])
        || typeof technique.id !== "string" || !/^T[0-9]{4}(?:\.[0-9]{3})?$/.test(technique.id)
        || !nonEmptyString(technique.name) || !uriOrNull(technique.url) || !stringArray(technique.platforms)
        || (technique.command_source !== "curated" && technique.command_source !== "fallback")
        || typeof technique.supported !== "boolean" || typeof technique.run !== "boolean"
        || (technique.data_sources !== undefined && !stringArray(technique.data_sources))
        || (technique.detection !== undefined && typeof technique.detection !== "string")) throw new Error("Plan contains an invalid technique record");
      validateCommand(technique.command, technique.id);
      validateExecution(technique.execution);
    });
  });
}

function normalizeImportedCommand(command: Command): Command {
  return {
    ...command,
    note: `Imported plan — verify before use. ${command.note}`,
    untrusted: true,
    acknowledgment_required: true,
  };
}

export function scopeFromImportedPlan(plan: PlanExport): ScopeSettings {
  return {
    commandPlatform: plan.scope.command_platform,
    tactics: [...plan.scope.stages],
    includePre: plan.scope.include_pre,
    curatedOnly: plan.scope.curated_only,
    allowNetwork: plan.scope.allow_network,
    allowAdmin: plan.scope.allow_admin,
    allowHighRisk: plan.scope.allow_high_risk,
    operator: plan.execution_context.operator,
    target: plan.execution_context.target,
  };
}

export function workflowFromImportedPlan(plan: PlanExport): WorkflowResponse {
  return {
    actor: { ...plan.actor },
    summary: { ...plan.summary },
    kill_chain: plan.stages.map((stage) => ({ tactic: stage.tactic, title: stage.title })),
    stages: plan.stages.map((stage) => ({
      tactic: stage.tactic,
      title: stage.title,
      techniques: stage.techniques.map((technique) => ({
        attack_id: technique.id,
        name: technique.name,
        url: technique.url,
        platforms: [...technique.platforms],
        description: "Imported plan record",
        is_subtechnique: technique.id.includes("."),
        data_sources: [...(technique.data_sources ?? [])],
        detection: technique.detection ?? "",
        command_source: technique.command_source,
        commands: [normalizeImportedCommand({ ...technique.command, ...(!technique.supported ? { unsupported: true } : {}) })],
        tactics: [stage.tactic],
      })),
    })),
    metadata: { version: plan.tool_version, data_version: plan.data_version, domains: [...plan.domains] },
  };
}

export function evidenceFromImportedPlan(plan: PlanExport): Record<string, ExecutionEvidence> {
  const records: Record<string, ExecutionEvidence> = {};
  plan.stages.forEach((stage) => stage.techniques.forEach((technique) => {
    records[technique.id] = { ...technique.execution };
  }));
  return records;
}

declare global {
  interface Window {
    validateImportedPlan: (data: unknown) => void;
  }
}

window.validateImportedPlan = validateImportedPlan;
