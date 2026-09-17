import type { Actor, AttackDomain, Command, WorkflowResponse } from "../../api/contract";
import { isMarkedRun, type ExecutionEvidence } from "../review/evidence";
import { buildPlanPreview, tacticDescriptions, type PlanPreview, type ScopeSettings } from "../scope/scopeModel";
import type { PlanExport } from "./planContract";

function titlePlatform(platform: string): string {
  if (platform === "macos") return "macOS";
  return `${platform[0]?.toLocaleUpperCase() ?? ""}${platform.slice(1)}`;
}

function plainText(value: string): string {
  return value
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/\s*\(Citation:[^)]+\)/gi, "")
    .replace(/<[^>]*>/g, "")
    .trim();
}

function validDateTime(value: string | undefined): value is string {
  return Boolean(value && /^\d{4}-\d{2}-\d{2}T/.test(value) && !Number.isNaN(Date.parse(value)));
}

function compactEvidence(value: ExecutionEvidence | undefined): ExecutionEvidence {
  if (!value) return { outcome: "not_run" };
  const output: ExecutionEvidence = { outcome: value.outcome };
  if (validDateTime(value.updated_at)) output.updated_at = value.updated_at;
  if (typeof value.operator === "string" && value.operator.length <= 120) output.operator = value.operator;
  if (typeof value.target === "string" && value.target.length <= 200) output.target = value.target;
  if (typeof value.notes === "string" && value.notes.length <= 500) output.notes = value.notes;
  if (typeof value.cleanup_completed === "boolean") output.cleanup_completed = value.cleanup_completed;
  if (value.run_id && value.run_id.length <= 128) output.run_id = value.run_id;
  if (validDateTime(value.started_at)) output.started_at = value.started_at;
  if (validDateTime(value.completed_at)) output.completed_at = value.completed_at;
  if (Number.isInteger(value.exit_code) && Number(value.exit_code) >= -255 && Number(value.exit_code) <= 65_535) output.exit_code = value.exit_code;
  if (value.stdout_sha256 && /^[a-fA-F0-9]{64}$/.test(value.stdout_sha256)) output.stdout_sha256 = value.stdout_sha256;
  if (value.stderr_sha256 && /^[a-fA-F0-9]{64}$/.test(value.stderr_sha256)) output.stderr_sha256 = value.stderr_sha256;
  if (value.receipt_sha256 && /^[a-fA-F0-9]{64}$/.test(value.receipt_sha256)) output.receipt_sha256 = value.receipt_sha256;
  if (typeof value.receipt_verified === "boolean") output.receipt_verified = value.receipt_verified;
  if (value.telemetry_refs?.length) output.telemetry_refs = [...new Set(value.telemetry_refs.filter(Boolean))].slice(0, 20);
  if (value.evidence_source) output.evidence_source = value.evidence_source;
  if (value.detection_result) output.detection_result = value.detection_result;
  return output;
}

function commandForExport(command: Command): Command {
  const copy: Command = {
    platform: command.platform,
    command: command.command,
    note: command.note,
    cleanup: command.cleanup,
    risk: command.risk,
    side_effects: [...new Set(command.side_effects)],
    requires_admin: command.requires_admin,
    requires_network: command.requires_network,
    network_targets: [...new Set(command.network_targets)],
    prerequisites: [...command.prerequisites],
    expected_telemetry: command.expected_telemetry,
    expected_output: command.expected_output,
    timeout_seconds: command.timeout_seconds,
    rollback: command.rollback,
    cleanup_required: command.cleanup_required,
    acknowledgment_required: command.acknowledgment_required,
  };
  if (command.exercise_kind) copy.exercise_kind = command.exercise_kind;
  if (command.fidelity) copy.fidelity = command.fidelity;
  if (command.evidence_source) copy.evidence_source = command.evidence_source;
  if (command.telemetry_acceptance) copy.telemetry_acceptance = command.telemetry_acceptance;
  if (typeof command.unsupported === "boolean") copy.unsupported = command.unsupported;
  if (typeof command.restricted === "boolean") copy.restricted = command.restricted;
  return copy;
}

function contractDomains(workflow: WorkflowResponse, fallback: AttackDomain[]): AttackDomain[] {
  const valid = workflow.metadata.domains.filter((domain): domain is AttackDomain => domain === "enterprise" || domain === "ics" || domain === "mobile");
  return valid.length ? [...new Set(valid)] : fallback;
}

export interface ExportBundle {
  preview: PlanPreview;
  plan: PlanExport;
  slug: string;
}

export function buildExportBundle(
  actor: Actor,
  workflow: WorkflowResponse,
  scope: ScopeSettings,
  records: Record<string, ExecutionEvidence>,
  fallbackDomains: AttackDomain[],
): ExportBundle {
  const preview = buildPlanPreview(workflow, scope);
  const runnableIds = new Set(preview.stages.flatMap((stage) => stage.techniques.filter((technique) => !technique.selectedCommand.unsupported).map((technique) => technique.attack_id)));
  const markedRun = [...runnableIds].filter((id) => isMarkedRun(records[id]));
  const plan: PlanExport = {
    schema_version: "2.0",
    tool: "AdversaryFlow",
    tool_version: workflow.metadata.version,
    data_version: workflow.metadata.data_version,
    domains: contractDomains(workflow, fallbackDomains),
    generated: new Date().toISOString(),
    actor: { ...actor, aliases: [...actor.aliases] },
    scope: {
      command_platform: scope.commandPlatform,
      include_pre: scope.includePre,
      curated_only: scope.curatedOnly,
      allow_network: scope.allowNetwork,
      allow_admin: scope.allowAdmin,
      allow_high_risk: scope.allowHighRisk,
      stages: [...scope.tactics],
    },
    execution_context: { operator: scope.operator, target: scope.target },
    summary: {
      techniques: preview.total,
      runnable: preview.runnable,
      unsupported: preview.unsupported,
      stages: preview.stages.length,
      curated: preview.curated,
      fallback: preview.fallback,
      marked_run: markedRun,
    },
    stages: preview.stages.map((stage) => ({
      tactic: stage.tactic,
      title: stage.title,
      techniques: stage.techniques.map((technique) => ({
        id: technique.attack_id,
        name: technique.name,
        url: technique.url ?? null,
        platforms: [...(technique.platforms ?? [])],
        command_source: technique.command_source === "fallback" ? "fallback" : "curated",
        supported: !technique.selectedCommand.unsupported,
        command: commandForExport(technique.selectedCommand),
        run: !technique.selectedCommand.unsupported && isMarkedRun(records[technique.attack_id]),
        execution: compactEvidence(records[technique.attack_id]),
        data_sources: [...(technique.data_sources ?? [])],
        detection: technique.detection ?? "",
      })),
    })),
  };
  return { preview, plan, slug: `${actor.attack_id}_${actor.name.replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "")}` };
}

export function toMarkdown(bundle: ExportBundle): string {
  const { plan, preview } = bundle;
  let output = `# AdversaryFlow — ${plan.actor.name} (${plan.actor.attack_id})\n\n`;
  output += "> Development-lab emulation plan. AdversaryFlow generated this plan but did not execute it.\n\n";
  if (plan.execution_context.operator || plan.execution_context.target) {
    output += `**Execution context:** operator ${plan.execution_context.operator || "not recorded"} · target ${plan.execution_context.target || "not recorded"}\n\n`;
  }
  if (plan.actor.aliases.length) output += `*Aliases: ${plan.actor.aliases.join(", ")}*\n\n`;
  if (plan.actor.description) output += `${plainText(plan.actor.description)}\n\n`;
  output += `**${preview.total} techniques · ${preview.runnable} runnable · ${preview.unsupported} unsupported · ${preview.stages.length} stages · commands target ${titlePlatform(plan.scope.command_platform)}** (${preview.curated} curated / ${preview.fallback} fallback)\n\n`;
  plan.stages.forEach((stage, stageIndex) => {
    output += `## ${stageIndex + 1}. ${stage.title}\n\n_${tacticDescriptions[stage.tactic] ?? "Mapped ATT&CK tactic."}_\n\n`;
    stage.techniques.forEach((technique) => {
      const evidence = technique.execution;
      output += `### ${technique.id} — ${technique.name}${technique.run ? " ✅" : ""}\n\n`;
      output += `**Outcome:** ${evidence.outcome}${evidence.updated_at ? ` · ${evidence.updated_at}` : ""}${evidence.notes ? ` · ${evidence.notes}` : ""}\n\n`;
      output += `**Detection:** ${evidence.detection_result ?? "not_assessed"}\n\n`;
      if (evidence.run_id) output += `**Execution proof:** run ID \`${evidence.run_id}\`${evidence.started_at ? ` · started ${evidence.started_at}` : ""}${evidence.completed_at ? ` · completed ${evidence.completed_at}` : ""}${evidence.exit_code !== undefined ? ` · exit ${evidence.exit_code}` : ""}\n\n`;
      if (evidence.receipt_sha256) output += `**Receipt SHA-256:** \`${evidence.receipt_sha256}\` (${evidence.receipt_verified ? "digest verified; self-reported" : "not verified"})\n\n`;
      if (evidence.stdout_sha256 || evidence.stderr_sha256) output += `**Captured output hashes:** stdout \`${evidence.stdout_sha256 ?? "not recorded"}\` · stderr \`${evidence.stderr_sha256 ?? "not recorded"}\`\n\n`;
      if (evidence.telemetry_refs?.length) output += `**Independent telemetry:** ${evidence.telemetry_refs.join(", ")}\n\n`;
      if (technique.data_sources?.length) output += `**ATT&CK data sources:** ${technique.data_sources.join(", ")}\n\n`;
      if (technique.detection) output += `**ATT&CK detection:** ${plainText(technique.detection)}\n\n`;
      if (!technique.supported) {
        output += `**Unsupported on ${titlePlatform(plan.scope.command_platform)}.** ${technique.command.note}\n\n`;
        return;
      }
      const fidelity = technique.command.fidelity === "bounded_synthetic" ? "bounded synthetic" : technique.command.fidelity === "lab_proxy" ? "lab proxy" : "direct";
      output += `**Fidelity:** ${fidelity}\n\n**[${technique.command.platform}] lab command:**\n\n\`\`\`\n${technique.command.command}\n\`\`\`\n`;
      if (technique.command.note) output += `_${technique.command.note}_\n`;
      if (technique.command.cleanup) output += `_cleanup: \`${technique.command.cleanup}\`_\n`;
      output += "\n";
    });
  });
  return output;
}

function runbookSafe(value: unknown): string {
  return String(value ?? "").replace(/[\r\n&|<>^]+/g, " ").trim();
}

export function toRunbook(bundle: ExportBundle): string {
  const { plan } = bundle;
  const comment = plan.scope.command_platform === "windows" ? "REM" : "#";
  let output = `${comment} AdversaryFlow runbook — ${runbookSafe(plan.actor.name)} (${runbookSafe(plan.actor.attack_id)})\n`;
  output += `${comment} DEVELOPMENT-LAB EMULATION RUNBOOK.\n`;
  output += `${comment} Command platform: ${titlePlatform(plan.scope.command_platform)}\n`;
  output += `${comment} Data version: ${runbookSafe(plan.data_version)}\n`;
  output += `${comment} Operator: ${runbookSafe(plan.execution_context.operator) || "not recorded"}\n`;
  output += `${comment} Target: ${runbookSafe(plan.execution_context.target) || "not recorded"}\n`;
  plan.stages.forEach((stage, stageIndex) => {
    output += `\n${comment} ===== ${stageIndex + 1}. ${runbookSafe(stage.title).toLocaleUpperCase()} =====\n`;
    stage.techniques.forEach((technique) => {
      const evidence = technique.execution;
      const fidelity = technique.command.fidelity === "bounded_synthetic" ? "bounded synthetic" : technique.command.fidelity === "lab_proxy" ? "lab proxy" : "direct";
      output += `\n${comment} ${runbookSafe(technique.id)} ${runbookSafe(technique.name)} [${runbookSafe(technique.command.platform)}]${technique.run ? " (run)" : ""}\n`;
      output += `${comment} Fidelity: ${fidelity}\n`;
      output += `${comment} Outcome: ${evidence.outcome}${evidence.updated_at ? ` at ${evidence.updated_at}` : ""}\n`;
      output += `${comment} Detection: ${evidence.detection_result ?? "not_assessed"}\n`;
      if (evidence.notes) output += `${comment} Evidence: ${runbookSafe(evidence.notes)}\n`;
      if (evidence.run_id) output += `${comment} Run ID: ${runbookSafe(evidence.run_id)}\n`;
      if (evidence.receipt_sha256) output += `${comment} Receipt SHA-256: ${runbookSafe(evidence.receipt_sha256)} (${evidence.receipt_verified ? "digest verified; self-reported" : "not verified"})\n`;
      evidence.telemetry_refs?.forEach((reference) => { output += `${comment} Telemetry: ${runbookSafe(reference)}\n`; });
      if (!technique.supported) {
        output += `${comment} UNSUPPORTED: ${runbookSafe(technique.command.note)}\n`;
        return;
      }
      if (technique.command.note) output += `${comment}   ${runbookSafe(technique.command.note)}\n`;
      output += `${comment} COMMAND: ${runbookSafe(technique.command.command)}\n`;
      if (technique.command.cleanup) output += `${comment} MANUAL CLEANUP: ${runbookSafe(technique.command.cleanup)}\n`;
    });
  });
  return output;
}

export function executiveSummary(bundle: ExportBundle): string {
  const { plan } = bundle;
  const assessed = plan.stages.flatMap((stage) => stage.techniques).filter((technique) => technique.execution.detection_result && technique.execution.detection_result !== "not_assessed").length;
  return `${plan.actor.name} (${plan.actor.attack_id}) — ${plan.summary.techniques} techniques across ${plan.summary.stages} stages; ${plan.summary.runnable} runnable, ${plan.summary.marked_run.length} recorded, ${assessed} detection results assessed. Authorized disposable-lab plan; AdversaryFlow did not execute commands.`;
}

export function platformLabel(platform: string): string {
  return titlePlatform(platform);
}
