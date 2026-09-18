import type { Command, Technique, WorkflowResponse, WorkflowStage } from "../../api/contract";

export type CommandPlatform = "windows" | "linux" | "macos";

export interface ScopeSettings {
  commandPlatform: CommandPlatform;
  tactics: string[];
  includePre: boolean;
  curatedOnly: boolean;
  allowNetwork: boolean;
  allowAdmin: boolean;
  allowHighRisk: boolean;
  operator: string;
  target: string;
}

export interface ScopedTechnique extends Technique {
  selectedCommand: Command;
}

export interface ScopedStage extends Omit<WorkflowStage, "techniques"> {
  techniques: ScopedTechnique[];
}

export interface PlanPreview {
  stages: ScopedStage[];
  total: number;
  runnable: number;
  unsupported: number;
  curated: number;
  fallback: number;
  filteredFallback: number;
  withheld: {
    platform: number;
    network: number;
    admin: number;
    highRisk: number;
    catalog: number;
  };
}

export const preCompromiseTactics = new Set(["reconnaissance", "resource-development"]);

export const tacticDescriptions: Record<string, string> = {
  reconnaissance: "Researching the target from outside the environment.",
  "resource-development": "Preparing infrastructure or capabilities before access.",
  "initial-access": "Establishing the first foothold in the environment.",
  execution: "Running adversary-controlled commands or code.",
  persistence: "Maintaining access across reboots or identity changes.",
  "privilege-escalation": "Gaining higher-level permissions.",
  "defense-evasion": "Avoiding or weakening defensive controls.",
  "credential-access": "Obtaining account credentials or secrets.",
  discovery: "Learning about systems, accounts, and the environment.",
  "lateral-movement": "Moving between systems or identities.",
  collection: "Gathering data of interest.",
  "command-and-control": "Modeling documented external communications.",
  exfiltration: "Modeling data transfer from the lab environment.",
  impact: "Manipulating, interrupting, or destroying lab resources.",
};

export function detectedPlatform(): CommandPlatform {
  const values = [navigator.userAgent, navigator.platform].map((value) => value.toLocaleLowerCase());
  for (const value of values) {
    if (/windows|win32|win64/.test(value)) return "windows";
    if (/mac/.test(value)) return "macos";
    if (/linux|cros/.test(value)) return "linux";
  }
  return "windows";
}

export function titlePlatform(platform: CommandPlatform): string {
  return platform === "macos" ? "macOS" : `${platform[0]?.toLocaleUpperCase() ?? ""}${platform.slice(1)}`;
}

export function defaultScope(): ScopeSettings {
  return {
    commandPlatform: detectedPlatform(),
    tactics: [],
    includePre: true,
    curatedOnly: false,
    allowNetwork: false,
    allowAdmin: false,
    allowHighRisk: false,
    operator: "",
    target: "",
  };
}

export function resolveCommand(technique: Technique, scope: ScopeSettings): Command {
  const exact = technique.commands.find((command) => command.platform === scope.commandPlatform);
  if (!exact) {
    const platform = titlePlatform(scope.commandPlatform);
    return {
      platform: scope.commandPlatform,
      command: `No ${platform} test is available for this technique.`,
      note: "Choose another platform or contribute an exact-platform test.",
      cleanup: "",
      risk: "none",
      side_effects: [],
      requires_admin: false,
      requires_network: false,
      network_targets: [],
      prerequisites: [],
      expected_telemetry: "",
      expected_output: "",
      timeout_seconds: 0,
      rollback: "",
      cleanup_required: false,
      acknowledgment_required: false,
      unsupported: true,
    };
  }

  const restrictions: string[] = [];
  if (exact.requires_network && !scope.allowNetwork) restrictions.push("network-active commands are disabled");
  if (exact.requires_admin && !scope.allowAdmin) restrictions.push("administrator commands are disabled");
  if (exact.risk === "high" && !scope.allowHighRisk) restrictions.push("high-risk commands are disabled");
  if (!restrictions.length) return exact;
  return {
    ...exact,
    command: `Restricted by scope: ${restrictions.join("; ")}.`,
    note: "Enable the corresponding guardrail after reviewing its impact.",
    unsupported: true,
    restricted: true,
  };
}

export function buildPlanPreview(workflow: WorkflowResponse, scope: ScopeSettings): PlanPreview {
  const techniqueIds = new Set<string>();
  const runnableIds = new Set<string>();
  const curatedIds = new Set<string>();
  const filteredFallbackIds = new Set<string>();
  const platformIds = new Set<string>();
  const networkIds = new Set<string>();
  const adminIds = new Set<string>();
  const highRiskIds = new Set<string>();
  const catalogIds = new Set<string>();
  const stages: ScopedStage[] = [];

  for (const stage of workflow.stages) {
    if (!scope.tactics.includes(stage.tactic)) continue;
    if (!scope.includePre && preCompromiseTactics.has(stage.tactic)) continue;

    const techniques: ScopedTechnique[] = [];
    for (const technique of stage.techniques) {
      if (scope.curatedOnly && technique.command_source === "fallback") {
        filteredFallbackIds.add(technique.attack_id);
        continue;
      }

      const exact = technique.commands.find((command) => command.platform === scope.commandPlatform);
      if (!exact) {
        platformIds.add(technique.attack_id);
      } else {
        if (exact.unsupported) catalogIds.add(technique.attack_id);
        if (exact.requires_network && !scope.allowNetwork) networkIds.add(technique.attack_id);
        if (exact.requires_admin && !scope.allowAdmin) adminIds.add(technique.attack_id);
        if (exact.risk === "high" && !scope.allowHighRisk) highRiskIds.add(technique.attack_id);
      }
      techniques.push({ ...technique, selectedCommand: resolveCommand(technique, scope) });
    }
    if (!techniques.length) continue;

    for (const technique of techniques) {
      techniqueIds.add(technique.attack_id);
      if (!technique.selectedCommand.unsupported) runnableIds.add(technique.attack_id);
      if (technique.command_source === "curated") curatedIds.add(technique.attack_id);
    }
    stages.push({ ...stage, techniques });
  }

  return {
    stages,
    total: techniqueIds.size,
    runnable: runnableIds.size,
    unsupported: techniqueIds.size - runnableIds.size,
    curated: curatedIds.size,
    fallback: techniqueIds.size - curatedIds.size,
    filteredFallback: filteredFallbackIds.size,
    withheld: {
      platform: platformIds.size,
      network: networkIds.size,
      admin: adminIds.size,
      highRisk: highRiskIds.size,
      catalog: catalogIds.size,
    },
  };
}
