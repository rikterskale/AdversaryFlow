import type {
  Actor,
  ActorsResponse,
  BootstrapResponse,
  HealthPhase,
  HealthResponse,
  DoctorResponse,
  SessionResponse,
  Command,
  Technique,
  WorkflowResponse,
  WorkflowStage,
} from "./contract";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isActor(value: unknown): value is Actor {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  const actorKeys = ["stix_id", "attack_id", "name", "type", "aliases", "description", "technique_count"];
  return (
    keys.length === actorKeys.length &&
    actorKeys.every((key) => key in value) &&
    typeof value.stix_id === "string" &&
    typeof value.attack_id === "string" &&
    typeof value.name === "string" &&
    (value.type === "group" || value.type === "campaign") &&
    isStringArray(value.aliases) &&
    typeof value.description === "string" &&
    Number.isInteger(value.technique_count) &&
    Number(value.technique_count) >= 0
  );
}

export function parseSession(value: unknown): SessionResponse {
  if (!isRecord(value) || typeof value.csrf_token !== "string" || typeof value.version !== "string") {
    throw new Error("The service returned an invalid session response.");
  }
  return { csrf_token: value.csrf_token, version: value.version };
}

export function parseActors(value: unknown): ActorsResponse {
  if (
    !isRecord(value) ||
    !Array.isArray(value.actors) ||
    !value.actors.every(isActor) ||
    !isStringArray(value.domains) ||
    typeof value.data_version !== "string" ||
    typeof value.version !== "string"
  ) {
    throw new Error("The service returned an invalid actor catalog.");
  }
  return {
    actors: value.actors,
    domains: value.domains,
    data_version: value.data_version,
    version: value.version,
  };
}

function isCommand(value: unknown): value is Command {
  if (!isRecord(value)) return false;
  return (
    typeof value.platform === "string" &&
    (value.interpreter === undefined || ["cmd", "powershell", "bash"].includes(String(value.interpreter))) &&
    typeof value.command === "string" &&
    typeof value.note === "string" &&
    typeof value.cleanup === "string" &&
    (value.risk === "none" || value.risk === "low" || value.risk === "medium" || value.risk === "high") &&
    isStringArray(value.side_effects) &&
    typeof value.requires_admin === "boolean" &&
    typeof value.requires_network === "boolean" &&
    isStringArray(value.network_targets) &&
    isStringArray(value.prerequisites) &&
    typeof value.expected_telemetry === "string" &&
    typeof value.expected_output === "string" &&
    typeof value.timeout_seconds === "number" &&
    typeof value.rollback === "string" &&
    typeof value.cleanup_required === "boolean" &&
    typeof value.acknowledgment_required === "boolean"
  );
}

function isTechnique(value: unknown): value is Technique {
  if (!isRecord(value)) return false;
  return (
    typeof value.attack_id === "string" &&
    typeof value.name === "string" &&
    Array.isArray(value.commands) &&
    value.commands.every(isCommand) &&
    typeof value.command_source === "string" &&
    (value.tactics === undefined || isStringArray(value.tactics)) &&
    (value.platforms === undefined || isStringArray(value.platforms)) &&
    (value.data_sources === undefined || isStringArray(value.data_sources))
  );
}

function isWorkflowStage(value: unknown): value is WorkflowStage {
  return (
    isRecord(value) &&
    typeof value.tactic === "string" &&
    typeof value.title === "string" &&
    Array.isArray(value.techniques) &&
    value.techniques.every(isTechnique)
  );
}

export function parseWorkflow(value: unknown): WorkflowResponse {
  if (
    !isRecord(value) ||
    !isRecord(value.actor) ||
    !isRecord(value.summary) ||
    !Array.isArray(value.kill_chain) ||
    !value.kill_chain.every((item) => isRecord(item) && typeof item.tactic === "string" && typeof item.title === "string") ||
    !Array.isArray(value.stages) ||
    !value.stages.every(isWorkflowStage) ||
    !isRecord(value.metadata) ||
    !isStringArray(value.metadata.domains) ||
    typeof value.metadata.data_version !== "string" ||
    typeof value.metadata.version !== "string"
  ) {
    throw new Error("The service returned an incomplete workflow.");
  }
  return {
    actor: value.actor,
    summary: value.summary,
    kill_chain: value.kill_chain as { tactic: string; title: string }[],
    stages: value.stages,
    metadata: {
      domains: value.metadata.domains,
      data_version: value.metadata.data_version,
      version: value.metadata.version,
    },
  };
}

const healthPhases = new Set<HealthPhase>([
  "not_started",
  "loading",
  "refreshing",
  "ready",
  "failed",
]);

export function parseHealth(value: unknown): HealthResponse {
  if (
    !isRecord(value) ||
    (value.status !== "ready" && value.status !== "degraded") ||
    typeof value.ready !== "boolean" ||
    typeof value.loading !== "boolean" ||
    typeof value.phase !== "string" ||
    !healthPhases.has(value.phase as HealthPhase) ||
    !(typeof value.version === "string" || value.version === null) ||
    !(typeof value.error === "string" || value.error === null) ||
    !isRecord(value.attack_data) ||
    !isRecord(value.service)
  ) {
    throw new Error("The service returned an invalid health response.");
  }
  return {
    status: value.status,
    ready: value.ready,
    loading: value.loading,
    phase: value.phase as HealthPhase,
    version: value.version,
    error: value.error,
    attack_data: value.attack_data,
    service: value.service,
  };
}

export function parseDoctor(value: unknown): DoctorResponse {
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    typeof value.generated_at !== "string" ||
    typeof value.ok !== "boolean" ||
    !isRecord(value.summary) ||
    typeof value.summary.passed !== "number" ||
    typeof value.summary.failed !== "number" ||
    typeof value.summary.required_failed !== "number" ||
    !Array.isArray(value.checks) ||
    !value.checks.every((check) => (
      isRecord(check) &&
      typeof check.id === "string" &&
      typeof check.label === "string" &&
      (check.status === "PASS" || check.status === "FAIL") &&
      typeof check.required === "boolean" &&
      typeof check.detail === "string" &&
      typeof check.fix === "string"
    ))
  ) {
    throw new Error("The service returned an invalid diagnostics report.");
  }
  return value as unknown as DoctorResponse;
}

export function parseBootstrap(value: unknown): BootstrapResponse {
  if (!isRecord(value)) throw new Error("The service returned an invalid setup response.");
  const runtime = isRecord(value.runtime)
    ? {
        ready: typeof value.runtime.ready === "boolean" ? value.runtime.ready : undefined,
        phase: typeof value.runtime.phase === "string" ? value.runtime.phase : undefined,
        error:
          typeof value.runtime.error === "string" || value.runtime.error === null
            ? value.runtime.error
            : undefined,
      }
    : undefined;
  return {
    ...(runtime ? { runtime } : {}),
    ...(isRecord(value.cache) ? { cache: value.cache } : {}),
  };
}

export function displayScalar(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return null;
}
