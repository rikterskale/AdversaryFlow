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
  IntelligenceImportResponse,
  ProcedureCandidate,
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

export function parseIntelligenceImport(value: unknown): IntelligenceImportResponse {
  if (!isRecord(value) || value.schema_version !== "1.0" || !isRecord(value.source)
    || !["csv", "navigator_layer", "stix2_bundle"].includes(String(value.source.kind))
    || typeof value.source.name !== "string"
    || !(typeof value.source.url === "string" || value.source.url === null)
    || typeof value.source.sha256 !== "string"
    || !isRecord(value.actor)
    || typeof value.actor.stix_id !== "string" || typeof value.actor.attack_id !== "string"
    || typeof value.actor.name !== "string" || !["group", "campaign"].includes(String(value.actor.type))
    || typeof value.data_version !== "string" || !isRecord(value.comparison)
    || !isStringArray(value.comparison.report_only) || !isStringArray(value.comparison.attack_only)
    || !isStringArray(value.comparison.both) || !Array.isArray(value.candidates)) {
    throw new Error("The service returned an invalid intelligence comparison.");
  }
  const candidateKeys = ["candidate_id", "technique_id", "technique_name", "tactics", "platforms", "source_kind", "source_name", "source_url", "source_sha256", "evidence_quote", "procedure", "confidence", "review_status", "reviewed_by", "reviewed_at", "accepted_by", "accepted_at", "technique_url", "technique_known", "catalog_source", "abilities"];
  const candidates = value.candidates;
  if (!candidates.every((candidate): candidate is ProcedureCandidate => isRecord(candidate)
    && candidateKeys.every((key) => key in candidate)
    && typeof candidate.candidate_id === "string" && typeof candidate.technique_id === "string"
    && typeof candidate.technique_name === "string" && isStringArray(candidate.tactics)
    && isStringArray(candidate.platforms) && typeof candidate.source_kind === "string"
    && typeof candidate.source_name === "string"
    && (typeof candidate.source_url === "string" || candidate.source_url === null)
    && typeof candidate.source_sha256 === "string" && typeof candidate.evidence_quote === "string"
    && typeof candidate.procedure === "string"
    && (typeof candidate.confidence === "number" || candidate.confidence === null)
    && ["needs_review", "accepted", "rejected"].includes(String(candidate.review_status))
    && typeof candidate.reviewed_by === "string" && typeof candidate.reviewed_at === "string"
    && typeof candidate.accepted_by === "string" && typeof candidate.accepted_at === "string"
    && (typeof candidate.technique_url === "string" || candidate.technique_url === null)
    && typeof candidate.technique_known === "boolean"
    && ["curated", "fallback", "unsupported"].includes(String(candidate.catalog_source))
    && Array.isArray(candidate.abilities) && candidate.abilities.every((ability) => isRecord(ability)
      && typeof ability.ability_id === "string" && typeof ability.platform === "string"
      && typeof ability.executor === "string" && ["direct", "bounded_synthetic", "lab_proxy"].includes(String(ability.fidelity))
      && ["none", "low", "medium", "high"].includes(String(ability.safety_class))
      && typeof ability.content_source === "string"
      && ["unassessed", "draft", "reviewed", "retired"].includes(String(ability.review_status))
      && typeof ability.content_sha256 === "string" && typeof ability.requires_admin === "boolean"
      && typeof ability.requires_network === "boolean" && typeof ability.cleanup_available === "boolean"))) {
    throw new Error("The service returned invalid intelligence review candidates.");
  }
  return value as unknown as IntelligenceImportResponse;
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
