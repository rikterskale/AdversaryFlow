import type {
  Actor,
  ActorsResponse,
  BootstrapResponse,
  HealthPhase,
  HealthResponse,
  SessionResponse,
} from "./contract";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isActor(value: unknown): value is Actor {
  if (!isRecord(value)) return false;
  return (
    typeof value.stix_id === "string" &&
    typeof value.attack_id === "string" &&
    typeof value.name === "string" &&
    (value.type === "group" || value.type === "campaign") &&
    isStringArray(value.aliases) &&
    typeof value.description === "string" &&
    typeof value.technique_count === "number"
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
