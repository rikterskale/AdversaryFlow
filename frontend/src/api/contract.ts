export type AttackDomain = "enterprise" | "ics" | "mobile";
export type ActorType = "group" | "campaign";

export interface SessionResponse {
  csrf_token: string;
  version: string;
}

export interface Actor {
  stix_id: string;
  attack_id: string;
  name: string;
  type: ActorType;
  aliases: string[];
  description: string;
  technique_count: number;
}

export interface ActorsResponse {
  actors: Actor[];
  domains: string[];
  data_version: string;
  version: string;
}

export type HealthPhase = "not_started" | "loading" | "refreshing" | "ready" | "failed";

export interface HealthResponse {
  status: "ready" | "degraded";
  ready: boolean;
  loading: boolean;
  phase: HealthPhase;
  version: string | null;
  error: string | null;
  attack_data: Record<string, unknown>;
  service: Record<string, unknown>;
}

export interface BootstrapResponse {
  runtime?: {
    ready?: boolean;
    phase?: string;
    error?: string | null;
  };
  cache?: Record<string, unknown>;
}

export interface ApiErrorBody {
  error: string;
  message: string;
  request_id?: string;
  version: string;
}
