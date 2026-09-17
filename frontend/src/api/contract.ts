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

export type CommandRisk = "none" | "low" | "medium" | "high";

export interface Command {
  platform: string;
  command: string;
  note: string;
  cleanup: string;
  risk: CommandRisk;
  side_effects: string[];
  requires_admin: boolean;
  requires_network: boolean;
  network_targets: string[];
  prerequisites: string[];
  expected_telemetry: string;
  expected_output: string;
  timeout_seconds: number;
  rollback: string;
  cleanup_required: boolean;
  acknowledgment_required: boolean;
  exercise_kind?: "technique_relevant_bounded";
  fidelity?: "direct" | "bounded_synthetic" | "lab_proxy";
  evidence_source?: "self_reported_receipt";
  unsupported?: boolean;
  restricted?: boolean;
  telemetry_acceptance?: Record<string, unknown>;
}

export interface Technique {
  attack_id: string;
  name: string;
  commands: Command[];
  command_source: string;
  stix_id?: string;
  description?: string;
  tactics?: string[];
  platforms?: string[];
  is_subtechnique?: boolean;
  data_sources?: string[];
  detection?: string | null;
  url?: string | null;
}

export interface WorkflowStage {
  tactic: string;
  title: string;
  techniques: Technique[];
}

export interface WorkflowResponse {
  actor: Record<string, unknown>;
  summary: Record<string, unknown>;
  kill_chain: { tactic: string; title: string }[];
  stages: WorkflowStage[];
  metadata: {
    domains: string[];
    data_version: string;
    version: string;
  };
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

export type DoctorStatus = "PASS" | "FAIL";

export interface DoctorCheck {
  id: string;
  label: string;
  status: DoctorStatus;
  required: boolean;
  detail: string;
  fix: string;
}

export interface DoctorResponse {
  version: string;
  generated_at: string;
  ok: boolean;
  summary: {
    passed: number;
    failed: number;
    required_failed: number;
  };
  checks: DoctorCheck[];
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
