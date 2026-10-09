export type AttackDomain = "enterprise" | "ics" | "mobile";
export type ActorType = "group" | "campaign";

export interface SessionResponse {
  csrf_token: string;
  version: string;
}

export interface EngagementSaveResponse {
  engagement_id: string;
  revision: number;
  plan_sha256: string;
  content_pack_sha256?: string;
  content_packs?: Array<{
    pack_id: string;
    pack_version: string;
    attack_version: string;
    signer_key_id: string;
    pack_sha256: string;
    ability_count: number;
    detection_binding_count: number;
  }>;
  created_at: string;
}

export type AbilityGapStatus = "open" | "in_progress" | "accepted" | "closed";

export interface AbilityBacklogItem {
  id: string;
  technique_id: string;
  platform: string;
  gap: "no_ability" | "wrong_shape" | "out_of_scope" | "not_accepted";
  reason: string;
  ability_id: string | null;
  procedure_candidate_ids: string[];
  owner: string | null;
  status: AbilityGapStatus;
  created_at: string;
  updated_at: string;
}

export interface ReceiptEvidence {
  technique_id: string;
  run_id: string;
  receipt_sha256: string;
  receipt: Record<string, unknown>;
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
  command_id?: string;
  environment?: "endpoint" | "cloud" | "container" | "pre_compromise";
  execution_role?: "endpoint_test" | "planning" | "environment_validation";
  required_tools?: string[];
  required_credentials?: string[];
  availability_status?: "runnable" | "permission_required" | "unsupported" | "not_applicable" | "prerequisites_unverified";
  availability_reasons?: string[];
  platform: string;
  interpreter?: "cmd" | "powershell" | "bash";
  untrusted?: boolean;
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

export type ProcedureReviewStatus = "needs_review" | "accepted" | "rejected";

export interface ProcedureCandidate {
  candidate_id: string;
  technique_id: string;
  technique_name: string;
  tactics: string[];
  platforms: string[];
  source_kind: "csv" | "navigator_layer" | "stix2_bundle";
  source_name: string;
  source_url: string | null;
  source_sha256: string;
  evidence_quote: string;
  procedure: string;
  confidence: number | null;
  review_status: ProcedureReviewStatus;
  reviewed_by: string;
  reviewed_at: string;
  accepted_by: string;
  accepted_at: string;
  technique_url: string | null;
  technique_known: boolean;
  catalog_source: "curated" | "fallback" | "unsupported";
  abilities: {
    ability_id: string;
    platform: string;
    executor: string;
    fidelity: "direct" | "bounded_synthetic" | "lab_proxy";
    safety_class: CommandRisk;
    content_source: string;
    review_status: "unassessed" | "draft" | "reviewed" | "retired";
    content_sha256: string;
    requires_admin: boolean;
    requires_network: boolean;
    cleanup_available: boolean;
  }[];
}

export interface ProcedureEvidence {
  candidate_id: string;
  actor_stix_id: string;
  mapping_data_version: string;
  technique_id: string;
  technique_name: string;
  tactics: string[];
  platforms: string[];
  source_kind: ProcedureCandidate["source_kind"];
  source_name: string;
  source_url: string | null;
  source_sha256: string;
  evidence_quote: string;
  procedure: string;
  confidence: number | null;
  review_status: "accepted";
  reviewed_by: string;
  reviewed_at: string;
  accepted_by: string;
  accepted_at: string;
}

export interface IntelligenceImportResponse {
  schema_version: "1.0";
  source: { kind: ProcedureCandidate["source_kind"]; name: string; url: string | null; sha256: string };
  actor: Pick<Actor, "stix_id" | "attack_id" | "name" | "type">;
  data_version: string;
  comparison: { report_only: string[]; attack_only: string[]; both: string[] };
  candidates: ProcedureCandidate[];
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
