import type { Actor, Command, ProcedureEvidence, WorkflowResponse } from "../api/contract";
import { defaultScope } from "../features/scope/scopeModel";

export const actor: Actor = { stix_id: "intrusion-set--test", attack_id: "G0001", name: "Fixture Actor", type: "group", aliases: [], description: "Fixture", technique_count: 2 };
export const command: Command = { platform: "windows", command: "whoami", note: "Identity", cleanup: "", risk: "low", side_effects: [], requires_admin: false, requires_network: false, network_targets: [], prerequisites: [], expected_telemetry: "Process", expected_output: "Identity", timeout_seconds: 60, rollback: "", cleanup_required: false, acknowledgment_required: false };
export const workflow: WorkflowResponse = { actor: { ...actor }, summary: {}, kill_chain: [{ tactic: "execution", title: "Execution" }],
  stages: [{ tactic: "execution", title: "Execution", techniques: ["T1033", "T1059.001"].map((id) => ({
    attack_id: id, name: id, command_source: "curated", commands: [command], tactics: ["execution"], platforms: ["Windows"],
  })) }], metadata: { domains: ["enterprise"], data_version: "fixture", version: "0.5.3" } };
export const scope = { ...defaultScope(), commandPlatform: "windows" as const, tactics: ["execution"] };
export const procedure: ProcedureEvidence = { candidate_id: "candidate-1", actor_stix_id: actor.stix_id, mapping_data_version: "fixture",
  technique_id: "T1033", technique_name: "Identity", tactics: ["execution"], platforms: ["Windows"], source_kind: "csv", source_name: "fixture.csv",
  source_url: null, source_sha256: "a".repeat(64), evidence_quote: "Quote", procedure: "Read-only identity", confidence: 1,
  review_status: "accepted", reviewed_by: "Reviewer", reviewed_at: "2026-10-06T20:00:00Z", accepted_by: "Reviewer", accepted_at: "2026-10-06T20:00:00Z" };
