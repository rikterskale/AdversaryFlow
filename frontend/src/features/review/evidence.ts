export type ExecutionOutcome = "not_run" | "passed" | "failed" | "skipped";
export type DetectionResult = "not_assessed" | "alerted" | "silent" | "blocked" | "not_instrumented";
export type EvidenceSource = "operator_supplied" | "exercise_receipt" | "endpoint_verified" | "siem_verified";

export interface ExecutionEvidence {
  outcome: ExecutionOutcome;
  updated_at?: string;
  operator?: string;
  target?: string;
  notes?: string;
  cleanup_completed?: boolean;
  run_id?: string;
  started_at?: string;
  completed_at?: string;
  exit_code?: number;
  stdout_sha256?: string;
  stderr_sha256?: string;
  receipt_sha256?: string;
  receipt_verified?: boolean;
  telemetry_refs?: string[];
  evidence_source?: EvidenceSource;
  detection_result?: DetectionResult;
}

export const outcomeOptions: { value: ExecutionOutcome; label: string }[] = [
  { value: "not_run", label: "Not run" },
  { value: "passed", label: "Ran" },
  { value: "failed", label: "Failed" },
  { value: "skipped", label: "Skipped" },
];

export const detectionOptions: { value: DetectionResult; label: string }[] = [
  { value: "not_assessed", label: "Not assessed" },
  { value: "alerted", label: "Alerted" },
  { value: "silent", label: "Silent" },
  { value: "blocked", label: "Blocked" },
  { value: "not_instrumented", label: "Not instrumented" },
];

export const evidenceSourceOptions: { value: EvidenceSource; label: string }[] = [
  { value: "operator_supplied", label: "Operator supplied" },
  { value: "exercise_receipt", label: "Exercise receipt" },
  { value: "endpoint_verified", label: "Endpoint verified" },
  { value: "siem_verified", label: "SIEM verified" },
];

export function isMarkedRun(evidence: ExecutionEvidence | undefined): boolean {
  return Boolean(evidence && evidence.outcome !== "not_run");
}

export function dateTimeLocalValue(value: string | undefined): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 19);
}

export function dateTimeIsoValue(value: string): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validDateTime(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !Number.isNaN(Date.parse(value));
}

export async function evidenceFromReceipt(source: string, techniqueId: string): Promise<Partial<ExecutionEvidence>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    throw new Error("The receipt is not valid JSON.");
  }
  if (!isRecord(parsed) || parsed.technique_id !== techniqueId || typeof parsed.receipt_sha256 !== "string") {
    throw new Error(`Receipt must be for ${techniqueId}.`);
  }
  if (
    typeof parsed.run_id !== "string" || !parsed.run_id || parsed.run_id.length > 128 ||
    !validDateTime(parsed.started_at) || !validDateTime(parsed.completed_at) ||
    !Number.isInteger(parsed.exit_code) || Number(parsed.exit_code) < -255 || Number(parsed.exit_code) > 65_535 ||
    typeof parsed.cleanup_verified !== "boolean" ||
    (parsed.status !== "passed" && parsed.status !== "failed") ||
    !Array.isArray(parsed.events)
  ) {
    throw new Error("Receipt fields are incomplete or invalid.");
  }
  const claimed = parsed.receipt_sha256.toLocaleLowerCase();
  const unsigned: Record<string, unknown> = { ...parsed };
  delete unsigned.receipt_sha256;
  if (!/^[a-f0-9]{64}$/.test(claimed) || await sha256Hex(canonicalJson(unsigned)) !== claimed) {
    throw new Error("Receipt digest does not match its contents.");
  }
  return {
    outcome: parsed.status,
    run_id: parsed.run_id,
    started_at: parsed.started_at,
    completed_at: parsed.completed_at,
    exit_code: parsed.exit_code as number,
    cleanup_completed: parsed.cleanup_verified,
    receipt_sha256: claimed,
    receipt_verified: true,
    evidence_source: "exercise_receipt",
  };
}
