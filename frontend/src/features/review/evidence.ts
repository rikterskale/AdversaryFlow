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
  receipt_payload?: Record<string, unknown>;
  telemetry_refs?: string[];
  telemetry_refs_draft?: string;
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
  return evidence?.outcome === "passed" || evidence?.outcome === "failed";
}

export function isRecorded(evidence: ExecutionEvidence | undefined): boolean {
  return Boolean(evidence && evidence.outcome !== "not_run");
}

export function normalizeReferences(text: string): string[] {
  return [...new Set(text.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))];
}

export function referenceError(references: string[]): string | null {
  if (references.length > 20) return "Use at most 20 unique telemetry references. Your draft is retained; correct it before exporting.";
  if (references.some((item) => [...item].length > 500)) return "Each telemetry reference must be at most 500 Unicode characters. Your draft is retained; correct it before exporting.";
  return null;
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

export function validDateTime(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/i.test(value) && !Number.isNaN(Date.parse(value));
}

export function validReceiptFields(value: unknown, techniqueId: string): value is Record<string, unknown> {
  return isRecord(value) && value.schema_version === "1.0" && value.technique_id === techniqueId
    && utf8Bytes(JSON.stringify(value)) <= RECEIPT_MAX_BYTES
    && typeof value.receipt_sha256 === "string" && /^[a-fA-F0-9]{64}$/.test(value.receipt_sha256)
    && typeof value.run_id === "string" && Boolean(value.run_id) && value.run_id.length <= 128
    && validDateTime(value.started_at) && validDateTime(value.completed_at)
    && Number.isInteger(value.exit_code) && Number(value.exit_code) >= -255 && Number(value.exit_code) <= 65_535
    && typeof value.cleanup_verified === "boolean" && (value.status === "passed" || value.status === "failed")
    && Array.isArray(value.events) && value.events.length <= 10_000 && value.events.every(isRecord);
}

export async function verifyReceiptDigest(value: Record<string, unknown>): Promise<boolean> {
  if (typeof value.receipt_sha256 !== "string" || !/^[a-fA-F0-9]{64}$/.test(value.receipt_sha256)) return false;
  const unsigned = { ...value };
  delete unsigned.receipt_sha256;
  const canonical = canonicalJson(unsigned);
  const claimed = value.receipt_sha256.toLowerCase();
  if (await sha256Hex(canonical) === claimed) return true;
  // Python's schema 1.0 exercise receipts escape non-ASCII characters.
  const ascii = canonical.replace(/[\u007f-\uffff]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
  return ascii !== canonical && await sha256Hex(ascii) === claimed;
}

export async function evidenceFromReceipt(source: string, techniqueId: string): Promise<Partial<ExecutionEvidence>> {
  requireByteLimit(source, RECEIPT_MAX_BYTES, "Receipt JSON");
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    throw new Error("The receipt is not valid JSON.");
  }
  if (!isRecord(parsed) || parsed.technique_id !== techniqueId || typeof parsed.receipt_sha256 !== "string") {
    throw new Error(`Receipt must be for ${techniqueId}.`);
  }
  if (!validReceiptFields(parsed, techniqueId)) {
    throw new Error("Receipt fields are incomplete or invalid.");
  }
  const claimed = parsed.receipt_sha256.toLocaleLowerCase();
  if (!await verifyReceiptDigest(parsed)) {
    throw new Error("Receipt digest does not match its contents.");
  }
  const receiptPayload = { ...parsed, receipt_sha256: claimed };
  return {
    outcome: parsed.status as ExecutionOutcome,
    run_id: parsed.run_id as string,
    started_at: parsed.started_at as string,
    completed_at: parsed.completed_at as string,
    exit_code: parsed.exit_code as number,
    cleanup_completed: parsed.cleanup_verified as boolean,
    receipt_sha256: claimed,
    receipt_verified: true,
    receipt_payload: receiptPayload,
    evidence_source: "exercise_receipt",
  };
}
import { RECEIPT_MAX_BYTES, requireByteLimit, utf8Bytes } from "../../state/workspaceIO";
