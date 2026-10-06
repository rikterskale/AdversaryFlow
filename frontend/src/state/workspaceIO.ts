export const PLAN_MAX_BYTES = 32 * 1024 * 1024;
export const WORKSPACE_MAX_BYTES = 128 * 1024 * 1024;
export const RECEIPT_MAX_BYTES = 1024 * 1024;

export function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export function requireByteLimit(value: string, limit: number, label: string): void {
  if (utf8Bytes(value) > limit) throw new Error(`${label} exceeds the ${limit / 1024 / 1024} MiB UTF-8 limit. Keep this workspace open and download a workspace recovery copy before reducing the plan.`);
}

export function boundedJson(value: unknown, limit = PLAN_MAX_BYTES): string {
  const compact = JSON.stringify(value);
  requireByteLimit(compact, limit, "JSON");
  const pretty = JSON.stringify(value, null, 2);
  return utf8Bytes(pretty) <= limit ? pretty : compact;
}

export function downloadJson(text: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
