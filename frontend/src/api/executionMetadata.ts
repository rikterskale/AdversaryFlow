const environments = ["endpoint", "cloud", "container", "pre_compromise"];
const roles = ["endpoint_test", "planning", "environment_validation"];
const statuses = ["runnable", "permission_required", "unsupported", "not_applicable", "prerequisites_unverified"];

export function validCommandSelections(value: unknown): value is Record<string, string> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length <= 4000 && Object.entries(value).every(([key, id]) => /^T[0-9]{4}(?:\.[0-9]{3})?$/.test(key) && typeof id === "string" && /^[a-f0-9]{64}$/.test(id)));
}

export function validExecutionMetadata(value: Record<string, unknown>): boolean {
  if (value.command_id !== undefined && (typeof value.command_id !== "string" || !/^[a-f0-9]{64}$/.test(value.command_id))) return false;
  for (const [key, allowed] of [["environment", environments], ["execution_role", roles], ["availability_status", statuses]] as const) {
    if (value[key] !== undefined && (typeof value[key] !== "string" || !allowed.includes(value[key] as string))) return false;
  }
  for (const key of ["required_tools", "required_credentials", "availability_reasons"]) {
    const items = value[key];
    if (items !== undefined && (!Array.isArray(items) || items.length > 100 || items.some((item) => typeof item !== "string" || !item || item.length > 2000) || new Set(items).size !== items.length)) return false;
  }
  return true;
}

export const executionMetadataKeys = ["command_id", "environment", "execution_role", "required_tools", "required_credentials", "availability_status", "availability_reasons"];
