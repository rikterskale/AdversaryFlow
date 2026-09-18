import { isRecord, parseActors, parseBootstrap, parseDoctor, parseHealth, parseSession, parseWorkflow } from "./guards";
import type { ActorsResponse, AttackDomain, BootstrapResponse, DoctorResponse, HealthResponse, SessionResponse, WorkflowResponse } from "./contract";

const TOKEN_KEY = "af_api_token";

function storedApiToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

let apiToken = storedApiToken();

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly requestId: string | null;

  constructor(message: string, status: number, code: string | null = null, requestId: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export function setApiToken(token: string): void {
  apiToken = token.trim();
  try {
    if (apiToken) sessionStorage.setItem(TOKEN_KEY, apiToken);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Keep the token in memory for this tab when session storage is denied.
  }
}

function authorizationHeaders(headers?: HeadersInit): Headers {
  const next = new Headers(headers);
  next.set("Accept", "application/json");
  if (apiToken) next.set("Authorization", `Bearer ${apiToken}`);
  return next;
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(path, { ...init, headers: authorizationHeaders(init.headers) });
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new ApiError(`The service returned an unreadable response (${response.status}).`, response.status);
  }
}

export async function responseJson(response: Response): Promise<unknown> {
  const body = await readJson(response);
  if (!response.ok) {
    const message = isRecord(body) && typeof body.message === "string"
      ? body.message
      : isRecord(body) && typeof body.error === "string"
        ? body.error
        : `Request failed (${response.status}).`;
    const code = isRecord(body) && typeof body.error === "string" ? body.error : null;
    const requestId = isRecord(body) && typeof body.request_id === "string" ? body.request_id : null;
    throw new ApiError(message, response.status, code, requestId);
  }
  return body;
}

export async function getSession(): Promise<SessionResponse> {
  return parseSession(await responseJson(await apiFetch("/api/session")));
}

export async function getActors(domains: AttackDomain[]): Promise<ActorsResponse> {
  const query = new URLSearchParams({ domains: domains.join(",") });
  return parseActors(await responseJson(await apiFetch(`/api/actors?${query.toString()}`)));
}

export async function getHealth(): Promise<HealthResponse> {
  return parseHealth(await responseJson(await apiFetch("/api/health")));
}

export async function getDoctor(): Promise<DoctorResponse> {
  return parseDoctor(await responseJson(await apiFetch("/api/doctor")));
}

export async function getWorkflow(stixId: string, domains: AttackDomain[]): Promise<WorkflowResponse> {
  const query = new URLSearchParams({ domains: domains.join(",") });
  return parseWorkflow(await responseJson(await apiFetch(`/api/workflow/${encodeURIComponent(stixId)}?${query.toString()}`)));
}

export async function refreshAttackData(domains: AttackDomain[], csrfToken: string): Promise<void> {
  const query = new URLSearchParams({ domains: domains.join(",") });
  await responseJson(await apiFetch(`/api/refresh?${query.toString()}`, {
    method: "POST",
    headers: { "X-AdversaryFlow-CSRF": csrfToken },
  }));
}

export async function prepareService(csrfToken: string): Promise<BootstrapResponse> {
  const deadline = Date.now() + 15 * 60_000;
  let response = await apiFetch("/api/bootstrap");
  if (response.status === 503) {
    response = await apiFetch("/api/bootstrap", {
      method: "POST",
      headers: { "X-AdversaryFlow-CSRF": csrfToken },
    });
  }

  for (;;) {
    const body = parseBootstrap(await responseJson(response));
    if (body.runtime?.ready) return body;
    if (body.runtime?.phase === "failed") {
      throw new Error(body.runtime.error ?? "ATT&CK data could not be prepared.");
    }
    if (Date.now() >= deadline) {
      throw new Error("Preparing ATT&CK data timed out. Check the service log, then retry setup.");
    }
    await new Promise<void>((resolve) => window.setTimeout(resolve, 750));
    response = await apiFetch("/api/bootstrap");
  }
}
