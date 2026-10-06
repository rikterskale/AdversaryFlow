import { isRecord, parseActors, parseBootstrap, parseDoctor, parseHealth, parseIntelligenceImport, parseSession, parseWorkflow } from "./guards";
import type { ActorsResponse, AttackDomain, BootstrapResponse, DoctorResponse, HealthResponse, IntelligenceImportResponse, SessionResponse, WorkflowResponse } from "./contract";

const TOKEN_KEY = "af_api_token";

function storedApiToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

let apiToken = storedApiToken();
let csrfToken = "";
export const AUTH_REQUIRED_EVENT = "adversaryflow-auth-required";

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
  csrfToken = "";
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

export const REQUEST_TIMEOUT_MS = 30_000;
export const PREPARATION_TIMEOUT_MS = 15 * 60_000;
export interface ApiRequestInit extends RequestInit { timeoutMs?: number }

export async function withDeadline<T>(work: (signal: AbortSignal) => Promise<T>, timeoutMs: number, signal?: AbortSignal | null, timeoutMessage = "The service request timed out. Check service health and retry."): Promise<T> {
  const controller = new AbortController();
  let timer: number | undefined;
  let rejectAbort: (error: ApiError) => void = () => undefined;
  const aborted = new Promise<never>((_resolve, reject) => { rejectAbort = reject; });
  const cancel = (): void => {
    controller.abort();
    rejectAbort(new ApiError("Request cancelled. Retry when you are ready.", 0, "cancelled"));
  };
  signal?.addEventListener("abort", cancel, { once: true });
  if (signal?.aborted) cancel();
  else timer = window.setTimeout(() => {
    controller.abort();
    rejectAbort(new ApiError(timeoutMessage, 0, "timeout"));
  }, timeoutMs);
  try {
    if (signal?.aborted) return await aborted;
    return await Promise.race([work(controller.signal), aborted]);
  } finally {
    window.clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
  }
}

export async function apiFetch(path: string, init: ApiRequestInit = {}): Promise<Response> {
  const { timeoutMs = /\/(?:report|execution-kit|playbook|refresh|intelligence)\b/.test(path) ? 120_000 : REQUEST_TIMEOUT_MS, signal, ...options } = init;
  return withDeadline(async (requestSignal) => {
  const headers = authorizationHeaders(init.headers);
  if (csrfToken && headers.has("X-AdversaryFlow-CSRF")) headers.set("X-AdversaryFlow-CSRF", csrfToken);
  const request = async (nextHeaders: Headers): Promise<Response> => {
    try {
      const response = await fetch(path, { ...options, headers: nextHeaders, signal: requestSignal });
      // Keep the deadline active through body transfer, not just response headers.
      const body = await response.arrayBuffer();
      return new Response(response.status === 204 || response.status === 205 || response.status === 304 ? null : body, {
        status: response.status, statusText: response.statusText, headers: response.headers,
      });
    } catch (error: unknown) {
      if (requestSignal.aborted) throw new ApiError("Request cancelled.", 0, "cancelled");
      throw new ApiError(error instanceof Error ? `Cannot reach the service: ${error.message}` : "Cannot reach the service.", 0, "network");
    }
  };
  let response = await request(headers);
  if (response.status === 403 && headers.has("X-AdversaryFlow-CSRF")) {
    const body: unknown = await response.clone().json().catch(() => null);
    if (isRecord(body) && body.error === "csrf_expired") {
      const renewed = await getSession(requestSignal);
      headers.set("X-AdversaryFlow-CSRF", renewed.csrf_token);
      response = await request(headers);
    }
  }
  if (response.status === 401 && (!init.method || ["GET", "HEAD"].includes(init.method.toUpperCase())) && headers.get("Authorization") !== authorizationHeaders().get("Authorization")) {
    // Another request may have prompted a successful reconnect while this
    // request was in flight. Do not reopen the dialog for its obsolete token.
    const current = authorizationHeaders(init.headers);
    if (csrfToken && current.has("X-AdversaryFlow-CSRF")) current.set("X-AdversaryFlow-CSRF", csrfToken);
    response = await request(current);
  }
  if (response.status === 401) window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
  return response;
  }, timeoutMs, signal);
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

export async function getSession(signal?: AbortSignal): Promise<SessionResponse> {
  const session = parseSession(await responseJson(await apiFetch("/api/session", { signal })));
  if (signal?.aborted) throw new ApiError("Request cancelled.", 0, "cancelled");
  csrfToken = session.csrf_token;
  return session;
}

export async function getActors(domains: AttackDomain[], signal?: AbortSignal): Promise<ActorsResponse> {
  const query = new URLSearchParams({ domains: domains.join(",") });
  return parseActors(await responseJson(await apiFetch(`/api/actors?${query.toString()}`, { signal })));
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return parseHealth(await responseJson(await apiFetch("/api/health", { signal })));
}

export async function getDoctor(signal?: AbortSignal): Promise<DoctorResponse> {
  return parseDoctor(await responseJson(await apiFetch("/api/doctor", { signal })));
}

export async function getWorkflow(stixId: string, domains: AttackDomain[], signal?: AbortSignal): Promise<WorkflowResponse> {
  const query = new URLSearchParams({ domains: domains.join(",") });
  return parseWorkflow(await responseJson(await apiFetch(`/api/workflow/${encodeURIComponent(stixId)}?${query.toString()}`, { signal })));
}

export async function previewIntelligenceImport(args: {
  file: File;
  source_kind: "csv" | "json";
  source_name: string;
  source_url?: string;
  actor_stix_id: string;
  domains: AttackDomain[];
  csrfToken: string;
  signal?: AbortSignal;
}): Promise<IntelligenceImportResponse> {
  const query = new URLSearchParams({
    domains: args.domains.join(","),
    actor_stix_id: args.actor_stix_id,
    source_kind: args.source_kind,
    source_name: args.source_name,
  });
  if (args.source_url) query.set("source_url", args.source_url);
  return parseIntelligenceImport(await responseJson(await apiFetch(`/api/intelligence/import?${query.toString()}`, {
    method: "POST",
    headers: { "Content-Type": args.source_kind === "csv" ? "text/csv; charset=utf-8" : "application/json", "X-AdversaryFlow-CSRF": args.csrfToken },
    body: args.file,
    signal: args.signal,
  })));
}

export async function refreshAttackData(domains: AttackDomain[], csrfToken: string, signal?: AbortSignal): Promise<void> {
  const query = new URLSearchParams({ domains: domains.join(",") });
  await responseJson(await apiFetch(`/api/refresh?${query.toString()}`, {
    method: "POST",
    headers: { "X-AdversaryFlow-CSRF": csrfToken },
    signal,
  }));
}

export async function prepareService(csrfToken: string, signal?: AbortSignal): Promise<BootstrapResponse> {
  return withDeadline(async (preparationSignal) => {
  let response = await apiFetch("/api/bootstrap", { signal: preparationSignal });
  if (response.status === 503) {
    response = await apiFetch("/api/bootstrap", {
      method: "POST",
      headers: { "X-AdversaryFlow-CSRF": csrfToken },
      signal: preparationSignal,
    });
  }

  for (;;) {
    const body = parseBootstrap(await responseJson(response));
    if (body.runtime?.ready) return body;
    if (body.runtime?.phase === "failed") {
      throw new Error(body.runtime.error ?? "ATT&CK data could not be prepared.");
    }
    await new Promise<void>((resolve, reject) => {
      const cancel = (): void => { window.clearTimeout(timer); reject(new ApiError("Preparation cancelled.", 0, "cancelled")); };
      const timer = window.setTimeout(() => { preparationSignal.removeEventListener("abort", cancel); resolve(); }, 750);
      preparationSignal.addEventListener("abort", cancel, { once: true });
      if (preparationSignal.aborted) cancel();
    });
    response = await apiFetch("/api/bootstrap", { signal: preparationSignal });
  }
  }, PREPARATION_TIMEOUT_MS, signal, "Preparing ATT&CK data timed out. Check the service log, then retry setup.");
}
