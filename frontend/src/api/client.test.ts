import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch, AUTH_REQUIRED_EVENT, getSession, prepareService, setApiToken } from "./client";

const jsonResponse = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), {
  status, headers: { "Content-Type": "application/json" },
});

describe("session recovery", () => {
  beforeEach(() => { setApiToken(""); });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("renews an expired CSRF token once and uses it for later mutations", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ error: "csrf_expired" }, 403))
      .mockResolvedValueOnce(jsonResponse({ csrf_token: "fresh", version: "0.5.3" }))
      .mockImplementation(async () => jsonResponse({ status: "ok" }));
    vi.stubGlobal("fetch", fetchMock);
    const init = { method: "POST", headers: { "X-AdversaryFlow-CSRF": "old" }, body: "plan" };
    expect((await apiFetch("/api/report/html", init)).status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[2]?.[1].headers.get("X-AdversaryFlow-CSRF")).toBe("fresh");
    await apiFetch("/api/report/pdf", init);
    expect(fetchMock.mock.calls[3]?.[1].headers.get("X-AdversaryFlow-CSRF")).toBe("fresh");
    expect(fetchMock.mock.calls[2]?.[1].body).toBe("plan");
  });

  it("does not retry authorization-boundary failures or loop on a second CSRF rejection", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ error: "forbidden" }, 403));
    vi.stubGlobal("fetch", fetchMock);
    const init = { method: "POST", headers: { "X-AdversaryFlow-CSRF": "old" } };
    expect((await apiFetch("/api/refresh", init)).status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    fetchMock.mockReset()
      .mockResolvedValueOnce(jsonResponse({ error: "csrf_expired" }, 403))
      .mockResolvedValueOnce(jsonResponse({ csrf_token: "fresh", version: "0.5.3" }))
      .mockResolvedValue(jsonResponse({ error: "csrf_expired" }, 403));
    expect((await apiFetch("/api/refresh", init)).status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("requests authorization again when any API operation returns 401", async () => {
    const reconnect = vi.fn();
    window.addEventListener(AUTH_REQUIRED_EVENT, reconnect);
    try {
      vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => jsonResponse({ error: "unauthorized" }, 401)));
      expect((await apiFetch("/api/report/html", { method: "POST" })).status).toBe(401);
      expect(reconnect).toHaveBeenCalledOnce();
      await expect(getSession()).rejects.toMatchObject({ status: 401 });
      expect(reconnect).toHaveBeenCalledTimes(2);
    } finally { window.removeEventListener(AUTH_REQUIRED_EVENT, reconnect); }
  });

  it("retries an obsolete token instead of reopening authorization after reconnect", async () => {
    setApiToken("old-token");
    const reconnect = vi.fn();
    window.addEventListener(AUTH_REQUIRED_EVENT, reconnect);
    try {
      const fetchMock = vi.fn().mockImplementationOnce(async () => {
        setApiToken("new-token");
        return jsonResponse({ error: "unauthorized" }, 401);
      }).mockResolvedValue(jsonResponse({ status: "ok" }));
      vi.stubGlobal("fetch", fetchMock);
      expect((await apiFetch("/api/health")).status).toBe(200);
      expect(fetchMock.mock.calls[1]?.[1].headers.get("Authorization")).toBe("Bearer new-token");
      expect(reconnect).not.toHaveBeenCalled();
    } finally { window.removeEventListener(AUTH_REQUIRED_EVENT, reconnect); }
  });

  it("F12 bounds a hanging fetch even when the implementation ignores abort", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetchMock);
    const request = expect(apiFetch("/api/session", { timeoutMs: 100 })).rejects.toMatchObject({ code: "timeout" });
    await vi.advanceTimersByTimeAsync(100);
    await request;
    expect(fetchMock.mock.calls[0]?.[1].signal.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("F12 distinguishes cancellation/network failures and does not blindly retry a mutating save", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => new Promise<Response>(() => undefined)));
    const controller = new AbortController();
    const request = expect(apiFetch("/api/engagements", { method: "POST", signal: controller.signal })).rejects.toMatchObject({ code: "cancelled" });
    controller.abort(); await request;
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("offline"));
    vi.stubGlobal("fetch", fetchMock);
    await expect(apiFetch("/api/engagements", { method: "POST" })).rejects.toMatchObject({ code: "network" });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("F12 bounds complete setup and cleans polling timers on cancellation", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => jsonResponse({ runtime: { phase: "loading", ready: false } })));
    const request = expect(prepareService("fixture")).rejects.toMatchObject({ code: "timeout" });
    await vi.advanceTimersByTimeAsync(15 * 60_000);
    await request;
    expect(vi.getTimerCount()).toBe(0);
    const controller = new AbortController();
    const cancelled = expect(prepareService("fixture", controller.signal)).rejects.toMatchObject({ code: "cancelled" });
    await vi.advanceTimersByTimeAsync(1);
    controller.abort(); await cancelled;
    expect(vi.getTimerCount()).toBe(0);
  });
});
