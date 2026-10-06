import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { actor, scope, workflow } from "../test/remediationFixtures";
import { buildExportBundle } from "../features/export/exportModel";
import { useWizardStore, workspaceSnapshot } from "../state/wizardStore";
import { App } from "./App";

const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
beforeEach(() => {
  useWizardStore.getState().restart();
  useWizardStore.getState().selectActor(actor);
  useWizardStore.getState().updateScope(scope);
  useWizardStore.getState().ensureEvidenceKey("fixture-key", workflow);
  useWizardStore.getState().updateEvidence("T1033", { outcome: "passed", notes: "Keep my evidence" });
  useWizardStore.getState().setStep(3);
  vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
    if (path === "/api/session") return json({ csrf_token: "fixture", version: "0.5.3" });
    if (path === "/api/bootstrap") return json({ runtime: { ready: true } });
    if (path.startsWith("/api/actors")) return json({ actors: [actor], domains: ["enterprise"], data_version: "fixture", version: "0.5.3" });
    if (path.startsWith("/api/workflow")) return json(workflow);
    if (path.startsWith("/api/engagements")) return json({ engagements: [] });
    return json({ status: "ready", ready: true, loading: false, phase: "ready", version: "0.5.3", error: null, attack_data: {}, service: {} });
  }));
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function mount(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<QueryClientProvider client={client}><App /></QueryClientProvider>);
}

describe("workspace replacement UX", () => {
  it("F01 reopened Begin prompts; cancel preserves the whole workspace and confirm clears intentionally", async () => {
    mount();
    await waitFor(() => expect(screen.getByRole("button", { name: "Begin emulation plan" })).toBeEnabled());
    const before = workspaceSnapshot(useWizardStore.getState());
    fireEvent.click(screen.getByRole("button", { name: "Begin emulation plan" }));
    const dialog = screen.getByRole("dialog", { name: "Begin a new plan?" });
    expect(within(dialog).getByRole("button", { name: "Download recovery copy" })).toBeEnabled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Keep current workspace" }));
    expect(workspaceSnapshot(useWizardStore.getState())).toEqual(before);
    fireEvent.click(screen.getByRole("button", { name: "Begin emulation plan" }));
    fireEvent.click(screen.getByRole("button", { name: "Clear and begin" }));
    expect(useWizardStore.getState().records).toEqual({});
    expect(useWizardStore.getState().evidenceArchive).toEqual({});
    expect(useWizardStore.getState().scope.target).toBe("");
  });

  it("F02 scope storage failure is visible on welcome and review re-entry without editing evidence", async () => {
    mount();
    await screen.findByRole("button", { name: "Resume Fixture Actor plan" });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage denied"); });
    act(() => useWizardStore.getState().updateScope({ target: "unsaved-target" }));
    expect(screen.getByRole("alert")).toHaveTextContent("not saved in this browser");
    fireEvent.click(screen.getByRole("button", { name: "Resume Fixture Actor plan" }));
    await waitFor(() => expect(screen.getByText("Not saved in this browser")).toBeVisible());
    expect(screen.queryByText("Saved in this browser")).not.toBeInTheDocument();
  });

  it("F05 restored server revisions require confirmation and the next save appends to their engagement", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    const startupFetch = vi.mocked(fetch);
    let savedBody: unknown;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string, init: RequestInit) => {
      if (path === "/api/engagements" && init.method === "POST") {
        savedBody = JSON.parse(String(init.body)) as unknown;
        return json({ engagement_id: "server-engagement", revision: 3, plan_sha256: "b".repeat(64), created_at: plan.generated }, 201);
      }
      if (path.startsWith("/api/engagements?")) return json({ engagements: [{ id: "server-engagement", actor_name: actor.name, revision: 2, data_version: "fixture" }] });
      if (path === "/api/engagements/server-engagement") return json({ id: "server-engagement", revisions: [{ revision: 2, plan_sha256: "a".repeat(64) }] });
      if (path === "/api/engagements/server-engagement/revisions/2") return json({ engagement_id: "server-engagement", revision: 2, plan_sha256: "a".repeat(64), created_at: plan.generated, plan });
      return startupFetch(path, init);
    }));
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Browse saved engagements" }));
    fireEvent.click(await screen.findByRole("button", { name: /Fixture Actor · revision 2/ }));
    fireEvent.change(await screen.findByLabelText("Saved engagement revision"), { target: { value: "2" } });
    fireEvent.click(await screen.findByRole("button", { name: "Restore selected revision" }));
    expect(useWizardStore.getState().engagementId).toBeNull();
    fireEvent.click(await screen.findByRole("button", { name: "Replace and restore" }));
    expect(useWizardStore.getState().engagementId).toBe("server-engagement");
    expect(useWizardStore.getState().engagementRevision).toBe(2);
    fireEvent.click(screen.getByRole("button", { name: "Export kit" }));
    fireEvent.click(await screen.findByRole("button", { name: "Save new revision" }));
    await waitFor(() => expect(useWizardStore.getState().engagementRevision).toBe(3));
    expect(savedBody).toMatchObject({ engagement_id: "server-engagement", plan: { actor: { stix_id: actor.stix_id } } });
  });

  it("F12 obsolete startup is cancelled on unmount and never advances ready state", async () => {
    let signal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_path: string, init: RequestInit) => {
      signal = init.signal ?? undefined;
      return new Promise<Response>(() => undefined);
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const result = render(<QueryClientProvider client={client}><App /></QueryClientProvider>);
    expect(signal?.aborted).toBe(false);
    result.unmount();
    expect(signal?.aborted).toBe(true);
  });
});
