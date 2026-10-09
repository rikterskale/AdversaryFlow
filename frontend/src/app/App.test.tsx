import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { actor, scope, workflow } from "../test/remediationFixtures";
import { buildExportBundle } from "../features/export/exportModel";
import * as evidenceModule from "../features/review/evidence";
import type { ExecutionEvidence } from "../features/review/evidence";
import { evidenceIdentity, useWizardStore, workspaceSnapshot } from "../state/wizardStore";
import { App } from "./App";

const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
beforeEach(() => {
  useWizardStore.getState().restart();
  useWizardStore.getState().selectActor(actor);
  useWizardStore.getState().updateScope(scope);
  useWizardStore.getState().ensureEvidenceKey(evidenceIdentity(actor.stix_id, workflow, scope.commandPlatform), workflow);
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
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })): void {
  render(<QueryClientProvider client={client}><App /></QueryClientProvider>);
}

describe("workspace replacement UX", () => {
  it.each(["restart", "platform change"])("discards a delayed receipt after %s", async (change) => {
    const boundedWorkflow = { ...workflow, stages: workflow.stages.map((stage) => ({ ...stage,
      techniques: stage.techniques.map((technique) => ({ ...technique,
        commands: technique.commands.map((command) => ({ ...command, exercise_kind: "technique_relevant_bounded" as const })),
      })),
    })) };
    useWizardStore.getState().importPlan(buildExportBundle(actor, boundedWorkflow, scope, {}, ["enterprise"]).plan);
    let finishVerification: (value: Partial<ExecutionEvidence>) => void = () => undefined;
    vi.spyOn(evidenceModule, "evidenceFromReceipt").mockImplementation(() => new Promise((resolve) => { finishVerification = resolve; }));
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Resume Fixture Actor plan" }));
    fireEvent.change(screen.getByLabelText("Exercise receipt for T1033"), { target: { value: "receipt fixture" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Verify and import receipt" })[0]!);
    act(() => {
      if (change === "restart") useWizardStore.getState().restart();
      else useWizardStore.getState().updateScope({ commandPlatform: "linux" });
    });
    await act(async () => { finishVerification({ outcome: "passed", run_id: "obsolete-run" }); });
    expect(useWizardStore.getState().records).toEqual({});
  });
  it("shows a saved revision immediately when returning to the engagement browser", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    const startupFetch = vi.mocked(fetch);
    let revision = 2;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string, init: RequestInit) => {
      if (path === "/api/engagements" && init.method === "POST") {
        revision++;
        return json({ engagement_id: "server-engagement", revision, plan_sha256: "b".repeat(64), created_at: plan.generated }, 201);
      }
      if (path.startsWith("/api/engagements?")) return json({ engagements: [{ id: "server-engagement", actor_name: actor.name, revision, data_version: "fixture" }] });
      if (path === "/api/engagements/server-engagement") return json({ id: "server-engagement", revisions: [{ revision, plan_sha256: "b".repeat(64) }] });
      return startupFetch(path, init);
    }));
    mount(new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 } } }));
    fireEvent.click(screen.getByRole("button", { name: "Browse saved engagements" }));
    fireEvent.click(await screen.findByRole("button", { name: /Fixture Actor · revision 2/ }));
    await screen.findByRole("option", { name: /Revision 2/ });
    fireEvent.click(screen.getByRole("button", { name: "Resume Fixture Actor plan" }));
    fireEvent.click(screen.getByRole("button", { name: "Finish & export" }));
    act(() => useWizardStore.getState().setEngagementRecord("server-engagement", 2));
    fireEvent.click(await screen.findByRole("button", { name: "Save new revision" }));
    await waitFor(() => expect(useWizardStore.getState().engagementRevision).toBe(3));
    fireEvent.click(screen.getByRole("button", { name: "Return to workspace home" }));
    fireEvent.click(screen.getByRole("button", { name: "Browse saved engagements" }));
    fireEvent.click(await screen.findByRole("button", { name: /Fixture Actor · revision 3/ }));
    expect(await screen.findByRole("option", { name: /Revision 3/ })).toBeInTheDocument();
  });

  it("keeps the latest file selection when an earlier recovery file finishes reading later", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    let finishEarlier: (text: string) => void = () => undefined;
    const earlier = Object.assign(new File([], "earlier.json"), { text: () => new Promise<string>((resolve) => { finishEarlier = resolve; }) });
    const latest = Object.assign(new File([], "latest.json"), { text: async () => JSON.stringify({ ...plan, actor: { ...plan.actor, name: "Latest Actor" } }) });
    mount();
    fireEvent.change(screen.getByLabelText("Resume JSON plan"), { target: { files: [earlier] } });
    await act(async () => { fireEvent.change(screen.getByLabelText("Resume JSON plan"), { target: { files: [latest] } }); });
    expect(screen.getByRole("dialog", { name: "Replace this browser workspace?" })).toBeVisible();
    await act(async () => { finishEarlier(JSON.stringify(plan)); });
    fireEvent.click(screen.getByRole("button", { name: "Replace and restore" }));
    expect(useWizardStore.getState().selectedActor?.name).toBe("Latest Actor");
  });

  it("discards a pending file import when the user starts another workspace", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    let finishRead: (text: string) => void = () => undefined;
    const file = Object.assign(new File([], "delayed.json"), { text: () => new Promise<string>((resolve) => { finishRead = resolve; }) });
    mount();
    fireEvent.change(screen.getByLabelText("Resume JSON plan"), { target: { files: [file] } });
    act(() => useWizardStore.getState().restart());
    await act(async () => { finishRead(JSON.stringify(plan)); });
    expect(useWizardStore.getState().selectedActor).toBeNull();
    expect(screen.queryByRole("dialog", { name: "Replace this browser workspace?" })).not.toBeInTheDocument();
  });
  it("Home exposes saved engagements and imports without clearing evidence or server identity", async () => {
    useWizardStore.getState().setEngagementRecord("saved-engagement", 2);
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Resume Fixture Actor plan" }));
    await screen.findByRole("heading", { name: "Fixture Actor · G0001" });
    const before = workspaceSnapshot(useWizardStore.getState());
    fireEvent.click(screen.getByRole("button", { name: "Return to workspace home" }));
    expect(screen.getByRole("button", { name: "Browse saved engagements" })).toBeVisible();
    expect(screen.getByLabelText("Resume JSON plan")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Resume Fixture Actor plan" }));
    expect(workspaceSnapshot(useWizardStore.getState())).toEqual(before);
  });

  it("a pending service connection does not block resuming the saved workflow", async () => {
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(new Promise<Response>(() => undefined)));
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Resume Fixture Actor plan" }));
    expect(await screen.findByRole("heading", { name: "Fixture Actor · G0001" })).toBeVisible();
    expect(screen.getByLabelText("Evidence note for T1033")).toHaveValue("Keep my evidence");
  });

  it("a token prompt can be dismissed to recover saved work and reopened to reconnect", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ error: "unauthorized", message: "Token required" }, 401)));
    mount();
    await screen.findByRole("dialog", { name: "Connect to this AdversaryFlow service" });
    fireEvent.click(screen.getByRole("button", { name: "Continue with saved work" }));
    fireEvent.click(screen.getByRole("button", { name: "Resume Fixture Actor plan" }));
    expect(screen.getByLabelText("Evidence note for T1033")).toHaveValue("Keep my evidence");
    fireEvent.click(screen.getByRole("button", { name: "Connect to service" }));
    expect(screen.getByRole("dialog", { name: "Connect to this AdversaryFlow service" })).toBeVisible();
  });

  it("invalid plan imports keep an actionable error after the notification expires", async () => {
    mount();
    await screen.findByRole("button", { name: "Resume Fixture Actor plan" });
    const before = workspaceSnapshot(useWizardStore.getState());
    const file = Object.assign(new File(["invalid"], "invalid.json"), { text: async () => "invalid" });
    vi.useFakeTimers();
    await act(async () => { fireEvent.change(screen.getByLabelText("Resume JSON plan"), { target: { files: [file] } }); });
    expect(screen.getByRole("alert")).toHaveTextContent("Could not restore this file");
    act(() => { vi.advanceTimersByTime(5000); });
    expect(document.querySelector(".toast")).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Your current workspace is unchanged");
    expect(workspaceSnapshot(useWizardStore.getState())).toEqual(before);
    vi.useRealTimers();
  });

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

  it("a first-run browser restores a JSON plan without a replace-workspace prompt", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    useWizardStore.getState().restart();
    expect(useWizardStore.getState().selectedActor).toBeNull();
    mount();
    const text = JSON.stringify(plan);
    const file = Object.assign(new File([text], "plan.json"), { text: async () => text });
    await act(async () => { fireEvent.change(screen.getByLabelText("Resume JSON plan"), { target: { files: [file] } }); });
    expect(screen.queryByRole("dialog", { name: "Replace this browser workspace?" })).not.toBeInTheDocument();
    await waitFor(() => expect(useWizardStore.getState().selectedActor?.stix_id).toBe(actor.stix_id));
  });

  it("restoring over existing work still asks before replacing it", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    mount();
    await screen.findByRole("button", { name: "Resume Fixture Actor plan" });
    const before = workspaceSnapshot(useWizardStore.getState());
    const text = JSON.stringify(plan);
    const file = Object.assign(new File([text], "plan.json"), { text: async () => text });
    await act(async () => { fireEvent.change(screen.getByLabelText("Resume JSON plan"), { target: { files: [file] } }); });
    expect(await screen.findByRole("dialog", { name: "Replace this browser workspace?" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Cancel restore" }));
    expect(workspaceSnapshot(useWizardStore.getState())).toEqual(before);
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
