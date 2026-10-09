import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Actor, Command, WorkflowResponse } from "../../api/contract";
import { evidenceIdentity, useWizardStore } from "../../state/wizardStore";
import { ExportScreen } from "./ExportScreen";

const actor: Actor = {
  stix_id: "intrusion-set--test",
  attack_id: "G0001",
  name: "Test Actor",
  type: "group",
  aliases: ["Fixture"],
  description: "Fixture actor",
  technique_count: 1,
};

const command: Command = {
  platform: "windows",
  command: "whoami",
  note: "Identity check",
  cleanup: "",
  risk: "low",
  side_effects: [],
  requires_admin: false,
  requires_network: false,
  network_targets: [],
  prerequisites: ["Authorized lab"],
  expected_telemetry: "Process telemetry",
  expected_output: "Identity",
  timeout_seconds: 60,
  rollback: "",
  cleanup_required: false,
  acknowledgment_required: false,
};

const workflow: WorkflowResponse = {
  actor: {},
  summary: {},
  kill_chain: [{ tactic: "execution", title: "Execution" }],
  stages: [{
    tactic: "execution",
    title: "Execution",
    techniques: [{
      attack_id: "T1033",
      name: "System Owner/User Discovery",
      commands: [command],
      command_source: "curated",
      tactics: ["execution"],
      platforms: ["Windows"],
      data_sources: ["Process: Process Creation"],
      detection: "Review process creation telemetry.",
    }],
  }],
  metadata: { domains: ["enterprise"], data_version: "enterprise:fixture", version: "0.4.0" },
};

function renderScreen(): void {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ExportScreen
        actor={actor}
        csrfToken="csrf-fixture"
        domains={["enterprise"]}
        onBack={vi.fn()}
        onNotice={vi.fn()}
        onRestart={vi.fn()}
        workflow={workflow}
      />
    </QueryClientProvider>,
  );
}

describe("ExportScreen report generation", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    useWizardStore.getState().restart();
    useWizardStore.setState((state) => ({
      scope: {
        ...state.scope,
        commandPlatform: "windows",
        tactics: ["execution"],
        operator: "Purple Team",
        target: "lab-host-01",
      },
      records: { T1033: { outcome: "passed", detection_result: "alerted" } },
    }));
    vi.restoreAllMocks();
  });

  it("shows an explicit empty state before generation", () => {
    renderScreen();

    expect(screen.getByText("No report generated yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate report" })).toBeEnabled();
    expect(screen.queryByTitle("Engagement report preview")).not.toBeInTheDocument();
  });

  it.each([
    ["Download Windows execution kit", "Execution kit"],
    ["Atomic Red Team draft + gap backlog", "Atomic export"],
    ["Save engagement", "Engagement save"],
    ["Manage ability backlog", "Ability backlog"],
  ])("keeps %s failures visible beside enabled retry actions", async (button, action) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ message: "Service unavailable; retry after reconnecting" }), {
      status: 503, headers: { "Content-Type": "application/json" },
    })));
    renderScreen();
    const control = screen.getByRole("button", { name: new RegExp(button.replace("+", "\\+")) });
    fireEvent.click(control);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(`${action} needs attention`));
    expect(screen.getByRole("alert")).toHaveTextContent("Service unavailable");
    expect(control).toBeEnabled();
  });

  it("clears a failed engagement save after a successful retry", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ message: "Database unavailable" }), {
      status: 503, headers: { "Content-Type": "application/json" },
    })).mockResolvedValue(new Response(JSON.stringify({ engagement_id: "current-plan", revision: 1, plan_sha256: "a".repeat(64), created_at: "2026-10-09T00:00:00Z" }), {
      status: 201, headers: { "Content-Type": "application/json" },
    })));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Save engagement" }));
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Save engagement" }));
    await screen.findByRole("button", { name: "Save new revision" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("loads backlog pages beyond 200 without dropping edits to already loaded rows", async () => {
    const item = (index: number) => ({ id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`, technique_id: `T${1000 + index}`,
      platform: "windows", gap: "not_accepted", reason: "Review required", ability_id: null, procedure_candidate_ids: [], owner: null, status: "open",
      created_at: "2026-10-09T00:00:00Z", updated_at: "2026-10-09T00:00:00Z" });
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => new Response(JSON.stringify(path.endsWith("offset=200")
      ? { items: [item(200)], next_offset: null }
      : { items: Array.from({ length: 200 }, (_, index) => item(index)), next_offset: 200 }), { headers: { "Content-Type": "application/json" } })));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Manage ability backlog" }));
    const more = await screen.findByRole("button", { name: "Load more backlog items" });
    fireEvent.change(screen.getAllByLabelText("Owner")[0]!, { target: { value: "Draft owner" } });
    fireEvent.click(more);
    await waitFor(() => expect(screen.getAllByLabelText("Owner")).toHaveLength(201));
    expect(screen.getAllByLabelText("Owner")[0]).toHaveValue("Draft owner");
    expect(screen.queryByRole("button", { name: "Load more backlog items" })).not.toBeInTheDocument();
  });

  it("shows an actionable error for malformed backlog responses instead of crashing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [{}] }), { headers: { "Content-Type": "application/json" } })));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Manage ability backlog" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("invalid ability backlog item"));
    expect(screen.getByRole("button", { name: "Manage ability backlog" })).toBeEnabled();
  });

  it("preserves later backlog edits when an earlier save response arrives", async () => {
    const item = { id: "00000000-0000-4000-8000-000000000001", technique_id: "T1033", platform: "windows", gap: "not_accepted",
      reason: "Review required", ability_id: null, procedure_candidate_ids: [], owner: null, status: "open",
      created_at: "2026-10-09T00:00:00Z", updated_at: "2026-10-09T00:00:00Z" };
    let finishSave: ((response: Response) => void) | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (_path: string, init: RequestInit) => init.method === "PATCH"
      ? new Promise<Response>((resolve) => { finishSave = resolve; })
      : new Response(JSON.stringify({ items: [item], next_offset: null }), { headers: { "Content-Type": "application/json" } })));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Manage ability backlog" }));
    const owner = await screen.findByLabelText("Owner");
    const status = screen.getByLabelText("Status");
    fireEvent.change(owner, { target: { value: "First owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.change(owner, { target: { value: "Newer draft owner" } });
    fireEvent.change(status, { target: { value: "in_progress" } });
    finishSave?.(new Response(JSON.stringify({ ...item, owner: "First owner" }), { headers: { "Content-Type": "application/json" } }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save" })).toBeEnabled());
    expect(owner).toHaveValue("Newer draft owner");
    expect(status).toHaveValue("in_progress");
  });

  it("keeps a local JSON download error visible without crashing or losing the plan", async () => {
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => { throw new Error("Download unavailable"); });
    const store = useWizardStore.getState();
    store.selectActor(actor);
    store.updateScope({ commandPlatform: "windows", tactics: ["execution"] });
    store.ensureEvidenceKey(evidenceIdentity(actor.stix_id, workflow, "windows"), workflow);
    store.updateEvidence("T1033", { outcome: "passed" });
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Save JSON plan" }));
    expect(screen.getByRole("alert")).toHaveTextContent("JSON plan download needs attention");
    expect(screen.getByRole("alert")).toHaveTextContent("Download unavailable");
    expect(screen.getByRole("button", { name: "Save JSON plan" })).toBeEnabled();
    expect(useWizardStore.getState().records.T1033?.outcome).toBe("passed");
  });

  it("keeps HTML download failures attached to the ready report so downloading can be retried", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html><body>Report</body></html>")));
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => { throw new Error("Download unavailable"); });
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
    const download = await screen.findByRole("button", { name: "Download HTML engagement report" });
    fireEvent.click(download);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Download unavailable"));
    expect(download).toBeEnabled();
    expect(screen.getByTitle("Engagement report preview")).toBeInTheDocument();
  });

  it("moves from loading to a self-contained preview with all download formats", async () => {
    let resolveResponse: ((response: Response) => void) | undefined;
    const responsePromise = new Promise<Response>((resolve) => { resolveResponse = resolve; });
    const fetchMock = vi.fn().mockReturnValue(responsePromise);
    vi.stubGlobal("fetch", fetchMock);
    renderScreen();

    fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
    expect(screen.getByRole("status")).toHaveTextContent("Generating report preview");

    resolveResponse?.(new Response("<!doctype html><html><body><h1>Fixture report</h1></body></html>", {
      status: 200,
      headers: { "Content-Disposition": 'attachment; filename="AdversaryFlow_fixture_report.html"' },
    }));

    await waitFor(() => expect(screen.getByTitle("Engagement report preview")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("Preview ready");
    expect(screen.getByRole("button", { name: "Download HTML engagement report" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Download PDF engagement report" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Download Schema-versioned JSON" })).toBeEnabled();
    expect(fetchMock).toHaveBeenCalledWith("/api/report/html", expect.objectContaining({ method: "POST" }));
  });

  it("shows an actionable error state and keeps retry available", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: "bad_request",
      message: "Plan evidence is incomplete",
    }), { status: 400, headers: { "Content-Type": "application/json" } })));
    renderScreen();

    fireEvent.click(screen.getByRole("button", { name: "Generate report" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Plan evidence is incomplete"));
    expect(screen.getByRole("button", { name: "Retry report generation" })).toBeEnabled();
    expect(screen.queryByTitle("Engagement report preview")).not.toBeInTheDocument();
  });

  it("does not attach a delayed engagement save to a different plan", async () => {
    useWizardStore.getState().selectActor(actor);
    useWizardStore.getState().updateScope({ commandPlatform: "windows", tactics: ["execution"] });
    let resolveResponse: ((response: Response) => void) | undefined;
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(new Promise<Response>((resolve) => { resolveResponse = resolve; })));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Save engagement" }));
    act(() => { useWizardStore.getState().selectActor({ ...actor, stix_id: "intrusion-set--other", attack_id: "G0002" }); });
    resolveResponse?.(new Response(JSON.stringify({ engagement_id: "old-plan-id", revision: 1, plan_sha256: "a".repeat(64) }), {
      headers: { "Content-Type": "application/json" }, status: 201,
    }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save engagement" })).toBeInTheDocument());
    expect(useWizardStore.getState().engagementId).toBeNull();
  });

  it("F12 cancels a delayed report immediately on evidence edits and keeps regeneration available", async () => {
    let resolveResponse: ((response: Response) => void) | undefined;
    let signal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_path: string, init: RequestInit) => {
      signal = init.signal ?? undefined;
      return new Promise<Response>((resolve) => { resolveResponse = resolve; });
    }));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
    act(() => {
      useWizardStore.getState().updateEvidence("T1033", { notes: "New workspace evidence" });
      expect(signal?.aborted).toBe(true);
      resolveResponse?.(new Response("<html><body>Obsolete report</body></html>"));
    });
    await waitFor(() => expect(screen.getByText("No report generated yet")).toBeVisible());
    expect(screen.queryByTitle("Engagement report preview")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate report" })).toBeEnabled();
  });

  it("stores the engagement ID when the saved workspace is still active", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      engagement_id: "current-plan-id", revision: 1, plan_sha256: "a".repeat(64),
      created_at: "2026-10-06T20:00:00Z",
    }), { headers: { "Content-Type": "application/json" }, status: 201 })));
    renderScreen();
    fireEvent.click(screen.getByRole("button", { name: "Save engagement" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save new revision" })).toBeEnabled());
    expect(useWizardStore.getState().engagementId).toBe("current-plan-id");
  });
});
