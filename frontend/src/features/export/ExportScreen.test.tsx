import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Actor, Command, WorkflowResponse } from "../../api/contract";
import { useWizardStore } from "../../state/wizardStore";
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
    <ExportScreen
      actor={actor}
      csrfToken="csrf-fixture"
      domains={["enterprise"]}
      onBack={vi.fn()}
      onNotice={vi.fn()}
      onRestart={vi.fn()}
      workflow={workflow}
    />,
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
});
