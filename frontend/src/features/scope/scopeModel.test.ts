import { describe, expect, it } from "vitest";

import type { Command, Technique, WorkflowResponse } from "../../api/contract";
import { buildPlanPreview, defaultScope, resolveCommand, type ScopeSettings } from "./scopeModel";

const baseCommand: Command = {
  platform: "windows",
  command: "whoami",
  note: "Read-only identity check.",
  cleanup: "",
  risk: "low",
  side_effects: ["read_only_or_process_telemetry"],
  requires_admin: false,
  requires_network: false,
  network_targets: [],
  prerequisites: ["authorized disposable lab"],
  expected_telemetry: "Process telemetry.",
  expected_output: "Current user identity.",
  timeout_seconds: 60,
  rollback: "",
  cleanup_required: false,
  acknowledgment_required: false,
};

function technique(overrides: Partial<Technique> = {}): Technique {
  return {
    attack_id: "T1033",
    name: "System Owner/User Discovery",
    commands: [baseCommand],
    command_source: "curated",
    ...overrides,
  };
}

function workflow(techniques: Technique[] = [technique()]): WorkflowResponse {
  return {
    actor: {},
    summary: {},
    kill_chain: [
      { tactic: "reconnaissance", title: "Reconnaissance" },
      { tactic: "execution", title: "Execution" },
    ],
    stages: [
      { tactic: "reconnaissance", title: "Reconnaissance", techniques: [technique({ attack_id: "T1595", name: "Active Scanning" })] },
      { tactic: "execution", title: "Execution", techniques },
    ],
    metadata: { domains: ["enterprise"], data_version: "enterprise:fixture", version: "1.0.0" },
  };
}

function scope(overrides: Partial<ScopeSettings> = {}): ScopeSettings {
  return { ...defaultScope(), commandPlatform: "windows", tactics: ["reconnaissance", "execution"], ...overrides };
}

describe("scopeModel", () => {
  it("never substitutes a command from another platform", () => {
    const selected = resolveCommand(technique(), scope({ commandPlatform: "linux" }));
    expect(selected).toMatchObject({ unsupported: true, platform: "linux" });
    expect(selected.command).toBe("No Linux test is available for this technique.");
  });

  it("withholds commands until every required guardrail is enabled", () => {
    const risky = technique({ commands: [{ ...baseCommand, risk: "high", requires_admin: true, requires_network: true }] });
    const blocked = resolveCommand(risky, scope());
    expect(blocked).toMatchObject({ restricted: true, unsupported: true });
    expect(blocked.command).toContain("network-active commands are disabled");
    expect(blocked.command).toContain("administrator commands are disabled");
    expect(blocked.command).toContain("high-risk commands are disabled");

    const allowed = resolveCommand(risky, scope({ allowNetwork: true, allowAdmin: true, allowHighRisk: true }));
    expect(allowed.command).toBe("whoami");
    expect(allowed.unsupported).not.toBe(true);
  });

  it("updates the live preview for pre-compromise and curated-only filters", () => {
    const mixed = workflow([
      technique(),
      technique({ attack_id: "T1059", name: "Command and Scripting Interpreter", command_source: "fallback" }),
    ]);
    const preview = buildPlanPreview(mixed, scope({ includePre: false, curatedOnly: true }));
    expect(preview).toMatchObject({ total: 1, runnable: 1, unsupported: 0, curated: 1, fallback: 0, filteredFallback: 1 });
    expect(preview.stages.map((stage) => stage.tactic)).toEqual(["execution"]);
  });

  it("explains every reason a scoped technique is withheld", () => {
    const risky = technique({
      attack_id: "T1001",
      commands: [{ ...baseCommand, risk: "high", requires_admin: true, requires_network: true }],
    });
    const wrongPlatform = technique({
      attack_id: "T1002",
      commands: [{ ...baseCommand, platform: "linux" }],
    });
    const catalogUnsupported = technique({
      attack_id: "T1003",
      commands: [{ ...baseCommand, unsupported: true }],
    });
    const filteredFallback = technique({ attack_id: "T1004", command_source: "fallback" });

    const preview = buildPlanPreview(
      workflow([risky, wrongPlatform, catalogUnsupported, filteredFallback]),
      scope({ tactics: ["execution"], curatedOnly: true }),
    );

    expect(preview).toMatchObject({ total: 3, runnable: 0, unsupported: 3, filteredFallback: 1 });
    expect(preview.withheld).toEqual({ platform: 1, network: 1, admin: 1, highRisk: 1, catalog: 1 });
  });
});
