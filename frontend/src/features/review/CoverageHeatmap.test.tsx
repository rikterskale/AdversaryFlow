import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Command } from "../../api/contract";
import type { PlanPreview, ScopedTechnique } from "../scope/scopeModel";
import { CoverageHeatmap, coverageStatus } from "./CoverageHeatmap";

const command: Command = {
  platform: "windows", command: "whoami", note: "", cleanup: "", risk: "low",
  side_effects: [], requires_admin: false, requires_network: false, network_targets: [],
  prerequisites: [], expected_telemetry: "Process telemetry", expected_output: "", timeout_seconds: 60,
  rollback: "", cleanup_required: false, acknowledgment_required: false,
};

function scopedTechnique(id: string, source: "curated" | "fallback"): ScopedTechnique {
  return { attack_id: id, name: `${id} technique`, commands: [command], command_source: source, selectedCommand: command };
}

const plan: PlanPreview = {
  stages: [
    { tactic: "execution", title: "Execution", techniques: [scopedTechnique("T1059", "curated")] },
    { tactic: "discovery", title: "Discovery", techniques: [scopedTechnique("T1033", "fallback")] },
  ],
  total: 2, runnable: 2, unsupported: 0, curated: 1, fallback: 1,
};

describe("CoverageHeatmap", () => {
  it("renders tactic columns with source and detection status", () => {
    render(<CoverageHeatmap onSelect={vi.fn()} plan={plan} records={{ T1059: { outcome: "passed", detection_result: "alerted" }, T1033: { outcome: "passed", detection_result: "silent" } }} selectedTechniqueId={null} />);
    expect(screen.getByRole("button", { name: /T1059.*curated coverage.*detected/ })).toHaveClass("status-detected");
    expect(screen.getByRole("button", { name: /T1033.*fallback coverage.*silent/ })).toHaveClass("coverage-fallback");
  });

  it("jumps to the selected technique", () => {
    const onSelect = vi.fn();
    render(<CoverageHeatmap onSelect={onSelect} plan={plan} records={{}} selectedTechniqueId={null} />);
    fireEvent.click(screen.getByRole("button", { name: /T1033/ }));
    expect(onSelect).toHaveBeenCalledWith(1, expect.objectContaining({ attack_id: "T1033" }));
  });

  it("keeps blocked and missing-sensor results distinct from alerted detections", () => {
    expect(coverageStatus({ outcome: "passed", detection_result: "blocked" })).toBe("blocked");
    expect(coverageStatus({ outcome: "passed", detection_result: "not_instrumented" })).toBe("not-instrumented");
    expect(coverageStatus({ outcome: "passed", detection_result: "alerted" })).toBe("detected");
  });
});
