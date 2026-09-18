import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Command } from "../../api/contract";
import type { ScopedTechnique } from "../scope/scopeModel";
import { TechniqueCard } from "./TechniqueCard";

const command: Command = {
  platform: "windows", command: "whoami", note: "Read-only identity check.", cleanup: "Remove-Item fixture.txt",
  risk: "medium", side_effects: ["process_telemetry"], requires_admin: true, requires_network: true,
  network_targets: ["lab.example"], prerequisites: ["Authorized disposable lab", "PowerShell"],
  expected_telemetry: "Process creation telemetry", expected_output: "Current user identity", timeout_seconds: 60,
  rollback: "Restore the fixture", cleanup_required: true, acknowledgment_required: false,
};

const technique: ScopedTechnique = {
  attack_id: "T1033", name: "System Owner/User Discovery", commands: [command], command_source: "curated", selectedCommand: command,
};

function renderCard(onUpdate = vi.fn()): void {
  render(<TechniqueCard evidence={undefined} firstLab={false} focused onCopy={vi.fn()} onFocus={vi.fn()} onNotice={vi.fn()} onUpdate={onUpdate} technique={technique} />);
}

describe("TechniqueCard", () => {
  it("shows every contract-backed impact field before the copy action", () => {
    renderCard();
    const preview = screen.getByRole("region", { name: "What this will touch" });
    expect(within(preview).getByText("Medium")).toBeInTheDocument();
    expect(within(preview).getByText("Administrator / root")).toBeInTheDocument();
    expect(within(preview).getByText("lab.example")).toBeInTheDocument();
    expect(within(preview).getByText("Authorized disposable lab; PowerShell")).toBeInTheDocument();
    expect(within(preview).getByText("Restore the fixture")).toBeInTheDocument();
    expect(within(preview).getByText("Remove-Item fixture.txt")).toBeInTheDocument();
  });

  it("records command and detection outcomes independently", () => {
    const onUpdate = vi.fn();
    renderCard(onUpdate);
    fireEvent.change(screen.getByLabelText("Outcome for T1033"), { target: { value: "failed" } });
    fireEvent.change(screen.getByLabelText("Detection for T1033"), { target: { value: "silent" } });
    expect(onUpdate).toHaveBeenNthCalledWith(1, { outcome: "failed" });
    expect(onUpdate).toHaveBeenNthCalledWith(2, { detection_result: "silent" });
  });
});
