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
  it("can recover a stale selected ID even when only one current variant exists", () => {
    const onSelectCommand = vi.fn();
    const current = { ...command, command_id: "a".repeat(64) };
    const stale = { ...technique, commands: [current], selectedCommand: { ...command, unsupported: true } };
    render(<TechniqueCard evidence={undefined} firstLab={false} focused onCopy={vi.fn()} onFocus={vi.fn()} onNotice={vi.fn()} onUpdate={vi.fn()} onSelectCommand={onSelectCommand} technique={stale} />);
    fireEvent.change(screen.getByRole("combobox", { name: "Command variant for T1033" }), { target: { value: current.command_id } });
    expect(onSelectCommand).toHaveBeenCalledWith(current.command_id);
  });
  it("shows the bounded exercise's technique-specific independent telemetry criteria", () => {
    const bounded = { ...technique, selectedCommand: { ...command, telemetry_acceptance: {
      technique_id: "T1033", requirements: ["Correlate the exact run and technique markers", "Check the same host and time window"],
      activity_event_types: ["process_start"], minimum_activity_events: 2, limitation: "Bounded observation only",
    } } };
    render(<TechniqueCard evidence={undefined} firstLab={false} focused onCopy={vi.fn()} onFocus={vi.fn()} onNotice={vi.fn()} onUpdate={vi.fn()} technique={bounded} />);
    fireEvent.click(screen.getByText("Execution proof"));
    const criteria = screen.getByRole("region", { name: "Independent telemetry requirements for T1033" });
    expect(criteria).toHaveTextContent("at least 2 in the receipt window");
    expect(criteria).toHaveTextContent("process_start");
    expect(criteria).toHaveTextContent("Bounded observation only");
  });
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

  it("lets an operator type telemetry references on separate lines", () => {
    const onUpdate = vi.fn();
    renderCard(onUpdate);
    const field = screen.getByLabelText("Telemetry references");
    fireEvent.change(field, { target: { value: "event-1\n" } });
    expect(field).toHaveValue("event-1\n");
    fireEvent.change(field, { target: { value: "event-1\nevent-2" } });
    expect(onUpdate).toHaveBeenLastCalledWith({ telemetry_refs: ["event-1", "event-2"], telemetry_refs_draft: "event-1\nevent-2" });
  });
});
