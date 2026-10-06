import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useWizardStore, WIZARD_STORAGE_KEY } from "../state/wizardStore";
import { parseWorkspaceFile } from "../state/workspaceRecovery";
import { ErrorBoundary } from "./ErrorBoundary";

function Broken(): React.JSX.Element { throw new Error("Corrupt workspace fixture"); }
afterEach(() => vi.restoreAllMocks());

describe("interface recovery", () => {
  it("roundtrips the actual boundary file and requires explicit saved-file confirmation before reset", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    useWizardStore.getState().restart();
    useWizardStore.getState().updateEvidence("T1033", { outcome: "passed", notes: "Recovered evidence" });
    const createUrl = vi.fn().mockReturnValue("blob:recovery");
    vi.stubGlobal("URL", { createObjectURL: createUrl, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<ErrorBoundary><Broken /></ErrorBoundary>);
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Download recovery copy" }));
    expect(createUrl).toHaveBeenCalledWith(expect.any(Blob));
    expect(click).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeDisabled();
    const blob = createUrl.mock.calls[0]?.[0] as Blob;
    const text = await new Promise<string>((resolve) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(blob); });
    const recovered = await parseWorkspaceFile(text);
    expect(recovered.kind).toBe("workspace");
    if (recovered.kind === "workspace") expect(recovered.workspace.records.T1033?.notes).toBe("Recovered evidence");
    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeEnabled();
    expect(localStorage.getItem(WIZARD_STORAGE_KEY)).toContain("T1033");
    vi.unstubAllGlobals();
  });

  it("can recover in-memory evidence when browser storage is denied, but still requires confirmation", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("storage blocked"); });
    vi.stubGlobal("URL", { createObjectURL: vi.fn().mockReturnValue("blob:recovery"), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<ErrorBoundary><Broken /></ErrorBoundary>);
    fireEvent.click(screen.getByRole("button", { name: "Download recovery copy" }));
    expect(screen.getByRole("checkbox")).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeDisabled();
    vi.unstubAllGlobals();
  });
});
