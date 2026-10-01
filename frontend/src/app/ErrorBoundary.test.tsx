import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { WIZARD_STORAGE_KEY } from "../state/wizardStore";
import { ErrorBoundary } from "./ErrorBoundary";

function Broken(): React.JSX.Element { throw new Error("Corrupt workspace fixture"); }
afterEach(() => vi.restoreAllMocks());

describe("interface recovery", () => {
  it("preserves browser evidence and requires a recovery download before reset", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    localStorage.setItem(WIZARD_STORAGE_KEY, '{"state":{"records":{"T1033":{"outcome":"passed"}}}}');
    const createUrl = vi.fn().mockReturnValue("blob:recovery");
    vi.stubGlobal("URL", { createObjectURL: createUrl, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<ErrorBoundary><Broken /></ErrorBoundary>);
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Download recovery copy" }));
    expect(createUrl).toHaveBeenCalledWith(expect.any(Blob));
    expect(click).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeEnabled();
    expect(localStorage.getItem(WIZARD_STORAGE_KEY)).toContain("T1033");
    vi.unstubAllGlobals();
  });

  it("keeps reset disabled when the browser cannot read the saved evidence", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("storage blocked"); });
    render(<ErrorBoundary><Broken /></ErrorBoundary>);
    fireEvent.click(screen.getByRole("button", { name: "Download recovery copy" }));
    expect(screen.getByRole("alert")).toHaveTextContent("could not save a recovery copy");
    expect(screen.getByRole("button", { name: "Reset browser workspace" })).toBeDisabled();
  });
});
