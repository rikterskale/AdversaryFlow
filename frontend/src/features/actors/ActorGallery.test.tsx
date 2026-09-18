import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ActorsResponse } from "../../api/contract";
import { ActorGallery } from "./ActorGallery";

const response: ActorsResponse = {
  actors: [
    { stix_id: "intrusion-set--one", attack_id: "G0001", name: "Alpha Group", type: "group", aliases: ["First"], description: "[Alpha](https://example.test) fixture. (Citation: Example)", technique_count: 2 },
    { stix_id: "campaign--two", attack_id: "C0002", name: "Beta Campaign", type: "campaign", aliases: ["Second"], description: "Campaign fixture", technique_count: 8 },
  ],
  domains: ["enterprise"],
  data_version: "enterprise:fixture",
  version: "1.0.0",
};

function renderGallery(overrides: Partial<React.ComponentProps<typeof ActorGallery>> = {}): void {
  render(
    <ActorGallery
      domains={["enterprise"]}
      error={null}
      loading={false}
      onContinue={vi.fn()}
      onDomainsChange={vi.fn()}
      onNotice={vi.fn()}
      onRetry={vi.fn()}
      onSelect={vi.fn()}
      response={response}
      selectedActor={null}
      {...overrides}
    />,
  );
}

describe("ActorGallery", () => {
  it("searches actor names and strips source markdown from summaries", () => {
    renderGallery();

    expect(screen.getByText("Alpha fixture.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search actors"), { target: { value: "Second" } });
    expect(screen.getByRole("button", { name: /Beta Campaign/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Alpha Group/ })).not.toBeInTheDocument();
  });

  it("requires an actor before continuing", () => {
    renderGallery();
    expect(screen.getByRole("button", { name: /Continue to scope/ })).toBeDisabled();
    expect(screen.getByText("Select a threat actor to continue")).toBeInTheDocument();
  });

  it("prevents clearing the final ATT&CK domain", () => {
    const onNotice = vi.fn();
    const onDomainsChange = vi.fn();
    renderGallery({ onNotice, onDomainsChange });
    fireEvent.click(screen.getByRole("button", { name: "Enterprise" }));
    expect(onNotice).toHaveBeenCalledWith("Keep at least one ATT&CK domain selected.");
    expect(onDomainsChange).not.toHaveBeenCalled();
  });

  it("opts into an additional domain without dropping Enterprise", () => {
    const onDomainsChange = vi.fn();
    renderGallery({ onDomainsChange });
    fireEvent.click(screen.getByRole("button", { name: "ICS / OT" }));
    expect(onDomainsChange).toHaveBeenCalledWith(["enterprise", "ics"]);
  });

  it("filters groups and campaigns and explains a type-only empty result", () => {
    renderGallery();
    fireEvent.click(screen.getByRole("button", { name: "Groups" }));
    expect(screen.getByRole("button", { name: /Alpha Group/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Beta Campaign/ })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search actors"), { target: { value: "Beta" } });
    expect(screen.getByRole("heading", { name: "No actors match the active filters." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  });

  it("selects an actor and continues with the selected record", () => {
    const onSelect = vi.fn();
    const onContinue = vi.fn();
    renderGallery({ onContinue, onSelect, selectedActor: response.actors[0] });

    expect(screen.getByRole("button", { name: /Select Alpha Group/ })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByRole("button", { name: /Select Beta Campaign/ }));
    expect(onSelect).toHaveBeenCalledWith(response.actors[1]);
    fireEvent.click(screen.getByRole("button", { name: /Continue to scope/ }));
    expect(onContinue).toHaveBeenCalledOnce();
  });

  it("uses a catalog-specific recovery action", () => {
    const onRetry = vi.fn();
    renderGallery({ error: new Error("Catalog unavailable"), onRetry, response: null });
    fireEvent.click(screen.getByRole("button", { name: "Retry catalog" }));
    expect(onRetry).toHaveBeenCalledOnce();
  });
});
