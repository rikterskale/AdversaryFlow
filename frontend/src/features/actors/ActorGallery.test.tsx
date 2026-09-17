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
});
