import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { actor, scope, workflow } from "../../test/remediationFixtures";
import { buildExportBundle } from "../export/exportModel";
import { SavedEngagements } from "./SavedEngagements";

afterEach(() => { vi.unstubAllGlobals(); });
const json = (body: unknown): Response => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
function mount(onRestore = vi.fn()): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<QueryClientProvider client={client}><SavedEngagements onNotice={vi.fn()} onRestore={onRestore} /></QueryClientProvider>);
  fireEvent.click(screen.getByRole("button", { name: "Browse saved engagements" }));
}

describe("saved engagement browser", () => {
  it("browses older engagements past the first 200 and returns to the latest page", async () => {
    const fetchMock = vi.fn().mockImplementation(async (path: string) => path.endsWith("offset=200")
      ? json({ engagements: [{ id: "old-record", actor_name: "Older Actor", revision: 1, data_version: "fixture" }], next_offset: null })
      : json({ engagements: Array.from({ length: 200 }, (_, index) => ({ id: `saved-${index}`, actor_name: `Actor ${index}`, revision: 1, data_version: "fixture" })), next_offset: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    mount();
    fireEvent.click(await screen.findByRole("button", { name: "Older engagements" }));
    expect(await screen.findByRole("button", { name: /Older Actor · revision 1/ })).toBeVisible();
    expect(screen.getByRole("button", { name: "Older engagements" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Newer engagements" }));
    expect(await screen.findByRole("button", { name: /Actor 0 · revision 1/ })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith("/api/engagements?limit=200&offset=200", expect.anything());
  });

  it("refreshes the selected engagement's revision menu along with the list", async () => {
    let revision = 1;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => path.includes("?")
      ? json({ engagements: [{ id: "saved-1", actor_name: actor.name, revision, data_version: "fixture" }] })
      : json({ id: "saved-1", revisions: [{ revision, plan_sha256: "a".repeat(64) }] })));
    mount();
    fireEvent.click(await screen.findByRole("button", { name: /Fixture Actor · revision 1/ }));
    await screen.findByRole("option", { name: /Revision 1/ });
    revision = 2;
    fireEvent.click(screen.getByRole("button", { name: "Refresh saved engagements" }));
    await screen.findByRole("button", { name: /Fixture Actor · revision 2/ });
    expect(await screen.findByRole("option", { name: /Revision 2/ })).toBeInTheDocument();
  });
  it("F05 works from a fresh browser, exposes revisions and returns the selected server identity for append", async () => {
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan;
    const onRestore = vi.fn();
    const requests: string[] = [];
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      requests.push(path);
      if (path.includes("?")) return json({ engagements: [{ id: "saved-1", actor_name: actor.name, revision: 2, data_version: "fixture" }] });
      if (path.endsWith("/saved-1")) return json({ id: "saved-1", revisions: [{ revision: 2, plan_sha256: "b".repeat(64) }, { revision: 1, plan_sha256: "a".repeat(64) }] });
      return json({ engagement_id: "saved-1", revision: 1, plan_sha256: "a".repeat(64), created_at: plan.generated, plan });
    }));
    mount(onRestore);
    fireEvent.click(await screen.findByRole("button", { name: /Fixture Actor · revision 2/ }));
    const select = await screen.findByLabelText("Saved engagement revision");
    fireEvent.change(select, { target: { value: "1" } });
    fireEvent.click(await screen.findByRole("button", { name: "Restore selected revision" }));
    expect(onRestore).toHaveBeenCalledWith(expect.objectContaining({ engagement_id: "saved-1", revision: 1, plan }));
    expect(requests).toContain("/api/engagements/saved-1/revisions/1");
    expect(screen.getByRole("button", { name: "Download selected revision" })).toBeEnabled();
  });
  it("F05 validates responses, provides retry and shows the empty state", async () => {
    const fetchMock = vi.fn().mockImplementationOnce(async () => json({ engagements: [{ id: null }] }))
      .mockImplementation(async () => json({ engagements: [] }));
    vi.stubGlobal("fetch", fetchMock);
    mount();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("invalid"));
    fireEvent.click(screen.getByRole("button", { name: "Retry saved engagements" }));
    expect(await screen.findByText("No saved engagements yet.")).toBeVisible();
  });
});
