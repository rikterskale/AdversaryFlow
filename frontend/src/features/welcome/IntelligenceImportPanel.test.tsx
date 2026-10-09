import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { IntelligenceImportResponse, ProcedureCandidate } from "../../api/contract";
import { useWizardStore } from "../../state/wizardStore";
import { actor, procedure } from "../../test/remediationFixtures";
import { IntelligenceImportPanel } from "./IntelligenceImportPanel";

beforeEach(() => useWizardStore.getState().restart());
describe("intelligence decisions", () => {
  it("keeps comparison failures visible and permits a corrected retry", async () => {
    const onImport = vi.fn().mockRejectedValue(new Error("CSV needs a technique_id column"));
    render(<IntelligenceImportPanel actors={[actor]} domains={["enterprise"]} csrfToken="fixture" onImport={onImport} onNotice={vi.fn()} onAttachProcedures={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Import and compare" }));
    fireEvent.change(screen.getByLabelText("Structured source"), { target: { files: [new File(["invalid"], "fixture.csv")] } });
    fireEvent.click(screen.getByRole("button", { name: "Compare mappings" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("CSV needs a technique_id column");
    expect(screen.getByRole("button", { name: "Compare mappings" })).toBeEnabled();
    fireEvent.change(screen.getByLabelText("Source URL (optional)"), { target: { value: "http://example.org/report" } });
    fireEvent.click(screen.getByRole("button", { name: "Compare mappings" }));
    expect(screen.getByRole("alert")).toHaveTextContent("complete HTTPS address");
    expect(onImport).toHaveBeenCalledOnce();
  });
  it("F08 Accept -> Attach -> Reject revokes export evidence; reimport and all-rejected remain synchronized", async () => {
    const { actor_stix_id: _actorId, mapping_data_version: _version, ...base } = procedure;
    const candidate: ProcedureCandidate = { ...base, review_status: "needs_review", accepted_by: "", accepted_at: "", reviewed_by: "", reviewed_at: "",
      technique_url: null, technique_known: true, catalog_source: "curated", abilities: [] };
    const result: IntelligenceImportResponse = { schema_version: "1.0", actor, source: { kind: "csv", name: "fixture.csv", url: null, sha256: procedure.source_sha256 },
      data_version: "fixture", comparison: { report_only: [], attack_only: [], both: ["T1033"] }, candidates: [candidate] };
    render(<IntelligenceImportPanel actors={[actor]} domains={["enterprise"]} csrfToken="fixture" onImport={vi.fn().mockResolvedValue(result)}
      onNotice={vi.fn()} onAttachProcedures={(items) => useWizardStore.getState().attachProcedureEvidence(items)} />);
    fireEvent.click(screen.getByRole("button", { name: "Import and compare" }));
    fireEvent.change(screen.getByLabelText("Structured source"), { target: { files: [new File(["technique_id\nT1033"], "fixture.csv")] } });
    fireEvent.click(screen.getByRole("button", { name: "Compare mappings" }));
    await screen.findByLabelText("Reviewer name");
    fireEvent.change(screen.getByLabelText("Reviewer name"), { target: { value: "Reviewer" } });
    fireEvent.click(screen.getByRole("button", { name: "Accept mapping" }));
    expect(useWizardStore.getState().procedureEvidence).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Attach accepted procedures to planning workspace" }));
    expect(useWizardStore.getState().procedureEvidence).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Compare mappings" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Accept mapping" })).toBeDisabled());
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(useWizardStore.getState().procedureEvidence).toEqual([]);
    expect(screen.getByRole("button", { name: "Attach accepted procedures to planning workspace" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Attach accepted procedures to planning workspace" }));
    expect(useWizardStore.getState().procedureEvidence).toEqual([]);
    expect(screen.getByRole("status")).toHaveTextContent("0 procedures currently attached");
  });
});
