import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildExportBundle, executiveSummary } from "../features/export/exportModel";
import { validateImportedPlan } from "../features/export/planContract";
import { isMarkedRun, isRecorded, normalizeReferences, referenceError } from "../features/review/evidence";
import { buildPlanPreview } from "../features/scope/scopeModel";
import { actor, command, procedure, scope, workflow } from "../test/remediationFixtures";
import { evidenceIdentity, useStorageHealth, useWizardStore, workspaceSnapshot } from "./wizardStore";
import { createRecoveryCopy, parseWorkspaceFile } from "./workspaceRecovery";
import { boundedJson, PLAN_MAX_BYTES, requireByteLimit, utf8Bytes } from "./workspaceIO";

beforeEach(() => {
  useWizardStore.getState().restart();
  useWizardStore.getState().selectActor(actor);
  useWizardStore.getState().updateScope(scope);
  useWizardStore.getState().ensureEvidenceKey(evidenceIdentity(actor.stix_id, workflow, "windows"), workflow);
});
afterEach(() => vi.restoreAllMocks());

describe("all13 workspace regressions", () => {
  it("F02 tracks failures for scope, workflow, import and archives across re-entry; only a successful write clears the warning", () => {
    const fail = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Quota exceeded"); });
    useWizardStore.getState().updateScope({ target: "unsaved" });
    expect(useStorageHealth.getState().status).toBe("failed");
    useWizardStore.getState().ensureEvidenceKey("another-key", workflow);
    useWizardStore.getState().importPlan(buildExportBundle(actor, workflow, scope, {}, ["enterprise"]).plan);
    expect(useStorageHealth.getState().status).toBe("failed");
    useWizardStore.getState().setStep(0);
    expect(useStorageHealth.getState().message).toContain("download");
    fail.mockRestore();
    useWizardStore.getState().updateScope({ target: "durable" });
    expect(useStorageHealth.getState().status).toBe("saved");
  });

  it.each([-1, 0, 1])("F03 enforces the exact UTF-8 plan boundary %i", (offset) => {
    const value = "a".repeat(PLAN_MAX_BYTES + offset - 6) + "李雷";
    expect(utf8Bytes(value)).toBe(PLAN_MAX_BYTES + offset);
    if (offset <= 0) expect(() => requireByteLimit(value, PLAN_MAX_BYTES, "Plan")).not.toThrow();
    else expect(() => requireByteLimit(value, PLAN_MAX_BYTES, "Plan")).toThrow("UTF-8");
  });

  it("F03 roundtrips a representative 1400-procedure schema3 plan larger than the old 5MiB limit", async () => {
    const procedures = Array.from({ length: 1400 }, (_, index) => ({ ...procedure, candidate_id: `candidate-${index}`,
      evidence_quote: "李".repeat(2000), procedure: "x".repeat(2000) }));
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"], procedures).plan;
    validateImportedPlan(plan);
    const text = boundedJson(plan);
    expect(utf8Bytes(text)).toBeGreaterThan(5 * 1024 * 1024);
    const parsed = await parseWorkspaceFile(text);
    expect(parsed.kind).toBe("plan");
    if (parsed.kind === "plan") expect(parsed.plan.procedures).toEqual(procedures);
    const compactOnly = boundedJson({ a: "x".repeat(100) }, 110);
    expect(compactOnly).toBe(JSON.stringify({ a: "x".repeat(100) }));
  });

  it("F04 roundtrips workflow, archive, evidence, drafts, settings and server identity; accepts original wrapper", async () => {
    const store = useWizardStore.getState();
    store.updateEvidence("T1033", { outcome: "passed", operator: "Alice", telemetry_refs_draft: "x".repeat(501) });
    store.updateScope({ commandPlatform: "linux" });
    store.attachProcedureEvidence([procedure]);
    store.setEngagementRecord("engagement-fixture", 2);
    const snapshot = workspaceSnapshot(useWizardStore.getState());
    for (const text of [createRecoveryCopy(), JSON.stringify({ saved_workspace: JSON.stringify({ state: snapshot, version: 0 }), captured_at: new Date().toISOString() })]) {
      const parsed = await parseWorkspaceFile(text);
      expect(parsed.kind).toBe("workspace");
      if (parsed.kind === "workspace") {
        expect(parsed.workspace.engagementRevision).toBe(2);
        expect(parsed.workspace.procedureEvidence).toEqual([procedure]);
        expect(Object.values(parsed.workspace.evidenceArchive)[0]?.records.T1033?.telemetry_refs_draft).toHaveLength(501);
        expect(parsed.workspace.savedWorkflow?.stages[0]?.techniques[0]?.commands[0]?.untrusted).toBe(true);
      }
    }
  });

  it("F04 rejects malformed and unsafe recovery without mutating the workspace", async () => {
    const before = workspaceSnapshot(useWizardStore.getState());
    await expect(parseWorkspaceFile('{"saved_workspace":"broken","captured_at":"2026-10-06T20:00:00Z"}')).rejects.toThrow("malformed");
    await expect(parseWorkspaceFile('{"recovery_version":"1.0","tool":"AdversaryFlow","workspace":{"__proto__":{}}}')).rejects.toThrow("unsafe");
    const bad = JSON.parse(createRecoveryCopy()) as { workspace: { scope: { allowHighRisk: unknown } } };
    bad.workspace.scope.allowHighRisk = "yes";
    await expect(parseWorkspaceFile(JSON.stringify(bad))).rejects.toThrow("scope");
    expect(workspaceSnapshot(useWizardStore.getState())).toEqual(before);
  });

  it("F06 keeps restricted imports withheld until explicit catalog reload; exact platform gaps remain blocked", () => {
    const risky = { ...workflow, stages: [{ ...workflow.stages[0]!, techniques: [
      { ...workflow.stages[0]!.techniques[0]!, commands: [{ ...command, risk: "high" as const }] },
      { ...workflow.stages[0]!.techniques[1]!, commands: [{ ...command, platform: "linux" }] },
    ] }] };
    const plan = buildExportBundle(actor, risky, scope, { T1033: { outcome: "passed", operator: "Alice" } }, ["enterprise"], [procedure]).plan;
    const store = useWizardStore.getState();
    store.importPlan(plan);
    store.updateScope({ allowHighRisk: true });
    expect(buildPlanPreview(useWizardStore.getState().importedWorkflow!, useWizardStore.getState().scope).runnable).toBe(0);
    store.reloadCatalog(risky);
    const preview = buildPlanPreview(useWizardStore.getState().importedWorkflow!, useWizardStore.getState().scope);
    expect(preview.runnable).toBe(1);
    expect(preview.stages[0]?.techniques[0]?.selectedCommand.command).toBe("whoami");
    expect(preview.stages[0]?.techniques[1]?.selectedCommand.unsupported).toBe(true);
    expect(useWizardStore.getState().records.T1033?.operator).toBe("Alice");
    expect(useWizardStore.getState().procedureEvidence).toEqual([procedure]);
    expect(Object.values(useWizardStore.getState().evidenceArchive).some((item) => item.workflow?.stages[0]?.techniques[0]?.commands[0]?.restricted)).toBe(true);
    expect(() => store.reloadCatalog({ ...risky, actor: { stix_id: "different" } })).toThrow("identity");
  });

  it("F07 keeps two actors for the same source/candidate and exports only the matching actor", () => {
    const second = { ...procedure, actor_stix_id: "intrusion-set--second" };
    useWizardStore.getState().attachProcedureEvidence([procedure, second, procedure]);
    expect(useWizardStore.getState().procedureEvidence).toHaveLength(2);
    const plan = buildExportBundle(actor, workflow, scope, {}, ["enterprise"], useWizardStore.getState().procedureEvidence).plan;
    expect(plan.procedures).toEqual([procedure]);
    validateImportedPlan(plan);
  });

  it("F08 revokes only the rejected actor/source attachment including archived copies", () => {
    const unrelated = { ...procedure, candidate_id: "other", source_sha256: "b".repeat(64) };
    const otherActor = { ...procedure, actor_stix_id: "intrusion-set--second" };
    const store = useWizardStore.getState();
    store.attachProcedureEvidence([procedure, unrelated, otherActor]);
    store.updateEvidence("T1033", { outcome: "passed" }); store.updateScope({ commandPlatform: "linux" });
    store.revokeProcedures(actor.stix_id, procedure.source_sha256, [procedure.candidate_id]);
    expect(useWizardStore.getState().procedureEvidence).toEqual([unrelated, otherActor]);
    expect(Object.values(useWizardStore.getState().evidenceArchive)[0]?.procedureEvidence).toEqual([unrelated]);
  });

  it.each([{ notes: "Updated note" }, { detection_result: "alerted" as const }, { cleanup_completed: true }])("F09 preserves execution attribution on edit %j", (patch) => {
    const store = useWizardStore.getState();
    store.importPlan(buildExportBundle(actor, workflow, { ...scope, operator: "Bob", target: "current-host" },
      { T1033: { outcome: "passed", operator: "Alice", target: "original-host" } }, ["enterprise"]).plan);
    store.updateEvidence("T1033", patch);
    expect(useWizardStore.getState().records.T1033).toMatchObject({ operator: "Alice", target: "original-host" });
    store.updateEvidence("T1033", { operator: "", target: "" }); store.updateEvidence("T1033", patch);
    expect(useWizardStore.getState().records.T1033).toMatchObject({ operator: "", target: "" });
    store.updateEvidence("T1110", { notes: "New" });
    expect(useWizardStore.getState().records.T1110).toMatchObject({ operator: "Bob", target: "current-host" });
    store.updateEvidence("T1059.001", patch);
    expect(useWizardStore.getState().records["T1059.001"]?.operator).toBeUndefined();
    expect(useWizardStore.getState().records["T1059.001"]?.target).toBeUndefined();
  });

  it("F10 validates 20/21 references, 500/501 Unicode characters, deduplication and draft recovery without loss", async () => {
    expect(referenceError(Array.from({ length: 20 }, (_, i) => String(i)))).toBeNull();
    expect(referenceError(Array.from({ length: 21 }, (_, i) => String(i)))).toContain("20");
    expect(referenceError(["🔍".repeat(500)])).toBeNull();
    expect(referenceError(["李".repeat(501)])).toContain("500");
    expect(normalizeReferences("one\none, two\n")).toEqual(["one", "two"]);
    useWizardStore.getState().updateEvidence("T1033", { telemetry_refs_draft: "李".repeat(501), telemetry_refs: ["previous"] });
    const parsed = await parseWorkspaceFile(createRecoveryCopy());
    if (parsed.kind === "workspace") expect(parsed.workspace.records.T1033?.telemetry_refs_draft).toHaveLength(501);
    const plan = buildExportBundle(actor, workflow, scope, useWizardStore.getState().records, ["enterprise"]).plan;
    expect(plan.stages[0]?.techniques[0]?.execution.telemetry_refs).toEqual(["李".repeat(501)]);
    expect(() => validateImportedPlan(plan)).toThrow("execution");
  });

  it("F11 counts all-skipped as zero executed; mixed results and roundtrip remain truthful", async () => {
    expect(isMarkedRun({ outcome: "skipped" })).toBe(false);
    expect(isRecorded({ outcome: "skipped" })).toBe(true);
    const skipped = { T1033: { outcome: "skipped" as const }, "T1059.001": { outcome: "skipped" as const } };
    const bundle = buildExportBundle(actor, workflow, scope, skipped, ["enterprise"]);
    expect(bundle.plan.summary.marked_run).toEqual([]);
    expect(bundle.plan.stages[0]?.techniques.every((item) => !item.run)).toBe(true);
    expect(executiveSummary(bundle)).toContain("0 executed, 2 skipped");
    const mixed = buildExportBundle(actor, workflow, scope, { ...skipped, T1033: { outcome: "failed" } }, ["enterprise"]);
    expect(mixed.plan.summary.marked_run).toEqual(["T1033"]);
    const parsed = await parseWorkspaceFile(boundedJson(mixed.plan));
    expect(parsed.kind).toBe("plan");
    if (parsed.kind === "plan") expect(parsed.plan.summary.marked_run).toEqual(["T1033"]);
  });
});
