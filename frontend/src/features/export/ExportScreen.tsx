import { useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { ApiError, apiFetch, responseJson } from "../../api/client";
import { isRecord } from "../../api/guards";
import type { AbilityBacklogItem, AbilityGapStatus, Actor, AttackDomain, WorkflowResponse } from "../../api/contract";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { useWizardStore } from "../../state/wizardStore";
import { useWorkspaceEvidence } from "../../state/useWorkspaceEvidence";
import { buildExportBundle, executiveSummary, platformLabel, summarizeExportReadiness, toMarkdown, toRunbook } from "./exportModel";
import { validateImportedPlan } from "./planContract";
import { boundedJson } from "../../state/workspaceIO";
import { parseEngagementSave } from "../welcome/SavedEngagements";
import { validDateTime } from "../review/evidence";

interface ExportScreenProps {
  actor: Actor;
  workflow: WorkflowResponse;
  domains: AttackDomain[];
  csrfToken: string;
  onBack: () => void;
  onNotice: (message: string) => void;
  onRestart: () => void;
}

type TextFormat = "markdown" | "runbook";
type ReportFormat = "html" | "pdf" | "json";
type ReportPreviewState =
  | { status: "empty" }
  | { status: "loading" }
  | { status: "ready"; html: string; filename: string }
  | { status: "error"; message: string };

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // WebKit starts some downloads asynchronously after the click task.
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function contentDispositionFilename(value: string | null, fallback: string): string {
  const match = value?.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
  if (!match?.[1]) return fallback;
  try {
    return decodeURIComponent(match[1].replace(/^"|"$/g, "")).replace(/^.*[\\/]/, "") || fallback;
  } catch {
    return fallback;
  }
}

function parseBacklogItem(value: unknown): AbilityBacklogItem {
  if (!isRecord(value) || typeof value.id !== "string" || !/^[0-9a-f-]{36}$/i.test(value.id)
      || typeof value.technique_id !== "string" || !/^T\d{4}(?:\.\d{3})?$/.test(value.technique_id)
      || typeof value.platform !== "string" || typeof value.reason !== "string"
      || !["no_ability", "wrong_shape", "out_of_scope", "not_accepted"].includes(String(value.gap))
      || !["open", "in_progress", "accepted", "closed"].includes(String(value.status))
      || (value.owner !== null && typeof value.owner !== "string")
      || (value.ability_id !== null && typeof value.ability_id !== "string")
      || !Array.isArray(value.procedure_candidate_ids) || !value.procedure_candidate_ids.every((id) => typeof id === "string")
      || !validDateTime(value.created_at) || !validDateTime(value.updated_at)) throw new Error("The service returned an invalid ability backlog item. Retry loading the backlog.");
  return value as unknown as AbilityBacklogItem;
}

export function ExportScreen({ actor, workflow, domains, csrfToken, onBack, onNotice, onRestart }: ExportScreenProps): React.JSX.Element {
  const queryClient = useQueryClient();
  const scope = useWizardStore((state) => state.scope);
  const engagementId = useWizardStore((state) => state.engagementId);
  const engagementRevision = useWizardStore((state) => state.engagementRevision);
  const procedureEvidence = useWizardStore((state) => state.procedureEvidence);
  const setEngagementRecord = useWizardStore((state) => state.setEngagementRecord);
  const records = useWorkspaceEvidence(actor, workflow);
  const generation = useWizardStore((state) => state.workspaceGeneration);
  const operation = useRef(new AbortController());
  const operationSignal = (): AbortSignal => operation.current.signal;
  useEffect(() => {
    const controller = new AbortController();
    operation.current = controller;
    setReportPreview({ status: "empty" }); setReportDownloadError(null);
    setActionErrors({});
    const unsubscribe = useWizardStore.subscribe((next, previous) => {
      if (next.workspaceGeneration !== previous.workspaceGeneration || next.scope !== previous.scope
          || next.records !== previous.records || next.procedureEvidence !== previous.procedureEvidence
          || next.selectedActor !== previous.selectedActor || next.savedWorkflow !== previous.savedWorkflow
          || next.importedWorkflow !== previous.importedWorkflow) controller.abort();
    });
    return () => { unsubscribe(); controller.abort(); };
  }, [generation, actor, workflow, scope, records, procedureEvidence]);
  const [kitLoading, setKitLoading] = useState(false);
  const [atomicLoading, setAtomicLoading] = useState(false);
  const [engagementLoading, setEngagementLoading] = useState(false);
  const [backlogOpen, setBacklogOpen] = useState(false);
  const [backlogLoading, setBacklogLoading] = useState(false);
  const [backlogItems, setBacklogItems] = useState<AbilityBacklogItem[]>([]);
  const [backlogNextOffset, setBacklogNextOffset] = useState<number | null>(null);
  const [backlogSaving, setBacklogSaving] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState<ReportFormat | null>(null);
  const [reportPreview, setReportPreview] = useState<ReportPreviewState>({ status: "empty" });
  const [reportDownloadError, setReportDownloadError] = useState<string | null>(null);
  const [restartOpen, setRestartOpen] = useState(false);
  const [actionErrors, setActionErrors] = useState<Record<string, string>>({});
  const clearActionError = (action: string): void => setActionErrors((errors) => Object.fromEntries(Object.entries(errors).filter(([key]) => key !== action)));
  const actionFailed = (action: string, message: string): void => { setActionErrors((errors) => ({ ...errors, [action]: message })); onNotice(message); };
  const bundle = useMemo(() => buildExportBundle(actor, workflow, scope, records, domains, procedureEvidence), [actor, domains, procedureEvidence, records, scope, workflow]);
  const validationError = useMemo(() => {
    try {
      validateImportedPlan(bundle.plan);
      boundedJson(bundle.plan);
      return null;
    } catch (error: unknown) {
      return error instanceof Error ? error.message : "The plan does not match the published export schema.";
    }
  }, [bundle]);
  const exportReady = validationError === null;
  const markedRun = bundle.plan.summary.marked_run.length;
  const platform = platformLabel(scope.commandPlatform);
  const runner = scope.commandPlatform === "windows" ? "PowerShell" : "Bash";
  const hasBoundedExercise = bundle.plan.stages.some((stage) => stage.techniques.some((technique) => technique.supported && technique.command.fidelity === "bounded_synthetic"));
  const readiness = useMemo(() => summarizeExportReadiness(bundle.plan), [bundle]);

  const exportText = (format: TextFormat): void => {
    clearActionError("Planning export");
    try {
      if (validationError) throw new Error(validationError);
      let content: string;
      let filename: string;
      let mime: string;
      if (format === "markdown") {
        content = toMarkdown(bundle);
        filename = `AdversaryFlow_${bundle.slug}.md`;
        mime = "text/markdown";
      } else {
        content = toRunbook(bundle);
        filename = `AdversaryFlow_${bundle.slug}_runbook.${scope.commandPlatform === "windows" ? "cmd" : "sh"}.txt`;
        mime = "text/plain";
      }
      downloadBlob(new Blob([content], { type: `${mime};charset=utf-8` }), filename);
      onNotice(`Exported ${filename}`);
    } catch (error: unknown) {
      actionFailed("Planning export", error instanceof Error ? `Export failed: ${error.message}` : "The export could not be created. Try again.");
    }
  };

  const exportKit = async (): Promise<void> => {
    if (kitLoading || validationError) return;
    clearActionError("Execution kit");
    const signal = operationSignal();
    setKitLoading(true);
    try {
      const response = await apiFetch("/api/execution-kit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify(bundle.plan),
        signal,
      });
      if (!response.ok) await responseJson(response);
      const filename = contentDispositionFilename(response.headers.get("Content-Disposition"), "AdversaryFlow_execution_kit.zip");
      const blob = await response.blob();
      if (signal.aborted) return;
      downloadBlob(blob, filename);
      onNotice(`Execution kit ready: ${filename}`);
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      actionFailed("Execution kit", error instanceof Error ? error.message : "Execution kit generation failed. Check service health and try again.");
    } finally {
      setKitLoading(false);
    }
  };

  const exportAtomicDraft = async (): Promise<void> => {
    if (atomicLoading || validationError || !csrfToken) return;
    clearActionError("Atomic export");
    const signal = operationSignal();
    setAtomicLoading(true);
    try {
      const response = await apiFetch("/api/playbook/atomic", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify(bundle.plan),
        signal,
      });
      if (!response.ok) await responseJson(response);
      const filename = contentDispositionFilename(response.headers.get("Content-Disposition"), "AdversaryFlow_Atomic_Red_Team_draft.zip");
      const included = Number(response.headers.get("X-AdversaryFlow-Atomic-Included") ?? "0");
      const gaps = Number(response.headers.get("X-AdversaryFlow-Atomic-Gaps") ?? "0");
      const blob = await response.blob();
      if (signal.aborted) return;
      downloadBlob(blob, filename);
      onNotice(`Atomic Red Team draft ready · ${included} reviewed tests included · ${gaps} items in the manifest gap backlog`);
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      actionFailed("Atomic export", error instanceof Error ? `Atomic export failed: ${error.message}` : "Atomic playbook generation failed.");
    } finally {
      setAtomicLoading(false);
    }
  };

  const saveEngagement = async (): Promise<void> => {
    if (engagementLoading || validationError || !csrfToken) return;
    clearActionError("Engagement save");
    const workspace = useWizardStore.getState();
    const signal = operationSignal();
    setEngagementLoading(true);
    try {
      const response = await apiFetch("/api/engagements", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify({ plan: bundle.plan, ...(engagementId ? { engagement_id: engagementId } : {}) }),
        signal,
      });
      const saved = parseEngagementSave(await responseJson(response));
      if (signal.aborted) return;
      const current = useWizardStore.getState();
      if (current.workspaceGeneration !== workspace.workspaceGeneration || current.selectedActor?.stix_id !== workspace.selectedActor?.stix_id
          || current.evidenceKey !== workspace.evidenceKey || current.engagementId !== workspace.engagementId) return;
      setEngagementRecord(saved.engagement_id, saved.revision);
      void queryClient.invalidateQueries({ queryKey: ["engagements"] });
      void queryClient.invalidateQueries({ queryKey: ["engagement", saved.engagement_id] });
      const packPin = saved.content_pack_sha256 ? ` · pack set ${saved.content_pack_sha256.slice(0, 12)}` : "";
      onNotice(`Engagement saved · revision ${saved.revision} · plan SHA-256 ${saved.plan_sha256.slice(0, 12)}${packPin}`);
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      actionFailed("Engagement save", error instanceof Error ? `Engagement save failed: ${error.message}` : "The engagement could not be saved.");
    } finally {
      setEngagementLoading(false);
    }
  };

  const loadAbilityBacklog = async (offset = 0): Promise<void> => {
    if (backlogLoading) return;
    clearActionError("Ability backlog");
    const signal = operationSignal();
    setBacklogLoading(true);
    try {
      const response = await apiFetch(`/api/ability-backlog?limit=200&offset=${offset}`, { signal });
      const result = await responseJson(response);
      if (!isRecord(result) || !Array.isArray(result.items) || result.items.length > 200) throw new Error("The service returned an invalid ability backlog. Retry loading the backlog.");
      const items = result.items.map(parseBacklogItem);
      const nextOffset = result.next_offset ?? (result.next_offset === undefined && items.length === 200 ? offset + 200 : null);
      if (nextOffset !== null && (!Number.isSafeInteger(nextOffset) || nextOffset !== offset + items.length || !items.length)) throw new Error("The service returned invalid backlog pagination.");
      if (signal.aborted) return;
      setBacklogItems((previous) => offset ? [...new Map([...previous, ...items].map((item) => [item.id, item])).values()] : items);
      setBacklogNextOffset(nextOffset as number | null);
      setBacklogOpen(true);
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      actionFailed("Ability backlog", error instanceof Error ? error.message : "The ability backlog could not be loaded.");
    } finally {
      setBacklogLoading(false);
    }
  };

  const updateBacklogItem = async (item: AbilityBacklogItem): Promise<void> => {
    if (backlogSaving || !csrfToken) return;
    clearActionError("Backlog save");
    const signal = operationSignal();
    setBacklogSaving(item.id);
    try {
      const response = await apiFetch(`/api/ability-backlog/${encodeURIComponent(item.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify({ owner: item.owner?.trim() || null, status: item.status }),
        signal,
      });
      const updated = parseBacklogItem(await responseJson(response));
      if (updated.id !== item.id) throw new Error("The service returned a different backlog item. Retry saving this item.");
      if (signal.aborted) return;
      setBacklogItems((items) => items.map((current) => current.id === updated.id ? {
        ...updated,
        owner: current.owner === item.owner ? updated.owner : current.owner,
        status: current.status === item.status ? updated.status : current.status,
      } : current));
      onNotice(`Backlog item ${updated.technique_id} updated`);
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      actionFailed("Backlog save", error instanceof Error ? error.message : "The backlog item could not be updated.");
    } finally {
      setBacklogSaving(null);
    }
  };

  const generateReport = async (): Promise<void> => {
    if (reportPreview.status === "loading" || reportLoading || validationError || !csrfToken) return;
    const signal = operationSignal();
    setReportPreview({ status: "loading" });
    setReportDownloadError(null);
    try {
      const response = await apiFetch("/api/report/html", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify(bundle.plan),
        signal,
      });
      if (!response.ok) await responseJson(response);
      const html = await response.text();
      if (signal.aborted) return;
      if (!html.trim()) throw new Error("The service returned an empty HTML report.");
      const fallback = `AdversaryFlow_${bundle.slug}_report.html`;
      const filename = contentDispositionFilename(response.headers.get("Content-Disposition"), fallback);
      setReportPreview({ status: "ready", html, filename });
      onNotice("Engagement report preview ready");
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      const message = error instanceof Error ? error.message : "Report generation failed. Check service health and try again.";
      setReportPreview({ status: "error", message });
      onNotice(message);
    }
  };

  const exportReport = async (format: ReportFormat): Promise<void> => {
    if (reportLoading || validationError || reportPreview.status !== "ready" || !csrfToken) return;
    const signal = operationSignal();
    setReportDownloadError(null);
    setReportLoading(format);
    try {
      if (format === "html") {
        downloadBlob(new Blob([reportPreview.html], { type: "text/html;charset=utf-8" }), reportPreview.filename);
        onNotice(`Engagement report ready: ${reportPreview.filename}`);
        return;
      }
      const response = await apiFetch(`/api/report/${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify(bundle.plan),
        signal,
      });
      if (!response.ok) await responseJson(response);
      const fallback = format === "json"
        ? `AdversaryFlow_${bundle.slug}.json`
        : `AdversaryFlow_${bundle.slug}_report.${format}`;
      const filename = contentDispositionFilename(response.headers.get("Content-Disposition"), fallback);
      const blob = await response.blob();
      if (signal.aborted) return;
      downloadBlob(blob, filename);
      onNotice(`Engagement report ready: ${filename}`);
    } catch (error: unknown) {
      if (signal.aborted || (error instanceof ApiError && error.code === "cancelled")) return;
      const message = error instanceof Error ? error.message : "Report download failed. Check service health and try again.";
      setReportDownloadError(message);
      onNotice(message);
    } finally {
      setReportLoading(null);
    }
  };

  const copySummary = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(executiveSummary(bundle));
      onNotice("Plan summary copied to clipboard");
    } catch {
      onNotice("Clipboard access was denied. Export the Markdown report instead.");
    }
  };

  const saveJsonPlan = (): void => {
    clearActionError("JSON plan download");
    try {
      downloadBlob(new Blob([boundedJson(bundle.plan)], { type: "application/json" }), `AdversaryFlow_${bundle.slug}.json`);
      onNotice("JSON plan download requested. Confirm the file is saved.");
    } catch (error: unknown) {
      actionFailed("JSON plan download", error instanceof Error ? error.message : "JSON download failed. Keep this tab open and retry.");
    }
  };

  return (
    <section aria-busy={kitLoading || atomicLoading || engagementLoading || backlogLoading || Boolean(backlogSaving) || reportPreview.status === "loading" || Boolean(reportLoading)} aria-labelledby="export-title" className="screen export-screen">
      <header className="export-hero">
        <span aria-hidden="true" className={`export-hero__check ${exportReady ? "" : "is-invalid"}`}><Icon name={exportReady ? "check" : "close"} /></span>
        <p className="eyebrow">Step 4 of 4 · Export kit</p>
        <h1 id="export-title">{exportReady ? "Your emulation plan is ready" : "Your plan needs attention"}</h1>
        <p>{actor.name} · {actor.attack_id} · {platform} · {bundle.plan.procedures?.length ?? 0} accepted procedure citations · generated from ATT&amp;CK data <code>{workflow.metadata.data_version}</code></p>
      </header>

      {validationError ? <div className="export-validation" role="alert"><Icon name="shield" /><div><strong>Export is paused</strong><p>{validationError} Return to review or scope, correct the plan, then try again.</p></div></div> : null}
      {Object.entries(actionErrors).map(([action, message]) => <div className="export-validation" key={action} role="alert"><Icon name="close" /><div><strong>{action} needs attention</strong><p>{message}</p><p>Retry using the same action below. You can keep a local backup with Save JSON plan or Download workspace recovery copy.</p></div></div>)}

      <div className="engagement-save-bar">
        <div><strong>{engagementId ? `Server engagement · revision ${engagementRevision}` : "Save an auditable server record"}</strong><span>Stores this plan revision, its ATT&amp;CK data version, and a SHA-256 digest on this service. {bundle.plan.procedures?.length ? `${bundle.plan.procedures.length} accepted procedure citation(s) included.` : "No accepted procedure citations match this actor."} {bundle.plan.receipts?.length ? `${bundle.plan.receipts.length} digest-verified self-reported receipt(s) attached.` : "No raw exercise receipts attached."}</span></div>
        <Button disabled={!exportReady || engagementLoading || !csrfToken} onClick={() => { void saveEngagement(); }} variant="secondary">
          <Icon className="button-icon" name="save" /> {engagementLoading ? "Saving…" : engagementId ? "Save new revision" : "Save engagement"}
        </Button>
      </div>

      <div aria-label="Plan summary" className="export-stats">
        <div className="statbox"><strong>{bundle.preview.total}</strong><span>Techniques</span></div>
        <div className="statbox"><strong>{bundle.preview.stages.length}</strong><span>Stages</span></div>
        <div className="statbox statbox--success"><strong>{bundle.preview.runnable}</strong><span>Runnable tests</span></div>
        <div className="statbox"><strong>{markedRun}</strong><span>Executed · {bundle.plan.summary.skipped?.length ?? 0} skipped</span></div>
      </div>

      <div className="export-layout">
        <div className="export-primary">
          <div className="export-section-heading"><div><p className="eyebrow">Operator handoff</p><h2>Take the plan to the disposable lab</h2></div><span className="export-safety"><Icon name="shield" /> Catalog rebound</span></div>
          {bundle.preview.runnable === 0 ? <p className="callout" role="status">This plan has no runnable commands under the current platform and guardrails. Save it or generate a report to document coverage gaps. Return to scope if you need an execution kit.</p> : null}
          <button className={`kit-card ${kitLoading ? "is-loading" : ""}`} disabled={!exportReady || bundle.preview.runnable === 0 || kitLoading || !csrfToken} onClick={() => { void exportKit(); }} type="button">
            <span className="kit-card__icon"><Icon name="package" /></span>
            <span className="kit-card__copy">
              <span className="kit-card__eyebrow">Recommended · offline handoff</span>
              <strong>{kitLoading ? "Building verified execution kit…" : `Download ${platform} execution kit`}</strong>
              <span>{hasBoundedExercise
                ? `CSV + self-contained ${runner} runner + portable bounded-exercise script. Python 3.10+ is required beside the kit for bounded steps.`
                : `CSV + self-contained ${runner} runner. No AdversaryFlow installation or destination network connection is required for direct steps.`}</span>
            </span>
            <span className="kit-card__action"><Icon name={kitLoading ? "package" : "download"} /> {kitLoading ? "Preparing" : "Download ZIP"}</span>
          </button>

          <div className="handoff-guide">
            <div className="handoff-guide__head"><div><p className="eyebrow">Operator checklist</p><h2>What happens on the lab host</h2></div><span>Nothing runs from this browser</span></div>
            <ol>
              <li><span>1</span><div><strong>Move the complete ZIP</strong><p>Extract every file together on the authorized disposable host; the CSV and runner are SHA-256 integrity-bound.</p></div></li>
              <li><span>2</span><div><strong>Review the plan CSV</strong><p>Confirm techniques, exact commands, risk, prerequisites, expected output, telemetry, and rollback before starting.</p></div></li>
              <li><span>3</span><div><strong>Start the local {runner} runner</strong><p>Each step asks the operator to run, edit, skip, or abort. Edited commands require a reason and second approval.</p></div></li>
              <li><span>4</span><div><strong>Bring evidence back</strong><p>Preserve the generated reports, result CSV, event log, stdout/stderr, and SHA256SUMS for detection validation.</p></div></li>
            </ol>
          </div>
        </div>

        <aside className="export-secondary" aria-label="Reports and planning exports">
          <div className="export-section-heading"><div><p className="eyebrow">Purple-team reporting</p><h2>Package outcomes and gaps</h2></div></div>
          <div className="report-readiness" aria-label="Report coverage snapshot">
            <div><strong>{bundle.plan.summary.reviewed?.length ?? markedRun}/{bundle.preview.total}</strong><span>Outcomes reviewed · {markedRun} executed</span></div>
            <div><strong>{readiness.detectionAssessed}/{readiness.techniques}</strong><span>Detections assessed</span></div>
            <div><strong>{readiness.coverageGaps}</strong><span>Catalog gaps</span></div>
          </div>
          <div className="report-builder">
            <div className="report-builder__heading">
              <div><strong>Engagement report</strong><span>Generate once, review, then download the format you need.</span></div>
              <Icon name="file" />
            </div>

            {reportPreview.status === "empty" ? (
              <div className="report-state report-state--empty">
                <Icon name="file" />
                <strong>No report generated yet</strong>
                <p>The preview will show the catalog-rebound telemetry, detection mappings, evidence, and gaps. Nothing is executed.</p>
              </div>
            ) : null}

            {reportPreview.status === "loading" ? (
              <div className="report-state report-state--loading" role="status">
                <span aria-hidden="true" className="report-spinner" />
                <strong>Generating report preview…</strong>
                <p>Rebinding the plan to the catalog and assembling the command-free report.</p>
              </div>
            ) : null}

            {reportPreview.status === "error" ? (
              <div className="report-state report-state--error" role="alert">
                <Icon name="close" />
                <strong>Report generation failed</strong>
                <p>{reportPreview.message}</p>
              </div>
            ) : null}

            {reportPreview.status === "ready" ? (
              <div className="report-preview">
                <div className="report-preview__status" role="status"><span aria-hidden="true" /><strong>Preview ready</strong><small>Self-contained HTML · command bodies excluded</small></div>
                <iframe referrerPolicy="no-referrer" sandbox="" srcDoc={reportPreview.html} title="Engagement report preview" />
                <div aria-label="Report downloads" className="report-downloads">
                  <button aria-label="Download HTML engagement report" disabled={Boolean(reportLoading)} onClick={() => { void exportReport("html"); }} type="button"><Icon name="download" /><span><strong>HTML</strong><small>Self-contained</small></span></button>
                  <button aria-label="Download PDF engagement report" disabled={Boolean(reportLoading)} onClick={() => { void exportReport("pdf"); }} type="button"><Icon name="download" /><span><strong>{reportLoading === "pdf" ? "Building…" : "PDF"}</strong><small>Print-ready</small></span></button>
                  <button aria-label="Download Schema-versioned JSON" disabled={Boolean(reportLoading)} onClick={() => { void exportReport("json"); }} type="button"><Icon name="download" /><span><strong>{reportLoading === "json" ? "Building…" : "JSON"}</strong><small>Schema {bundle.plan.schema_version}</small></span></button>
                </div>
                {reportDownloadError ? <p className="report-download-error" role="alert">{reportDownloadError}</p> : null}
              </div>
            ) : null}

            <Button
              className="report-generate"
              disabled={!exportReady || reportPreview.status === "loading" || Boolean(reportLoading) || !csrfToken}
              onClick={() => { void generateReport(); }}
              variant="primary"
            >
              <Icon className="button-icon" name="file" /> {reportPreview.status === "ready" ? "Regenerate report" : reportPreview.status === "error" ? "Retry report generation" : "Generate report"}
            </Button>
          </div>

          <div className="secondary-exports">
            <span>Additional planning artifacts</span>
            <button disabled={!exportReady || atomicLoading || !csrfToken} onClick={() => { void exportAtomicDraft(); }} type="button">{atomicLoading ? "Preparing Atomic draft…" : "Atomic Red Team draft + gap backlog"}<Icon name={atomicLoading ? "package" : "download"} /></button>
            <button disabled={backlogLoading} onClick={() => { if (backlogOpen) setBacklogOpen(false); else void loadAbilityBacklog(); }} type="button">{backlogLoading ? "Loading ability backlog…" : backlogOpen ? "Hide ability backlog" : "Manage ability backlog"}<Icon name="arrow-right" /></button>
            <button disabled={!exportReady} onClick={saveJsonPlan} type="button">Save JSON plan <Icon name="download" /></button>
            <button disabled={!exportReady} onClick={() => exportText("markdown")} type="button">Markdown report <Icon name="download" /></button>
            <button disabled={!exportReady} onClick={() => exportText("runbook")} type="button">Commented Runbook <Icon name="download" /></button>
          </div>

          {backlogOpen ? (
            <section aria-label="Persistent ability backlog" className="ability-backlog">
              <div className="ability-backlog__heading"><strong>Ability content backlog</strong><span>Assign an owner and move each gap through review.</span></div>
              {backlogItems.length ? backlogItems.map((item) => (
                <article className="ability-backlog__item" key={item.id}>
                  <div><strong>{item.technique_id} · {item.platform} · {item.gap.replaceAll("_", " ")}</strong><p>{item.reason}</p></div>
                  <label>Owner<input maxLength={120} onChange={(event) => setBacklogItems((items) => items.map((current) => current.id === item.id ? { ...current, owner: event.target.value } : current))} placeholder="Unassigned" value={item.owner ?? ""} /></label>
                  <label>Status<select onChange={(event) => setBacklogItems((items) => items.map((current) => current.id === item.id ? { ...current, status: event.target.value as AbilityGapStatus } : current))} value={item.status}><option value="open">Open</option><option value="in_progress">In progress</option><option value="accepted">Accepted</option><option value="closed">Closed</option></select></label>
                  <Button disabled={backlogSaving !== null} onClick={() => { void updateBacklogItem(item); }} variant="secondary">{backlogSaving === item.id ? "Saving…" : "Save"}</Button>
                </article>
              )) : <p className="muted">No backlog items yet. Generate an Atomic draft to classify current plan gaps.</p>}
              {backlogNextOffset !== null ? <Button disabled={backlogLoading || backlogSaving !== null} onClick={() => { void loadAbilityBacklog(backlogNextOffset); }} variant="secondary">{backlogLoading ? "Loading more backlog items…" : "Load more backlog items"}</Button> : null}
            </section>
          ) : null}

          <div className="verification-card">
            <div><Icon name="shield" /><span><strong>Evidence-aware, command-free reports</strong><small>Catalog mappings are rebound before rendering</small></span></div>
            <ul>
              <li>Reports never include runnable command bodies.</li>
              <li>Sigma links appear only when the catalog supplies one.</li>
              <li>JSON keeps the schema {bundle.plan.schema_version} source record intact, including any accepted procedure evidence.</li>
            </ul>
          </div>
          <Button className="summary-copy" disabled={!exportReady} onClick={() => { void copySummary(); }} variant="ghost"><Icon className="button-icon" name="copy" /> Copy plan summary</Button>
        </aside>
      </div>

      <div className="actionbar export-actionbar">
        <Button onClick={onBack} variant="ghost"><Icon className="button-icon" name="arrow-left" /> Back to review</Button>
        <div aria-live="polite" className="actionbar__context"><span aria-hidden="true" className={`context-dot ${exportReady ? "is-ready" : ""}`} /><div><span id="actionbarCtx">{exportReady ? "Plan complete" : "Export paused"}</span><small>{exportReady ? "Downloads are generated only when you choose them" : "Return to review or scope to correct the plan"}</small></div></div>
        <Button onClick={() => setRestartOpen(true)}>Plan another actor <Icon className="button-icon" name="arrow-right" /></Button>
      </div>

      <Dialog description="Your current browser-saved scope and evidence will be cleared. Export any records you want to keep before continuing." onClose={() => setRestartOpen(false)} open={restartOpen} title="Start a new plan?">
        <div className="callout"><strong>Current plan</strong><p>{actor.name} · {markedRun} of {bundle.preview.runnable} runnable techniques recorded</p></div>
        <div className="dialog-actions"><Button onClick={() => setRestartOpen(false)} variant="ghost">Cancel</Button><Button onClick={() => { setRestartOpen(false); onRestart(); }} variant="primary">Start new plan</Button></div>
      </Dialog>
    </section>
  );
}
