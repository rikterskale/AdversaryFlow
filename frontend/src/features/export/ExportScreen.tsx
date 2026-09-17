import { useMemo, useState } from "react";

import { apiFetch, responseJson } from "../../api/client";
import type { Actor, AttackDomain, WorkflowResponse } from "../../api/contract";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { useWizardStore } from "../../state/wizardStore";
import { buildExportBundle, executiveSummary, platformLabel, toMarkdown, toRunbook } from "./exportModel";

interface ExportScreenProps {
  actor: Actor;
  workflow: WorkflowResponse;
  domains: AttackDomain[];
  csrfToken: string;
  onBack: () => void;
  onNotice: (message: string) => void;
  onRestart: () => void;
}

type TextFormat = "json" | "markdown" | "runbook";

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function contentDispositionFilename(value: string | null): string {
  const match = value?.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
  if (!match?.[1]) return "AdversaryFlow_execution_kit.zip";
  try {
    return decodeURIComponent(match[1].replace(/^"|"$/g, "")).replace(/^.*[\\/]/, "") || "AdversaryFlow_execution_kit.zip";
  } catch {
    return "AdversaryFlow_execution_kit.zip";
  }
}

export function ExportScreen({ actor, workflow, domains, csrfToken, onBack, onNotice, onRestart }: ExportScreenProps): JSX.Element {
  const scope = useWizardStore((state) => state.scope);
  const records = useWizardStore((state) => state.records);
  const [kitLoading, setKitLoading] = useState(false);
  const [restartOpen, setRestartOpen] = useState(false);
  const bundle = useMemo(() => buildExportBundle(actor, workflow, scope, records, domains), [actor, domains, records, scope, workflow]);
  const markedRun = bundle.plan.summary.marked_run.length;
  const platform = platformLabel(scope.commandPlatform);
  const runner = scope.commandPlatform === "windows" ? "PowerShell" : "Bash";
  const hasBoundedExercise = bundle.plan.stages.some((stage) => stage.techniques.some((technique) => technique.supported && technique.command.fidelity === "bounded_synthetic"));

  const exportText = (format: TextFormat): void => {
    try {
      let content: string;
      let filename: string;
      let mime: string;
      if (format === "json") {
        content = JSON.stringify(bundle.plan, null, 2);
        filename = `AdversaryFlow_${bundle.slug}.json`;
        mime = "application/json";
      } else if (format === "markdown") {
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
      onNotice(error instanceof Error ? `Export failed: ${error.message}` : "The export could not be created. Try again.");
    }
  };

  const exportKit = async (): Promise<void> => {
    if (kitLoading) return;
    setKitLoading(true);
    try {
      const response = await apiFetch("/api/execution-kit", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-AdversaryFlow-CSRF": csrfToken },
        body: JSON.stringify(bundle.plan),
      });
      if (!response.ok) await responseJson(response);
      const filename = contentDispositionFilename(response.headers.get("Content-Disposition"));
      downloadBlob(await response.blob(), filename);
      onNotice(`Execution kit ready: ${filename}`);
    } catch (error: unknown) {
      onNotice(error instanceof Error ? error.message : "Execution kit generation failed. Check service health and try again.");
    } finally {
      setKitLoading(false);
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

  return (
    <section aria-labelledby="export-title" className="screen export-screen">
      <header className="export-hero">
        <span aria-hidden="true" className="export-hero__check"><Icon name="check" /></span>
        <p className="eyebrow">Step 4 of 4 · Export kit</p>
        <h1 id="export-title">Your emulation plan is ready</h1>
        <p>{actor.name} · {actor.attack_id} · {platform} · generated from ATT&amp;CK data <code>{workflow.metadata.data_version}</code></p>
      </header>

      <div aria-label="Plan summary" className="export-stats">
        <div className="statbox"><strong>{bundle.preview.total}</strong><span>Techniques</span></div>
        <div className="statbox"><strong>{bundle.preview.stages.length}</strong><span>Stages</span></div>
        <div className="statbox statbox--success"><strong>{bundle.preview.runnable}</strong><span>Runnable tests</span></div>
        <div className="statbox"><strong>{markedRun}</strong><span>Marked run</span></div>
      </div>

      <div className="export-layout">
        <div className="export-primary">
          <div className="export-section-heading"><div><p className="eyebrow">Operator handoff</p><h2>Take the plan to the disposable lab</h2></div><span className="export-safety"><Icon name="shield" /> Catalog rebound</span></div>
          <button className={`kit-card ${kitLoading ? "is-loading" : ""}`} disabled={kitLoading || !csrfToken} onClick={() => { void exportKit(); }} type="button">
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

        <aside className="export-secondary" aria-label="Planning exports">
          <div className="export-section-heading"><div><p className="eyebrow">Planning artifacts</p><h2>Share, review, or resume</h2></div></div>
          <div className="export-card-list">
            <button className="export-card" onClick={() => exportText("markdown")} type="button"><span><Icon name="file" /></span><div><strong>Markdown report</strong><p>Human-readable plan, outcomes, detection results, evidence, and commands.</p></div><Icon name="download" /></button>
            <button className="export-card" onClick={() => exportText("json")} type="button"><span><Icon name="file" /></span><div><strong>Schema-versioned JSON</strong><p>AdversaryFlow 2.0 record for validation, archival, and later resume.</p></div><Icon name="download" /></button>
            <button className="export-card" onClick={() => exportText("runbook")} type="button"><span><Icon name="file" /></span><div><strong>Runbook</strong><p>Review-only text; every command and cleanup line remains commented.</p></div><Icon name="download" /></button>
          </div>

          <div className="verification-card">
            <div><Icon name="shield" /><span><strong>Verify before transfer</strong><small>Keep the extracted kit together</small></span></div>
            <ul>
              <li>The service rebinds techniques to the live bounded catalog.</li>
              <li>The runner refuses a missing or changed plan CSV.</li>
              <li>Direct steps need no callback to this web service.</li>
            </ul>
          </div>
          <Button className="summary-copy" onClick={() => { void copySummary(); }} variant="ghost"><Icon className="button-icon" name="copy" /> Copy plan summary</Button>
        </aside>
      </div>

      <div className="actionbar export-actionbar">
        <Button onClick={onBack} variant="ghost"><Icon className="button-icon" name="arrow-left" /> Back to review</Button>
        <div className="actionbar__context"><span aria-hidden="true" className="context-dot is-ready" /><div><span id="actionbarCtx">Plan complete</span><small>Downloads are generated only when you choose them</small></div></div>
        <Button onClick={() => setRestartOpen(true)}>Plan another actor <Icon className="button-icon" name="arrow-right" /></Button>
      </div>

      <Dialog description="Your current browser-saved scope and evidence will be cleared. Export any records you want to keep before continuing." onClose={() => setRestartOpen(false)} open={restartOpen} title="Start a new plan?">
        <div className="callout"><strong>Current plan</strong><p>{actor.name} · {markedRun} of {bundle.preview.runnable} runnable techniques recorded</p></div>
        <div className="dialog-actions"><Button onClick={() => setRestartOpen(false)} variant="ghost">Cancel</Button><Button onClick={() => { setRestartOpen(false); onRestart(); }} variant="primary">Start new plan</Button></div>
      </Dialog>
    </section>
  );
}
