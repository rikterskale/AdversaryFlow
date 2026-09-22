import { useState } from "react";

import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import type { ScopedTechnique } from "../scope/scopeModel";
import {
  detectionOptions,
  dateTimeIsoValue,
  dateTimeLocalValue,
  evidenceFromReceipt,
  evidenceSourceOptions,
  outcomeOptions,
  type DetectionResult,
  type EvidenceSource,
  type ExecutionEvidence,
  type ExecutionOutcome,
} from "./evidence";
import { titleMetadataValue, TouchPreview } from "./TouchPreview";

interface TechniqueCardProps {
  technique: ScopedTechnique;
  evidence: ExecutionEvidence | undefined;
  focused: boolean;
  firstLab: boolean;
  onFocus: () => void;
  onUpdate: (patch: Partial<ExecutionEvidence>) => void;
  onCopy: (value: string, kind: "command" | "cleanup") => void;
  onNotice: (message: string) => void;
}

function cleanText(value: string): string {
  return value.replace(/\[([^\]]+)]\([^)]*\)/g, "$1").replace(/\s*\(Citation:[^)]+\)/gi, "").replace(/\s+/g, " ").trim();
}

function safeUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

function fidelityLabel(technique: ScopedTechnique): { className: string; label: string } {
  if (technique.selectedCommand.unsupported) return { className: "unsupported", label: "unsupported" };
  if (technique.selectedCommand.fidelity === "bounded_synthetic") return { className: "bounded", label: "bounded synthetic" };
  if (technique.selectedCommand.fidelity === "lab_proxy") return { className: "proxy", label: "lab proxy" };
  return { className: "direct", label: "direct" };
}

export function TechniqueCard({ technique, evidence, focused, firstLab, onFocus, onUpdate, onCopy, onNotice }: TechniqueCardProps): React.JSX.Element {
  const [receipt, setReceipt] = useState("");
  const command = technique.selectedCommand;
  const unsupported = Boolean(command.unsupported);
  const marked = Boolean(evidence && evidence.outcome !== "not_run");
  const fidelity = fidelityLabel(technique);
  const attackUrl = safeUrl(technique.url);
  const detection = evidence?.detection_result ?? "not_assessed";

  const importReceipt = async (): Promise<void> => {
    try {
      onUpdate(await evidenceFromReceipt(receipt, technique.attack_id));
      setReceipt("");
      onNotice(`Verified and imported ${technique.attack_id} receipt`);
    } catch (error: unknown) {
      onNotice(error instanceof Error ? error.message : "Receipt import failed.");
    }
  };

  const updateHash = (key: "stdout_sha256" | "stderr_sha256", value: string): void => {
    const normalized = value.trim();
    if (normalized && !/^[a-fA-F0-9]{64}$/.test(normalized)) {
      onNotice("SHA-256 values must contain 64 hexadecimal characters.");
      return;
    }
    onUpdate({ [key]: normalized || undefined });
  };

  return (
    <article className={`techcard ${marked ? "is-run" : ""} ${focused ? "is-focused" : ""} ${firstLab ? "is-firstlab" : ""}`} data-tid={technique.attack_id} onClick={onFocus} onFocus={onFocus} tabIndex={focused ? 0 : -1}>
      <header className="techcard__header">
        <button
          aria-label={unsupported ? `No ${technique.attack_id} test available for this platform` : `Mark ${technique.attack_id} as run`}
          aria-pressed={marked}
          className="techcard__check"
          disabled={unsupported}
          onClick={(event) => { event.stopPropagation(); onUpdate({ outcome: marked ? "not_run" : "passed" }); }}
          title={unsupported ? "No test available for this platform" : "Mark as run"}
          type="button"
        ><Icon name="check" /></button>
        <div className="techcard__identity">
          <div className="techcard__title-row">
            {attackUrl ? <a className="techcard__id" href={attackUrl} onClick={(event) => event.stopPropagation()} rel="noreferrer" target="_blank">{technique.attack_id}<Icon name="external" /></a> : <span className="techcard__id">{technique.attack_id}</span>}
            <h3 className="techcard__name">{technique.name}</h3>
            {technique.is_subtechnique ? <span className="techcard__sub">sub-technique</span> : null}
            {firstLab ? <span className="firstlabbadge">Try this first</span> : null}
          </div>
          {technique.platforms?.length ? <div className="techcard__plats">{technique.platforms.slice(0, 6).map((platform) => <span className="plat" key={platform}>{platform}</span>)}</div> : null}
        </div>
        <div className="techcard__source"><span className={`srcbadge srcbadge--${fidelity.className}`}>{fidelity.label}</span>{technique.command_source === "fallback" ? <span className="srcbadge srcbadge--fallback">fallback</span> : null}</div>
      </header>

      <TouchPreview command={command} techniqueId={technique.attack_id} />

      <div className={`command ${unsupported ? "cmd--unsupported" : ""}`}>
        <div className="cmd__head"><span className="cmd__plat">{command.platform}</span><Button className="copybtn" disabled={unsupported} onClick={(event) => { event.stopPropagation(); onCopy(command.command, "command"); }}><Icon className="button-icon" name="copy" /> Copy command</Button></div>
        <pre className="cmd__code">{command.command}</pre>
        {command.note ? <p className="cmd__note">{command.note}</p> : null}
        {command.cleanup ? <div className="cmd__cleanup"><div><strong>Cleanup</strong><code>{command.cleanup}</code></div><Button className="copybtn" disabled={unsupported} onClick={(event) => { event.stopPropagation(); onCopy(command.cleanup, "cleanup"); }} variant="ghost"><Icon className="button-icon" name="copy" /> Copy cleanup</Button></div> : null}
      </div>

      {!unsupported ? (
        <div className={`safety safety--${command.risk}`}>
          <div className="safety__badges"><span className={`riskbadge riskbadge--${command.risk}`}>{command.risk} risk</span>{command.requires_admin ? <span className="riskbadge">admin</span> : null}{command.requires_network ? <span className="riskbadge">network</span> : null}{command.cleanup_required ? <span className="riskbadge">cleanup required</span> : null}</div>
          <div className="safety__grid">
            <div><strong>Effects:</strong> {command.side_effects.length ? command.side_effects.map(titleMetadataValue).join(", ") : "Not classified"} · <strong>Expected:</strong> {command.expected_telemetry || "Verify relevant telemetry"}</div>
            {command.prerequisites.length ? <div><strong>Prerequisites:</strong> {command.prerequisites.join("; ")}</div> : null}
            {command.expected_output ? <div><strong>Expected output:</strong> {command.expected_output}</div> : null}
            {command.rollback ? <div><strong>Rollback:</strong> {command.rollback}</div> : null}
            {command.timeout_seconds ? <div><strong>Timeout:</strong> {command.timeout_seconds}s</div> : null}
          </div>
        </div>
      ) : null}

      {!unsupported ? (
        <div className="evidence-panel" onClick={(event) => event.stopPropagation()}>
          <div className="evidence-panel__heading"><div><span>Operator record</span><p>Command outcome and detection result are tracked separately.</p></div><span className={`evidence-state evidence-state--${evidence?.outcome ?? "not_run"}`}>{outcomeOptions.find((item) => item.value === (evidence?.outcome ?? "not_run"))?.label}</span></div>
          <div className="evidence-grid">
            <label className="evidence__pair">Command outcome<select aria-label={`Outcome for ${technique.attack_id}`} className="evidence__outcome" onChange={(event) => onUpdate({ outcome: event.target.value as ExecutionOutcome })} value={evidence?.outcome ?? "not_run"}>{outcomeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
            <label className="evidence__pair">Detection result<select aria-label={`Detection for ${technique.attack_id}`} className="evidence__detection" onChange={(event) => onUpdate({ detection_result: event.target.value as DetectionResult })} value={detection}>{detectionOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
            <label className="evidence-note">Evidence note<input aria-label={`Evidence note for ${technique.attack_id}`} className="evidence__note" maxLength={500} onChange={(event) => onUpdate({ notes: event.target.value })} placeholder="Observation, alert, or investigation note—no secrets" type="text" value={evidence?.notes ?? ""} /></label>
            <label className="cleanupcheck"><input checked={Boolean(evidence?.cleanup_completed)} disabled={!command.cleanup} onChange={(event) => onUpdate({ cleanup_completed: event.target.checked })} type="checkbox" /> Cleanup verified</label>
          </div>
        </div>
      ) : null}

      {technique.description || technique.data_sources?.length || technique.detection ? (
        <details className="techcard__more" onClick={(event) => event.stopPropagation()}>
          <summary>ATT&amp;CK context</summary>
          {technique.description ? <p className="techcard__desc">{cleanText(technique.description)}</p> : null}
          {technique.data_sources?.length ? <div className="techcard__plats">{technique.data_sources.slice(0, 8).map((item) => <span className="plat plat--source" key={item}>{item}</span>)}</div> : null}
          {technique.detection ? <p className="techcard__detect"><strong>ATT&amp;CK detection:</strong> {cleanText(technique.detection)}</p> : null}
        </details>
      ) : null}

      {!unsupported ? (
        <details className="evidenceproof" onClick={(event) => event.stopPropagation()}>
          <summary>Execution proof {evidence?.receipt_verified ? <span className="proofbadge">receipt digest verified (self-reported)</span> : null}</summary>
          <p>Correlate run IDs and timestamps with endpoint or SIEM telemetry for independent proof.</p>
          <div className="evidenceproof__grid">
            <label>Run ID<input maxLength={128} onChange={(event) => onUpdate({ run_id: event.target.value || undefined })} value={evidence?.run_id ?? ""} /></label>
            <label>Exit code<input max={65535} min={-255} onChange={(event) => onUpdate({ exit_code: event.target.value ? Number(event.target.value) : undefined })} type="number" value={evidence?.exit_code ?? ""} /></label>
            <label>Started<input aria-label={`Started at for ${technique.attack_id}`} onChange={(event) => onUpdate({ started_at: dateTimeIsoValue(event.target.value) })} step="1" type="datetime-local" value={dateTimeLocalValue(evidence?.started_at)} /></label>
            <label>Completed<input aria-label={`Completed at for ${technique.attack_id}`} onChange={(event) => onUpdate({ completed_at: dateTimeIsoValue(event.target.value) })} step="1" type="datetime-local" value={dateTimeLocalValue(evidence?.completed_at)} /></label>
            <label>stdout SHA-256<input defaultValue={evidence?.stdout_sha256 ?? ""} maxLength={64} onBlur={(event) => updateHash("stdout_sha256", event.target.value)} /></label>
            <label>stderr SHA-256<input defaultValue={evidence?.stderr_sha256 ?? ""} maxLength={64} onBlur={(event) => updateHash("stderr_sha256", event.target.value)} /></label>
            <label>Evidence source<select aria-label={`Evidence source for ${technique.attack_id}`} onChange={(event) => onUpdate({ evidence_source: event.target.value as EvidenceSource })} value={evidence?.evidence_source ?? "operator_supplied"}>{evidenceSourceOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
            <label>Telemetry references<textarea maxLength={10000} onChange={(event) => onUpdate({ telemetry_refs: [...new Set(event.target.value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))] })} placeholder="SIEM event IDs or endpoint links, one per line" value={(evidence?.telemetry_refs ?? []).join("\n")} /></label>
          </div>
          {command.exercise_kind === "technique_relevant_bounded" ? <div className="receipt-import"><label>Exercise receipt JSON<textarea aria-label={`Exercise receipt for ${technique.attack_id}`} onChange={(event) => setReceipt(event.target.value)} placeholder="Paste the JSON emitted by the bounded lab exercise" value={receipt} /></label><Button onClick={() => { void importReceipt(); }} variant="ghost">Verify and import receipt</Button></div> : null}
        </details>
      ) : null}
    </article>
  );
}
