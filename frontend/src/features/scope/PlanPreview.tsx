import type { Actor } from "../../api/contract";
import { Icon } from "../../components/Icon";
import type { PlanPreview as PlanPreviewModel, CommandPlatform } from "./scopeModel";
import { titlePlatform } from "./scopeModel";

interface PlanPreviewProps {
  actor: Actor;
  commandPlatform: CommandPlatform;
  dataVersion: string;
  preview: PlanPreviewModel;
}

export function PlanPreview({ actor, commandPlatform, dataVersion, preview }: PlanPreviewProps): React.JSX.Element {
  const curatedWidth = preview.total ? `${(preview.curated / preview.total) * 100}%` : "0%";
  const fallbackWidth = preview.total ? `${(preview.fallback / preview.total) * 100}%` : "0%";
  const withheldReasons = [
    { key: "platform", label: `No exact ${titlePlatform(commandPlatform)} test`, count: preview.withheld.platform },
    { key: "network", label: "Network permission required", count: preview.withheld.network },
    { key: "admin", label: "Administrator permission required", count: preview.withheld.admin },
    { key: "risk", label: "High-risk permission required", count: preview.withheld.highRisk },
    { key: "catalog", label: "Catalog marks unsupported", count: preview.withheld.catalog },
  ].filter((reason) => reason.count > 0);

  return (
    <aside aria-label="Live plan preview" className="scope-summary" id="scopeSummary">
      <div aria-live="polite" className="summary-status">
        <span className={preview.runnable ? "is-ready" : ""} aria-hidden="true" />
        <div><p>Live plan preview</p><strong>{preview.runnable ? `${preview.runnable} lab tests ready` : "No runnable tests"}</strong></div>
      </div>
      <div className="summary-actor"><span>{actor.attack_id}</span><div><strong>{actor.name}</strong><p>{dataVersion}</p></div></div>
      <dl className="summary-metrics">
        <div><dt>Techniques</dt><dd>{preview.total}</dd></div>
        <div><dt>Runnable on {titlePlatform(commandPlatform)}</dt><dd>{preview.runnable}</dd></div>
        <div><dt>Unsupported or withheld</dt><dd>{preview.unsupported}</dd></div>
        <div><dt>Kill-chain stages</dt><dd>{preview.stages.length}</dd></div>
      </dl>
      <div className="coverage-summary">
        <div aria-label={`${preview.curated} curated and ${preview.fallback} fallback techniques`} className="coverage-summary__bar" role="img"><span className="is-curated" style={{ width: curatedWidth }} /><span className="is-fallback" style={{ width: fallbackWidth }} /></div>
        <div><span><i className="legend-dot legend-dot--curated" />{preview.curated} curated</span><span><i className="legend-dot legend-dot--fallback" />{preview.fallback} fallback</span></div>
      </div>
      {withheldReasons.length || preview.filteredFallback ? (
        <div className="summary-withheld">
          <div><strong>Why tests are withheld</strong><span>Counts can overlap</span></div>
          <ul>
            {withheldReasons.map((reason) => <li key={reason.key}><span>{reason.label}</span><strong>{reason.count}</strong></li>)}
            {preview.filteredFallback ? <li><span>Fallback filtered from plan</span><strong>{preview.filteredFallback}</strong></li> : null}
          </ul>
        </div>
      ) : null}
      <div className="summary-boundary"><Icon name="shield" /><p><strong>Planner boundary intact</strong>No commands execute from this service.</p></div>
    </aside>
  );
}
