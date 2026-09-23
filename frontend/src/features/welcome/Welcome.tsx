import type { ChangeEvent } from "react";

import type { Actor } from "../../api/contract";
import { Button } from "../../components/Button";
import { ErrorState } from "../../components/Feedback";
import { Icon } from "../../components/Icon";

interface WelcomeProps {
  onBegin: () => void;
  onImport: (file: File) => Promise<void>;
  onResume: () => void;
  ready: boolean;
  resumeActor: Actor | null;
  setupError?: string;
  onRetrySetup?: () => void;
  catalogError?: string;
  catalogRetrying?: boolean;
  onRetryCatalog?: () => void;
}

export function Welcome({ onBegin, onImport, onResume, ready, resumeActor, setupError = "", onRetrySetup, catalogError = "", catalogRetrying = false, onRetryCatalog }: WelcomeProps): React.JSX.Element {
  const importPlan = (event: ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) void onImport(file);
  };

  return (
    <section className="welcome-screen screen" aria-labelledby="welcome-title">
      <div className="welcome-glow" aria-hidden="true" />
      <div className="welcome-copy">
        <div className="welcome-badge"><Icon className="icon" name="shield" /> Authorized adversary-emulation planner</div>
        <h1 id="welcome-title">Turn a threat actor into an <span>end-to-end emulation plan</span></h1>
        <p className="welcome-lead">Build a guided, ATT&amp;CK-mapped workflow for detection validation—then export an operator-gated kit to use offline on a disposable lab host.</p>
        <div className="welcome-actions">
          <Button disabled={!ready && !setupError} onClick={onBegin} variant="primary">Begin emulation plan <Icon className="button-icon" name="arrow-right" /></Button>
          <span role="status">{setupError ? "Setup needs attention" : catalogError ? catalogRetrying ? "Retrying catalog…" : "Catalog needs attention" : ready ? "Live ATT&CK catalog ready" : "Preparing the catalog…"}</span>
        </div>
        {setupError ? <ErrorState message={setupError} onRetry={onRetrySetup} title="Could not prepare ATT&CK data" /> : null}
        {catalogError ? (
          <div className="error-state" role="alert">
            <div><strong>The actor catalog could not be loaded</strong><p>{catalogError}</p></div>
            <Button disabled={catalogRetrying} onClick={onRetryCatalog}>{catalogRetrying ? "Retrying catalog…" : "Retry catalog"}</Button>
          </div>
        ) : null}
        <div className="resume-panel">
          <div><p className="eyebrow">Continue existing work</p><p>Resume browser-saved progress or import a schema 2.0 plan. Imported commands require review; your saved guardrails stay in place.</p></div>
          <div className="resume-panel__actions">
            {resumeActor ? <Button onClick={onResume} variant="secondary">Resume {resumeActor.name} plan</Button> : null}
            <label className="button button--ghost import-button" htmlFor="importPlan"><Icon className="button-icon" name="file" /> Resume JSON plan</label>
            <input accept="application/json,.json" className="sr-only" id="importPlan" onChange={importPlan} type="file" />
          </div>
        </div>
      </div>
      <div className="boundary-card">
        <div className="boundary-card__head"><span className="boundary-icon"><Icon name="shield" /></span><div><p className="eyebrow">Product boundary</p><h2>Planner, never executor</h2></div></div>
        <div className="boundary-flow">
          <div><span>01</span><p><strong>Choose</strong>Mapped actor behavior</p></div>
          <div><span>02</span><p><strong>Constrain</strong>Platform and risk</p></div>
          <div><span>03</span><p><strong>Review</strong>Every lab action</p></div>
          <div><span>04</span><p><strong>Export</strong>Offline operator kit</p></div>
        </div>
        <div className="boundary-rule"><span aria-hidden="true" /><p><strong>No live execution path</strong>The service does not run commands or contact targets.</p></div>
      </div>
    </section>
  );
}
