import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";

export function Welcome({ onBegin, ready }: { onBegin: () => void; ready: boolean }): JSX.Element {
  return (
    <section className="welcome-screen screen" aria-labelledby="welcome-title">
      <div className="welcome-glow" aria-hidden="true" />
      <div className="welcome-copy">
        <div className="welcome-badge"><Icon className="icon" name="shield" /> Authorized adversary-emulation planner</div>
        <h1 id="welcome-title">Turn a threat actor into an <span>end-to-end emulation plan</span></h1>
        <p className="welcome-lead">Build a guided, ATT&amp;CK-mapped workflow for detection validation—then export an operator-gated kit to use offline on a disposable lab host.</p>
        <div className="welcome-actions">
          <Button disabled={!ready} onClick={onBegin} variant="primary">Begin emulation plan <Icon className="button-icon" name="arrow-right" /></Button>
          <span>{ready ? "Live ATT&CK catalog ready" : "Preparing the catalog…"}</span>
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
