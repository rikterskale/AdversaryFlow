import { Component, type ErrorInfo, type ReactNode } from "react";

import { Button } from "../components/Button";
import { WIZARD_STORAGE_KEY } from "../state/wizardStore";
import { createRecoveryCopy } from "../state/workspaceRecovery";

interface ErrorBoundaryProps { children: ReactNode }
interface ErrorBoundaryState { failed: boolean; backedUp: boolean; downloaded: boolean; recoveryError: string }

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { failed: false, backedUp: false, downloaded: false, recoveryError: "" };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true, backedUp: false, downloaded: false, recoveryError: "" };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("AdversaryFlow interface error", error, info.componentStack);
  }

  private saveRecovery = (): void => {
    try {
      const url = URL.createObjectURL(new Blob([createRecoveryCopy()], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = "AdversaryFlow_browser_recovery.json"; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      this.setState({ downloaded: true, backedUp: false, recoveryError: "" });
    } catch {
      this.setState({ recoveryError: "The browser could not save a recovery copy. Keep this window open to preserve your work." });
    }
  };

  private resetWorkspace = (): void => {
    if (!this.state.backedUp) return;
    try {
      localStorage.removeItem(WIZARD_STORAGE_KEY);
      window.location.reload();
    } catch {
      this.setState({ recoveryError: "The browser could not reset its saved workspace." });
    }
  };

  override render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="fatal-state">
          <div className="fatal-state__card">
            <span className="brand-mark" aria-hidden="true">AF</span>
            <p className="eyebrow">Interface recovery</p>
            <h1>AdversaryFlow hit an unexpected problem</h1>
            <p>Reload to try recovering your saved plan. If the problem repeats, download a recovery copy, confirm it is saved, then reset this browser workspace. Server-saved engagements remain available.</p>
            <Button onClick={() => window.location.reload()} variant="primary">Reload AdversaryFlow</Button>
            <Button onClick={this.saveRecovery}>Download recovery copy</Button>
            {this.state.downloaded ? <label><input checked={this.state.backedUp} onChange={(event) => this.setState({ backedUp: event.target.checked })} type="checkbox" /> I opened the downloaded recovery file and confirmed it contains my workspace</label> : null}
            <Button disabled={!this.state.backedUp} onClick={this.resetWorkspace}>Reset browser workspace</Button>
            {this.state.recoveryError ? <p role="alert">{this.state.recoveryError}</p> : null}
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}
