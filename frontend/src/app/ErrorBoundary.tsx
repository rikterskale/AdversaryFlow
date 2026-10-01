import { Component, type ErrorInfo, type ReactNode } from "react";

import { Button } from "../components/Button";
import { WIZARD_STORAGE_KEY } from "../state/wizardStore";

interface ErrorBoundaryProps { children: ReactNode }
interface ErrorBoundaryState { failed: boolean; backedUp: boolean; recoveryError: string }

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { failed: false, backedUp: false, recoveryError: "" };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true, backedUp: false, recoveryError: "" };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("AdversaryFlow interface error", error, info.componentStack);
  }

  private saveRecovery = (): void => {
    try {
      const saved = localStorage.getItem(WIZARD_STORAGE_KEY);
      const url = URL.createObjectURL(new Blob([JSON.stringify({ saved_workspace: saved, captured_at: new Date().toISOString() }, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = "AdversaryFlow_browser_recovery.json"; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      this.setState({ backedUp: true, recoveryError: "" });
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
            <Button disabled={!this.state.backedUp} onClick={this.resetWorkspace}>Reset browser workspace</Button>
            {this.state.recoveryError ? <p role="alert">{this.state.recoveryError}</p> : null}
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}
