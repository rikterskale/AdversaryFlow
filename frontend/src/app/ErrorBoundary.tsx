import { Component, type ErrorInfo, type ReactNode } from "react";

import { Button } from "../components/Button";

interface ErrorBoundaryProps { children: ReactNode }
interface ErrorBoundaryState { failed: boolean }

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("AdversaryFlow interface error", error, info.componentStack);
  }

  override render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="fatal-state">
          <div className="fatal-state__card">
            <span className="brand-mark" aria-hidden="true">AF</span>
            <p className="eyebrow">Interface recovery</p>
            <h1>AdversaryFlow hit an unexpected problem</h1>
            <p>Your saved plan is still in this browser. Reload the interface to recover it.</p>
            <Button onClick={() => window.location.reload()} variant="primary">Reload AdversaryFlow</Button>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}
