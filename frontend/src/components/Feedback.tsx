import { Button } from "./Button";

export function LoadingState({ label, detail }: { label: string; detail: string }): JSX.Element {
  return (
    <div aria-live="polite" className="loading-state" role="status">
      <span aria-hidden="true" className="spinner" />
      <div><strong>{label}</strong><p>{detail}</p></div>
    </div>
  );
}

export function ErrorState({ title, message, onRetry, retryLabel = "Retry setup" }: { title: string; message: string; onRetry?: () => void; retryLabel?: string }): JSX.Element {
  return (
    <div className="error-state" role="alert">
      <div><strong>{title}</strong><p>{message}</p></div>
      {onRetry ? <Button onClick={onRetry}>{retryLabel}</Button> : null}
    </div>
  );
}

export function EmptyState({ title, message, action }: { title: string; message: string; action?: React.ReactNode }): JSX.Element {
  return <div className="empty-state"><div className="empty-state__mark" aria-hidden="true">⌁</div><h3>{title}</h3><p>{message}</p>{action}</div>;
}
