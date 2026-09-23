import { useLayoutEffect, useId, useRef, type ReactNode } from "react";

import { Icon } from "./Icon";

interface DialogProps {
  title: string;
  description?: string;
  open: boolean;
  onClose?: () => void;
  children: ReactNode;
  closeLabel?: string;
}

export function Dialog({ title, description, open, onClose, children, closeLabel = "Close dialog" }: DialogProps): React.JSX.Element | null {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useLayoutEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!panelRef.current?.contains(document.activeElement)) panelRef.current?.focus();
    const handleDialogKeys = (event: KeyboardEvent): void => {
      if (event.key === "Escape" && onClose) onClose();
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = [...panelRef.current.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )];
      if (!focusable.length) {
        event.preventDefault();
        panelRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === panelRef.current)) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === panelRef.current)) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", handleDialogKeys);
    return () => {
      document.removeEventListener("keydown", handleDialogKeys);
      previous?.focus();
    };
  }, [onClose, open]);

  if (!open) return null;
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.target === event.currentTarget && onClose) onClose();
    }}>
      <div aria-describedby={description ? descriptionId : undefined} aria-labelledby={titleId} aria-modal="true" className="dialog-panel" ref={panelRef} role="dialog" tabIndex={-1}>
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">AdversaryFlow guidance</p>
            <h2 id={titleId}>{title}</h2>
          </div>
          {onClose ? (
            <button aria-label={closeLabel} className="icon-button" onClick={onClose} type="button">
              <Icon className="icon" name="close" />
            </button>
          ) : null}
        </div>
        {description ? <p className="dialog-description" id={descriptionId}>{description}</p> : null}
        {children}
      </div>
    </div>
  );
}
