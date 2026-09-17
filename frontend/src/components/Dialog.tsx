import { useEffect, useId, useRef, type ReactNode } from "react";

import { Icon } from "./Icon";

interface DialogProps {
  title: string;
  description?: string;
  open: boolean;
  onClose?: () => void;
  children: ReactNode;
  closeLabel?: string;
}

export function Dialog({ title, description, open, onClose, children, closeLabel = "Close dialog" }: DialogProps): JSX.Element | null {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    panelRef.current?.focus();
    const closeOnEscape = (event: KeyboardEvent): void => {
      if (event.key === "Escape" && onClose) onClose();
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("keydown", closeOnEscape);
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
