import { useState, type FormEvent } from "react";

import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";

// docker/entrypoint.sh prints `  API token: <value> (<note>)`. Copying the
// whole line is an easy mistake, so strip exactly that label, the two notes it
// can print, and wrapping quotes. Anything else is passed through unchanged.
const TOKEN_LABEL = /^API token:\s*/i;
const TOKEN_NOTE = /\s+\((?:generated for this container start|supplied through ADVERSARYFLOW_API_TOKEN)\)$/i;
const WRAPPING_QUOTES = /^(["'`])(.*)\1$/;

export function normalizeApiToken(raw: string): string {
  let token = raw.trim().replace(TOKEN_LABEL, "").replace(TOKEN_NOTE, "").trim();
  const quoted = WRAPPING_QUOTES.exec(token);
  if (quoted?.[2] !== undefined) token = quoted[2].trim();
  return token;
}

interface AuthDialogProps {
  open: boolean;
  message: string;
  onConnect: (token: string) => void;
  onClose: () => void;
}

export function AuthDialog({ open, message, onConnect, onClose }: AuthDialogProps): React.JSX.Element | null {
  const [token, setToken] = useState("");
  const [validation, setValidation] = useState("");

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const next = normalizeApiToken(token);
    if (!next) {
      setValidation("Enter the API token to continue.");
      return;
    }
    setValidation("");
    setToken("");
    onConnect(next);
  };

  return (
    <Dialog
      description="This service requires its startup API token. The token stays in this browser tab."
      open={open}
      onClose={onClose}
      title="Connect to this AdversaryFlow service"
    >
      <form className="auth-form" onSubmit={submit}>
        <p>For Docker, copy the value after <strong>API token:</strong> in the startup window. You can also find it with <code>docker compose logs adversaryflow</code>. Use the most recent token, without the parenthesized note. For a managed service, ask its operator for the token.</p>
        <label htmlFor="auth-token"><span>API token</span><input autoComplete="off" autoFocus id="auth-token" onChange={(event) => setToken(event.target.value)} spellCheck={false} type="password" value={token} /></label>
        {validation || message ? <p className="field-error" role="alert">{validation || message}</p> : null}
        <Button type="submit" variant="primary">Connect securely</Button>
        <Button onClick={onClose} variant="ghost">Continue with saved work</Button>
      </form>
    </Dialog>
  );
}
