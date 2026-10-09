import { useState, type FormEvent } from "react";

import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";

interface AuthDialogProps {
  open: boolean;
  message: string;
  onConnect: (token: string) => void;
}

export function AuthDialog({ open, message, onConnect }: AuthDialogProps): React.JSX.Element | null {
  const [token, setToken] = useState("");
  const [validation, setValidation] = useState("");

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const next = token.trim();
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
      title="Connect to this AdversaryFlow service"
    >
      <form className="auth-form" onSubmit={submit}>
        <p>For Docker, copy the value after <strong>API token:</strong> in the startup window. You can also find it with <code>docker compose logs adversaryflow</code>. Use the most recent token, without the parenthesized note. For a managed service, ask its operator for the token.</p>
        <label htmlFor="auth-token"><span>API token</span><input autoComplete="off" autoFocus id="auth-token" onChange={(event) => setToken(event.target.value)} spellCheck={false} type="password" value={token} /></label>
        {validation || message ? <p className="field-error" role="alert">{validation || message}</p> : null}
        <Button type="submit" variant="primary">Connect securely</Button>
      </form>
    </Dialog>
  );
}
