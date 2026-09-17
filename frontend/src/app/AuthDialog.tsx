import { useState, type FormEvent } from "react";

import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";

interface AuthDialogProps {
  open: boolean;
  message: string;
  onConnect: (token: string) => void;
}

export function AuthDialog({ open, message, onConnect }: AuthDialogProps): JSX.Element | null {
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
      description="This AdversaryFlow service is bound beyond loopback and requires its configured bearer token. The token stays in this browser tab."
      open={open}
      title="Connect to this AdversaryFlow service"
    >
      <form className="auth-form" onSubmit={submit}>
        <label htmlFor="auth-token"><span>API token</span><input autoComplete="off" autoFocus id="auth-token" onChange={(event) => setToken(event.target.value)} spellCheck={false} type="password" value={token} /></label>
        {validation || message ? <p className="field-error" role="alert">{validation || message}</p> : null}
        <Button type="submit" variant="primary">Connect securely</Button>
      </form>
    </Dialog>
  );
}
