import type { Actor } from "../../api/contract";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";

export function ScopePlaceholder({ actor, onBack }: { actor: Actor; onBack: () => void }): React.JSX.Element {
  return (
    <section className="screen placeholder-screen" aria-labelledby="scope-title">
      <p className="eyebrow">Step 2 of 4</p>
      <h1 id="scope-title">Scope the engagement</h1>
      <p>The selected actor is ready. Platform, tactic, privilege, network, and risk controls are added in the next reviewed checkpoint.</p>
      <div className="selected-summary"><span>{actor.attack_id}</span><div><strong>{actor.name}</strong><p>{actor.technique_count} documented technique mappings</p></div></div>
      <Button onClick={onBack}><Icon className="button-icon" name="arrow-left" /> Back to threat actors</Button>
    </section>
  );
}
