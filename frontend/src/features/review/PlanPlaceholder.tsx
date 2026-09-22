import type { Actor } from "../../api/contract";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";

export function PlanPlaceholder({ actor, onBack }: { actor: Actor; onBack: () => void }): React.JSX.Element {
  return (
    <section className="screen placeholder-screen" aria-labelledby="plan-title">
      <p className="eyebrow">Step 3 of 4</p>
      <h1 id="plan-title">{actor.name} · {actor.attack_id}</h1>
      <p>The scoped plan is ready. Technique cards, command previews, evidence tracking, and the ATT&amp;CK coverage matrix arrive in the next reviewed checkpoint.</p>
      <Button onClick={onBack}><Icon className="button-icon" name="arrow-left" /> Back to scope</Button>
    </section>
  );
}
