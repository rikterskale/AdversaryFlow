import type { Actor } from "../../api/contract";
import { Icon } from "../../components/Icon";

interface ActorCardProps {
  actor: Actor;
  selected: boolean;
  onSelect: (actor: Actor) => void;
}

function cleanDescription(value: string): string {
  return value
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/\s*\(Citation:[^)]+\)/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function actorMonogram(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  const initials = words.slice(0, 2).map((word) => word[0] ?? "").join("");
  return (initials || name.slice(0, 2)).toLocaleUpperCase();
}

export function ActorCard({ actor, selected, onSelect }: ActorCardProps): React.JSX.Element {
  const description = cleanDescription(actor.description);

  return (
    <button
      aria-label={`Select ${actor.name}, ${actor.attack_id}, ${actor.technique_count} techniques`}
      aria-pressed={selected}
      className={`actorcard ${selected ? "is-selected" : ""}`}
      data-actor-id={actor.attack_id}
      onClick={() => onSelect(actor)}
      type="button"
    >
      <span className="actorcard__top">
        <span className="actorcard__identity">
          <span className="actorcard__monogram" aria-hidden="true">{actorMonogram(actor.name)}</span>
          <span><strong>{actor.name}</strong><small>{actor.attack_id} · {actor.type}</small></span>
        </span>
        <span className="selection-mark" aria-hidden="true"><Icon name="check" /></span>
      </span>
      <span className="actorcard__desc">{description || "No ATT&CK summary is available for this actor."}</span>
      {actor.aliases.length ? <span className="actorcard__aliases"><span>Also known as</span> {actor.aliases.slice(0, 3).join(" · ")}</span> : null}
      <span className="actorcard__footer">
        <span className="metric"><strong>{actor.technique_count}</strong><span>mapped techniques</span></span>
        <span className="coverage-badge" title="Coverage reflects ATT&CK mappings in the selected domains"><span aria-hidden="true" />Mapped coverage</span>
      </span>
    </button>
  );
}
