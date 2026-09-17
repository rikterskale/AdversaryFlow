import { useMemo, useState } from "react";

import type { Actor, ActorsResponse, ActorType, AttackDomain } from "../../api/contract";
import { Button } from "../../components/Button";
import { EmptyState, ErrorState, LoadingState } from "../../components/Feedback";
import { Icon } from "../../components/Icon";

type TypeFilter = "all" | ActorType;
type SortOption = "name" | "ttps";

interface ActorGalleryProps {
  response: ActorsResponse | null;
  loading: boolean;
  error: Error | null;
  domains: AttackDomain[];
  selectedActor: Actor | null;
  onDomainsChange: (domains: AttackDomain[]) => void;
  onSelect: (actor: Actor) => void;
  onContinue: () => void;
  onRetry: () => void;
  onNotice: (message: string) => void;
}

const domainOptions: { value: AttackDomain; label: string; description: string }[] = [
  { value: "enterprise", label: "Enterprise", description: "Windows, Linux, macOS, identity, cloud, and network infrastructure" },
  { value: "ics", label: "ICS / OT", description: "Industrial control and operational technology environments" },
  { value: "mobile", label: "Mobile", description: "Android and iOS platforms" },
];

function cleanDescription(value: string): string {
  return value
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/\s*\(Citation:[^)]+\)/gi, "")
    .replace(/\s+/g, " ")
    .trim();
}

function actorSearchText(actor: Actor): string {
  return [actor.name, actor.attack_id, actor.type, ...actor.aliases].join(" ").toLocaleLowerCase();
}

function pluralizeTechniques(count: number): string {
  return `${count} technique${count === 1 ? "" : "s"}`;
}

export function ActorGallery({
  response,
  loading,
  error,
  domains,
  selectedActor,
  onDomainsChange,
  onSelect,
  onContinue,
  onRetry,
  onNotice,
}: ActorGalleryProps): JSX.Element {
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [sort, setSort] = useState<SortOption>("name");

  const actors = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    return [...(response?.actors ?? [])]
      .filter((actor) => typeFilter === "all" || actor.type === typeFilter)
      .filter((actor) => !normalized || actorSearchText(actor).includes(normalized))
      .sort((left, right) => sort === "ttps"
        ? right.technique_count - left.technique_count || left.name.localeCompare(right.name)
        : left.name.localeCompare(right.name));
  }, [query, response, sort, typeFilter]);

  const toggleDomain = (domain: AttackDomain): void => {
    const next = domains.includes(domain)
      ? domains.filter((item) => item !== domain)
      : domainOptions.map((item) => item.value).filter((item) => item === domain || domains.includes(item));
    if (next.length === 0) {
      onNotice("Keep at least one ATT&CK domain selected.");
      return;
    }
    onDomainsChange(next);
  };

  return (
    <section className="screen actor-screen" aria-labelledby="actor-title">
      <div className="screen-heading">
        <div>
          <p className="eyebrow">Step 1 of 4 · Live ATT&amp;CK catalog</p>
          <h1 id="actor-title">Choose a threat actor</h1>
          <p>Select the group or campaign whose publicly documented behavior you want to model in your authorized lab.</p>
        </div>
        <aside className="touch-preview">
          <span>What this does</span>
          <p>Loads ATT&amp;CK technique mappings and curated bounded exercises. Nothing is executed and no target is contacted.</p>
        </aside>
      </div>

      <div className="actor-toolbar">
        <div className="domain-control" id="domainFilter">
          <div className="control-label"><span>ATT&amp;CK domains</span><small>Select one or more</small></div>
          <div aria-label="ATT&CK domains" className="segmented" role="group">
            {domainOptions.map((option) => {
              const active = domains.includes(option.value);
              return (
                <button
                  aria-pressed={active}
                  className={`segmented__button ${active ? "is-on" : ""}`}
                  data-domain={option.value}
                  key={option.value}
                  onClick={() => toggleDomain(option.value)}
                  title={option.description}
                  type="button"
                >
                  {active ? <Icon className="segmented__check" name="check" /> : null}
                  {option.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="catalog-controls">
          <label className="search-field" htmlFor="actorSearch">
            <span className="sr-only">Search actors</span>
            <Icon className="search-icon" name="search" />
            <input
              autoComplete="off"
              id="actorSearch"
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search name, alias, or ATT&CK ID"
              type="search"
              value={query}
            />
            {query ? (
              <button aria-label="Clear actor search" className="search-clear" id="searchClear" onClick={() => setQuery("")} type="button">
                <Icon className="icon" name="close" />
              </button>
            ) : null}
          </label>

          <div aria-label="Actor type" className="segmented segmented--compact" role="group">
            {(["all", "group", "campaign"] as const).map((value) => (
              <button aria-pressed={typeFilter === value} className={`segmented__button ${typeFilter === value ? "is-on" : ""}`} key={value} onClick={() => setTypeFilter(value)} type="button">
                {value === "all" ? "All" : value === "group" ? "Groups" : "Campaigns"}
              </button>
            ))}
          </div>

          <label className="sort-field" htmlFor="sortSel">
            <span>Sort</span>
            <select id="sortSel" onChange={(event) => setSort(event.target.value as SortOption)} value={sort}>
              <option value="name">Name A–Z</option>
              <option value="ttps">Most techniques</option>
            </select>
          </label>
        </div>
      </div>

      {loading ? <LoadingState detail="This usually takes a moment after the cache is ready." label="Loading actors from ATT&CK…" /> : null}
      {error ? <ErrorState message={error.message} onRetry={onRetry} title="The actor catalog could not be loaded" /> : null}

      {!loading && !error ? (
        <>
          <div className="results-line" role="status">
            <span id="actorResults">{actors.length} result{actors.length === 1 ? "" : "s"}</span>
            <span className="results-source">Source · MITRE ATT&amp;CK STIX 2.1</span>
          </div>

          {actors.length ? (
            <div className="actor-grid">
              {actors.map((actor) => {
                const selected = selectedActor?.stix_id === actor.stix_id;
                const description = cleanDescription(actor.description);
                return (
                  <button
                    aria-label={`Select ${actor.name}, ${actor.attack_id}, ${actor.technique_count} techniques`}
                    aria-pressed={selected}
                    className={`actorcard ${selected ? "is-selected" : ""}`}
                    key={actor.stix_id}
                    onClick={() => onSelect(actor)}
                    type="button"
                  >
                    <span className="actorcard__top">
                      <span className="actorcard__identity">
                        <span className="actorcard__monogram" aria-hidden="true">{actor.name.slice(0, 2).toLocaleUpperCase()}</span>
                        <span><strong>{actor.name}</strong><small>{actor.attack_id} · {actor.type}</small></span>
                      </span>
                      <span className="selection-mark" aria-hidden="true"><Icon name="check" /></span>
                    </span>
                    <span className="actorcard__desc">{description || "No ATT&CK summary is available for this actor."}</span>
                    {actor.aliases.length ? <span className="actorcard__aliases"><span>Also known as</span> {actor.aliases.slice(0, 3).join(" · ")}</span> : null}
                    <span className="actorcard__footer">
                      <span className="metric"><strong>{actor.technique_count}</strong><span>mapped techniques</span></span>
                      <span className="coverage-badge"><span aria-hidden="true" />ATT&amp;CK mapped</span>
                    </span>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState
              action={query || typeFilter !== "all" ? <Button onClick={() => { setQuery(""); setTypeFilter("all"); }}>Clear filters</Button> : undefined}
              message={query ? "Try a broader name, alias, or ATT&CK identifier." : "No actors are available for the selected domains."}
              title={query ? "No actors match your search." : "No actors found"}
            />
          )}
        </>
      ) : null}

      <div className="actionbar">
        <div className="actionbar__context">
          <span className={`context-dot ${selectedActor ? "is-ready" : ""}`} aria-hidden="true" />
          <div><span id="actionbarCtx">{selectedActor ? `Selected: ${selectedActor.name}` : "Select a threat actor to continue"}</span><small>{selectedActor ? `${selectedActor.attack_id} · ${pluralizeTechniques(selectedActor.technique_count)}` : "You can change this later without losing safety settings."}</small></div>
        </div>
        <Button disabled={!selectedActor} onClick={onContinue} variant="primary">Continue to scope <Icon className="button-icon" name="arrow-right" /></Button>
      </div>
    </section>
  );
}
