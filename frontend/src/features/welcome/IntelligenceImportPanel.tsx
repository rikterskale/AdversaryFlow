import { useEffect, useState } from "react";

import type { Actor, AttackDomain, IntelligenceImportResponse, ProcedureCandidate } from "../../api/contract";
import { Button } from "../../components/Button";

interface IntelligenceImportPanelProps {
  actors: Actor[];
  domains: AttackDomain[];
  csrfToken: string;
  onImport: (args: {
    file: File;
    source_kind: "csv" | "json";
    source_name: string;
    source_url?: string;
    actor_stix_id: string;
    domains: AttackDomain[];
    csrfToken: string;
  }) => Promise<IntelligenceImportResponse>;
  onNotice: (message: string) => void;
}

function downloadReviewedCase(value: IntelligenceImportResponse): void {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `AdversaryFlow_${value.actor.attack_id}_intelligence-review.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function IntelligenceImportPanel({ actors, domains, csrfToken, onImport, onNotice }: IntelligenceImportPanelProps): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [actorId, setActorId] = useState(actors[0]?.stix_id ?? "");
  const [sourceUrl, setSourceUrl] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [result, setResult] = useState<IntelligenceImportResponse | null>(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    if (!actors.some((actor) => actor.stix_id === actorId)) setActorId(actors[0]?.stix_id ?? "");
  }, [actors, actorId]);

  const importFile = async (): Promise<void> => {
    if (!file || !actorId || working) return;
    if (file.size > 16 * 1024 * 1024) {
      onNotice("Structured input must be no larger than 16 MB");
      return;
    }
    setWorking(true);
    try {
      const next = await onImport({
        file,
        source_kind: file.name.toLocaleLowerCase().endsWith(".csv") ? "csv" : "json",
        source_name: file.name,
        source_url: sourceUrl.trim() || undefined,
        actor_stix_id: actorId,
        domains,
        csrfToken,
      });
      setResult(next);
      onNotice(`Compared ${next.candidates.length} imported ATT&CK mappings`);
    } catch (error: unknown) {
      onNotice(error instanceof Error ? error.message : "Structured intelligence import failed");
    } finally {
      setWorking(false);
    }
  };

  const decide = (candidateId: string, status: "accepted" | "rejected"): void => {
    if (!reviewer.trim()) {
      onNotice("Enter the reviewer name before recording a mapping decision");
      return;
    }
    if (!result) return;
    const now = new Date().toISOString();
    setResult({
      ...result,
      candidates: result.candidates.map((candidate) => candidate.candidate_id !== candidateId ? candidate : {
        ...candidate,
        review_status: status,
        reviewed_by: reviewer.trim().slice(0, 120),
        reviewed_at: now,
        accepted_by: status === "accepted" ? reviewer.trim().slice(0, 120) : "",
        accepted_at: status === "accepted" ? now : "",
      }),
    });
  };

  const techniqueGroups = result ? [
    ["Report only", result.comparison.report_only],
    ["ATT&CK only", result.comparison.attack_only],
    ["Both", result.comparison.both],
  ] as const : [];

  return (
    <section className="intelligence-import">
      <div className="intelligence-import__heading">
        <div><p className="eyebrow">Source-aware mapping review</p><h2>Compare structured ATT&CK input</h2></div>
        <Button onClick={() => setExpanded((value) => !value)} variant="secondary">{expanded ? "Close import" : "Import and compare"}</Button>
      </div>
      <p>Import a CSV, ATT&amp;CK Navigator layer, or STIX 2.1 bundle. Imported mappings start in review; the comparison keeps report input separate from ATT&amp;CK actor mappings.</p>
      {expanded ? (
        <div className="intelligence-import__body">
          <label>Compare against actor or campaign
            <select onChange={(event) => setActorId(event.target.value)} value={actorId}>
              {actors.map((actor) => <option key={actor.stix_id} value={actor.stix_id}>{actor.name} ({actor.attack_id})</option>)}
            </select>
          </label>
          <label>Source URL (optional)
            <input autoComplete="url" maxLength={2000} onChange={(event) => setSourceUrl(event.target.value)} placeholder="https://example.org/report" type="url" value={sourceUrl} />
          </label>
          <label>Structured source
            <input accept=".csv,.json,application/json,text/csv" onChange={(event) => { setFile(event.target.files?.[0] ?? null); setResult(null); }} type="file" />
          </label>
          <div className="intelligence-import__actions"><Button disabled={!file || !actorId || working} onClick={() => { void importFile(); }} variant="primary">{working ? "Comparing…" : "Compare mappings"}</Button></div>
          {result ? (
            <div className="intelligence-review" aria-live="polite">
              <div className="intelligence-review__meta"><strong>{result.source.name}</strong><span>SHA-256 {result.source.sha256}</span><span>ATT&amp;CK {result.data_version}</span></div>
              <div className="intelligence-review__diff">
                {techniqueGroups.map(([label, ids]) => <section key={label}><h3>{label} <span>{ids.length}</span></h3><p>{ids.join(", ") || "None"}</p></section>)}
              </div>
              <label>Reviewer name
                <input maxLength={120} onChange={(event) => setReviewer(event.target.value)} placeholder="Person reviewing mappings" value={reviewer} />
              </label>
              <div className="intelligence-review__list">
                {result.candidates.map((candidate: ProcedureCandidate) => (
                  <article className="intelligence-candidate" key={candidate.candidate_id}>
                    <div className="intelligence-candidate__title"><div><strong>{candidate.technique_id} · {candidate.technique_name}</strong><span>{candidate.tactics.join(", ") || "Tactic not supplied"} · {candidate.platforms.join(", ") || "Platform not supplied"}</span></div><span className={`review-status review-status--${candidate.review_status}`}>{candidate.review_status.replace("_", " ")}</span></div>
                    {!candidate.technique_known ? <p className="callout">This ID is not present in the selected ATT&amp;CK data version.</p> : null}
                    {candidate.procedure ? <p><strong>Procedure / note:</strong> {candidate.procedure}</p> : null}
                    {candidate.evidence_quote ? <blockquote>{candidate.evidence_quote}</blockquote> : <p className="muted">No report quotation was included in the structured source.</p>}
                    <p className="intelligence-candidate__source">Source: {candidate.source_name}{candidate.source_url ? <> · <a href={candidate.source_url} rel="noreferrer" target="_blank">open source</a></> : " · no source URL"} · catalog: {candidate.catalog_source}</p>
                    {candidate.abilities.length ? <p className="intelligence-candidate__source">Ability fidelity: {candidate.abilities.map((ability) => `${ability.platform} ${ability.fidelity} (${ability.review_status})`).join(" · ")}</p> : null}
                    <div className="intelligence-candidate__actions"><Button disabled={candidate.review_status === "accepted"} onClick={() => decide(candidate.candidate_id, "accepted")} variant="secondary">Accept mapping</Button><Button disabled={candidate.review_status === "rejected"} onClick={() => decide(candidate.candidate_id, "rejected")} variant="ghost">Reject</Button></div>
                  </article>
                ))}
              </div>
              <Button disabled={!result.candidates.some((item) => item.review_status !== "needs_review")} onClick={() => downloadReviewedCase(result)} variant="primary">Download reviewed mapping record</Button>
              <p className="muted">This record captures analyst decisions for the imported mappings. It does not execute commands or add the mappings to an engagement plan yet.</p>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
