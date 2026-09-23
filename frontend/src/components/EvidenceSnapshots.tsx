import { buildExportBundle } from "../features/export/exportModel";
import { titlePlatform } from "../features/scope/scopeModel";
import { useWizardStore } from "../state/wizardStore";
import { Button } from "./Button";

export function EvidenceSnapshots(): React.JSX.Element | null {
  const archive = useWizardStore((state) => state.evidenceArchive);
  const activeKey = useWizardStore((state) => state.evidenceKey);
  const restore = useWizardStore((state) => state.restoreEvidence);
  const entries = Object.entries(archive).filter(([key]) => key !== activeKey);
  if (!entries.length) return null;
  return <details className="callout workspace-notice"><summary>Saved evidence from other platforms or data versions ({entries.length})</summary>
    <p>Earlier results are preserved separately. Restore a snapshot to review it, or download it for safekeeping.</p>
    {entries.map(([key, snapshot]) => <div className="evidence-snapshot" key={key}>
      <span>{titlePlatform(snapshot.scope.commandPlatform)} · {key.split("|").slice(2, -1).join("|")} · {Object.keys(snapshot.records).length} {Object.keys(snapshot.records).length === 1 ? "record" : "records"}</span>
      <Button disabled={!snapshot.workflow || !snapshot.actor} onClick={() => restore(key)}>Restore snapshot</Button>
      <Button onClick={() => {
        const document = snapshot.actor && snapshot.workflow
          ? buildExportBundle(snapshot.actor, snapshot.workflow, snapshot.scope, snapshot.records, snapshot.domains).plan
          : { evidence_identity: key, records: snapshot.records };
        const url = URL.createObjectURL(new Blob([JSON.stringify(document, null, 2)], { type: "application/json" }));
        const link = window.document.createElement("a");
        link.href = url; link.download = "AdversaryFlow_saved_evidence.json"; link.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      }}>Download snapshot</Button>
    </div>)}
  </details>;
}
