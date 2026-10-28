import { isRecord } from "../../api/guards";

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function TelemetryAcceptance({ value, techniqueId }: { value: unknown; techniqueId: string }): React.JSX.Element | null {
  if (!isRecord(value) || value.technique_id !== techniqueId) return null;
  const requirements = strings(value.requirements);
  const eventTypes = strings(value.activity_event_types);
  if (!requirements.length || !eventTypes.length || !Number.isInteger(value.minimum_activity_events) || Number(value.minimum_activity_events) < 1) return null;
  return (
    <section aria-label={`Independent telemetry requirements for ${techniqueId}`} className="callout">
      <strong>Independent telemetry requirements</strong>
      <ol>{requirements.map((requirement, index) => <li key={index}>{requirement}</li>)}</ol>
      <p><strong>Activity events:</strong> {eventTypes.join(", ")} · at least {Number(value.minimum_activity_events)} in the receipt window.</p>
      {typeof value.limitation === "string" ? <p>{value.limitation}</p> : null}
      <p>Use <code>adversaryflow-telemetry correlate --receipt receipt.json --telemetry events.json</code> with your saved receipt and endpoint or SIEM export. Record the resulting event references below.</p>
    </section>
  );
}
