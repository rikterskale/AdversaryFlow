import type { Command } from "../../api/contract";

interface TouchPreviewProps {
  command: Command;
  techniqueId: string;
}

export function titleMetadataValue(value: string): string {
  return value.split("_").map((part) => part ? `${part[0]?.toLocaleUpperCase() ?? ""}${part.slice(1)}` : "").join(" ");
}

function cleanupText(command: Command): string {
  if (command.cleanup) return command.cleanup;
  if (command.cleanup_required) return "Required, but no cleanup command is supplied";
  return "No cleanup action specified";
}

export function TouchPreview({ command, techniqueId }: TouchPreviewProps): JSX.Element {
  const headingId = `touch-preview-${techniqueId.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
  return (
    <section aria-labelledby={headingId} className={`preaction ${command.unsupported ? "preaction--unsupported" : ""}`}>
      <div className="preaction__head"><h4 id={headingId}>What this will touch</h4><strong>Review before copy</strong></div>
      <dl className="preaction__grid">
        <div><dt>Risk</dt><dd><span className={`riskvalue riskvalue--${command.risk}`}>{titleMetadataValue(command.risk)}</span></dd></div>
        <div><dt>Privilege</dt><dd>{command.requires_admin ? "Administrator / root" : "Standard user"}</dd></div>
        <div><dt>Network</dt><dd>{command.requires_network ? command.network_targets.join(", ") || "Network active" : "No network required"}</dd></div>
        <div><dt>Expected telemetry</dt><dd>{command.expected_telemetry || "Relevant endpoint telemetry"}</dd></div>
        <div className="preaction__wide"><dt>Prerequisites</dt><dd>{command.prerequisites.length ? command.prerequisites.join("; ") : "No additional prerequisites"}</dd></div>
        <div><dt>Rollback</dt><dd>{command.rollback || "No rollback action specified"}</dd></div>
        <div><dt>Cleanup</dt><dd>{cleanupText(command)}</dd></div>
      </dl>
      {command.side_effects.length ? <p><strong>Side effects</strong>{command.side_effects.map(titleMetadataValue).join(" · ")}</p> : null}
    </section>
  );
}
