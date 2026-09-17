import type { ExecutionEvidence } from "./evidence";
import { isMarkedRun } from "./evidence";
import type { PlanPreview, ScopedTechnique } from "../scope/scopeModel";

interface CoverageHeatmapProps {
  plan: PlanPreview;
  records: Record<string, ExecutionEvidence>;
  selectedTechniqueId: string | null;
  onSelect: (stageIndex: number, technique: ScopedTechnique) => void;
}

type CellStatus = "planned" | "ran" | "detected" | "silent";

export function coverageStatus(evidence: ExecutionEvidence | undefined): CellStatus {
  if (evidence?.detection_result === "alerted" || evidence?.detection_result === "blocked") return "detected";
  if (evidence?.detection_result === "silent") return "silent";
  if (isMarkedRun(evidence)) return "ran";
  return "planned";
}

export function CoverageHeatmap({ plan, records, selectedTechniqueId, onSelect }: CoverageHeatmapProps): JSX.Element {
  return (
    <section className="heatmap-panel" aria-labelledby="heatmap-title">
      <div className="heatmap-heading">
        <div><p className="eyebrow">ATT&amp;CK coverage</p><h2 id="heatmap-title">Technique matrix</h2><p>Coverage source forms the cell color; execution and detection evidence adds the status marker.</p></div>
        <div className="heatmap-legend" aria-label="Coverage legend">
          <span><i className="legend-square is-curated" />Curated</span>
          <span><i className="legend-square is-fallback" />Fallback</span>
          <span><i className="legend-ring is-ran" />Ran</span>
          <span><i className="legend-ring is-detected" />Detected</span>
          <span><i className="legend-ring is-silent" />Silent</span>
        </div>
      </div>
      <div className="heatmap-scroll" tabIndex={0}>
        <div className="heatmap-matrix" style={{ gridTemplateColumns: `repeat(${Math.max(1, plan.stages.length)}, minmax(150px, 1fr))` }}>
          {plan.stages.map((stage, stageIndex) => (
            <div className="heatmap-column" key={stage.tactic}>
              <div className="heatmap-column__head"><strong>{stage.title}</strong><span>{stage.techniques.length}</span></div>
              <div className="heatmap-cells">
                {stage.techniques.map((technique) => {
                  const status = coverageStatus(records[technique.attack_id]);
                  const source = technique.command_source === "fallback" ? "fallback" : "curated";
                  const selected = technique.attack_id === selectedTechniqueId;
                  return (
                    <button
                      aria-label={`${technique.attack_id} ${technique.name}, ${source} coverage, ${status}`}
                      className={`heatmap-cell coverage-${source} status-${status} ${selected ? "is-selected" : ""}`}
                      key={`${stage.tactic}-${technique.attack_id}`}
                      onClick={() => onSelect(stageIndex, technique)}
                      title={`${technique.attack_id} · ${technique.name}`}
                      type="button"
                    >
                      <span>{technique.attack_id}</span><i aria-hidden="true" />
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
