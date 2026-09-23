import { useCallback, useEffect, useMemo, useState } from "react";

import type { Actor, WorkflowResponse } from "../../api/contract";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { consumeStorageWriteFailure, useWizardStore } from "../../state/wizardStore";
import { useWorkspaceEvidence } from "../../state/useWorkspaceEvidence";
import { buildPlanPreview, tacticDescriptions, titlePlatform, type PlanPreview, type ScopedTechnique } from "../scope/scopeModel";
import { CoverageHeatmap } from "./CoverageHeatmap";
import { isMarkedRun, type ExecutionEvidence } from "./evidence";
import { TechniqueCard } from "./TechniqueCard";

interface ReviewScreenProps {
  actor: Actor;
  workflow: WorkflowResponse;
  onBack: () => void;
  onFinish: () => void;
  onNotice: (message: string) => void;
}

interface FirstLabCandidate {
  stageIndex: number;
  technique: ScopedTechnique;
}

interface PendingCopy {
  value: string;
  risk: string;
}

const preferredFirstLab: Record<string, string[]> = {
  windows: ["T1059.001", "T1059.003", "T1059.006"],
  linux: ["T1059.006", "T1059.004"],
  macos: ["T1059.006", "T1059.004"],
};

function firstLabCommand(plan: PlanPreview, platform: string): FirstLabCandidate | null {
  const preferred = preferredFirstLab[platform] ?? [];
  const candidates: (FirstLabCandidate & { preference: number })[] = [];
  plan.stages.forEach((stage, stageIndex) => {
    stage.techniques.forEach((technique) => {
      const command = technique.selectedCommand;
      if (command.unsupported || command.fidelity === "bounded_synthetic") return;
      if (command.risk === "high" || command.acknowledgment_required || command.requires_admin || command.requires_network) return;
      const preferredIndex = preferred.indexOf(technique.attack_id);
      candidates.push({ stageIndex, technique, preference: preferredIndex < 0 ? 100 : preferredIndex });
    });
  });
  candidates.sort((left, right) => left.preference - right.preference || left.stageIndex - right.stageIndex);
  return candidates[0] ?? null;
}

function cardForTechnique(techniqueId: string): HTMLElement | null {
  return document.querySelector<HTMLElement>(`.techcard[data-tid="${CSS.escape(techniqueId)}"]`);
}

export function ReviewScreen({ actor, workflow, onBack, onFinish, onNotice }: ReviewScreenProps): React.JSX.Element {
  const scope = useWizardStore((state) => state.scope);
  const records = useWorkspaceEvidence(actor, workflow);
  const updateEvidence = useWizardStore((state) => state.updateEvidence);
  const plan = useMemo(() => buildPlanPreview(workflow, scope), [scope, workflow]);
  const firstLab = useMemo(() => firstLabCommand(plan, scope.commandPlatform), [plan, scope.commandPlatform]);
  const firstRunnableStage = Math.max(0, plan.stages.findIndex((stage) => stage.techniques.some((technique) => !technique.selectedCommand.unsupported)));
  const [activeStage, setActiveStage] = useState(() => firstLab?.stageIndex ?? firstRunnableStage);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const [focusTarget, setFocusTarget] = useState<string | null>(null);
  const [pendingCopy, setPendingCopy] = useState<PendingCopy | null>(null);
  const [saveFailed, setSaveFailed] = useState(false);

  useEffect(() => {
    if (activeStage >= plan.stages.length) setActiveStage(0);
  }, [activeStage, plan.stages.length]);

  const stage = plan.stages[activeStage];
  const stageTechniques = useMemo(() => {
    if (!stage) return [];
    return [...stage.techniques].sort((left, right) => {
      const supportOrder = Number(Boolean(left.selectedCommand.unsupported)) - Number(Boolean(right.selectedCommand.unsupported));
      if (supportOrder) return supportOrder;
      if (!firstLab || firstLab.stageIndex !== activeStage) return 0;
      if (left.attack_id === firstLab.technique.attack_id) return -1;
      if (right.attack_id === firstLab.technique.attack_id) return 1;
      return 0;
    });
  }, [activeStage, firstLab, stage]);

  useEffect(() => {
    const targetIndex = focusTarget ? stageTechniques.findIndex((technique) => technique.attack_id === focusTarget) : 0;
    const nextIndex = Math.max(0, targetIndex);
    const moveDomFocus = Boolean(focusTarget);
    setFocusedIndex(nextIndex);
    setFocusTarget(null);
    window.requestAnimationFrame(() => {
      const card = cardForTechnique(stageTechniques[nextIndex]?.attack_id ?? "");
      if (moveDomFocus) card?.focus({ preventScroll: true });
      card?.scrollIntoView({ block: "nearest" });
    });
  }, [activeStage, focusTarget, stageTechniques]);

  const runnableIds = useMemo(() => new Set(plan.stages.flatMap((item) => item.techniques.filter((technique) => !technique.selectedCommand.unsupported).map((technique) => technique.attack_id))), [plan.stages]);
  const done = [...runnableIds].filter((id) => isMarkedRun(records[id])).length;
  const detectionsAssessed = [...runnableIds].filter((id) => {
    const result = records[id]?.detection_result;
    return Boolean(result && result !== "not_assessed");
  }).length;
  const progress = runnableIds.size ? Math.round((done / runnableIds.size) * 100) : 0;
  const focusedTechnique = stageTechniques[focusedIndex] ?? null;

  const persistEvidence = (techniqueId: string, patch: Partial<ExecutionEvidence>): void => {
    updateEvidence(techniqueId, patch);
    if (consumeStorageWriteFailure()) {
      setSaveFailed(true);
      onNotice("Progress can't be saved in this browser — export the plan to keep your records");
    } else {
      setSaveFailed(false);
    }
  };

  const writeClipboard = useCallback(async (value: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(value);
      onNotice("Command copied to clipboard");
    } catch {
      onNotice("Clipboard access was denied. Select the command text and copy it manually.");
    }
  }, [onNotice]);

  const requestCopy = useCallback((technique: ScopedTechnique, value: string, kind: "command" | "cleanup"): void => {
    if (technique.selectedCommand.untrusted || (kind === "command" && technique.selectedCommand.acknowledgment_required)) {
      setPendingCopy({ value, risk: technique.selectedCommand.untrusted ? "unverified imported" : technique.selectedCommand.risk });
      return;
    }
    void writeClipboard(value);
  }, [writeClipboard]);

  const moveFocus = useCallback((next: number): void => {
    const bounded = Math.max(0, Math.min(next, stageTechniques.length - 1));
    setFocusedIndex(bounded);
    const id = stageTechniques[bounded]?.attack_id;
    if (id) {
      const card = cardForTechnique(id);
      card?.focus({ preventScroll: true });
      window.requestAnimationFrame(() => card?.scrollIntoView({ block: "nearest", behavior: "smooth" }));
    }
  }, [stageTechniques]);

  useEffect(() => {
    const handleKeys = (event: KeyboardEvent): void => {
      if (event.altKey || event.ctrlKey || event.metaKey || pendingCopy) return;
      if (event.target instanceof HTMLElement && event.target.matches("input,select,textarea,a,button,[contenteditable]")) return;
      if (event.key.toLocaleLowerCase() === "j") { event.preventDefault(); moveFocus(focusedIndex + 1); }
      if (event.key.toLocaleLowerCase() === "k") { event.preventDefault(); moveFocus(focusedIndex - 1); }
      if (event.key.toLocaleLowerCase() === "c" && focusedTechnique && !focusedTechnique.selectedCommand.unsupported) {
        event.preventDefault();
        requestCopy(focusedTechnique, focusedTechnique.selectedCommand.command, "command");
      }
    };
    document.addEventListener("keydown", handleKeys);
    return () => document.removeEventListener("keydown", handleKeys);
  }, [focusedIndex, focusedTechnique, moveFocus, pendingCopy, requestCopy]);

  const selectStage = (index: number, techniqueId: string | null = null): void => {
    setActiveStage(index);
    setFocusTarget(techniqueId);
  };

  return (
    <section className="screen review-screen" aria-labelledby="plan-title">
      <header className="plan-header">
        <div><p className="eyebrow">Step 3 of 4 · Review and track</p><h1 id="plan-title">{actor.name} · {actor.attack_id}</h1><p id="planActorMeta">Authorized lab plan · commands target <strong>{titlePlatform(scope.commandPlatform)}</strong> · every copy remains operator initiated</p></div>
        <div className="plan-progress">
          <div aria-label="Runnable technique progress" aria-valuemax={100} aria-valuemin={0} aria-valuenow={progress} aria-valuetext={`${done} of ${runnableIds.size} runnable techniques`} className="progress-ring" id="progressRing" role="progressbar" style={{ "--progress": `${progress * 3.6}deg` } as React.CSSProperties}><span id="progressPct">{progress}%</span></div>
          <div><strong id="progressCount">{done} / {runnableIds.size}</strong><span>techniques recorded</span><small className="detection-progress">{detectionsAssessed} / {runnableIds.size} detections assessed</small><small className={saveFailed ? "is-error" : ""} id="saveStatus">{saveFailed ? "Not saved in this browser" : "Saved in this browser"}</small></div>
        </div>
      </header>

      <ol className="plan-coach">
        <li><span>1</span><p><strong>Review impact</strong>Confirm risk, privilege, network, telemetry, and rollback.</p></li>
        <li><span>2</span><p><strong>Copy deliberately</strong>Paste only on the authorized disposable lab host.</p></li>
        <li><span>3</span><p><strong>Record evidence</strong>Track command and detection results separately.</p></li>
      </ol>

      <CoverageHeatmap onSelect={(stageIndex, technique) => selectStage(stageIndex, technique.attack_id)} plan={plan} records={records} selectedTechniqueId={focusedTechnique?.attack_id ?? null} />

      {firstLab && firstLab.stageIndex === activeStage ? <div className="first-lab-hint" id="firstLabHint"><strong>Try this first:</strong> {firstLab.technique.attack_id} {firstLab.technique.name} is a low-risk direct lab action. Review its impact, then copy it to your lab host.</div> : <div hidden id="firstLabHint" />}

      <div className="plan-layout">
        <nav aria-label="Kill-chain stages" className="plan-rail">
          {plan.stages.map((item, index) => {
            const runnable = item.techniques.filter((technique) => !technique.selectedCommand.unsupported);
            const stageDone = runnable.filter((technique) => isMarkedRun(records[technique.attack_id])).length;
            return <button aria-current={index === activeStage ? "step" : undefined} className={`railitem ${index === activeStage ? "is-active" : ""}`} key={item.tactic} onClick={() => selectStage(index)} type="button"><span className="railitem__num">{index + 1}</span><span className="railitem__name">{item.title}</span><span className="railitem__meta">{stageDone}/{runnable.length}</span>{runnable.length > 0 && stageDone === runnable.length ? <span className="railitem__done"><Icon name="check" /></span> : null}</button>;
          })}
        </nav>

        <div className="stage-panel">
          {stage ? <><div className="stagepanel__head"><span>{activeStage + 1}</span><div><h3>{stage.title}</h3><p>{tacticDescriptions[stage.tactic] ?? "Mapped ATT&CK tactic."} · {stage.techniques.length} technique{stage.techniques.length === 1 ? "" : "s"}</p></div></div><p className="kbdhint">Keyboard: <kbd>j</kbd>/<kbd>k</kbd> move between techniques · <kbd>c</kbd> copies the focused command</p><div className="techlist">{stageTechniques.map((technique, index) => <TechniqueCard evidence={records[technique.attack_id]} firstLab={firstLab?.technique.attack_id === technique.attack_id} focused={index === focusedIndex} key={technique.attack_id} onCopy={(value, kind) => requestCopy(technique, value, kind)} onFocus={() => setFocusedIndex(index)} onNotice={onNotice} onUpdate={(patch) => persistEvidence(technique.attack_id, patch)} technique={technique} />)}</div><div className="stage-nav"><Button disabled={activeStage === 0} onClick={() => selectStage(activeStage - 1)} variant="ghost"><Icon className="button-icon" name="arrow-left" /> Previous stage</Button><Button disabled={activeStage >= plan.stages.length - 1} onClick={() => selectStage(activeStage + 1)}>Next stage <Icon className="button-icon" name="arrow-right" /></Button></div></> : <div className="empty-state"><h3>No techniques in scope</h3><p>Return to Scope and enable at least one kill-chain stage.</p></div>}
        </div>
      </div>

      <div className="actionbar review-actionbar">
        <Button onClick={onBack} variant="ghost"><Icon className="button-icon" name="arrow-left" /> Back</Button>
        <div aria-live="polite" className="actionbar__context"><span className={`context-dot ${done ? "is-ready" : ""}`} aria-hidden="true" /><div><span id="actionbarCtx">{plan.stages.length ? `${done} / ${runnableIds.size} runnable techniques marked run` : "No techniques in scope"}</span><small>{plan.stages.length ? "Evidence autosaves locally · export when this review is complete" : "Return to Scope Engagement and enable a stage before exporting."}</small></div></div>
        <Button disabled={!plan.stages.length} onClick={onFinish} variant="primary">Finish &amp; export <Icon className="button-icon" name="arrow-right" /></Button>
      </div>

      <Dialog description="Review prerequisites, side effects, telemetry, and rollback in the technique card before copying. AdversaryFlow does not execute this command." onClose={() => setPendingCopy(null)} open={Boolean(pendingCopy)} title={`Copy this ${pendingCopy?.risk ?? ""} risk lab command?`}>
        <pre className="confirm-command">{pendingCopy?.value}</pre>
        <div className="dialog-actions"><Button onClick={() => setPendingCopy(null)} variant="ghost">Cancel</Button><Button onClick={() => { if (pendingCopy) void writeClipboard(pendingCopy.value); setPendingCopy(null); }} variant="primary">Copy command</Button></div>
      </Dialog>
    </section>
  );
}
