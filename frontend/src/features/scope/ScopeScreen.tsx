import { useEffect, useMemo } from "react";

import type { Actor, WorkflowResponse } from "../../api/contract";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useWizardStore } from "../../state/wizardStore";
import {
  buildPlanPreview,
  detectedPlatform,
  preCompromiseTactics,
  tacticDescriptions,
  type CommandPlatform,
} from "./scopeModel";

interface ScopeScreenProps {
  actor: Actor;
  workflow: WorkflowResponse;
  onBack: () => void;
  onBuild: () => void;
}

const platformOptions: { value: CommandPlatform; label: string; detail: string }[] = [
  { value: "windows", label: "Windows", detail: "PowerShell and Windows command-line exercises" },
  { value: "linux", label: "Linux", detail: "POSIX shell and Linux-native exercises" },
  { value: "macos", label: "macOS", detail: "Shell and macOS-native exercises" },
];

function titlePlatform(platform: CommandPlatform): string {
  return platform === "macos" ? "macOS" : `${platform[0]?.toLocaleUpperCase() ?? ""}${platform.slice(1)}`;
}

function GuardrailToggle({
  id,
  checked,
  title,
  description,
  tone = "default",
  onChange,
}: {
  id: string;
  checked: boolean;
  title: string;
  description: string;
  tone?: "default" | "warning";
  onChange: (checked: boolean) => void;
}): JSX.Element {
  return (
    <label className={`toggle ${tone === "warning" ? "toggle--warning" : ""}`} htmlFor={id}>
      <input checked={checked} id={id} onChange={(event) => onChange(event.target.checked)} type="checkbox" />
      <span aria-hidden="true" className="toggle__track"><span className="toggle__thumb" /></span>
      <span className="toggle__text"><strong>{title}</strong><span>{description}</span></span>
    </label>
  );
}

export function ScopeScreen({ actor, workflow, onBack, onBuild }: ScopeScreenProps): JSX.Element {
  const scope = useWizardStore((state) => state.scope);
  const initializeScope = useWizardStore((state) => state.initializeScope);
  const updateScope = useWizardStore((state) => state.updateScope);
  const availableTactics = workflow.kill_chain
    .filter((item) => workflow.stages.some((stage) => stage.tactic === item.tactic))
    .map((item) => item.tactic);

  useEffect(() => {
    initializeScope(actor.stix_id, availableTactics);
  }, [actor.stix_id, availableTactics.join("|"), initializeScope]);

  const preview = useMemo(() => buildPlanPreview(workflow, scope), [scope, workflow]);
  const browserPlatform = detectedPlatform();
  const selectableTactics = availableTactics.filter((tactic) => scope.includePre || !preCompromiseTactics.has(tactic));
  const allSelected = selectableTactics.length > 0 && selectableTactics.every((tactic) => scope.tactics.includes(tactic));

  const toggleTactic = (tactic: string): void => {
    updateScope({
      tactics: scope.tactics.includes(tactic)
        ? scope.tactics.filter((item) => item !== tactic)
        : availableTactics.filter((item) => item === tactic || scope.tactics.includes(item)),
    });
  };

  const toggleAllTactics = (): void => {
    updateScope({
      tactics: allSelected
        ? scope.tactics.filter((tactic) => !selectableTactics.includes(tactic))
        : availableTactics.filter((tactic) => scope.tactics.includes(tactic) || selectableTactics.includes(tactic)),
    });
  };

  const contextText = preview.total === 0
    ? "No techniques in scope — enable a stage"
    : `${preview.runnable} runnable · ${preview.unsupported} unsupported across ${preview.stages.length} stages`;
  const curatedWidth = preview.total ? `${(preview.curated / preview.total) * 100}%` : "0%";
  const fallbackWidth = preview.total ? `${(preview.fallback / preview.total) * 100}%` : "0%";

  return (
    <section className="screen scope-screen" aria-labelledby="scope-title">
      <div className="screen-heading scope-heading">
        <div>
          <p className="eyebrow">Step 2 of 4 · Operator guardrails</p>
          <h1 id="scope-title">Scope the engagement</h1>
          <p>Choose the disposable lab host OS and explicitly opt in to anything that raises privilege, network, or impact risk.</p>
        </div>
        <aside className="touch-preview">
          <span>What this will touch</span>
          <p>Only the exported plan changes here. Commands stay blocked until an operator reviews and copies them on the lab host.</p>
        </aside>
      </div>

      <div className="scope-layout">
        <div className="scope-main">
          <section className="scope-panel">
            <div className="scope-panel__heading"><span className="panel-number">01</span><div><h2>Command platform</h2><p>Exact-platform matching only. AdversaryFlow never substitutes a Windows command for Linux or macOS.</p></div></div>
            <div className="platform-grid" id="cmdPlatform" role="group" aria-label="Command platform">
              {platformOptions.map((option) => {
                const selected = scope.commandPlatform === option.value;
                return (
                  <button aria-label={option.label} aria-pressed={selected} className="platform-option" key={option.value} onClick={() => updateScope({ commandPlatform: option.value })} type="button">
                    <span className="platform-option__check"><Icon name="check" /></span>
                    <strong className={selected ? "is-on" : ""}>{option.label}</strong><span>{option.detail}</span>
                  </button>
                );
              })}
            </div>
            <div className="platform-hint" hidden={browserPlatform === scope.commandPlatform} id="platformHint">
              <span>This browser looks like <strong>{titlePlatform(browserPlatform)}</strong>; commands currently target <strong>{titlePlatform(scope.commandPlatform)}</strong>.</span>
              <button onClick={() => updateScope({ commandPlatform: browserPlatform })} type="button">Use {titlePlatform(browserPlatform)}</button>
            </div>
          </section>

          <section className="scope-panel">
            <div className="scope-panel__heading scope-panel__heading--action"><span className="panel-number">02</span><div><h2>Kill-chain stages</h2><p>All documented tactics are included by default. Remove stages that are outside this engagement.</p></div><button className="text-button" id="stagesAll" onClick={toggleAllTactics} type="button">{allSelected ? "Clear all" : "Select all"}</button></div>
            <div aria-label="Kill-chain stages" className="tactic-grid" id="tacticGrid" role="group">
              {workflow.kill_chain.map((item, index) => {
                const stage = workflow.stages.find((candidate) => candidate.tactic === item.tactic);
                if (!stage) return null;
                const disabled = !scope.includePre && preCompromiseTactics.has(item.tactic);
                const selected = scope.tactics.includes(item.tactic) && !disabled;
                const hue = Math.round(240 - (index / Math.max(1, workflow.kill_chain.length - 1)) * 225);
                return (
                  <button
                    aria-pressed={selected}
                    className={`tactic-chip ${selected ? "is-on" : ""}`}
                    disabled={disabled}
                    key={item.tactic}
                    onClick={() => toggleTactic(item.tactic)}
                    type="button"
                  >
                    <span className="tactic-chip__line" style={{ backgroundColor: `hsl(${hue} 70% 60%)` }} />
                    <span className="tactic-chip__body"><strong>{item.title}</strong><span>{tacticDescriptions[item.tactic] ?? "Mapped ATT&CK tactic."}</span></span>
                    <span className="tactic-chip__count">{stage.techniques.length}</span>
                    <span className="tactic-chip__check"><Icon name="check" /></span>
                  </button>
                );
              })}
            </div>
          </section>

          <section className="scope-panel">
            <div className="scope-panel__heading"><span className="panel-number">03</span><div><h2>Safety guardrails</h2><p>Conservative defaults keep elevated, network-active, and high-risk commands out of the runnable plan.</p></div></div>
            <div className="safe-defaults" role="status"><Icon name="shield" /><p><strong>Safe defaults active</strong>Nothing below is enabled unless you choose it.</p></div>
            <div className="toggle-list">
              <GuardrailToggle checked={scope.allowNetwork} description="Permits catalog commands that contact a documented host or service." id="optNetwork" onChange={(allowNetwork) => updateScope({ allowNetwork })} title="Allow network-active commands" />
              <GuardrailToggle checked={scope.allowAdmin} description="Permits commands that require administrator or root privileges." id="optAdmin" onChange={(allowAdmin) => updateScope({ allowAdmin })} title="Allow administrator commands" />
              <GuardrailToggle checked={scope.allowHighRisk} description="Permits catalog commands marked high risk or potentially disruptive." id="optHighRisk" onChange={(allowHighRisk) => updateScope({ allowHighRisk })} title="Allow high-risk commands" tone="warning" />
              <GuardrailToggle checked={scope.includePre} description="Includes Reconnaissance and Resource Development before host access." id="optPre" onChange={(includePre) => updateScope({ includePre })} title="Include pre-compromise tactics" />
              <GuardrailToggle checked={scope.curatedOnly} description="Excludes generated fallback coverage and keeps curated exercises only." id="optCurated" onChange={(curatedOnly) => updateScope({ curatedOnly })} title="Curated tests only" />
            </div>
          </section>

          <section className="scope-panel">
            <div className="scope-panel__heading"><span className="panel-number">04</span><div><h2>Execution record</h2><p>Optional context stored with browser progress and exports. Do not enter credentials or secrets.</p></div></div>
            <div className="field-grid">
              <label htmlFor="recordOperator"><span>Operator or team</span><input autoComplete="off" id="recordOperator" maxLength={120} onChange={(event) => updateScope({ operator: event.target.value })} placeholder="Purple team" type="text" value={scope.operator} /></label>
              <label htmlFor="recordTarget"><span>Target</span><input autoComplete="off" id="recordTarget" maxLength={200} onChange={(event) => updateScope({ target: event.target.value })} placeholder="Disposable lab identifier, for example lab-host-01" type="text" value={scope.target} /></label>
            </div>
          </section>
        </div>

        <aside className="scope-summary" id="scopeSummary">
          <div className="summary-status"><span className={preview.runnable ? "is-ready" : ""} aria-hidden="true" /><div><p>Live plan preview</p><strong>{preview.runnable ? `${preview.runnable} lab tests ready` : "No runnable tests"}</strong></div></div>
          <div className="summary-actor"><span>{actor.attack_id}</span><div><strong>{actor.name}</strong><p>{workflow.metadata.data_version}</p></div></div>
          <dl className="summary-metrics">
            <div><dt>Techniques</dt><dd>{preview.total}</dd></div>
            <div><dt>Runnable on {titlePlatform(scope.commandPlatform)}</dt><dd>{preview.runnable}</dd></div>
            <div><dt>Unsupported or withheld</dt><dd>{preview.unsupported}</dd></div>
            <div><dt>Kill-chain stages</dt><dd>{preview.stages.length}</dd></div>
          </dl>
          <div className="coverage-summary">
            <div className="coverage-summary__bar"><span className="is-curated" style={{ width: curatedWidth }} /><span className="is-fallback" style={{ width: fallbackWidth }} /></div>
            <div><span><i className="legend-dot legend-dot--curated" />{preview.curated} curated</span><span><i className="legend-dot legend-dot--fallback" />{preview.fallback} fallback</span></div>
          </div>
          <div className="summary-boundary"><Icon name="shield" /><p><strong>Planner boundary intact</strong>No commands execute from this service.</p></div>
        </aside>
      </div>

      <div className="actionbar scope-actionbar">
        <Button onClick={onBack} variant="ghost"><Icon className="button-icon" name="arrow-left" /> Back</Button>
        <div className="actionbar__context"><span className={`context-dot ${preview.runnable ? "is-ready" : ""}`} aria-hidden="true" /><div><span id="actionbarCtx">{contextText}</span><small>{preview.runnable ? `Commands target ${titlePlatform(scope.commandPlatform)} · review remains required before copy` : "Adjust platform, stages, or guardrails to continue."}</small></div></div>
        <Button disabled={preview.runnable === 0} onClick={onBuild} variant="primary">Build plan <Icon className="button-icon" name="arrow-right" /></Button>
      </div>
    </section>
  );
}
