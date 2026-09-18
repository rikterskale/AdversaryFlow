import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { getDoctor } from "../api/client";
import type { ActorsResponse, AttackDomain, DoctorResponse, HealthResponse, SessionResponse } from "../api/contract";
import { displayScalar } from "../api/guards";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { useWizardStore, type WizardStep } from "../state/wizardStore";

type Theme = "dark" | "light";

interface AppShellProps {
  children: ReactNode;
  session: SessionResponse | null;
  health: HealthResponse | null;
  healthFailed: boolean;
  setupFailed: boolean;
  actors: ActorsResponse | null;
  domains: AttackDomain[];
  onRefresh: () => Promise<void>;
  refreshing: boolean;
}

const steps: { step: WizardStep; label: string; shortLabel: string }[] = [
  { step: 1, label: "Choose threat actor", shortLabel: "Threat actor" },
  { step: 2, label: "Scope engagement", shortLabel: "Scope" },
  { step: 3, label: "Review and track plan", shortLabel: "Emulation plan" },
  { step: 4, label: "Export kit", shortLabel: "Export" },
];

const domainLabels: Record<AttackDomain, string> = {
  enterprise: "Enterprise",
  ics: "Ics",
  mobile: "Mobile",
};

function initialTheme(): Theme {
  try {
    const stored = localStorage.getItem("adversaryflow-theme");
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // Storage can be unavailable in hardened or private browser contexts.
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function diagnosticTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "time unavailable";
  return parsed.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

interface HealthDetailsProps extends Pick<AppShellProps, "health" | "actors" | "healthFailed"> {
  doctor: DoctorResponse | null;
  doctorError: Error | null;
  doctorLoading: boolean;
  onRetryDoctor: () => void;
}

function HealthDetails({ health, actors, healthFailed, doctor, doctorError, doctorLoading, onRetryDoctor }: HealthDetailsProps): React.JSX.Element {
  const cacheVersion = health ? displayScalar(health.attack_data, "data_version") : null;
  const source = health ? displayScalar(health.attack_data, "source") : null;
  const serviceMode = health ? displayScalar(health.service, "bind_mode") : null;
  const advisoryFailures = doctor?.checks.filter((check) => !check.required && check.status === "FAIL").length ?? 0;
  const doctorTone = !doctor?.ok ? "is-fail" : advisoryFailures ? "is-warn" : "is-pass";
  const rerunLabel = doctorLoading
    ? "Running self-test…"
    : doctorError
      ? "Retry self-test"
      : doctor
        ? "Run self-test again"
        : "Run self-test";
  return (
    <>
      <div className="health-grid">
        <div><span>Service</span><strong>{health?.status ?? (healthFailed ? "Unavailable" : "Checking")}</strong></div>
        <div><span>ATT&amp;CK phase</span><strong>{health?.phase.replaceAll("_", " ") ?? "Unknown"}</strong></div>
        <div><span>Loaded actors</span><strong>{actors?.actors.length ?? "—"}</strong></div>
        <div><span>Data version</span><strong>{cacheVersion ?? actors?.data_version ?? "—"}</strong></div>
        {source ? <div><span>Feed source</span><strong>{source}</strong></div> : null}
        {serviceMode ? <div><span>Bind mode</span><strong>{serviceMode}</strong></div> : null}
        {health?.error ? <p className="health-error">{health.error}</p> : null}
        {healthFailed ? <p className="health-note">The health endpoint did not respond. Actor planning can continue if the catalog is available.</p> : null}
      </div>

      <section aria-labelledby="host-self-test" className="doctor-panel">
        <div className="doctor-panel__heading">
          <div>
            <p className="eyebrow">Guided troubleshooting</p>
            <h3 id="host-self-test">Host self-test</h3>
          </div>
          <div className="doctor-panel__controls">
            {doctor ? (
              <>
                <span className={`doctor-summary ${doctorTone}`}>
                  {doctor.summary.required_failed
                    ? `${doctor.summary.required_failed} required failed`
                    : advisoryFailures
                      ? `${doctor.summary.passed}/${doctor.checks.length} pass · ${advisoryFailures} advisory`
                      : `${doctor.summary.passed}/${doctor.checks.length} passed`}
                </span>
                <small>Checked {diagnosticTimestamp(doctor.generated_at)}</small>
              </>
            ) : null}
            <button className="doctor-rerun" disabled={doctorLoading} onClick={onRetryDoctor} type="button">{rerunLabel}</button>
          </div>
        </div>

        {doctorLoading ? <div aria-live="polite" className="doctor-loading"><span className="spinner" />Checking the host and ATT&amp;CK source…</div> : null}
        {doctorError ? (
          <div className="doctor-error" role="alert">
            <div><strong>Self-test unavailable</strong><p>{doctorError.message}</p></div>
          </div>
        ) : null}
        {doctor ? (
          <ul className="doctor-checks">
            {doctor.checks.map((check) => (
              <li className={check.status === "PASS" ? "is-pass" : "is-fail"} key={check.id}>
                <span className="doctor-status">{check.status}</span>
                <div>
                  <strong>{check.label}{!check.required ? <small>Advisory</small> : null}</strong>
                  <p>{check.detail}</p>
                  {check.status === "FAIL" ? <p className="doctor-fix"><span>Fix</span>{check.fix}</p> : null}
                </div>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </>
  );
}

export function AppShell({ children, session, health, healthFailed, setupFailed, actors, domains, onRefresh, refreshing }: AppShellProps): React.JSX.Element {
  const currentStep = useWizardStore((state) => state.currentStep);
  const maxStep = useWizardStore((state) => state.maxStep);
  const setStep = useWizardStore((state) => state.setStep);
  const restart = useWizardStore((state) => state.restart);
  const selectedActor = useWizardStore((state) => state.selectedActor);
  const records = useWizardStore((state) => state.records);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [helpOpen, setHelpOpen] = useState(false);
  const [healthOpen, setHealthOpen] = useState(false);
  const [refreshOpen, setRefreshOpen] = useState(false);
  const [restartOpen, setRestartOpen] = useState(false);
  const doctorQuery = useQuery({
    queryKey: ["doctor"],
    queryFn: getDoctor,
    enabled: healthOpen,
    retry: false,
    staleTime: 30_000,
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const dataStatus = useMemo(() => {
    if (setupFailed) return "setup needs attention";
    if (actors) {
      const count = actors.actors.length;
      return `${count} actor${count === 1 ? "" : "s"} · ${domains.map((domain) => domainLabels[domain]).join(" + ")}`;
    }
    if (health?.loading) return "Preparing ATT&CK data";
    if (healthFailed || health?.status === "degraded") return "Service needs attention";
    return "Checking service";
  }, [actors, domains, health, healthFailed, setupFailed]);

  const healthTone = setupFailed || healthFailed || health?.status === "degraded" ? "warn" : actors ? "ok" : "loading";

  const toggleTheme = (): void => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    try {
      localStorage.setItem("adversaryflow-theme", next);
    } catch {
      // The active theme still changes for this session when storage is denied.
    }
  };

  const requestRestart = (): void => {
    if (maxStep > 0 || selectedActor) {
      setRestartOpen(true);
      return;
    }
    restart();
  };

  const recordedCount = Object.values(records).filter((record) => record.outcome !== "not_run").length;

  const requestRefresh = (): void => {
    if (maxStep >= 2) setRefreshOpen(true);
    else void onRefresh();
  };

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <header className="app-header">
        <button aria-label="Start a new AdversaryFlow plan" className="brand" onClick={requestRestart} type="button">
          <span className="brand-mark"><Icon className="brand-icon" name="shield" /></span>
          <span className="brand-word">Adversary<span>Flow</span></span>
        </button>

        <nav aria-label="Plan progress" className="stepper">
          {steps.map(({ step, label, shortLabel }, index) => {
            const reached = step <= maxStep;
            const current = step === currentStep;
            return (
              <div className="stepper__group" key={step}>
                {index > 0 ? <span aria-hidden="true" className={`stepper__line ${step <= maxStep ? "is-reached" : ""}`} /> : null}
                <button
                  aria-current={current ? "step" : undefined}
                  aria-label={`${label}${current ? ", current step" : ""}`}
                  className={`stepper__item ${current ? "is-current" : ""} ${reached ? "is-reached" : ""}`}
                  disabled={!reached}
                  onClick={() => setStep(step)}
                  type="button"
                >
                  <span className="stepper__dot">{step < currentStep ? <Icon className="step-check" name="check" /> : step}</span>
                  <span className="stepper__label">{shortLabel}</span>
                </button>
              </div>
            );
          })}
        </nav>

        <div className="header-actions">
          {session?.version ? <span className="version-chip">v{session.version}</span> : null}
          <button aria-label="Open system health" className={`health-chip health-chip--${healthTone}`} id="dataStatus" onClick={() => setHealthOpen(true)} type="button">
            <span aria-hidden="true" className="health-dot" />
            <span>{dataStatus}</span>
          </button>
          <button aria-label="Refresh the live ATT&CK feed" className={`icon-button ${refreshing ? "is-spinning" : ""}`} disabled={refreshing || !session} onClick={requestRefresh} type="button">
            <Icon className="icon" name="refresh" />
          </button>
          <button aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`} className="icon-button" onClick={toggleTheme} type="button">
            <Icon className="icon" name={theme === "dark" ? "sun" : "moon"} />
          </button>
          <button aria-label="How to use AdversaryFlow" className="icon-button" id="helpBtn" onClick={() => setHelpOpen(true)} type="button">
            <Icon className="icon" name="help" />
          </button>
        </div>
      </header>

      <aside aria-label="Safety boundary" className="safety-banner">
        <Icon className="safety-icon" name="shield" />
        <p><strong>Authorized lab use only.</strong> AdversaryFlow creates plans; it does not execute commands.</p>
      </aside>

      <main id="main-content" tabIndex={-1}>{children}</main>

      <Dialog description="Live service, cache, host, and ATT&CK source checks. The self-test never contacts a target system." onClose={() => setHealthOpen(false)} open={healthOpen} title="System health">
        <HealthDetails
          actors={actors}
          doctor={doctorQuery.data ?? null}
          doctorError={doctorQuery.error}
          doctorLoading={doctorQuery.isPending || doctorQuery.isFetching}
          health={health}
          healthFailed={healthFailed}
          onRetryDoctor={() => { void doctorQuery.refetch(); }}
        />
        <p className="doctor-hint">Run <code>adversaryflow doctor</code> on the host to capture the same structured report for support.</p>
      </Dialog>

      <Dialog description="Starting over clears the browser-saved scope and evidence for this plan." onClose={() => setRestartOpen(false)} open={restartOpen} title="Start a new plan?">
        <div className="callout"><strong>{selectedActor ? `${selectedActor.name} · ${selectedActor.attack_id}` : "Current browser plan"}</strong><p>{recordedCount ? `${recordedCount} technique outcome${recordedCount === 1 ? " is" : "s are"} recorded. Export anything you need to keep first.` : "No outcomes are recorded yet, but current scope settings will be cleared."}</p></div>
        <div className="dialog-actions"><button className="button button--ghost" onClick={() => setRestartOpen(false)} type="button">Keep current plan</button><button className="button button--primary" onClick={() => { setRestartOpen(false); restart(); }} type="button">Start new plan</button></div>
      </Dialog>

      <Dialog description="Refreshing can change technique mappings and will rebuild the current plan." onClose={() => setRefreshOpen(false)} open={refreshOpen} title="Refresh the ATT&CK feed?">
        <div className="callout"><strong>Current browser plan</strong><p>Scope and evidence will be cleared after the refreshed catalog is ready. Export records you need to keep first.</p></div>
        <div className="dialog-actions"><button className="button button--ghost" onClick={() => setRefreshOpen(false)} type="button">Cancel</button><button className="button button--primary" onClick={() => { setRefreshOpen(false); void onRefresh(); }} type="button">Refresh feed</button></div>
      </Dialog>

      <Dialog description="A four-step, operator-gated workflow for preparing an authorized emulation in a disposable lab." onClose={() => setHelpOpen(false)} open={helpOpen} title="How to use AdversaryFlow">
        <ol className="help-list">
          <li><span>1</span><div><strong>Pick any threat actor</strong><p>Load the actor’s documented ATT&amp;CK technique mappings.</p></div></li>
          <li><span>2</span><div><strong>Scope the engagement</strong><p>Limit platform, tactics, privilege, network activity, and risk.</p></div></li>
          <li><span>3</span><div><strong>Review and track</strong><p>Preview every action and record outcome and detection evidence.</p></div></li>
          <li><span>4</span><div><strong>Export the kit</strong><p>Download an offline, operator-gated package for the lab host.</p></div></li>
        </ol>
        <div className="callout"><strong>Safety boundary</strong><p>The web service never executes catalog commands, contacts a target, or acts as C2.</p></div>
        <div className="dialog-actions"><button className="button button--primary" onClick={() => setHelpOpen(false)} type="button">Got it</button></div>
      </Dialog>
    </div>
  );
}
