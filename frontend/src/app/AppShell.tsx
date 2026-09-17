import { useEffect, useMemo, useState, type ReactNode } from "react";

import type { ActorsResponse, AttackDomain, HealthResponse, SessionResponse } from "../api/contract";
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
  actors: ActorsResponse | null;
  domains: AttackDomain[];
}

const steps: { step: WizardStep; label: string; shortLabel: string }[] = [
  { step: 1, label: "Choose threat actor", shortLabel: "Threat actor" },
  { step: 2, label: "Scope engagement", shortLabel: "Scope" },
  { step: 3, label: "Review and track plan", shortLabel: "Emulation plan" },
  { step: 4, label: "Export kit", shortLabel: "Export" },
];

const domainLabels: Record<AttackDomain, string> = {
  enterprise: "Enterprise",
  ics: "ICS / OT",
  mobile: "Mobile",
};

function initialTheme(): Theme {
  return localStorage.getItem("adversaryflow-theme") === "light" ? "light" : "dark";
}

function HealthDetails({ health, actors, healthFailed }: Pick<AppShellProps, "health" | "actors" | "healthFailed">): JSX.Element {
  const cacheVersion = health ? displayScalar(health.attack_data, "data_version") : null;
  const source = health ? displayScalar(health.attack_data, "source") : null;
  const serviceMode = health ? displayScalar(health.service, "bind_mode") : null;
  return (
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
  );
}

export function AppShell({ children, session, health, healthFailed, actors, domains }: AppShellProps): JSX.Element {
  const currentStep = useWizardStore((state) => state.currentStep);
  const maxStep = useWizardStore((state) => state.maxStep);
  const setStep = useWizardStore((state) => state.setStep);
  const restart = useWizardStore((state) => state.restart);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [helpOpen, setHelpOpen] = useState(false);
  const [healthOpen, setHealthOpen] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const dataStatus = useMemo(() => {
    if (actors) {
      const count = actors.actors.length;
      return `${count} actor${count === 1 ? "" : "s"} · ${domains.map((domain) => domainLabels[domain]).join(" + ")}`;
    }
    if (health?.loading) return "Preparing ATT&CK data";
    if (healthFailed || health?.status === "degraded") return "Service needs attention";
    return "Checking service";
  }, [actors, domains, health, healthFailed]);

  const healthTone = actors && health?.status !== "degraded" ? "ok" : healthFailed || health?.status === "degraded" ? "warn" : "loading";

  const toggleTheme = (): void => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("adversaryflow-theme", next);
  };

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <header className="app-header">
        <button aria-label="Restart AdversaryFlow" className="brand" onClick={restart} type="button">
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
          <button className={`health-chip health-chip--${healthTone}`} id="dataStatus" onClick={() => setHealthOpen(true)} type="button">
            <span aria-hidden="true" className="health-dot" />
            <span>{dataStatus}</span>
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

      <Dialog description="Live service and ATT&CK cache information. No target systems are contacted by this planner." onClose={() => setHealthOpen(false)} open={healthOpen} title="System health">
        <HealthDetails actors={actors} health={health} healthFailed={healthFailed} />
        <p className="doctor-hint">For deeper checks, run <code>adversaryflow doctor</code> on the host.</p>
      </Dialog>

      <Dialog description="A four-step, operator-gated workflow for preparing an authorized emulation in a disposable lab." onClose={() => setHelpOpen(false)} open={helpOpen} title="How AdversaryFlow works">
        <ol className="help-list">
          <li><span>1</span><div><strong>Choose a threat actor</strong><p>Load the actor’s documented ATT&amp;CK technique mappings.</p></div></li>
          <li><span>2</span><div><strong>Scope the engagement</strong><p>Limit platform, tactics, privilege, network activity, and risk.</p></div></li>
          <li><span>3</span><div><strong>Review and track</strong><p>Preview every action and record outcome and detection evidence.</p></div></li>
          <li><span>4</span><div><strong>Export the kit</strong><p>Download an offline, operator-gated package for the lab host.</p></div></li>
        </ol>
        <div className="callout"><strong>Safety boundary</strong><p>The web service never runs attack commands, contacts a target, or acts as C2.</p></div>
      </Dialog>
    </div>
  );
}
