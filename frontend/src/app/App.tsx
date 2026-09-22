import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, getActors, getHealth, getSession, getWorkflow, prepareService, refreshAttackData, setApiToken } from "../api/client";
import type { Actor, AttackDomain, SessionResponse } from "../api/contract";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { ErrorState, LoadingState } from "../components/Feedback";
import { ActorGallery } from "../features/actors/ActorGallery";
import { ExportScreen } from "../features/export/ExportScreen";
import { validateImportedPlan } from "../features/export/planContract";
import { ReviewScreen } from "../features/review/ReviewScreen";
import { ScopeScreen } from "../features/scope/ScopeScreen";
import { Welcome } from "../features/welcome/Welcome";
import { useWizardStore, type WizardStep } from "../state/wizardStore";
import { AppShell } from "./AppShell";
import { AuthDialog } from "./AuthDialog";

type StartupPhase = "connecting" | "preparing" | "ready" | "failed";
type PendingPlanReset =
  | { kind: "actor"; actor: Actor }
  | { kind: "domains"; domains: AttackDomain[] };

export function App(): React.JSX.Element {
  const currentStep = useWizardStore((state) => state.currentStep);
  const domains = useWizardStore((state) => state.domains);
  const selectedActor = useWizardStore((state) => state.selectedActor);
  const maxStep = useWizardStore((state) => state.maxStep);
  const importedWorkflow = useWizardStore((state) => state.importedWorkflow);
  const setStep = useWizardStore((state) => state.setStep);
  const setDomains = useWizardStore((state) => state.setDomains);
  const selectActor = useWizardStore((state) => state.selectActor);
  const importPlan = useWizardStore((state) => state.importPlan);
  const resetAfterRefresh = useWizardStore((state) => state.resetAfterRefresh);
  const restart = useWizardStore((state) => state.restart);
  const initialWorkspaceStep = useRef<WizardStep>(currentStep);
  const queryClient = useQueryClient();

  const [session, setSession] = useState<SessionResponse | null>(null);
  const [startupPhase, setStartupPhase] = useState<StartupPhase>("connecting");
  const [startupError, setStartupError] = useState("");
  const [startupAttempt, setStartupAttempt] = useState(0);
  const [authOpen, setAuthOpen] = useState(false);
  const [authAttempted, setAuthAttempted] = useState(false);
  const [notice, setNotice] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [catalogRetryError, setCatalogRetryError] = useState("");
  const [pendingPlanReset, setPendingPlanReset] = useState<PendingPlanReset | null>(null);

  const start = useCallback(async (): Promise<void> => {
    setStartupError("");
    setStartupPhase("connecting");
    try {
      const nextSession = await getSession();
      setSession(nextSession);
      setAuthOpen(false);
      setStartupPhase("preparing");
      await prepareService(nextSession.csrf_token);
      setStartupPhase("ready");
    } catch (error: unknown) {
      if (error instanceof ApiError && error.status === 401) {
        setAuthOpen(true);
        setStartupPhase("connecting");
        return;
      }
      setStartupError(error instanceof Error ? error.message : "The service could not be prepared.");
      setStartupPhase("failed");
    }
  }, []);

  useEffect(() => {
    void start();
  }, [start, startupAttempt]);

  useEffect(() => {
    if (initialWorkspaceStep.current > 0) useWizardStore.getState().setStep(0);
  }, []);

  useEffect(() => {
    if (!notice) return undefined;
    const timer = window.setTimeout(() => setNotice(""), 4200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const actorsQuery = useQuery({
    queryKey: ["actors", ...domains],
    queryFn: () => getActors(domains),
    enabled: startupPhase === "ready",
  });

  const retryCatalog = async (): Promise<void> => {
    // Preserve recovery controls while refetch clears the query error.
    setCatalogRetryError(actorsQuery.error?.message ?? "The actor catalog could not be loaded.");
    try {
      await actorsQuery.refetch();
    } finally {
      setCatalogRetryError("");
    }
  };

  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: getHealth,
    enabled: startupPhase === "ready",
    retry: false,
    refetchInterval: 15_000,
  });

  const workflowQuery = useQuery({
    queryKey: ["workflow", selectedActor?.stix_id ?? "", ...domains],
    queryFn: () => {
      if (!selectedActor) throw new Error("Choose a threat actor before loading a workflow.");
      return getWorkflow(selectedActor.stix_id, domains);
    },
    enabled: startupPhase === "ready" && Boolean(selectedActor) && currentStep >= 2 && !importedWorkflow,
  });

  const workflow = importedWorkflow ?? workflowQuery.data ?? null;

  const connect = (token: string): void => {
    setApiToken(token);
    setAuthAttempted(true);
    setAuthOpen(false);
    setStartupAttempt((value) => value + 1);
  };

  const requestDomainsChange = (nextDomains: AttackDomain[]): void => {
    if (maxStep >= 2) {
      setPendingPlanReset({ kind: "domains", domains: nextDomains });
      return;
    }
    setDomains(nextDomains);
  };

  const requestActorChange = (actor: Actor): void => {
    if (maxStep >= 2 && selectedActor?.stix_id !== actor.stix_id) {
      setPendingPlanReset({ kind: "actor", actor });
      return;
    }
    selectActor(actor);
  };

  const confirmPlanReset = (): void => {
    if (!pendingPlanReset) return;
    if (pendingPlanReset.kind === "domains") {
      setDomains(pendingPlanReset.domains);
      setNotice("ATT&CK domains changed; choose an actor to rebuild the plan");
    } else {
      selectActor(pendingPlanReset.actor);
      setNotice(`Threat actor changed to ${pendingPlanReset.actor.name}; scope and evidence were reset`);
    }
    setPendingPlanReset(null);
  };

  const beginPlan = (): void => {
    if (selectedActor || maxStep > 0) restart();
    useWizardStore.getState().setStep(1);
  };

  const resumePlan = (): void => {
    const destination = Math.min(Math.max(maxStep, 2), 3) as WizardStep;
    setStep(destination);
  };

  const loadPlanFile = async (file: File): Promise<void> => {
    if (file.size > 5 * 1024 * 1024) {
      setNotice("Plan file is larger than 5 MB");
      return;
    }
    try {
      const value = JSON.parse(await file.text()) as unknown;
      validateImportedPlan(value);
      importPlan(value);
      setNotice("Plan imported as high-risk; verify its data version before execution");
    } catch (error: unknown) {
      setNotice(error instanceof Error ? error.message : "Plan import failed. Choose a schema 2.0 JSON export.");
    }
  };

  const refreshFeed = async (): Promise<void> => {
    if (!session || refreshing) return;
    setRefreshing(true);
    try {
      await refreshAttackData(domains, session.csrf_token);
      resetAfterRefresh();
      queryClient.removeQueries({ queryKey: ["workflow"] });
      await queryClient.invalidateQueries({ queryKey: ["actors"] });
      setNotice("ATT&CK feed refreshed; the plan was rebuilt");
    } catch (error: unknown) {
      setNotice(error instanceof Error ? error.message : "The ATT&CK feed could not be refreshed. Try again.");
    } finally {
      setRefreshing(false);
    }
  };

  let content: React.JSX.Element;
  let focusKey = "welcome";
  if (startupPhase === "failed") {
    content = <Welcome onBegin={beginPlan} onImport={loadPlanFile} onResume={resumePlan} onRetrySetup={() => setStartupAttempt((value) => value + 1)} ready={false} resumeActor={maxStep >= 2 ? selectedActor : null} setupError={startupError} />;
  } else if (startupPhase !== "ready") {
    content = (
      <section className="screen setup-screen">
        <LoadingState
          detail={startupPhase === "preparing" ? "The first run downloads and validates the live STIX 2.1 bundle." : "Checking the local service and authorization boundary."}
          label={startupPhase === "preparing" ? "Preparing MITRE ATT&CK data…" : "Connecting to AdversaryFlow…"}
        />
      </section>
    );
  } else if (currentStep === 0) {
    content = <Welcome catalogError={catalogRetryError || actorsQuery.error?.message} catalogRetrying={actorsQuery.isFetching} onBegin={beginPlan} onImport={loadPlanFile} onResume={resumePlan} onRetryCatalog={() => { void retryCatalog(); }} ready={Boolean(actorsQuery.data)} resumeActor={maxStep >= 2 ? selectedActor : null} />;
  } else if (currentStep === 1 || !selectedActor) {
    focusKey = "actors";
    content = (
      <ActorGallery
        domains={domains}
        error={actorsQuery.error}
        loading={actorsQuery.isPending || actorsQuery.isFetching}
        onContinue={() => setStep(2)}
        onDomainsChange={requestDomainsChange}
        onNotice={setNotice}
        onRetry={() => { void actorsQuery.refetch(); }}
        onSelect={requestActorChange}
        response={actorsQuery.data ?? null}
        selectedActor={selectedActor}
      />
    );
  } else if (!workflow && (workflowQuery.isPending || workflowQuery.isFetching)) {
    focusKey = `scope-loading-${selectedActor.stix_id}`;
    content = <section className="screen setup-screen"><LoadingState detail="Resolving mapped techniques and bounded catalog exercises." label={`Building ${selectedActor.name}'s lab plan…`} /></section>;
  } else if (workflowQuery.error || !workflow) {
    focusKey = `scope-error-${selectedActor.stix_id}`;
    content = <section className="screen setup-screen"><ErrorState message={workflowQuery.error?.message ?? "The workflow response was empty."} onRetry={() => { void workflowQuery.refetch(); }} title="Could not build the actor workflow" /><Button onClick={() => setStep(1)} variant="ghost"><span aria-hidden="true">←</span> Back to threat actors</Button></section>;
  } else if (currentStep === 2) {
    focusKey = `scope-${selectedActor.stix_id}`;
    content = <ScopeScreen actor={selectedActor} onBack={() => setStep(1)} onBuild={() => setStep(3)} workflow={workflow} />;
  } else if (currentStep === 3) {
    focusKey = `review-${selectedActor.stix_id}`;
    content = <ReviewScreen actor={selectedActor} onBack={() => setStep(2)} onFinish={() => setStep(4)} onNotice={setNotice} workflow={workflow} />;
  } else {
    focusKey = `export-${selectedActor.stix_id}`;
    content = <ExportScreen actor={selectedActor} csrfToken={session?.csrf_token ?? ""} domains={domains} onBack={() => setStep(3)} onNotice={setNotice} onRestart={restart} workflow={workflow} />;
  }

  return (
    <AppShell
      actors={actorsQuery.data ?? null}
      domains={domains}
      focusKey={focusKey}
      health={healthQuery.data ?? null}
      healthFailed={healthQuery.isError}
      onRefresh={refreshFeed}
      refreshing={refreshing}
      session={session}
      setupFailed={startupPhase === "failed" || actorsQuery.isError}
    >
      {content}
      <AuthDialog
        message={authAttempted ? "That token was not accepted. Check it and try again." : ""}
        onConnect={connect}
        open={authOpen}
      />
      <Dialog
        description="Changing the plan source rebuilds the workflow so evidence cannot be attributed to the wrong actor or ATT&CK data set."
        onClose={() => setPendingPlanReset(null)}
        open={Boolean(pendingPlanReset)}
        title={pendingPlanReset?.kind === "domains" ? "Change ATT&CK domains?" : "Change threat actor?"}
      >
        <div className="callout">
          <strong>Current browser plan</strong>
          <p>Scope settings and recorded evidence will be cleared. Export anything you need to keep before confirming.</p>
        </div>
        <div className="dialog-actions">
          <Button onClick={() => setPendingPlanReset(null)} variant="ghost">Keep current plan</Button>
          <Button onClick={confirmPlanReset} variant="primary">Clear and rebuild</Button>
        </div>
      </Dialog>
      {notice ? <div aria-live="polite" className="toast" role="status"><span aria-hidden="true">i</span>{notice}</div> : null}
    </AppShell>
  );
}
