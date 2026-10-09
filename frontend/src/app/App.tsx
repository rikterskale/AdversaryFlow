import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError, AUTH_REQUIRED_EVENT, getActors, getHealth, getSession, getWorkflow, prepareService, previewIntelligenceImport, refreshAttackData, setApiToken } from "../api/client";
import type { Actor, AttackDomain, SessionResponse } from "../api/contract";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { EvidenceSnapshots } from "../components/EvidenceSnapshots";
import { ErrorState, LoadingState } from "../components/Feedback";
import { ActorGallery } from "../features/actors/ActorGallery";
import { ExportScreen } from "../features/export/ExportScreen";
import type { PlanExport } from "../features/export/planContract";
import { ReviewScreen } from "../features/review/ReviewScreen";
import { ScopeScreen } from "../features/scope/ScopeScreen";
import { Welcome } from "../features/welcome/Welcome";
import { evidenceIdentity, useStorageHealth, useWizardStore, type WizardStep, type WorkspaceState } from "../state/wizardStore";
import { downloadWorkspace, parseWorkspaceFile } from "../state/workspaceRecovery";
import { WORKSPACE_MAX_BYTES } from "../state/workspaceIO";
import { SavedEngagements, type SavedRevision } from "../features/welcome/SavedEngagements";
import { AppShell } from "./AppShell";
import { AuthDialog } from "./AuthDialog";

type StartupPhase = "connecting" | "preparing" | "ready" | "failed" | "authentication";
type PendingPlanReset =
  | { kind: "actor"; actor: Actor }
  | { kind: "domains"; domains: AttackDomain[] };

export function App(): React.JSX.Element {
  const currentStep = useWizardStore((state) => state.currentStep);
  const domains = useWizardStore((state) => state.domains);
  const selectedActor = useWizardStore((state) => state.selectedActor);
  const procedureEvidence = useWizardStore((state) => state.procedureEvidence);
  const maxStep = useWizardStore((state) => state.maxStep);
  const importedWorkflow = useWizardStore((state) => state.importedWorkflow);
  const savedWorkflow = useWizardStore((state) => state.savedWorkflow);
  const commandPlatform = useWizardStore((state) => state.scope.commandPlatform);
  const setStep = useWizardStore((state) => state.setStep);
  const setDomains = useWizardStore((state) => state.setDomains);
  const selectActor = useWizardStore((state) => state.selectActor);
  const importPlan = useWizardStore((state) => state.importPlan);
  const resetAfterRefresh = useWizardStore((state) => state.resetAfterRefresh);
  const restart = useWizardStore((state) => state.restart);
  const attachProcedureEvidence = useWizardStore((state) => state.attachProcedureEvidence);
  const initialWorkspaceStep = useRef<WizardStep>(currentStep);
  const queryClient = useQueryClient();

  const [session, setSession] = useState<SessionResponse | null>(null);
  const [startupPhase, setStartupPhase] = useState<StartupPhase>("connecting");
  const [startupError, setStartupError] = useState("");
  const [startupAttempt, setStartupAttempt] = useState(0);
  const [authOpen, setAuthOpen] = useState(false);
  const [connectionRequired, setConnectionRequired] = useState(false);
  const [authAttempted, setAuthAttempted] = useState(false);
  const [notice, setNotice] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [catalogRetryError, setCatalogRetryError] = useState("");
  const [pendingPlanReset, setPendingPlanReset] = useState<PendingPlanReset | null>(null);
  const [beginOpen, setBeginOpen] = useState(false);
  const [reloadOpen, setReloadOpen] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [pendingImport, setPendingImport] = useState<{ plan: PlanExport; saved?: SavedRevision } | { workspace: WorkspaceState } | null>(null);
  const [importError, setImportError] = useState("");
  const storageHealth = useStorageHealth();
  const operation = useRef<AbortController | null>(null);
  const workspaceGeneration = useWizardStore((state) => state.workspaceGeneration);

  const start = useCallback(async (signal: AbortSignal): Promise<void> => {
    setStartupError("");
    setStartupPhase("connecting");
    try {
      const nextSession = await getSession(signal);
      if (signal.aborted) return;
      setSession(nextSession);
      setConnectionRequired(false);
      setAuthAttempted(false);
      setAuthOpen(false);
      setStartupPhase("preparing");
      await prepareService(nextSession.csrf_token, signal);
      if (signal.aborted) return;
      setStartupPhase("ready");
      void queryClient.invalidateQueries();
    } catch (error: unknown) {
      if (signal.aborted) return;
      if (error instanceof ApiError && error.status === 401) {
        setAuthOpen(true);
        setStartupPhase("authentication");
        return;
      }
      setStartupError(error instanceof Error ? error.message : "The service could not be prepared.");
      setStartupPhase("failed");
    }
  }, [queryClient]);

  useEffect(() => {
    const reconnect = (): void => { setConnectionRequired(true); setAuthOpen(true); };
    window.addEventListener(AUTH_REQUIRED_EVENT, reconnect);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, reconnect);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void start(controller.signal);
    return () => controller.abort();
  }, [start, startupAttempt]);

  useEffect(() => () => { operation.current?.abort(); }, [workspaceGeneration]);

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
    queryFn: ({ signal }) => getActors(domains, signal),
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
    queryFn: ({ signal }) => getHealth(signal),
    enabled: startupPhase === "ready",
    retry: false,
    refetchInterval: 15_000,
  });

  const workflowQuery = useQuery({
    queryKey: ["workflow", selectedActor?.stix_id ?? "", ...domains],
    queryFn: ({ signal }) => {
      if (!selectedActor) throw new Error("Choose a threat actor before loading a workflow.");
      return getWorkflow(selectedActor.stix_id, domains, signal);
    },
    enabled: startupPhase === "ready" && Boolean(selectedActor) && currentStep >= 2 && !importedWorkflow,
  });

  const workflow = importedWorkflow ?? workflowQuery.data ?? savedWorkflow;
  const canUseSavedPlan = Boolean(workflow && selectedActor && currentStep >= 2);
  useEffect(() => {
    if (workflow && selectedActor && currentStep >= 2) {
      const activeScope = useWizardStore.getState().scope;
      useWizardStore.getState().ensureEvidenceKey(evidenceIdentity(selectedActor.stix_id, workflow, commandPlatform, activeScope.commandSelections, activeScope), workflow);
    }
  }, [workflow, selectedActor, currentStep, commandPlatform]);

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

  const confirmBegin = (): void => {
    const acceptedProcedures = procedureEvidence;
    restart();
    attachProcedureEvidence(acceptedProcedures);
    useWizardStore.getState().setStep(1);
    setBeginOpen(false);
  };
  // A browser with no actor, progress, or evidence has nothing a restore or new
  // plan could overwrite, so it should not ask the user to confirm replacing it.
  const hasWorkspaceContent = (includeProcedures: boolean): boolean => {
    const state = useWizardStore.getState();
    return Boolean(state.selectedActor || state.maxStep > 0 || Object.keys(state.records).length
      || Object.keys(state.evidenceArchive).length || (includeProcedures && state.procedureEvidence.length));
  };
  const beginPlan = (): void => {
    // Begin carries accepted procedures forward (see confirmBegin), so they do not count here.
    if (hasWorkspaceContent(false)) setBeginOpen(true);
    else confirmBegin();
  };

  const resumePlan = (): void => {
    const destination = Math.min(Math.max(maxStep, 2), 3) as WizardStep;
    setStep(destination);
  };

  const loadPlanFile = async (file: File): Promise<void> => {
    setImportError("");
    if (file.size > WORKSPACE_MAX_BYTES) {
      setImportError("Recovery file is larger than 128 MiB. Keep the existing workspace open.");
      setNotice("Recovery file is larger than 128 MiB. Keep the existing workspace open.");
      return;
    }
    try {
      const parsed = await parseWorkspaceFile(await file.text());
      requestImport(parsed.kind === "plan" ? { plan: parsed.plan } : { workspace: parsed.workspace });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Plan import failed. Choose a schema 2.0 or 3.0 JSON export.";
      setImportError(message);
      setNotice(message);
    }
  };

  const applyImport = (incoming: NonNullable<typeof pendingImport>): void => {
    if ("workspace" in incoming) useWizardStore.getState().importWorkspace(incoming.workspace);
    else {
      importPlan(incoming.plan);
      if (incoming.saved) useWizardStore.getState().setEngagementRecord(incoming.saved.engagement_id, incoming.saved.revision);
    }
    setPendingImport(null);
    setNotice("workspace" in incoming ? "Workspace recovered with saved settings. Review commands before use." : "Plan imported with its saved guardrails; verify commands and data version before use");
  };
  // Only ask before replacing when there is something to lose.
  const requestImport = (incoming: NonNullable<typeof pendingImport>): void => {
    if (hasWorkspaceContent(true)) setPendingImport(incoming);
    else applyImport(incoming);
  };
  const restoreEngagement = (saved: SavedRevision): void => requestImport({ plan: saved.plan, saved });
  const confirmImport = (): void => {
    if (pendingImport) applyImport(pendingImport);
  };
  const backup = (): void => {
    try { downloadWorkspace(); setNotice("Recovery download requested. Confirm the file is saved before clearing any work."); }
    catch (error: unknown) { setNotice(error instanceof Error ? error.message : "Recovery download failed. Keep this tab open."); }
  };
  const reloadCatalog = async (): Promise<void> => {
    if (!selectedActor || reloading || !session) return;
    const generation = useWizardStore.getState().workspaceGeneration;
    const controller = new AbortController();
    operation.current?.abort();
    operation.current = controller;
    setReloading(true);
    try {
      await getSession(controller.signal);
      const next = await getWorkflow(selectedActor.stix_id, domains, controller.signal);
      if (controller.signal.aborted || generation !== useWizardStore.getState().workspaceGeneration) return;
      useWizardStore.getState().reloadCatalog(next);
      setStep(2);
      setReloadOpen(false);
      setNotice("Catalog reloaded. Review current scope and command changes; the imported snapshot is retained in recovery history.");
    } catch (error: unknown) { if (!controller.signal.aborted) setNotice(error instanceof Error ? error.message : "Catalog reload failed. Retry after reconnecting."); }
    finally { setReloading(false); }
  };

  const refreshFeed = async (): Promise<void> => {
    if (!session || refreshing) return;
    setRefreshing(true);
    try {
      const controller = new AbortController();
      operation.current?.abort(); operation.current = controller;
      const generation = useWizardStore.getState().workspaceGeneration;
      await refreshAttackData(domains, session.csrf_token, controller.signal);
      if (controller.signal.aborted || generation !== useWizardStore.getState().workspaceGeneration) return;
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

  const welcomeProps = {
    actors: actorsQuery.data?.actors ?? [],
    csrfToken: session?.csrf_token ?? "",
    domains,
    importError,
    onAttachProcedures: attachProcedureEvidence,
    onBegin: beginPlan,
    onImport: loadPlanFile,
    onIntelligenceImport: previewIntelligenceImport,
    onNotice: setNotice,
    onResume: resumePlan,
    resumeActor: maxStep >= 2 ? selectedActor : null,
    savedEngagements: <SavedEngagements onNotice={setNotice} onRestore={restoreEngagement} />,
  };
  let content: React.JSX.Element;
  let focusKey = "welcome";
  if (startupPhase === "failed" && !canUseSavedPlan) {
    content = <Welcome {...welcomeProps} onRetrySetup={() => setStartupAttempt((value) => value + 1)} ready={false} setupError={startupError} />;
  } else if (startupPhase !== "ready" && !canUseSavedPlan) {
    content = <Welcome {...welcomeProps} ready={false} setupPending={startupPhase === "authentication" ? undefined : startupPhase === "preparing" ? "preparing" : "connecting"} />;
  } else if (currentStep === 0) {
    content = <Welcome {...welcomeProps} catalogError={catalogRetryError || actorsQuery.error?.message} catalogRetrying={actorsQuery.isFetching} onRetryCatalog={() => { void retryCatalog(); }} ready={Boolean(actorsQuery.data)} />;
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
  } else if (!workflow) {
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
      {storageHealth.status === "failed" ? <div className="callout workspace-notice" role="alert"><p>{storageHealth.message}</p><Button onClick={backup}>Download workspace recovery copy</Button></div> : null}
      {connectionRequired ? <div className="callout workspace-notice" role="status"><p>Connect to this service to load live data and save server records. You can still review saved work and download JSON.</p><Button onClick={() => setAuthOpen(true)}>Connect to service</Button></div> : null}
      {maxStep > 0 || procedureEvidence.length > 0 ? <div className="workspace-notice"><Button onClick={backup} variant="ghost">Download workspace recovery copy</Button>{importedWorkflow && selectedActor ? <Button disabled={reloading || !session} onClick={() => setReloadOpen(true)}>Reload catalog and review changes</Button> : null}</div> : null}
      {canUseSavedPlan && startupPhase === "failed" ? <div className="callout workspace-notice" role="status"><p>Working from your saved plan. You can review evidence and save JSON while ATT&amp;CK setup is unavailable.</p><Button onClick={() => setStartupAttempt((value) => value + 1)}>Retry connection</Button></div> : null}
      {currentStep >= 2 ? <EvidenceSnapshots /> : null}
      {content}
      <AuthDialog
        message={authAttempted ? "That token was not accepted. Check it and try again." : ""}
        onConnect={connect}
        onClose={() => setAuthOpen(false)}
        open={authOpen}
      />
      <Dialog title="Begin a new plan?" description="Your scope, recorded evidence, and recovery history will be cleared. Accepted procedure citations are kept. Download a recovery copy first if needed." open={beginOpen} onClose={() => setBeginOpen(false)}>
        <div className="dialog-actions"><Button onClick={backup}>Download recovery copy</Button><Button onClick={() => setBeginOpen(false)} variant="ghost">Keep current workspace</Button><Button onClick={confirmBegin} variant="primary">Clear and begin</Button></div>
      </Dialog>
      <Dialog title="Replace this browser workspace?" description="Restoring replaces scope, evidence and history. Cancel keeps the whole current workspace unchanged." open={Boolean(pendingImport)} onClose={() => setPendingImport(null)}>
        <div className="dialog-actions"><Button onClick={backup}>Download current recovery copy</Button><Button onClick={() => setPendingImport(null)} variant="ghost">Cancel restore</Button><Button onClick={confirmImport} variant="primary">Replace and restore</Button></div>
      </Dialog>
      <Dialog title="Reload catalog and review changes?" description="Authenticated catalog commands for the same actor and domains replace the imported snapshot, never execute it. Current guardrails and procedure provenance stay in place. The original snapshot is retained; evidence from another data version remains partitioned." open={reloadOpen} onClose={() => setReloadOpen(false)}>
        <div className="dialog-actions"><Button onClick={() => setReloadOpen(false)} variant="ghost">Keep imported snapshot</Button><Button disabled={reloading} onClick={() => { void reloadCatalog(); }} variant="primary">{reloading ? "Reloading…" : "Reload and review scope"}</Button></div>
      </Dialog>
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
