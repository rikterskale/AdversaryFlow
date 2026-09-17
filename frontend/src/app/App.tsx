import { useCallback, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { ApiError, getActors, getHealth, getSession, getWorkflow, prepareService, setApiToken } from "../api/client";
import type { SessionResponse } from "../api/contract";
import { Button } from "../components/Button";
import { ErrorState, LoadingState } from "../components/Feedback";
import { ActorGallery } from "../features/actors/ActorGallery";
import { ReviewScreen } from "../features/review/ReviewScreen";
import { ScopeScreen } from "../features/scope/ScopeScreen";
import { Welcome } from "../features/welcome/Welcome";
import { useWizardStore } from "../state/wizardStore";
import { AppShell } from "./AppShell";
import { AuthDialog } from "./AuthDialog";

type StartupPhase = "connecting" | "preparing" | "ready" | "failed";

export function App(): JSX.Element {
  const currentStep = useWizardStore((state) => state.currentStep);
  const domains = useWizardStore((state) => state.domains);
  const selectedActor = useWizardStore((state) => state.selectedActor);
  const setStep = useWizardStore((state) => state.setStep);
  const setDomains = useWizardStore((state) => state.setDomains);
  const selectActor = useWizardStore((state) => state.selectActor);

  const [session, setSession] = useState<SessionResponse | null>(null);
  const [startupPhase, setStartupPhase] = useState<StartupPhase>("connecting");
  const [startupError, setStartupError] = useState("");
  const [startupAttempt, setStartupAttempt] = useState(0);
  const [authOpen, setAuthOpen] = useState(false);
  const [authAttempted, setAuthAttempted] = useState(false);
  const [notice, setNotice] = useState("");

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
    if (!notice) return undefined;
    const timer = window.setTimeout(() => setNotice(""), 4200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const actorsQuery = useQuery({
    queryKey: ["actors", ...domains],
    queryFn: () => getActors(domains),
    enabled: startupPhase === "ready",
  });

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
    enabled: startupPhase === "ready" && Boolean(selectedActor) && currentStep >= 2,
  });

  const connect = (token: string): void => {
    setApiToken(token);
    setAuthAttempted(true);
    setAuthOpen(false);
    setStartupAttempt((value) => value + 1);
  };

  let content: JSX.Element;
  if (startupPhase === "failed") {
    content = (
      <section className="screen setup-screen">
        <ErrorState message={startupError} onRetry={() => setStartupAttempt((value) => value + 1)} title="Could not prepare ATT&CK data" />
      </section>
    );
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
    content = <Welcome onBegin={() => setStep(1)} ready={Boolean(actorsQuery.data)} />;
  } else if (currentStep === 1 || !selectedActor) {
    content = (
      <ActorGallery
        domains={domains}
        error={actorsQuery.error}
        loading={actorsQuery.isPending || actorsQuery.isFetching}
        onContinue={() => setStep(2)}
        onDomainsChange={setDomains}
        onNotice={setNotice}
        onRetry={() => { void actorsQuery.refetch(); }}
        onSelect={selectActor}
        response={actorsQuery.data ?? null}
        selectedActor={selectedActor}
      />
    );
  } else if (workflowQuery.isPending || workflowQuery.isFetching) {
    content = <section className="screen setup-screen"><LoadingState detail="Resolving mapped techniques and bounded catalog exercises." label={`Building ${selectedActor.name}'s lab plan…`} /></section>;
  } else if (workflowQuery.error || !workflowQuery.data) {
    content = <section className="screen setup-screen"><ErrorState message={workflowQuery.error?.message ?? "The workflow response was empty."} onRetry={() => { void workflowQuery.refetch(); }} title="Could not build the actor workflow" /><Button onClick={() => setStep(1)} variant="ghost"><span aria-hidden="true">←</span> Back to threat actors</Button></section>;
  } else if (currentStep === 2) {
    content = <ScopeScreen actor={selectedActor} onBack={() => setStep(1)} onBuild={() => setStep(3)} workflow={workflowQuery.data} />;
  } else if (currentStep === 3) {
    content = <ReviewScreen actor={selectedActor} onBack={() => setStep(2)} onFinish={() => setStep(4)} onNotice={setNotice} workflow={workflowQuery.data} />;
  } else {
    content = <section className="screen placeholder-screen"><p className="eyebrow">Step 4 of 4</p><h1>Your emulation plan is ready</h1><p>Export formats and the operator execution kit arrive in the next reviewed checkpoint.</p><Button onClick={() => setStep(3)} variant="ghost"><span aria-hidden="true">←</span> Back to review</Button></section>;
  }

  return (
    <AppShell
      actors={actorsQuery.data ?? null}
      domains={domains}
      health={healthQuery.data ?? null}
      healthFailed={healthQuery.isError}
      session={session}
    >
      {content}
      <AuthDialog
        message={authAttempted ? "That token was not accepted. Check it and try again." : ""}
        onConnect={connect}
        open={authOpen}
      />
      {notice ? <div aria-live="polite" className="toast" role="status"><span aria-hidden="true">i</span>{notice}</div> : null}
    </AppShell>
  );
}
