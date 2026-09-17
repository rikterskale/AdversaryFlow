import { useCallback, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { ApiError, getActors, getHealth, getSession, prepareService, setApiToken } from "../api/client";
import type { SessionResponse } from "../api/contract";
import { ErrorState, LoadingState } from "../components/Feedback";
import { ActorGallery } from "../features/actors/ActorGallery";
import { ScopePlaceholder } from "../features/scope/ScopePlaceholder";
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
  } else {
    content = <ScopePlaceholder actor={selectedActor} onBack={() => setStep(1)} />;
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
