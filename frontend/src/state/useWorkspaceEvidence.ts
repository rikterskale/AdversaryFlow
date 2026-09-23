import { useEffect } from "react";
import type { Actor, WorkflowResponse } from "../api/contract";
import type { ExecutionEvidence } from "../features/review/evidence";
import { evidenceIdentity, useWizardStore } from "./wizardStore";

const emptyRecords: Record<string, ExecutionEvidence> = {};

export function useWorkspaceEvidence(actor: Actor, workflow: WorkflowResponse): Record<string, ExecutionEvidence> {
  const platform = useWizardStore((state) => state.scope.commandPlatform);
  const key = evidenceIdentity(actor.stix_id, workflow, platform);
  // Select by identity during render, before effects run, so no export or
  // evidence editor can see records from a different platform/data version.
  const records = useWizardStore((state) => state.evidenceKey === key
    ? state.records : state.evidenceArchive[key]?.records ?? emptyRecords);
  useEffect(() => { useWizardStore.getState().ensureEvidenceKey(key, workflow); }, [key, workflow]);
  return records;
}
