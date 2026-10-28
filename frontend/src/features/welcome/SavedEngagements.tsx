import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiFetch, responseJson } from "../../api/client";
import { isRecord } from "../../api/guards";
import { Button } from "../../components/Button";
import { validateImportedPlan, verifyImportedPlanReceipts, type PlanExport } from "../export/planContract";
import { validDateTime } from "../review/evidence";
import { boundedJson, downloadJson } from "../../state/workspaceIO";

export interface SavedRevision { engagement_id: string; revision: number; plan_sha256: string; plan: PlanExport }
interface Entry { id: string; actor_name: string; revision: number; data_version: string }
const sha256 = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);

export function parseEngagementSave(value: unknown): { engagement_id: string; revision: number; plan_sha256: string; content_pack_sha256?: string } {
  if (!isRecord(value) || typeof value.engagement_id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.engagement_id)
    || !Number.isInteger(value.revision) || Number(value.revision) < 1 || !sha256(value.plan_sha256)
    || !validDateTime(value.created_at) || (value.content_pack_sha256 !== undefined && !sha256(value.content_pack_sha256))) throw new Error("The service returned an invalid engagement revision.");
  return { engagement_id: value.engagement_id, revision: Number(value.revision), plan_sha256: value.plan_sha256,
    ...(typeof value.content_pack_sha256 === "string" ? { content_pack_sha256: value.content_pack_sha256 } : {}) };
}

function parseList(value: unknown, offset: number): { entries: Entry[]; nextOffset: number | null } {
  if (!isRecord(value) || !Array.isArray(value.engagements) || value.engagements.length > 200) throw new Error("The service returned an invalid engagement list.");
  const entries = value.engagements.map((item) => {
    if (!isRecord(item) || typeof item.id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(item.id)
      || typeof item.actor_name !== "string" || typeof item.data_version !== "string" || !Number.isInteger(item.revision) || Number(item.revision) < 1) throw new Error("The service returned an invalid saved engagement.");
    return { id: item.id, actor_name: item.actor_name, data_version: item.data_version, revision: Number(item.revision) };
  });
  const nextOffset = value.next_offset ?? (value.next_offset === undefined && entries.length === 200 ? offset + 200 : null);
  if (nextOffset !== null && (!Number.isSafeInteger(nextOffset) || nextOffset !== offset + entries.length || !entries.length)) throw new Error("The service returned invalid engagement pagination.");
  return { entries, nextOffset: nextOffset as number | null };
}

export function SavedEngagements({ onRestore, onNotice }: { onRestore: (saved: SavedRevision) => void; onNotice: (message: string) => void }): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState("");
  const [revision, setRevision] = useState<number | null>(null);
  const [offset, setOffset] = useState(0);
  const list = useQuery({ queryKey: ["engagements", offset], enabled: open, retry: false, staleTime: 0,
    queryFn: async ({ signal }) => parseList(await responseJson(await apiFetch(`/api/engagements?limit=200&offset=${offset}`, { signal })), offset) });
  const detail = useQuery({ queryKey: ["engagement", selected], enabled: open && Boolean(selected), retry: false,
    queryFn: async ({ signal }) => {
      const value = await responseJson(await apiFetch(`/api/engagements/${encodeURIComponent(selected)}`, { signal }));
      if (!isRecord(value) || value.id !== selected || !Array.isArray(value.revisions) || !value.revisions.length) throw new Error("The service returned invalid engagement details.");
      return value.revisions.map((item) => {
        if (!isRecord(item) || !Number.isInteger(item.revision) || Number(item.revision) < 1 || !sha256(item.plan_sha256)) throw new Error("The service returned invalid revision metadata.");
        return { revision: Number(item.revision), plan_sha256: item.plan_sha256 };
      });
    } });
  const saved = useQuery({ queryKey: ["engagement-revision", selected, revision], enabled: open && Boolean(selected) && revision !== null, retry: false,
    queryFn: async ({ signal }): Promise<SavedRevision> => {
      const value = await responseJson(await apiFetch(`/api/engagements/${encodeURIComponent(selected)}/revisions/${revision}`, { signal }));
      const metadata = parseEngagementSave(value);
      if (!isRecord(value) || metadata.engagement_id !== selected || metadata.revision !== revision) throw new Error("The service returned a different engagement revision.");
      validateImportedPlan(value.plan);
      boundedJson(value.plan);
      await verifyImportedPlanReceipts(value.plan);
      return { ...metadata, plan: value.plan };
    } });
  const error = list.error ?? detail.error ?? saved.error;
  const changePage = (nextOffset: number): void => { setOffset(nextOffset); setSelected(""); setRevision(null); };
  return <section className="saved-engagements" aria-label="Saved server engagements">
    <h2>Saved engagements on this service</h2>
    <p>Available from a fresh browser. Restore any revision or download its plan; saving again appends to the same engagement.</p>
    <Button onClick={() => setOpen((value) => !value)}>{open ? "Close saved engagements" : "Browse saved engagements"}</Button>
    {open ? <>
      <Button onClick={() => { if (offset) changePage(0); else void list.refetch(); if (selected) void detail.refetch(); }}>Refresh saved engagements</Button>
      {list.isFetching || detail.isFetching || saved.isFetching ? <p role="status">Loading saved engagements…</p> : null}
      {error ? <div role="alert"><p>{error.message}</p><Button onClick={() => { if (list.error) void list.refetch(); else if (detail.error) void detail.refetch(); else void saved.refetch(); }}>Retry saved engagements</Button></div> : null}
      {list.data?.entries.length === 0 ? <p>{offset ? "No engagements on this page. Refresh to show the latest saved records." : "No saved engagements yet."}</p> : null}
      {list.data?.entries.map((item) => <Button key={item.id} onClick={() => { setSelected(item.id); setRevision(null); }}>{item.actor_name} · revision {item.revision} · {item.data_version}</Button>)}
      {offset > 0 || list.data?.nextOffset !== null && list.data?.nextOffset !== undefined ? <nav aria-label="Saved engagement pages" className="dialog-actions">
        <Button disabled={offset === 0 || list.isFetching} onClick={() => changePage(Math.max(0, offset - 200))}>Newer engagements</Button>
        <span>{list.data?.entries.length ? `Showing ${offset + 1}–${offset + list.data.entries.length}` : `Page ${Math.floor(offset / 200) + 1}`}</span>
        <Button disabled={list.isFetching || list.data?.nextOffset == null} onClick={() => { if (list.data?.nextOffset != null) changePage(list.data.nextOffset); }}>Older engagements</Button>
      </nav> : null}
      {detail.data ? <label>Revision<select aria-label="Saved engagement revision" value={revision ?? ""} onChange={(event) => setRevision(Number(event.target.value))}><option value="" disabled>Choose a revision</option>{detail.data.map((item) => <option key={item.revision} value={item.revision}>Revision {item.revision} · SHA-256 {item.plan_sha256.slice(0, 12)}</option>)}</select></label> : null}
      {saved.data ? <div className="saved-engagements__actions"><Button onClick={() => { if (saved.data) onRestore(saved.data); }} variant="primary">Restore selected revision</Button><Button onClick={() => {
        try { if (saved.data) downloadJson(boundedJson(saved.data.plan), `AdversaryFlow_${saved.data.engagement_id}_revision_${saved.data.revision}.json`); }
        catch (failure: unknown) { onNotice(failure instanceof Error ? failure.message : "Revision download failed."); }
      }}>Download selected revision</Button></div> : null}
    </> : null}
  </section>;
}
