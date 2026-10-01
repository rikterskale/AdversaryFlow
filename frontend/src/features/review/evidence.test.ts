import { afterEach, describe, expect, it, vi } from "vitest";

import { dateTimeIsoValue, dateTimeLocalValue, evidenceFromReceipt, validReceiptFields } from "./evidence";

afterEach(() => vi.unstubAllGlobals());

const receipt = { schema_version: "1.0", technique_id: "T1033", run_id: "receipt-run", started_at: "2026-09-18T14:30:45Z", completed_at: "2026-09-18T14:31:45Z", exit_code: 0, cleanup_verified: true, status: "passed", events: [], attestation: "café", receipt_sha256: "6a998011a3183237715fd32f883cc173f91f800cc54efa619df664cc646514e1" };

describe("review evidence", () => {
  it("round-trips browser-local timestamps to schema-safe ISO 8601", () => {
    const source = "2026-09-18T14:30:45.000Z";
    expect(dateTimeIsoValue(dateTimeLocalValue(source))).toBe(source);
    expect(dateTimeIsoValue("")).toBeUndefined();
  });

  it("rejects receipt values outside the published execution schema bounds", async () => {
    const receipt = JSON.stringify({ technique_id: "T1033", receipt_sha256: "0".repeat(64), run_id: "r".repeat(129), started_at: "2026-09-18T14:30:45.000Z", completed_at: "2026-09-18T14:31:45.000Z", exit_code: 70_000, cleanup_verified: true, status: "passed", events: [] });
    await expect(evidenceFromReceipt(receipt, "T1033")).rejects.toThrow("incomplete or invalid");
  });

  it("verifies an unmodified Python receipt containing non-ASCII text", async () => {
    const { webcrypto } = await vi.importActual<{ webcrypto: Crypto }>("node:crypto");
    vi.stubGlobal("crypto", webcrypto);
    await expect(evidenceFromReceipt(JSON.stringify(receipt), "T1033")).resolves.toMatchObject({ receipt_verified: true, run_id: "receipt-run" });
    await expect(evidenceFromReceipt(JSON.stringify({ ...receipt, attestation: "changed" }), "T1033")).rejects.toThrow("digest does not match");
  });

  it("rejects malformed receipt versions, events, and timestamps before hashing", () => {
    for (const patch of [{ schema_version: "2.0" }, { events: [null] }, { started_at: "2026-09-18T14:30:45" }]) {
      expect(validReceiptFields({ ...receipt, ...patch }, "T1033")).toBe(false);
    }
  });
});
