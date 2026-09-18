import { describe, expect, it } from "vitest";

import { dateTimeIsoValue, dateTimeLocalValue, evidenceFromReceipt } from "./evidence";

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
});
