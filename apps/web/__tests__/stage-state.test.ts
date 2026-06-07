// Stage-rail derivation unit tests — covers the monotonic pipeline logic of
// `deriveStageStates`, not React rendering.

import { describe, expect, it } from "vitest";

import type { AuditLine } from "@/lib/audit-tail";
import { deriveStageStates } from "@/lib/stage-state";

function line(
  seq: number,
  kind: string,
  payload: Record<string, unknown>,
): AuditLine {
  return {
    seq,
    kind,
    ts: "2026-06-07T01:00:00Z",
    payload,
    line_hash: "deadbeef".padEnd(64, "0").slice(0, 64),
    raw_line: JSON.stringify({ seq, kind, payload }),
  };
}

/** Convenience: map stage id -> status for assertions. */
function statuses(events: AuditLine[], reportReady = false): Record<string, string> {
  return Object.fromEntries(
    deriveStageStates(events, reportReady).map((s) => [s.id, s.status]),
  );
}

describe("deriveStageStates", () => {
  it("returns all-idle for an empty event log", () => {
    const stages = deriveStageStates([]);
    expect(stages.every((s) => s.status === "idle")).toBe(true);
    expect(stages.map((s) => s.id)).toEqual([
      "case_open",
      "pool_a",
      "pool_b",
      "contradictions",
      "verify",
      "judge",
      "correlate",
      "manifest",
      "report",
    ]);
  });

  it("marks case_open active when only the opening tool call has fired", () => {
    const s = statuses([line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" })]);
    expect(s.case_open).toBe("active");
    expect(s.pool_a).toBe("idle");
    expect(s.report).toBe("idle");
  });

  it("lights both pools and marks case_open done once a pool tool runs", () => {
    const s = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "tool_call_start", { tool: "vol_psscan", tool_call_id: "tc-2" }),
    ]);
    expect(s.case_open).toBe("done");
    expect(s.pool_a).toBe("active");
    expect(s.pool_b).toBe("active");
    expect(s.contradictions).toBe("idle");
  });

  it("treats a skipped phase as done when a later phase has fired", () => {
    // No contradiction event, but verify fired -> contradictions reads done.
    const s = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "tool_call_start", { tool: "vol_psscan", tool_call_id: "tc-2" }),
      line(2, "verifier_action", { finding_id: "f-1", action: "approved" }),
    ]);
    expect(s.case_open).toBe("done");
    expect(s.pool_a).toBe("done");
    expect(s.contradictions).toBe("done"); // skipped but implied passed
    expect(s.verify).toBe("active");
    expect(s.judge).toBe("idle");
  });

  it("advances to judge on an acp_handoff to the judge role", () => {
    const s = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "acp_handoff", { from_role: "verifier", to_role: "judge" }),
    ]);
    expect(s.verify).toBe("done");
    expect(s.judge).toBe("active");
    expect(s.correlate).toBe("idle");
  });

  it("marks manifest active on manifest_finalize", () => {
    const s = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "manifest_finalize", { case_id: "c-1" }),
    ]);
    expect(s.correlate).toBe("done");
    expect(s.manifest).toBe("active");
    expect(s.report).toBe("idle");
  });

  it("reaches the manifest phase on the engine's real terminal beats", () => {
    // The engine emits verdict_artifact -> verdict_packet (and records
    // manifest_finalize as a tool call), never a manifest_finalize kind.
    const viaArtifact = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "verdict_artifact", { path: "verdict.json", sha256: "x" }),
    ]);
    expect(viaArtifact.manifest).toBe("active");

    const viaPacket = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "verdict_packet", { final_finding_ids: [] }),
    ]);
    expect(viaPacket.manifest).toBe("active");

    const viaTool = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "tool_call_start", { tool: "manifest_finalize", tool_call_id: "tc-9" }),
    ]);
    expect(viaTool.manifest).toBe("active");
  });

  it("marks everything done (manifest done, report done) when reportReady", () => {
    const s = statuses(
      [
        line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
        line(1, "manifest_finalize", { case_id: "c-1" }),
      ],
      true,
    );
    expect(s.manifest).toBe("done");
    expect(s.report).toBe("done");
  });

  it("reads pool_origin nested under finding (canonical finding_approved shape)", () => {
    const s = statuses([
      line(0, "tool_call_start", { tool: "case_open", tool_call_id: "tc-1" }),
      line(1, "finding_approved", {
        finding_id: "f-A-1",
        confidence: "CONFIRMED",
        finding: { pool_origin: "A", description: "x" },
      }),
    ]);
    // finding alone (no pool tool_call_start) still lights pool A.
    expect(s.pool_a).not.toBe("idle");
  });
});
