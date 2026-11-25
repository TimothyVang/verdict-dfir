// Phase 5 sprite-state derivation unit tests — Amendment A3 §1.2.
//
// These cover the *logic* of `deriveRoleStates`, not React rendering.
// The sprite components themselves are placeholder visuals about to
// be replaced by the Claude Design pass; locking their JSX into
// component-render tests now would be premature.

import { describe, expect, it } from "vitest";

import type { AuditLine } from "@/lib/audit-tail";
import { deriveRoleStates } from "@/lib/sprite-state";

function line(
  seq: number,
  kind: string,
  payload: Record<string, unknown>,
): AuditLine {
  return {
    seq,
    kind,
    ts: "2026-04-27T01:00:00Z",
    payload,
    line_hash: "deadbeef".padEnd(64, "0").slice(0, 64),
    raw_line: JSON.stringify({ seq, kind, payload }),
  };
}

describe("deriveRoleStates", () => {
  it("returns all-idle for an empty event log", () => {
    const states = deriveRoleStates([]);
    expect(states).toEqual({
      pool_a: "idle",
      pool_b: "idle",
      verifier: "idle",
      judge: "idle",
      correlator: "idle",
    });
  });

  it("flips Pool A to 'working' on a tool_call_start with pool='A'", () => {
    const states = deriveRoleStates([
      line(0, "tool_call_start", {
        tool_name: "evtx_query",
        tool_call_id: "tc-1",
        pool: "A",
      }),
    ]);
    expect(states.pool_a).toBe("working");
    expect(states.pool_b).toBe("idle");
  });

  it("flips both pools to 'working' on a tool_call_start with no pool field (shared probe)", () => {
    const states = deriveRoleStates([
      line(0, "tool_call_start", {
        tool_name: "case_open",
        tool_call_id: "tc-shared",
      }),
    ]);
    expect(states.pool_a).toBe("working");
    expect(states.pool_b).toBe("working");
  });

  it("flips Pool B to 'verdict' on a finding_approved with pool_origin='B'", () => {
    const states = deriveRoleStates([
      line(0, "finding_approved", {
        finding_id: "f-B-1",
        pool_origin: "B",
        confidence: "CONFIRMED",
      }),
    ]);
    expect(states.pool_b).toBe("verdict");
    expect(states.pool_a).toBe("idle");
  });

  it("verifier→judge handoff sets verifier='verdict' and judge='waiting'", () => {
    const states = deriveRoleStates([
      line(0, "acp_handoff", {
        from_role: "verifier",
        to_role: "judge",
        payload: { finding_id: "f-1", action: "approved" },
      }),
    ]);
    expect(states.verifier).toBe("verdict");
    expect(states.judge).toBe("waiting");
    expect(states.correlator).toBe("idle");
  });

  it("judge→correlator handoff sets judge='verdict' and correlator='waiting'", () => {
    const states = deriveRoleStates([
      line(0, "acp_handoff", {
        from_role: "judge",
        to_role: "correlator",
        payload: { finding_count: 3 },
      }),
    ]);
    expect(states.judge).toBe("verdict");
    expect(states.correlator).toBe("waiting");
  });

  it("later events override earlier ones for the same role", () => {
    // Pool A working → then Pool A approved finding → 'verdict' wins.
    const states = deriveRoleStates([
      line(0, "tool_call_start", {
        tool_name: "registry_query",
        tool_call_id: "tc-A1",
        pool: "A",
      }),
      line(1, "finding_approved", {
        finding_id: "f-A-1",
        pool_origin: "A",
        confidence: "CONFIRMED",
      }),
    ]);
    expect(states.pool_a).toBe("verdict");
  });

  it("ignores bookkeeping kinds (chain_update, …)", () => {
    const states = deriveRoleStates([
      line(1, "chain_update", { merkle_root: "abc", leaf_count: 3 }),
    ]);
    expect(states).toEqual({
      pool_a: "idle",
      pool_b: "idle",
      verifier: "idle",
      judge: "idle",
      correlator: "idle",
    });
  });

  it("flips verifier on contradiction_resolved", () => {
    const states = deriveRoleStates([
      line(0, "contradiction_resolved", {
        contradiction_id: "c-1",
        resolution: "auto_higher_credibility",
        approved_by: "auto",
      }),
    ]);
    expect(states.verifier).toBe("verdict");
  });

  it("settles on manifest_finalize: correlator=verdict, others idle", () => {
    const states = deriveRoleStates([
      line(0, "tool_call_start", { tool_name: "evtx_query", pool: "A" }),
      line(1, "tool_call_start", { tool_name: "pcap_triage", pool: "B" }),
      line(2, "manifest_finalize", { run_id: "r-1", manifest_hash: "abc" }),
    ]);
    expect(states.correlator).toBe("verdict");
    expect(states.pool_a).toBe("idle");
    expect(states.pool_b).toBe("idle");
    expect(states.verifier).toBe("idle");
    expect(states.judge).toBe("idle");
  });

  it("reads pool_origin from finding_approved payloads", () => {
    const states = deriveRoleStates([
      line(0, "finding_approved", {
        finding_id: "f-1",
        pool_origin: "B",
        confidence: "CONFIRMED",
      }),
    ]);
    expect(states.pool_b).toBe("verdict");
    expect(states.pool_a).toBe("idle");
  });
});
