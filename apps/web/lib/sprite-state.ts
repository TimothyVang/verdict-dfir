// Phase 5 sprite-state derivation — Amendment A3 §1.2.
//
// Maps the live audit.jsonl event stream (parsed via `tailAuditLog`
// in `lib/audit-tail.ts`) to a per-role visual state that the five
// `<RoleSprite>` components in `components/sprites/` consume.
//
// V0 RULES (deliberately coarse — refine when a real investigation
// surfaces what events actually fire in what order):
//
//   1. `tool_call_start` → the most recent emitting role goes
//      'working'. Pool affinity comes from the payload's `pool`
//      field ("A" → pool_a, "B" → pool_b). Tools without a `pool`
//      field default to setting BOTH pool_a and pool_b to 'working'
//      (the supervisor commonly fires shared probes).
//
//   2. `finding_approved` / `finding_draft` from a pool → that pool
//      flips to 'verdict'. The lib does NOT manage timers — the
//      consumer component is responsible for the post-verdict
//      decay back to 'idle' (per the task spec, ~1500ms).
//
//   3. `acp_handoff` (kind=`acp_handoff`, payload carries `from_role`
//      / `to_role` per AGENTS.md):
//        - verifier → judge:     verifier='verdict', judge='waiting'
//        - judge    → correlator: judge='verdict',   correlator='waiting'
//        - other handoffs are recorded but don't change visual state
//          in v0 (e.g. supervisor → pool_x).
//
//   4. Anything else → leave the role as it was (defaults to 'idle').
//
// We process events in order; later events override earlier ones for
// the same role. The reducer is pure — call it with the full event
// log every render. For the demo's event volume (single-digit
// thousands per investigation) that's cheap; if it ever bites, swap
// to an incremental reducer keyed off `seq`.
//
// State machine intentionally minimal: 'idle' | 'working' | 'waiting'
// | 'verdict'. We're not modeling per-finding fan-out, retry counts,
// or verifier downgrades — those land once the design pass produces
// real sprites and we know what affordances we need.

import type { AuditLine } from "@/lib/audit-tail";

export type Role = "pool_a" | "pool_b" | "verifier" | "judge" | "correlator";
export type SpriteState = "idle" | "working" | "waiting" | "verdict";

export const ALL_ROLES: readonly Role[] = [
  "pool_a",
  "pool_b",
  "verifier",
  "judge",
  "correlator",
] as const;

function emptyStates(): Record<Role, SpriteState> {
  return {
    pool_a: "idle",
    pool_b: "idle",
    verifier: "idle",
    judge: "idle",
    correlator: "idle",
  };
}

function poolFromPayload(payload: Record<string, unknown>): Role[] {
  // ToolCallStart events carry a `pool` field that is "A" | "B" |
  // "shared" | null (per services/agent/findevil_agent/events.py).
  // Map "A"/"B" to a single pool; treat "shared"/null as both.
  const raw = payload.pool;
  if (raw === "A") return ["pool_a"];
  if (raw === "B") return ["pool_b"];
  return ["pool_a", "pool_b"];
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

/**
 * Derive a per-role visual state from a chronologically-ordered audit
 * event log. Pure function; safe to call every render.
 *
 * Empty input → all roles 'idle'.
 */
export function deriveRoleStates(
  events: AuditLine[],
): Record<Role, SpriteState> {
  const states = emptyStates();

  for (const ev of events) {
    const payload = (ev.payload ?? {}) as Record<string, unknown>;

    switch (ev.kind) {
      case "tool_call_start": {
        // Most-recent tool call sets the originating pool(s) to working.
        for (const role of poolFromPayload(payload)) {
          states[role] = "working";
        }
        break;
      }

      case "finding_approved":
      case "finding_draft": {
        // pool_origin lives on Finding-shaped payloads; "A" | "B" |
        // "merged" per services/agent/findevil_agent/events.py.
        const origin = asString(payload.pool_origin);
        if (origin === "A") {
          states.pool_a = "verdict";
        } else if (origin === "B") {
          states.pool_b = "verdict";
        }
        // "merged" findings are emitted by the judge — we surface
        // them via judge's own state transition below if a handoff
        // accompanies them; nothing to do here in v0.
        break;
      }

      case "acp_handoff": {
        const from = asString(payload.from_role);
        const to = asString(payload.to_role);
        if (from === "verifier" && to === "judge") {
          states.verifier = "verdict";
          states.judge = "waiting";
        } else if (from === "judge" && to === "correlator") {
          states.judge = "verdict";
          states.correlator = "waiting";
        }
        // Other handoffs (supervisor → pool_x, pool_a → pool_b, …)
        // are recorded by the audit chain but don't drive sprite
        // state in v0.
        break;
      }

      case "contradiction_resolved": {
        // Verifier resolved a contradiction between pools — flip to verdict.
        states.verifier = "verdict";
        break;
      }

      case "manifest_finalize": {
        // Investigation complete — correlator settles to verdict, others idle.
        states.correlator = "verdict";
        states.pool_a = "idle";
        states.pool_b = "idle";
        states.verifier = "idle";
        states.judge = "idle";
        break;
      }

      default:
        // Bookkeeping records (`audit_append`, `chain_update`, etc.)
        // don't drive sprite visuals.
        break;
    }
  }

  return states;
}
