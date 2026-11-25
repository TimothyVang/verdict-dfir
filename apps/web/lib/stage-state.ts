// Stage-rail derivation — maps the live audit.jsonl event stream onto a
// left→right investigation pipeline the operator watches in mission control.
//
// This is the "is the machine alive, and where is it?" glance. Unlike
// `deriveRoleStates` (which models the 5 ACH *roles* as independent boxes),
// this models the *progression* of a single investigation through its phases:
//
//   case_open → pool A → pool B → contradictions → verify → judge
//             → correlate → manifest → report
//
// Each phase maps to a robust signal in the canonical audit vocab (the kinds
// `scripts/find_evil_auto.py` actually emits). Progression is monotonic: the
// furthest phase with a fired signal is `active`; everything before it is
// `done` (even phases whose own signal never fired — a skipped phase still
// reads as passed, not stuck); everything after is `idle`. Sparse signals
// (e.g. a run with no contradictions) therefore still render a sensible rail.
//
// Pure function over the full event log — safe to call every render.

import type { AuditLine } from "@/lib/audit-tail";

export type StageStatus = "idle" | "active" | "done";

export interface Stage {
  id: string;
  label: string;
  status: StageStatus;
}

type Payload = Record<string, unknown>;

interface StageDef {
  id: string;
  label: string;
  /** Pipeline position. Parallel phases (pool A / pool B) share an order. */
  order: number;
  /** True when this event is evidence the phase has been reached. */
  fired: (ev: AuditLine, p: Payload) => boolean;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/** pool_origin can live top-level or nested under `finding` depending on the
 *  emitter; read both. */
function poolOrigin(p: Payload): string | undefined {
  const top = str(p.pool_origin);
  if (top) return top;
  const finding = p.finding;
  if (finding && typeof finding === "object") {
    return str((finding as Payload).pool_origin);
  }
  return undefined;
}

function isToolCallStart(ev: AuditLine): boolean {
  return ev.kind === "tool_call_start";
}

/** A pool tool call — any tool_call_start that isn't the opening case_open. */
function isPoolTool(ev: AuditLine, p: Payload): boolean {
  return isToolCallStart(ev) && str(p.tool) !== "case_open";
}

const STAGE_DEFS: readonly StageDef[] = [
  {
    id: "case_open",
    label: "Evidence locked",
    order: 1,
    fired: (ev, p) =>
      (isToolCallStart(ev) && str(p.tool) === "case_open") ||
      ev.kind === "case_inventory",
  },
  {
    id: "pool_a",
    label: "Team A · persistence",
    order: 2,
    fired: (ev, p) =>
      isPoolTool(ev, p) ||
      (ev.kind === "finding_approved" && poolOrigin(p) === "A"),
  },
  {
    id: "pool_b",
    label: "Team B · exfiltration",
    order: 2,
    fired: (ev, p) =>
      isPoolTool(ev, p) ||
      (ev.kind === "finding_approved" && poolOrigin(p) === "B"),
  },
  {
    id: "contradictions",
    label: "Cross-check",
    order: 3,
    fired: (ev) => ev.kind.startsWith("contradiction"),
  },
  {
    id: "verify",
    label: "Verify findings",
    order: 4,
    fired: (ev) => ev.kind === "verifier_action" || ev.kind === "replay",
  },
  {
    id: "judge",
    label: "Weigh",
    order: 5,
    fired: (ev, p) =>
      (ev.kind === "acp_handoff" && str(p.to_role) === "judge") ||
      (ev.kind === "finding_approved" && poolOrigin(p) === "merged"),
  },
  {
    id: "correlate",
    label: "Correlate",
    order: 6,
    fired: (ev, p) =>
      ev.kind === "acp_handoff" && str(p.to_role) === "correlator",
  },
  {
    id: "manifest",
    label: "Sign",
    order: 7,
    // The engine records manifest_finalize as a tool call and closes with
    // verdict_artifact -> verdict_packet; any of these means the attestation
    // phase was reached.
    fired: (ev, p) =>
      ev.kind === "manifest_finalize" ||
      ev.kind === "verdict_artifact" ||
      ev.kind === "verdict_packet" ||
      (ev.kind === "tool_call_start" && str(p.tool) === "manifest_finalize"),
  },
  {
    id: "report",
    // Report has no audit kind — it renders after manifest. The page passes
    // `reportReady` once /api/report finds REPORT.pdf.
    label: "Report",
    order: 8,
    fired: () => false,
  },
] as const;

const REPORT_ORDER = 8;

/**
 * Derive the ordered pipeline stages with monotonic status from the audit log.
 *
 * @param events       chronological audit lines (the page's accumulated stream)
 * @param reportReady  true once the signed PDF report is available
 */
export function deriveStageStates(
  events: ReadonlyArray<AuditLine>,
  reportReady = false,
): Stage[] {
  let furthest = 0;
  for (const ev of events) {
    const p = (ev.payload ?? {}) as Payload;
    for (const def of STAGE_DEFS) {
      if (def.fired(ev, p) && def.order > furthest) {
        furthest = def.order;
      }
    }
  }
  if (reportReady) furthest = REPORT_ORDER;

  return STAGE_DEFS.map((def) => {
    let status: StageStatus;
    if (furthest === 0) {
      status = "idle";
    } else if (def.order < furthest) {
      status = "done";
    } else if (def.order === furthest) {
      // Terminal phase reads as done once the whole run has completed
      // (manifest signed + report ready), otherwise it's the active head.
      status = reportReady && def.order === REPORT_ORDER ? "done" : "active";
    } else {
      status = "idle";
    }
    return { id: def.id, label: def.label, status };
  });
}
