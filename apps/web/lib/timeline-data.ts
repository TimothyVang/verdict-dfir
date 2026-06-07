// Timeline data model + reducers for the LiveTimeline component.
//
// Dual-source by design:
//   - PROVISIONAL dots are synthesized live from the audit stream's
//     `finding_approved` events while the investigation runs.
//   - AUTHORITATIVE events come from the engine's normalized_timeline
//     (verdict.json / timeline.json) via /api/timeline once the run finalizes.
// The component prefers authoritative when present, keyed by tool_call_id.

import type { AuditLine } from "@/lib/audit-tail";

export interface TimelineEvent {
  id: string;
  ts: number; // epoch ms; NaN-safe (unparseable -> filtered out)
  artifactClass: string;
  significance: string; // context | triage_lead | finding_support | ...
  confidence?: string;
  summary: string;
  toolCallId?: string;
  provisional: boolean;
}

type Payload = Record<string, unknown>;

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/** Best-effort artifact class from a finding's artifact_path extension. */
function artifactClassFromPath(p?: string): string {
  if (!p) return "finding";
  const ext = p.toLowerCase().split(".").pop() ?? "";
  if (["mem", "raw", "vmem", "dmp", "img", "lime"].includes(ext)) return "memory";
  if (ext === "evtx") return "evtx";
  if (["pcap", "pcapng", "cap"].includes(ext)) return "network";
  if (["e01", "dd", "aff4", "001"].includes(ext)) return "disk";
  return "artifact";
}

/** Synthesize provisional timeline dots from the live audit stream. */
export function deriveProvisionalTimeline(
  events: ReadonlyArray<AuditLine>,
): TimelineEvent[] {
  const out: TimelineEvent[] = [];
  for (const ev of events) {
    if (ev.kind !== "finding_approved") continue;
    const p = (ev.payload ?? {}) as Payload;
    const finding = (p.finding ?? {}) as Payload;
    const ts = Date.parse(ev.ts);
    if (Number.isNaN(ts)) continue;
    out.push({
      id: str(p.finding_id) ?? `seq-${ev.seq}`,
      ts,
      artifactClass:
        str(finding.artifact_class) ??
        artifactClassFromPath(str(finding.artifact_path)),
      significance: "finding_support",
      confidence: str(p.confidence) ?? str(finding.confidence),
      summary: str(finding.description) ?? "finding",
      toolCallId: str(p.tool_call_id),
      provisional: true,
    });
  }
  return out;
}

/** Normalize the authoritative /api/timeline payload into TimelineEvent[]. */
export function normalizeAuthoritative(raw: unknown): TimelineEvent[] {
  if (!raw || typeof raw !== "object") return [];
  const events = (raw as Record<string, unknown>).events;
  if (!Array.isArray(events)) return [];
  const out: TimelineEvent[] = [];
  for (const e of events) {
    if (!e || typeof e !== "object") continue;
    const o = e as Payload;
    const ts = Date.parse(str(o.timestamp_utc) ?? "");
    if (Number.isNaN(ts)) continue;
    out.push({
      id: str(o.event_id) ?? `${str(o.tool_call_id) ?? "ev"}-${ts}`,
      ts,
      artifactClass: str(o.artifact_class) ?? "artifact",
      significance: str(o.significance) ?? "context",
      confidence: str(o.confidence),
      summary: str(o.summary) ?? "",
      toolCallId: str(o.tool_call_id),
      provisional: false,
    });
  }
  return out;
}

/**
 * Merge provisional + authoritative. Authoritative wins; provisional dots whose
 * tool_call_id is covered by an authoritative event are dropped (reconciled),
 * the rest are kept (dimmed) so a judge never loses data they already saw.
 */
export function mergeTimeline(
  provisional: TimelineEvent[],
  authoritative: TimelineEvent[],
): TimelineEvent[] {
  if (authoritative.length === 0) return provisional;
  const covered = new Set(
    authoritative.map((e) => e.toolCallId).filter((x): x is string => !!x),
  );
  const leftover = provisional.filter(
    (e) => !(e.toolCallId && covered.has(e.toolCallId)),
  );
  return [...authoritative, ...leftover];
}

export interface TimelineLayout {
  lanes: string[];
  minTs: number;
  maxTs: number;
  /** x position 0..1 for a timestamp (0.5 when the span is degenerate). */
  xFor: (ts: number) => number;
}

export function layoutTimeline(events: ReadonlyArray<TimelineEvent>): TimelineLayout {
  const lanes = Array.from(new Set(events.map((e) => e.artifactClass))).sort();
  const tss = events.map((e) => e.ts);
  const minTs = tss.length ? Math.min(...tss) : 0;
  const maxTs = tss.length ? Math.max(...tss) : 0;
  const span = maxTs - minTs;
  const xFor = (ts: number): number => (span > 0 ? (ts - minTs) / span : 0.5);
  return { lanes, minTs, maxTs, xFor };
}
