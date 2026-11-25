// InvestigationStreamPanel — Scene 3 of the VERDICT demo, ported from the
// Remotion TerminalScene into a static, data-driven dashboard panel.
//
// PURE PRESENTATIONAL: fed the same `events: AuditLine[]` that app/page.tsx
// already accumulates off /api/audit. It reduces the raw stream itself (no
// fetching, no stores) into:
//   - streamRows[]: the terminal-window lines, per-line semantic color
//   - findings[]:   the right-column finding cards (confidence/MITRE chips,
//                   inset description block, tool_call_id provenance, verify badge)
//
// All design tokens + chips + chrome come from "@/lib/verdict-ui" (the single
// source of truth ported from the video). globals.css pins "Press Start 2P" on
// <body>, so MONO is scoped via the panel root wrapper.
//
// DEFENSIVE BINDING: the headless orchestrator (scripts/find_evil_auto.py)
// writes audit lines whose payloads DIFFER from the idealized typed AgentEvent
// models. Bind to the real orchestrator shapes:
//   - tool_call_start  → payload.{tool, tool_call_id, arguments}   (NOT tool_name; no pool)
//   - tool_call_output → payload.{tool_call_id, output_hash, row_count?}
//   - finding_approved → payload.{finding_id, confidence, tool_call_id,
//                                  finding_sha256, finding:{description,
//                                  mitre_technique, artifact_path, pool_origin}}
//   - verifier_action  → payload merges {finding_id, action, reason} + replay
//                                  {replay_matched, replay_error, ...}
//
// PROMOTION CAVEAT (the video's marquee "INFERRED → CONFIRMED" beat): the
// orchestrator's _apply_verifier_actions (find_evil_auto.py:5191) only ever
// DOWNGRADES or rejects — there is no promote path, and finding_approved emits
// each finding already at its final resolved tier. So we render the verify step
// as a CONFIRMATION pulse on the already-final tier, never a literal upward-tier
// morph. A true promotion animation would need a `finding_draft` event carrying
// the pre-verification tier (named in sprite-state.ts but NOT emitted headless).
//
// The post-A5 stream carries signed-manifest state only; the old
// OpenTimestamps/Bitcoin receipt fields were removed from the generated schema.

"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  ConfidenceChip,
  ErrorChip,
  GROTESK,
  MitreChip,
  MONO,
  PanelTitle,
  RADIUS,
  Surface,
  VERDICT,
  type Confidence,
} from "@/lib/verdict-ui";

// Mirror app/page.tsx's local AuditLine shape — importing from
// @/lib/audit-tail would drag node:fs + chokidar into the client bundle.
// Keep in sync with `apps/web/lib/audit-tail.ts:AuditLine`.
interface AuditLine {
  seq: number;
  kind: string;
  ts: string;
  payload: Record<string, unknown>;
  line_hash?: string;
  raw_line: string;
}

interface InvestigationStreamPanelProps {
  /** Chronologically-ordered raw stream the page accumulated from /api/audit. */
  events: AuditLine[];
  /** Short id for the subtitle; derived from the first event if absent. */
  caseId?: string;
  /** Head-trim cap on rendered terminal rows to bound the DOM. */
  maxStreamRows?: number;
  className?: string;
}

const DEFAULT_MAX_STREAM_ROWS = 200;

// ---------------------------------------------------------------------------
// Derivation — pure reduction over AuditLine[] into terminal rows + cards.
// Exported for unit testing (mirrors __tests__/audit-tail.test.ts).
// ---------------------------------------------------------------------------

export interface StreamRow {
  /** Stable React key. tool_call_id where available; else seq-derived. */
  key: string;
  text: string;
  color: string;
}

export interface VerifyState {
  action: string;
  matched: boolean | null;
  reason: string;
}

export interface FindingCard {
  finding_id: string;
  confidence?: string;
  mitre?: string | null;
  description?: string;
  artifact_path?: string;
  pool_origin?: string | null;
  tool_call_id?: string | null;
  finding_sha256?: string;
  verify?: VerifyState;
}

export interface DerivedStream {
  streamRows: StreamRow[];
  findings: FindingCard[];
}

/** Safe string read off an unknown payload field. */
function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** Safe number read off an unknown payload field. */
function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** First clause of a sentence, for the compact terminal FINDING row. */
function firstClause(text: string): string {
  const cut = text.split(/[.;—]/)[0]?.trim() ?? text;
  return cut.length > 0 ? cut : text;
}

const VERIFY_COLOR: Record<string, string> = {
  approved: VERDICT.confirmed,
  downgraded: VERDICT.inferred,
  rejected: VERDICT.alertRed,
};

/**
 * Reduce the chronological audit stream into terminal rows + finding cards.
 *
 * Findings are tracked in a Map keyed by finding_id so a verifier_action that
 * arrives before OR after its finding_approved both resolve — the chain is
 * append-only chronological but pool/verify phases interleave.
 */
export function deriveInvestigationStream(
  events: ReadonlyArray<AuditLine>,
): DerivedStream {
  const streamRows: StreamRow[] = [];
  // tool_call_id → index in streamRows, so tool_call_output can append to
  // its matching tool-call line.
  const rowIndexByToolCall = new Map<string, number>();
  const findingsById = new Map<string, FindingCard>();
  // Preserve first-seen card order independent of late verifier_action joins.
  const findingOrder: string[] = [];

  const ensureCard = (findingId: string): FindingCard => {
    const existing = findingsById.get(findingId);
    if (existing) return existing;
    const created: FindingCard = { finding_id: findingId };
    findingsById.set(findingId, created);
    findingOrder.push(findingId);
    return created;
  };

  for (const line of events) {
    const p = line.payload ?? {};
    const seqKey = `seq-${line.seq}`;

    switch (line.kind) {
      case "tool_call_start": {
        const toolCallId = asString(p.tool_call_id) ?? seqKey;
        const tool = asString(p.tool) ?? asString(p.tool_name) ?? "tool";
        const idx = streamRows.length;
        rowIndexByToolCall.set(toolCallId, idx);
        streamRows.push({
          key: `tcs-${toolCallId}`,
          text: `[${tool}] ${toolCallId}`,
          color: VERDICT.muted,
        });
        break;
      }

      case "tool_call_output": {
        const toolCallId = asString(p.tool_call_id);
        const outputHash = asString(p.output_hash) ?? "";
        const rowCount = asNumber(p.row_count);
        const hashSuffix = outputHash
          ? `  sha256:${outputHash.slice(0, 12)}`
          : "";
        const rowSuffix = rowCount != null ? `  ${rowCount} rows` : "";
        const idx =
          toolCallId != null ? rowIndexByToolCall.get(toolCallId) : undefined;
        if (idx != null && streamRows[idx]) {
          const base = streamRows[idx];
          // Immutable update — replace the row rather than mutate in place.
          streamRows[idx] = {
            ...base,
            text: `${base.text}${hashSuffix}${rowSuffix}`,
          };
        } else {
          streamRows.push({
            key: `tco-${toolCallId ?? seqKey}`,
            text: `[output] ${toolCallId ?? ""}${hashSuffix}${rowSuffix}`.trim(),
            color: VERDICT.faint,
          });
        }
        break;
      }

      case "finding_approved": {
        const findingId = asString(p.finding_id) ?? seqKey;
        const nested = (p.finding ?? {}) as Record<string, unknown>;
        const confidence = asString(p.confidence);
        const description =
          asString(nested.description) ?? "finding recorded";
        const mitre = asString(nested.mitre_technique) ?? null;
        const card = ensureCard(findingId);
        const merged: FindingCard = {
          ...card,
          confidence,
          mitre,
          description,
          artifact_path: asString(nested.artifact_path),
          pool_origin: asString(nested.pool_origin) ?? null,
          tool_call_id: asString(p.tool_call_id) ?? null,
          finding_sha256: asString(p.finding_sha256),
        };
        findingsById.set(findingId, merged);

        const mitreSuffix = mitre ? `  ·  mitre ${mitre}` : "";
        const confSuffix = confidence ? `  ·  confidence ${confidence}` : "";
        streamRows.push({
          key: `fa-${findingId}`,
          text: `  FINDING: ${firstClause(description)}${confSuffix}${mitreSuffix}`,
          color:
            confidence === "CONFIRMED" ? VERDICT.confirmed : VERDICT.inferred,
        });
        break;
      }

      case "verifier_action": {
        const findingId = asString(p.finding_id) ?? seqKey;
        const action = asString(p.action) ?? "approved";
        const reason = asString(p.reason) ?? "";
        const matchedRaw = p.replay_matched;
        const matched =
          typeof matchedRaw === "boolean" ? matchedRaw : null;
        const card = ensureCard(findingId);
        findingsById.set(findingId, {
          ...card,
          verify: { action, matched, reason },
        });
        streamRows.push({
          key: `va-${findingId}-${line.seq}`,
          text: `[verify_finding] ${action} ${findingId}${reason ? ` — ${reason}` : ""}`,
          color: VERIFY_COLOR[action] ?? VERDICT.muted,
        });
        break;
      }

      default:
        // All other kinds (acp_handoff, manifest bookkeeping,
        // forward-looking chain_update/finding_draft, …) are not part of this
        // panel's terminal/finding view. Intentionally ignored.
        break;
    }
  }

  const findings = findingOrder
    .map((id) => findingsById.get(id))
    .filter((card): card is FindingCard => card != null);

  return { streamRows, findings };
}

/** Derive a compact case id for the subtitle from the first event payload. */
function deriveCaseId(events: ReadonlyArray<AuditLine>): string | undefined {
  for (const line of events) {
    const raw = asString((line.payload ?? {}).case_id);
    if (raw) return raw.slice(0, 8);
  }
  return undefined;
}

/** Pull the dominant in-flight confidence + most-recent MITRE for the header. */
function deriveHeaderSummary(findings: ReadonlyArray<FindingCard>): {
  confidence?: Confidence;
  mitre?: string;
} {
  let confidence: Confidence | undefined;
  let mitre: string | undefined;
  for (const f of findings) {
    if (f.confidence === "CONFIRMED" || f.confidence === "INFERRED" || f.confidence === "HYPOTHESIS") {
      // Prefer the strongest tier seen; CONFIRMED wins outright.
      if (confidence !== "CONFIRMED") confidence = f.confidence;
    }
    if (f.mitre) mitre = f.mitre;
  }
  return { confidence, mitre };
}

// ---------------------------------------------------------------------------
// Scoped motion — fade+rise for rows, spring-ish scale for cards, cursor blink.
// Injected once; honors prefers-reduced-motion by disabling the transforms.
// ---------------------------------------------------------------------------

const STYLE_ID = "verdict-investigation-stream-motion";

const MOTION_CSS = `
@keyframes verdictRowIn {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}
@keyframes verdictCardIn {
  0%   { opacity: 0; transform: scale(0.6); }
  70%  { opacity: 1; transform: scale(1.03); }
  100% { opacity: 1; transform: scale(1); }
}
@keyframes verdictPulse {
  0%   { transform: scale(0.7); }
  60%  { transform: scale(1.08); }
  100% { transform: scale(1); }
}
@keyframes verdictCursorBlink {
  0%, 49%  { opacity: 1; }
  50%, 100% { opacity: 0; }
}
.verdict-row-in  { animation: verdictRowIn 200ms cubic-bezier(0.16, 1, 0.3, 1) both; }
.verdict-card-in { animation: verdictCardIn 300ms cubic-bezier(0.16, 1, 0.3, 1) both; }
.verdict-pulse   { animation: verdictPulse 360ms cubic-bezier(0.16, 1, 0.3, 1) both; }
.verdict-cursor  { animation: verdictCursorBlink 940ms steps(1, end) infinite; }
@media (prefers-reduced-motion: reduce) {
  .verdict-row-in, .verdict-card-in, .verdict-pulse { animation: none; }
  .verdict-cursor { animation: none; opacity: 1; }
}
/* Content grid: terminal ~58% + cards ~42%; collapse to one column
   (terminal first, cards below) under ~1280px so the finding descriptions
   never get squished in a too-narrow column. Media query is the only
   reliable way to drop a ratioed 2-col grid to a single stacked column. */
.verdict-stream-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
  gap: clamp(16px, 2vw, 28px);
  align-items: start;
}
@media (max-width: 1280px) {
  .verdict-stream-grid { grid-template-columns: 1fr; }
}
`;

function MotionStyles() {
  // Render the keyframes inline once. Static, escaped string — no user input.
  return (
    <style id={STYLE_ID} dangerouslySetInnerHTML={{ __html: MOTION_CSS }} />
  );
}

// ---------------------------------------------------------------------------
// Terminal window — chrome bar + auto-scrolling body of stream rows.
// ---------------------------------------------------------------------------

const TRAFFIC_LIGHTS = [
  VERDICT.alertRed,
  VERDICT.inferred,
  VERDICT.confirmed,
];

interface TerminalWindowProps {
  rows: StreamRow[];
  isEmpty: boolean;
}

function TerminalWindow({ rows, isEmpty }: TerminalWindowProps) {
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const pinnedRef = useRef(true);

  // Track whether the user has scrolled up; if so, suppress auto-scroll.
  useEffect(() => {
    const el = bodyRef.current;
    if (!el) return;
    const onScroll = (): void => {
      const distanceFromBottom =
        el.scrollHeight - el.scrollTop - el.clientHeight;
      pinnedRef.current = distanceFromBottom < 24;
    };
    el.addEventListener("scroll", onScroll);
    return () => el.removeEventListener("scroll", onScroll);
  }, []);

  // Auto-scroll to bottom on new rows, but only when pinned.
  useEffect(() => {
    const el = bodyRef.current;
    if (el && pinnedRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [rows.length]);

  return (
    <div
      style={{
        background: VERDICT.bg,
        border: `1px solid ${VERDICT.border}`,
        borderRadius: RADIUS.card,
        overflow: "hidden",
        display: "flex",
        flexDirection: "column",
        minHeight: 0,
      }}
    >
      {/* Chrome bar */}
      <div
        style={{
          padding: "12px 18px",
          background: VERDICT.surface,
          borderBottom: `1px solid ${VERDICT.border}`,
          display: "flex",
          alignItems: "center",
          gap: 8,
          flexShrink: 0,
        }}
      >
        {TRAFFIC_LIGHTS.map((c) => (
          <span
            key={c}
            aria-hidden
            style={{ width: 12, height: 12, borderRadius: "50%", background: c }}
          />
        ))}
        <span
          style={{
            marginLeft: 12,
            fontFamily: GROTESK,
            fontSize: 13,
            color: VERDICT.muted,
          }}
        >
          find-evil-auto — bash
        </span>
      </div>

      {/* Body */}
      <div
        ref={bodyRef}
        style={{
          padding: "20px 24px",
          fontFamily: MONO,
          fontSize: 16,
          lineHeight: 1.7,
          overflowY: "auto",
          maxHeight: "60vh",
          flex: 1,
          minHeight: 0,
        }}
      >
        {isEmpty ? (
          <div style={{ color: VERDICT.muted }}>
            Waiting for the investigation stream…
            <span
              className="verdict-cursor"
              style={{ color: VERDICT.confirmed, marginLeft: 6 }}
            >
              █
            </span>
          </div>
        ) : (
          rows.map((row, i) => {
            const isLast = i === rows.length - 1;
            return (
              <div
                key={row.key}
                className="verdict-row-in"
                style={{
                  color: row.color,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  minHeight: row.text ? "auto" : 8,
                }}
              >
                {row.text}
                {isLast && (
                  <span
                    className="verdict-cursor"
                    style={{ color: VERDICT.confirmed, marginLeft: 2 }}
                  >
                    █
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// VerifyBadge — bottom-right pill on each finding card. Green check on
// approved+replay_matched (confirmation pulse, NOT a tier promotion morph).
// ---------------------------------------------------------------------------

interface VerifyBadgeProps {
  verify: VerifyState;
}

function VerifyBadge({ verify }: VerifyBadgeProps) {
  const { action, matched } = verify;
  let color: string = VERDICT.muted;
  let label = action;
  if (action === "approved") {
    color = VERDICT.confirmed;
    label = matched === false ? "verified (hash mismatch)" : "hash match ✓ verified";
  } else if (action === "downgraded") {
    color = VERDICT.inferred;
    label = "downgraded";
  } else if (action === "rejected") {
    color = VERDICT.alertRed;
    label = "rejected";
  }
  // One-shot pulse keyed on the verify identity so it fires when verify resolves.
  return (
    <span
      key={`${action}-${String(matched)}`}
      className="verdict-pulse"
      style={{
        display: "inline-block",
        alignSelf: "flex-end",
        fontFamily: MONO,
        fontSize: 13,
        fontWeight: 700,
        letterSpacing: 0.5,
        color,
        background: `${color}1a`,
        border: `1px solid ${color}`,
        borderRadius: RADIUS.pill,
        padding: "3px 12px",
        whiteSpace: "nowrap",
      }}
      title={verify.reason || undefined}
    >
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// FindingCardView — one finding: chip row, inset description, provenance, verify.
// ---------------------------------------------------------------------------

const CONFIDENCE_VARIANTS: ReadonlySet<string> = new Set([
  "CONFIRMED",
  "INFERRED",
  "HYPOTHESIS",
]);

interface FindingCardViewProps {
  card: FindingCard;
}

function FindingCardView({ card }: FindingCardViewProps) {
  const confidence =
    card.confidence && CONFIDENCE_VARIANTS.has(card.confidence)
      ? (card.confidence as Confidence)
      : undefined;
  const isRejected = card.verify?.action === "rejected";

  return (
    <Surface
      padding={24}
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 14,
      }}
    >
      {/* className is applied via a wrapping div in JSX below; Surface forwards
          only style, so motion is scoped to its own animated wrapper instead. */}
      <div className="verdict-card-in" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {/* Chip row */}
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            gap: 10,
          }}
        >
          {confidence ? (
            <ConfidenceChip confidence={confidence} fontSize={16} />
          ) : isRejected ? (
            <ErrorChip label="REJECTED" fontSize={16} />
          ) : null}
          {card.mitre ? <MitreChip technique={card.mitre} fontSize={16} /> : null}
        </div>

        {/* Description — inset code block */}
        <div
          style={{
            background: VERDICT.surfaceInset,
            border: `1px solid ${VERDICT.borderSubtle}`,
            borderRadius: RADIUS.tile,
            padding: "12px 16px",
            fontFamily: MONO,
            fontSize: 16,
            lineHeight: 1.55,
            color: VERDICT.text,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {card.description ?? "—"}
          {card.artifact_path ? (
            <div
              style={{
                marginTop: 8,
                fontSize: 13,
                color: VERDICT.muted,
              }}
            >
              {card.artifact_path}
              {card.pool_origin ? `  · pool ${card.pool_origin}` : ""}
            </div>
          ) : null}
        </div>

        {/* Footer: tool_call_id provenance (left) + verify badge (right) */}
        <div
          style={{
            display: "flex",
            alignItems: "flex-end",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <span
            style={{
              fontFamily: MONO,
              fontSize: 13,
              color: VERDICT.hypothesis,
              wordBreak: "break-all",
            }}
          >
            {card.tool_call_id
              ? `tool_call_id: ${card.tool_call_id}`
              : "tool_call_id: (absent — verifier veto)"}
          </span>
          {card.verify ? <VerifyBadge verify={card.verify} /> : null}
        </div>
      </div>
    </Surface>
  );
}

// ---------------------------------------------------------------------------
// InvestigationStreamPanel — the full two-region scene.
// ---------------------------------------------------------------------------

export function InvestigationStreamPanel({
  events,
  caseId,
  maxStreamRows = DEFAULT_MAX_STREAM_ROWS,
  className,
}: InvestigationStreamPanelProps) {
  const { streamRows, findings } = useMemo(
    () => deriveInvestigationStream(events),
    [events],
  );

  // Head-trim to bound the DOM (mirrors MAX_EVENTS in app/page.tsx).
  const boundedRows = useMemo(
    () =>
      streamRows.length > maxStreamRows
        ? streamRows.slice(streamRows.length - maxStreamRows)
        : streamRows,
    [streamRows, maxStreamRows],
  );

  // Raw terminal stream is demoted to a collapsible affordance — investigators
  // see the readable finding cards first; the machine log is opt-in.
  const [showRaw, setShowRaw] = useState(false);

  const resolvedCaseId = caseId ?? deriveCaseId(events);
  const header = useMemo(() => deriveHeaderSummary(findings), [findings]);

  const subtitle = resolvedCaseId
    ? `live tool-call stream · case ${resolvedCaseId}`
    : "live tool-call stream";

  const isEmpty = streamRows.length === 0 && findings.length === 0;

  // The readable finding cards — the primary, prominent content.
  const findingCards =
    findings.length === 0 ? (
      <Surface padding={24}>
        <div style={{ color: VERDICT.muted, fontSize: 14 }}>
          No findings yet. Cards appear as the pools emit confirmed,
          tool-cited findings.
        </div>
      </Surface>
    ) : (
      findings.map((card) => (
        <FindingCardView key={card.finding_id} card={card} />
      ))
    );

  return (
    <section
      className={className}
      style={{
        position: "relative",
        background: VERDICT.bg,
        color: VERDICT.text,
        fontFamily: MONO,
        borderRadius: RADIUS.card,
        border: `1px solid ${VERDICT.border}`,
        padding: "clamp(20px, 4vw, 48px)",
        overflow: "hidden",
        boxSizing: "border-box",
      }}
    >
      <MotionStyles />

      {/* Header band */}
      <div
        style={{
          position: "relative",
          display: "flex",
          flexWrap: "wrap",
          alignItems: "flex-end",
          justifyContent: "space-between",
          gap: 16,
          marginBottom: "clamp(16px, 2vw, 28px)",
        }}
      >
        <PanelTitle
          title="Investigation Stream"
          subtitle={subtitle}
          size={40}
          letterSpacing={2}
          style={{ flex: "1 1 auto" }}
        />
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {header.confidence ? (
            <ConfidenceChip confidence={header.confidence} fontSize={16} />
          ) : null}
          {header.mitre ? (
            <MitreChip technique={header.mitre} fontSize={16} />
          ) : null}
        </div>
      </div>

      {/* Findings-first: when the raw log is collapsed, the readable cards take
          the full width. Expanding restores the 2-col terminal + cards grid. */}
      {showRaw ? (
        <div className="verdict-stream-grid" style={{ position: "relative" }}>
          <TerminalWindow rows={boundedRows} isEmpty={isEmpty} />

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 16,
              minWidth: 0,
            }}
          >
            {findingCards}
          </div>
        </div>
      ) : (
        <div
          style={{
            position: "relative",
            display: "flex",
            flexDirection: "column",
            gap: 16,
            minWidth: 0,
          }}
        >
          {findingCards}
        </div>
      )}

      {/* Raw activity log toggle — editorial section-header affordance. */}
      <button
        type="button"
        onClick={() => setShowRaw((prev) => !prev)}
        aria-expanded={showRaw}
        style={{
          appearance: "none",
          width: "100%",
          marginTop: "clamp(16px, 2vw, 28px)",
          paddingTop: 16,
          borderTop: `1px solid ${VERDICT.border}`,
          borderRight: 0,
          borderBottom: 0,
          borderLeft: 0,
          background: "transparent",
          color: VERDICT.muted,
          fontFamily: GROTESK,
          fontSize: 13,
          fontWeight: 700,
          letterSpacing: 1.5,
          textTransform: "uppercase",
          textAlign: "left",
          cursor: "pointer",
          display: "block",
        }}
      >
        {`${showRaw ? "▾" : "▸"} Raw activity log (${streamRows.length} events)`}
      </button>
    </section>
  );
}

export default InvestigationStreamPanel;
