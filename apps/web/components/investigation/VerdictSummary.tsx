"use client";

import { useEffect, useMemo, useState } from "react";
import { deriveInvestigationStream } from "./InvestigationStreamPanel";
import {
  buildVerdictSummaryLine,
  deriveVerdictWord,
  summarizeVerdictCaveats,
  type VerdictPayload,
  type VerdictWord,
} from "@/lib/verdict-summary-policy";
import {
  VERDICT,
  MONO,
  SERIF,
  GROTESK,
  EvidenceTag,
  Kicker,
} from "@/lib/verdict-ui";

// Keep in sync with apps/web/app/page.tsx:AuditLine (importing from
// lib/audit-tail would drag node:fs into the client bundle).
interface AuditLine {
  seq: number;
  kind: string;
  ts: string;
  payload: Record<string, unknown>;
  line_hash?: string;
  raw_line: string;
}

interface VerdictMeta {
  color: string;
  line: string;
}

const VERDICT_META: Record<VerdictWord, VerdictMeta> = {
  SUSPICIOUS: {
    color: VERDICT.alertRed,
    line: "Evidence of compromise — treat as a positive and escalate.",
  },
  INDETERMINATE: {
    color: VERDICT.inferred,
    line: "Leads found, but none meet the two-source bar — corroboration needed.",
  },
  "NO EVIL": {
    color: VERDICT.confirmed,
    line: "No reportable findings in examined artifacts; scope remains explicit.",
  },
  INVESTIGATING: {
    color: VERDICT.accentPurpleLight,
    line: "Investigation in progress…",
  },
};

interface VerdictSummaryProps {
  events: AuditLine[];
  caseDir: string;
  manifestDone: boolean;
  evidenceName?: string;
}

/**
 * VerdictSummary — the human-first headline that answers, at a glance:
 * "is this machine compromised, how sure are we, and is it proven?" — before
 * the reader has to wade through the live terminal stream below it.
 *
 * The verdict word is taken from the signed verdict.json once the run finalizes;
 * until then (or for curated cases without a verdict.json) it is DERIVED from
 * the live findings' confidence tiers, so the banner is correct for both a
 * live run and a replayed/curated case.
 */
export function VerdictSummary({
  events,
  caseDir,
  manifestDone,
  evidenceName,
}: VerdictSummaryProps) {
  const findings = useMemo(
    () => deriveInvestigationStream(events).findings,
    [events],
  );

  const tally = useMemo(() => {
    let confirmed = 0;
    let inferred = 0;
    let hypothesis = 0;
    for (const f of findings) {
      const c = (f.confidence ?? "").toUpperCase();
      if (c === "CONFIRMED") confirmed += 1;
      else if (c === "INFERRED") inferred += 1;
      else if (c === "HYPOTHESIS") hypothesis += 1;
    }
    return { confirmed, inferred, hypothesis, total: findings.length };
  }, [findings]);

  // Authoritative verdict packet from the signed verdict.json once finalized.
  const [verdictPayload, setVerdictPayload] = useState<VerdictPayload | null>(null);
  useEffect(() => {
    if (!manifestDone || !caseDir) return;
    let cancelled = false;
    const tryFetch = async () => {
      try {
        const r = await fetch(
          `/api/report?case=${encodeURIComponent(caseDir)}&file=verdict.json`,
        );
        if (!r.ok) return;
        const d = (await r.json()) as VerdictPayload;
        if (!cancelled) setVerdictPayload(d);
      } catch {
        /* verdict.json may not exist (curated case) — fall back to derivation */
      }
    };
    void tryFetch();
    const id = setInterval(tryFetch, 2000);
    const stop = setTimeout(() => clearInterval(id), 12000);
    return () => {
      cancelled = true;
      clearInterval(id);
      clearTimeout(stop);
    };
  }, [manifestDone, caseDir]);

  const verdict = useMemo(
    () => deriveVerdictWord(verdictPayload?.verdict, tally, manifestDone),
    [verdictPayload, tally, manifestDone],
  );

  const caveats = useMemo(
    () => summarizeVerdictCaveats(verdictPayload),
    [verdictPayload],
  );

  // Nothing connected yet — let the empty-state of the page speak.
  if (!caseDir && events.length === 0) return null;

  const meta = VERDICT_META[verdict];
  const summaryLine = buildVerdictSummaryLine(
    verdict,
    tally,
    evidenceName,
    caveats,
  );

  return (
    <section
      aria-label="verdict summary"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${VERDICT.border}`,
        borderLeft: `4px solid ${meta.color}`,
        borderRadius: 12,
        padding: "24px 28px",
        marginBottom: 24,
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 24,
      }}
    >
      {/* Left — the answer */}
      <div style={{ minWidth: 0, flex: "1 1 420px" }}>
        <Kicker color={VERDICT.muted}>Verdict</Kicker>
        <div
          style={{
            fontFamily: SERIF,
            fontSize: 52,
            fontWeight: 900,
            lineHeight: 1.02,
            letterSpacing: -1,
            color: meta.color,
            margin: "8px 0 10px",
          }}
        >
          {verdict}
        </div>
        <div
          style={{
            fontFamily: GROTESK,
            fontSize: 17,
            lineHeight: 1.5,
            color: VERDICT.text,
            maxWidth: 640,
          }}
        >
          {summaryLine}
        </div>
        {caveats.length > 0 ? (
          <div
            aria-label="scope caveats"
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 8,
              marginTop: 14,
            }}
          >
            {caveats.slice(0, 6).map((caveat) => (
              <span
                key={caveat}
                style={{
                  fontFamily: MONO,
                  fontSize: 11,
                  color: VERDICT.inferred,
                  border: `1px solid ${VERDICT.inferred}`,
                  borderRadius: 999,
                  padding: "4px 9px",
                  background: `${VERDICT.inferred}16`,
                  whiteSpace: "nowrap",
                }}
              >
                {caveat}
              </span>
            ))}
          </div>
        ) : null}
      </div>

      {/* Right — the tallies + proof state */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 12,
          alignItems: "flex-end",
        }}
      >
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "flex-end" }}>
          {tally.confirmed > 0 && (
            <EvidenceTag label={`${tally.confirmed} confirmed`} tier="CONFIRMED" />
          )}
          {tally.inferred > 0 && (
            <EvidenceTag label={`${tally.inferred} inferred`} tier="INFERRED" />
          )}
          {tally.hypothesis > 0 && (
            <EvidenceTag label={`${tally.hypothesis} hypothesis`} tier="HYPOTHESIS" />
          )}
          {tally.total === 0 && (
            <span style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.muted }}>
              no findings yet
            </span>
          )}
        </div>
        <span
          style={{
            fontFamily: GROTESK,
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: 1,
            textTransform: "uppercase",
            color: manifestDone ? VERDICT.confirmed : VERDICT.muted,
            display: "inline-flex",
            alignItems: "center",
            gap: 7,
          }}
        >
          <span
            aria-hidden
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: manifestDone ? VERDICT.confirmed : VERDICT.mutedDark,
            }}
          />
          {manifestDone ? "Signed · verifiable offline" : "Investigation running"}
        </span>
      </div>
    </section>
  );
}

export default VerdictSummary;
