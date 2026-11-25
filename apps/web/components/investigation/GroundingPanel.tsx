"use client";

import { useEffect, useState } from "react";
import {
  VERDICT,
  MONO,
  GROTESK,
  RADIUS,
  Surface,
  SectionHeading,
} from "@/lib/verdict-ui";

/**
 * GroundingPanel — renders the post-verdict anti-hallucination sidecar
 * (`grounding.json`). It checks the verdict's MITRE-technique claims against
 * authoritative sources and shows, per claim, whether the source supports it.
 *
 * HARD BOUNDARY (agent-config/GROUNDING.md): grounding is an operator aid —
 * never evidence, never a tool_call_id, never in the audit/crypto chain, and it
 * never changes the verdict or a finding's Confidence. A `supported` status
 * confirms the technique DEFINITION is real, NOT that it happened on this host.
 * The panel states that boundary in its chrome.
 *
 * Self-fetches grounding.json for the active case via the same /api/report shim
 * the other case-file panels use; hides until the file exists (most cases are
 * never grounded), and polls briefly so it appears if grounding runs while open.
 */

interface GroundingSource {
  source: string;
  url: string;
  excerpt: string;
}

interface GroundingClaim {
  technique_id: string;
  claimed?: boolean;
  claimed_by?: string[];
  finding_confidence?: string;
  status: string; // supported | contradicted | unsupported | unknown
  possible_hallucination?: boolean;
  id_status?: string; // e.g. "renumbered"
  mitre_current_id?: string | null;
  mitre_name?: string | null;
  sources?: GroundingSource[];
  rationale?: string;
}

interface IocGrounding {
  ioc: string;
  type: string; // hash | domain | ip | url
  status: string; // malicious | clean | unknown
  possible_overclaim?: boolean;
  detections?: string;
  names?: string[];
  sources?: GroundingSource[];
  rationale?: string;
}

interface CveGrounding {
  cve_id: string;
  status: string; // supported | unsupported | unknown
  possible_hallucination?: boolean;
  cvss?: number | null;
  severity?: string | null;
  sources?: GroundingSource[];
  rationale?: string;
}

interface ActionItem {
  action: string;
  based_on?: string;
  why?: string;
  route?: string; // act | review
  auto?: boolean;
}

interface OpenWebItem {
  query: string;
  relevance?: string; // corroborates | contradicts | unrelated
  note?: string;
  sources?: GroundingSource[];
}

interface CoverageTargets {
  validated?: number;
  on_mitre?: number;
  renumbered?: string[];
  not_on_mitre?: string[];
  ids?: string[];
  note?: string;
}

interface GroundingSummary {
  claims_judged?: number;
  supported?: number;
  contradicted?: number;
  unsupported?: number;
  unknown?: number;
  possible_hallucinations?: number;
  renumbered_ids?: number;
  iocs_judged?: number;
  iocs_malicious?: number;
  iocs_clean?: number;
  iocs_unknown?: number;
}

interface GroundingData {
  case_id?: string;
  verdict?: string;
  generated_at?: string;
  source?: string;
  judged_by?: string;
  grounding?: GroundingClaim[];
  ioc_grounding?: IocGrounding[];
  cve_grounding?: CveGrounding[];
  open_web?: OpenWebItem[];
  actions?: ActionItem[];
  coverage_targets?: CoverageTargets;
  summary?: GroundingSummary;
}

const STATUS_COLOR: Record<string, string> = {
  supported: VERDICT.confirmed,
  contradicted: VERDICT.alertRed,
  unsupported: VERDICT.inferred,
  unknown: VERDICT.muted,
};

function statusColor(status: string): string {
  return STATUS_COLOR[status] ?? VERDICT.muted;
}

function Chip({ label, color }: { label: string; color: string }) {
  return (
    <span
      style={{
        fontFamily: GROTESK,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 1.5,
        textTransform: "uppercase",
        color,
        background: `${color}1a`,
        border: `1px solid ${color}`,
        borderRadius: RADIUS.pill,
        padding: "2px 9px",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 56 }}>
      <span style={{ fontFamily: MONO, fontSize: 22, fontWeight: 700, color }}>{value}</span>
      <span
        style={{
          fontFamily: GROTESK,
          fontSize: 10,
          letterSpacing: 1.2,
          textTransform: "uppercase",
          color: VERDICT.muted,
        }}
      >
        {label}
      </span>
    </div>
  );
}

function SourceQuote({ src }: { src: GroundingSource }) {
  const href = /^https?:\/\//.test(src.url || "") ? src.url : undefined;
  return (
    <div
      style={{
        marginTop: 8,
        padding: "8px 12px",
        background: VERDICT.surfaceInset,
        borderLeft: `2px solid ${VERDICT.accentPurple}`,
        borderRadius: RADIUS.tile,
      }}
    >
      {/* Untrusted web text rendered as inert quoted DATA — never interpreted. */}
      <blockquote
        style={{
          margin: 0,
          fontFamily: MONO,
          fontSize: 12.5,
          lineHeight: 1.6,
          color: VERDICT.text,
        }}
      >
        &ldquo;{src.excerpt}&rdquo;
      </blockquote>
      <div style={{ marginTop: 6, fontFamily: GROTESK, fontSize: 11, color: VERDICT.muted }}>
        {src.source}
        {href ? (
          <>
            {" · "}
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: VERDICT.accentPurpleLight, textDecoration: "none" }}
            >
              {src.url} ↗
            </a>
          </>
        ) : null}
      </div>
    </div>
  );
}

function ClaimCard({ claim }: { claim: GroundingClaim }) {
  const color = statusColor(claim.status);
  const renumbered = claim.id_status === "renumbered" && claim.mitre_current_id;
  const provenance = [
    claim.claimed_by?.length ? `claimed by ${claim.claimed_by.join(", ")}` : null,
    claim.finding_confidence ? claim.finding_confidence : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <div
      style={{
        padding: "12px 0",
        borderTop: `1px solid ${VERDICT.borderSubtle}`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <code style={{ fontFamily: MONO, fontSize: 14, fontWeight: 700, color: VERDICT.text }}>
          {claim.technique_id}
        </code>
        <Chip label={claim.status} color={color} />
        {claim.possible_hallucination ? (
          <Chip label="possible hallucination" color={VERDICT.alertRed} />
        ) : null}
        {renumbered ? (
          <Chip label={`renumbered → ${claim.mitre_current_id}`} color={VERDICT.inferred} />
        ) : null}
      </div>

      {claim.mitre_name ? (
        <div style={{ marginTop: 4, fontFamily: GROTESK, fontSize: 13, color: VERDICT.muted }}>
          {claim.mitre_name}
        </div>
      ) : null}

      {provenance ? (
        <div
          style={{
            marginTop: 4,
            fontFamily: GROTESK,
            fontSize: 11,
            letterSpacing: 0.4,
            textTransform: "uppercase",
            color: VERDICT.mutedDark,
          }}
        >
          {provenance}
        </div>
      ) : null}

      {claim.rationale ? (
        <p style={{ margin: "8px 0 0", fontFamily: MONO, fontSize: 12.5, lineHeight: 1.6, color: VERDICT.text }}>
          {claim.rationale}
        </p>
      ) : null}

      {(claim.sources ?? []).map((src, i) => (
        <SourceQuote key={`${claim.technique_id}-src-${i}`} src={src} />
      ))}
    </div>
  );
}

const CVE_STATUS_COLOR: Record<string, string> = {
  supported: VERDICT.confirmed,
  unsupported: VERDICT.alertRed,
  unknown: VERDICT.muted,
};

function CveRow({ item }: { item: CveGrounding }) {
  const color = CVE_STATUS_COLOR[item.status] ?? VERDICT.muted;
  return (
    <div style={{ padding: "10px 0", borderTop: `1px solid ${VERDICT.borderSubtle}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <code style={{ fontFamily: MONO, fontSize: 13, fontWeight: 700, color: VERDICT.text }}>
          {item.cve_id}
        </code>
        <Chip label={item.status} color={color} />
        {typeof item.cvss === "number" ? (
          <span style={{ fontFamily: MONO, fontSize: 12, color }}>
            CVSS {item.cvss}
            {item.severity ? ` ${item.severity}` : ""}
          </span>
        ) : null}
        {item.possible_hallucination ? (
          <Chip label="possible hallucination" color={VERDICT.alertRed} />
        ) : null}
      </div>
      {item.rationale ? (
        <p style={{ margin: "6px 0 0", fontFamily: MONO, fontSize: 12, lineHeight: 1.55, color: VERDICT.text }}>
          {item.rationale}
        </p>
      ) : null}
      {(item.sources ?? []).map((src, i) => (
        <SourceQuote key={`${item.cve_id}-src-${i}`} src={src} />
      ))}
    </div>
  );
}

const IOC_STATUS_COLOR: Record<string, string> = {
  malicious: VERDICT.alertRed,
  clean: VERDICT.confirmed,
  unknown: VERDICT.muted,
};

function IocRow({ ioc }: { ioc: IocGrounding }) {
  const color = IOC_STATUS_COLOR[ioc.status] ?? VERDICT.muted;
  return (
    <div style={{ padding: "10px 0", borderTop: `1px solid ${VERDICT.borderSubtle}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <Chip label={ioc.status} color={color} />
        <span
          style={{
            fontFamily: GROTESK,
            fontSize: 10.5,
            letterSpacing: 1.2,
            textTransform: "uppercase",
            color: VERDICT.mutedDark,
          }}
        >
          {ioc.type}
        </span>
        {ioc.detections ? (
          <span style={{ fontFamily: MONO, fontSize: 12, color }}>{ioc.detections}</span>
        ) : null}
        {ioc.possible_overclaim ? (
          <Chip label="possible over-claim" color={VERDICT.inferred} />
        ) : null}
      </div>
      <code
        style={{
          display: "block",
          marginTop: 4,
          fontFamily: MONO,
          fontSize: 12,
          color: VERDICT.text,
          wordBreak: "break-all",
        }}
      >
        {ioc.ioc}
      </code>
      {ioc.names && ioc.names.length ? (
        <div style={{ marginTop: 2, fontFamily: GROTESK, fontSize: 11, color: VERDICT.muted }}>
          {ioc.names.join(", ")}
        </div>
      ) : null}
      {ioc.rationale ? (
        <p style={{ margin: "6px 0 0", fontFamily: MONO, fontSize: 12, lineHeight: 1.55, color: VERDICT.text }}>
          {ioc.rationale}
        </p>
      ) : null}
      {(ioc.sources ?? []).map((src, i) => (
        <SourceQuote key={`${ioc.ioc}-src-${i}`} src={src} />
      ))}
    </div>
  );
}

function ActionRow({ item }: { item: ActionItem }) {
  const isAct = item.route === "act";
  const color = isAct ? VERDICT.accentPurpleLight : VERDICT.inferred;
  return (
    <div style={{ padding: "10px 0", borderTop: `1px solid ${VERDICT.borderSubtle}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <Chip label={item.route === "act" ? "act" : "review"} color={color} />
        {item.based_on ? (
          <code style={{ fontFamily: MONO, fontSize: 12, color: VERDICT.muted }}>
            {item.based_on.length > 20 ? item.based_on.slice(0, 17) + "…" : item.based_on}
          </code>
        ) : null}
      </div>
      <div style={{ marginTop: 4, fontFamily: MONO, fontSize: 12.5, lineHeight: 1.55, color: VERDICT.text }}>
        {item.action}
      </div>
      {item.why ? (
        <div style={{ marginTop: 2, fontFamily: GROTESK, fontSize: 11, color: VERDICT.mutedDark }}>
          {item.why}
        </div>
      ) : null}
    </div>
  );
}

const RELEVANCE_COLOR: Record<string, string> = {
  corroborates: VERDICT.hypothesis,
  contradicts: VERDICT.alertRed,
  unrelated: VERDICT.muted,
};

function OpenWebRow({ item }: { item: OpenWebItem }) {
  const color = RELEVANCE_COLOR[item.relevance ?? ""] ?? VERDICT.muted;
  return (
    <div style={{ padding: "10px 0", borderTop: `1px solid ${VERDICT.borderSubtle}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        {item.relevance ? <Chip label={item.relevance} color={color} /> : null}
        <span style={{ fontFamily: MONO, fontSize: 12.5, color: VERDICT.text }}>
          “{item.query}”
        </span>
      </div>
      {item.note ? (
        <p style={{ margin: "6px 0 0", fontFamily: MONO, fontSize: 12, lineHeight: 1.55, color: VERDICT.text }}>
          {item.note}
        </p>
      ) : null}
      {(item.sources ?? []).map((src, i) => (
        <SourceQuote key={`${item.query}-src-${i}`} src={src} />
      ))}
    </div>
  );
}

export function GroundingPanel({ caseDir }: { caseDir: string }) {
  const [data, setData] = useState<GroundingData | null>(null);

  useEffect(() => {
    setData(null);
    if (!caseDir) return;
    let cancelled = false;
    let done = false;
    let ticks = 0;
    const url = `/api/report?case=${encodeURIComponent(caseDir)}&file=grounding.json`;
    const load = async () => {
      try {
        const r = await fetch(url);
        if (!cancelled && r.ok) {
          const d = (await r.json()) as GroundingData;
          if (!cancelled && d) {
            setData(d);
            done = true;
          }
        }
      } catch {
        /* leave null — panel hides until grounding.json exists */
      }
    };
    void load();
    // grounding.json lands post-verdict via a separate step; poll briefly (~5 min)
    // so it surfaces without a manual refresh, then give up once found or timed out.
    const timer = setInterval(() => {
      ticks += 1;
      if (cancelled || done || ticks > 15) {
        clearInterval(timer);
        return;
      }
      void load();
    }, 20000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [caseDir]);

  if (!data) return null;

  const s = data.summary ?? {};
  const claims = data.grounding ?? [];
  const cov = data.coverage_targets;

  return (
    <Surface>
      <SectionHeading
        right={
          typeof s.claims_judged === "number" ? (
            <span>
              {s.claims_judged} claim{s.claims_judged === 1 ? "" : "s"} judged
            </span>
          ) : undefined
        }
      >
        grounding · anti-hallucination
      </SectionHeading>

      <div
        style={{
          fontFamily: GROTESK,
          fontSize: 11.5,
          lineHeight: 1.5,
          color: VERDICT.mutedDark,
          marginTop: 2,
          marginBottom: 14,
        }}
      >
        {data.source ?? "operator aid; not evidence, not in audit chain"}
      </div>

      <div style={{ display: "flex", gap: 18, flexWrap: "wrap", marginBottom: 6 }}>
        <Stat label="supported" value={s.supported ?? 0} color={VERDICT.confirmed} />
        <Stat label="contradicted" value={s.contradicted ?? 0} color={VERDICT.alertRed} />
        <Stat label="unsupported" value={s.unsupported ?? 0} color={VERDICT.inferred} />
        <Stat label="unknown" value={s.unknown ?? 0} color={VERDICT.muted} />
        <Stat
          label="poss. halluc."
          value={s.possible_hallucinations ?? 0}
          color={(s.possible_hallucinations ?? 0) > 0 ? VERDICT.alertRed : VERDICT.muted}
        />
        <Stat
          label="renumbered"
          value={s.renumbered_ids ?? 0}
          color={(s.renumbered_ids ?? 0) > 0 ? VERDICT.inferred : VERDICT.muted}
        />
      </div>

      {(data.actions?.length ?? 0) > 0 ? (
        <div
          style={{
            marginTop: 10,
            padding: "10px 12px",
            background: VERDICT.surfaceInset,
            border: `1px solid ${VERDICT.borderSubtle}`,
            borderRadius: RADIUS.tile,
          }}
        >
          <div
            style={{
              fontFamily: GROTESK,
              fontSize: 11,
              letterSpacing: 1.2,
              textTransform: "uppercase",
              color: VERDICT.muted,
            }}
          >
            Recommended actions
            <span style={{ color: VERDICT.mutedDark }}> (human-in-the-loop · nothing auto-run)</span>
          </div>
          {(data.actions ?? []).map((item, i) => (
            <ActionRow key={`act-${i}`} item={item} />
          ))}
        </div>
      ) : null}

      {claims.length > 0 ? (
        <div style={{ marginTop: 6 }}>
          {claims.map((claim, i) => (
            <ClaimCard key={`${claim.technique_id}-${i}`} claim={claim} />
          ))}
        </div>
      ) : (
        <div style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.muted, marginTop: 6 }}>
          No finding-asserted technique claims to ground.
        </div>
      )}

      {cov && (cov.ids?.length ?? 0) > 0 ? (
        <div
          style={{
            marginTop: 14,
            paddingTop: 12,
            borderTop: `1px solid ${VERDICT.borderSubtle}`,
          }}
        >
          <div
            style={{
              fontFamily: GROTESK,
              fontSize: 11,
              letterSpacing: 1.2,
              textTransform: "uppercase",
              color: VERDICT.muted,
              marginBottom: 8,
            }}
          >
            coverage targets · {cov.on_mitre ?? 0}/{cov.validated ?? cov.ids?.length} on MITRE
            <span style={{ color: VERDICT.mutedDark }}> (playbook, not claims)</span>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {(cov.ids ?? []).map((id) => {
              const flagged =
                (cov.renumbered ?? []).includes(id) || (cov.not_on_mitre ?? []).includes(id);
              const c = flagged ? VERDICT.inferred : VERDICT.mutedDark;
              return (
                <code
                  key={id}
                  style={{
                    fontFamily: MONO,
                    fontSize: 11.5,
                    color: c,
                    border: `1px solid ${flagged ? c : VERDICT.borderSubtle}`,
                    borderRadius: RADIUS.pill,
                    padding: "1px 7px",
                  }}
                >
                  {id}
                </code>
              );
            })}
          </div>
        </div>
      ) : null}

      {(data.ioc_grounding?.length ?? 0) > 0 ? (
        <div
          style={{
            marginTop: 14,
            paddingTop: 12,
            borderTop: `1px solid ${VERDICT.borderSubtle}`,
          }}
        >
          <div
            style={{
              fontFamily: GROTESK,
              fontSize: 11,
              letterSpacing: 1.2,
              textTransform: "uppercase",
              color: VERDICT.muted,
            }}
          >
            IOC reputation
            {typeof s.iocs_malicious === "number" ? (
              <span style={{ color: VERDICT.alertRed }}>
                {" "}· {s.iocs_malicious} malicious
              </span>
            ) : null}
            <span style={{ color: VERDICT.mutedDark }}> (VirusTotal · operator aid)</span>
          </div>
          {(data.ioc_grounding ?? []).map((ioc, i) => (
            <IocRow key={`${ioc.ioc}-${i}`} ioc={ioc} />
          ))}
        </div>
      ) : null}

      {(data.cve_grounding?.length ?? 0) > 0 ? (
        <div
          style={{
            marginTop: 14,
            paddingTop: 12,
            borderTop: `1px solid ${VERDICT.borderSubtle}`,
          }}
        >
          <div
            style={{
              fontFamily: GROTESK,
              fontSize: 11,
              letterSpacing: 1.2,
              textTransform: "uppercase",
              color: VERDICT.muted,
            }}
          >
            CVE grounding
            <span style={{ color: VERDICT.mutedDark }}> (NVD · severity context, not proof)</span>
          </div>
          {(data.cve_grounding ?? []).map((cve, i) => (
            <CveRow key={`${cve.cve_id}-${i}`} item={cve} />
          ))}
        </div>
      ) : null}

      {(data.open_web?.length ?? 0) > 0 ? (
        <div
          style={{
            marginTop: 14,
            paddingTop: 12,
            borderTop: `1px solid ${VERDICT.borderSubtle}`,
          }}
        >
          <div
            style={{
              fontFamily: GROTESK,
              fontSize: 11,
              letterSpacing: 1.2,
              textTransform: "uppercase",
              color: VERDICT.muted,
            }}
          >
            Open-web corroboration
            <span style={{ color: VERDICT.mutedDark }}> (lowest trust · self-hosted search)</span>
          </div>
          {(data.open_web ?? []).map((item, i) => (
            <OpenWebRow key={`ow-${i}`} item={item} />
          ))}
        </div>
      ) : null}

      {data.judged_by || data.generated_at ? (
        <div
          style={{
            marginTop: 14,
            fontFamily: GROTESK,
            fontSize: 10.5,
            letterSpacing: 0.3,
            color: VERDICT.mutedDark,
          }}
        >
          {data.judged_by ? data.judged_by : ""}
          {data.judged_by && data.generated_at ? " · " : ""}
          {data.generated_at ? data.generated_at : ""}
        </div>
      ) : null}
    </Surface>
  );
}

export default GroundingPanel;
