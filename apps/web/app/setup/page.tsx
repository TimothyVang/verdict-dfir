// /setup — the guided onboarding the launcher opens when dependencies are
// missing. Renders scripts/doctor.sh --json (via /api/doctor) as a live
// checklist: each dependency's status, copy-to-clipboard install commands, a
// re-check button (auto-polling while anything required is missing), and a
// "drop evidence" prompt once the box is ready. On-brand with the VERDICT
// design system.

"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";

import { DashboardNav } from "@/components/DashboardNav";
import { BrandMark, Kicker, MONO, RADIUS, RuleLine, SerifHeadline, VERDICT } from "@/lib/verdict-ui";

interface Check {
  group: string;
  label: string;
  status: "ok" | "warn" | "err";
  detail: string;
}

interface DoctorReport {
  ready: boolean;
  missing_required: number;
  checks: Check[];
  remedies: string[];
  error?: string;
}

const STATUS_COLOR: Record<Check["status"], string> = {
  ok: VERDICT.confirmed,
  warn: VERDICT.inferred,
  err: VERDICT.alertRed,
};

const STATUS_GLYPH: Record<Check["status"], string> = {
  ok: "✓",
  warn: "!",
  err: "✕",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={`copy: ${text}`}
      onClick={() => {
        void navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      style={{
        background: "transparent",
        border: `1px solid ${VERDICT.border}`,
        color: copied ? VERDICT.confirmed : VERDICT.muted,
        borderRadius: RADIUS.pill,
        padding: "2px 10px",
        fontFamily: MONO,
        fontSize: 11,
        cursor: "pointer",
        whiteSpace: "nowrap",
      }}
    >
      {copied ? "copied ✓" : "copy"}
    </button>
  );
}

export default function SetupPage() {
  const [report, setReport] = useState<DoctorReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const recheck = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/doctor");
      const data = (await res.json()) as DoctorReport;
      if (!res.ok || data.error) {
        setError(data.error ?? `doctor failed (HTTP ${res.status})`);
        setReport(null);
      } else {
        setError(null);
        setReport(data);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void recheck();
  }, [recheck]);

  // Auto-poll every 5s while a REQUIRED dep is missing, so the operator sees
  // the box go green as they install. Stop once ready.
  useEffect(() => {
    if (report && !report.ready) {
      pollRef.current = setInterval(() => void recheck(), 5000);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [report, recheck]);

  const groups = report
    ? Array.from(new Set(report.checks.map((c) => c.group)))
    : [];

  return (
    <main
      style={{
        position: "relative",
        minHeight: "100vh",
        background: "transparent",
        color: VERDICT.text,
        fontFamily: MONO,
        overflowX: "hidden",
      }}
    >
      <div
        className="verdict-reveal"
        style={{ position: "relative", maxWidth: 1100, margin: "0 auto", padding: "clamp(20px, 4vw, 40px)" }}
      >
        <header style={{ marginBottom: 16, display: "flex", flexDirection: "column", gap: 10 }}>
          <Kicker>Environment Setup</Kicker>
          <SerifHeadline size={44}>Prepare the Workbench</SerifHeadline>
          <BrandMark size={56} withWordmark withTagline />
        </header>

        <RuleLine style={{ marginBottom: 24 }} />

        <DashboardNav active="setup" variant="dark" />

        {/* Overall banner */}
        <section
          aria-live="polite"
          style={{
            background: report?.ready ? `${VERDICT.confirmed}1a` : `${VERDICT.inferred}1a`,
            border: `1px solid ${report?.ready ? VERDICT.confirmed : VERDICT.inferred}`,
            borderRadius: RADIUS.card,
            padding: 20,
            marginBottom: 24,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
            <div>
              <div style={{ fontSize: 18, fontWeight: 800, color: report?.ready ? VERDICT.confirmed : VERDICT.inferred }}>
                {loading && !report ? "checking environment…" : report?.ready ? "READY" : "SETUP NEEDED"}
              </div>
              <div style={{ fontSize: 13, color: VERDICT.muted, marginTop: 4 }}>
                {report
                  ? report.ready
                    ? "All required tools present. DFIR binaries below are optional — in-process EVTX/MFT/prefetch run without them."
                    : `${report.missing_required} required tool(s) missing — install below, then re-check.`
                  : error
                    ? `error: ${error}`
                    : "running scripts/doctor.sh…"}
              </div>
            </div>
            <button
              type="button"
              onClick={() => void recheck()}
              style={{
                background: `${VERDICT.accentPurple}26`,
                border: `1px solid ${VERDICT.accentPurple}`,
                color: VERDICT.accentPurpleLight,
                borderRadius: RADIUS.pill,
                padding: "8px 18px",
                fontFamily: MONO,
                fontWeight: 700,
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              {loading ? "checking…" : "Re-check"}
            </button>
          </div>
        </section>

        {/* Ready -> drop-evidence prompt */}
        {report?.ready ? (
          <section
            aria-live="polite"
            style={{
              background: VERDICT.surface,
              border: `1px solid ${VERDICT.confirmed}`,
              borderRadius: RADIUS.card,
              padding: 20,
              marginBottom: 24,
            }}
          >
            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8 }}>Next: drop evidence</div>
            <div style={{ fontSize: 13, color: VERDICT.muted, lineHeight: 1.6 }}>
              Drop a <code style={{ color: VERDICT.accentPurpleLight }}>pcap</code> / disk image /{" "}
              <code style={{ color: VERDICT.accentPurpleLight }}>.evtx</code> / memory image into{" "}
              <code style={{ color: VERDICT.accentPurpleLight }}>./evidence/</code>, then run{" "}
              <code style={{ color: VERDICT.accentPurpleLight }}>python3 scripts/find-evil-live</code> — it
              opens the live dashboard and investigates on drop.
            </div>
            <Link
              href="/"
              style={{
                display: "inline-block",
                marginTop: 14,
                background: `${VERDICT.confirmed}26`,
                border: `1px solid ${VERDICT.confirmed}`,
                color: VERDICT.confirmed,
                borderRadius: RADIUS.pill,
                padding: "8px 18px",
                fontWeight: 700,
                fontSize: 13,
                textDecoration: "none",
              }}
            >
              Open mission control →
            </Link>
          </section>
        ) : null}

        {/* Grouped checks */}
        {groups.map((group) => (
          <section
            key={group}
            style={{
              background: VERDICT.surface,
              border: `1px solid ${VERDICT.border}`,
              borderRadius: RADIUS.card,
              padding: 18,
              marginBottom: 16,
            }}
          >
            <h2 style={{ margin: "0 0 12px", fontSize: 14, color: VERDICT.text, letterSpacing: 1 }}>{group}</h2>
            <ul role="list" style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 }}>
              {report?.checks
                .filter((c) => c.group === group)
                .map((c) => (
                  <li key={c.label} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
                    <span aria-hidden style={{ width: 16, textAlign: "center", color: STATUS_COLOR[c.status], fontWeight: 700 }}>
                      {STATUS_GLYPH[c.status]}
                    </span>
                    <span style={{ minWidth: 120, color: VERDICT.text }}>{c.label}</span>
                    <span style={{ color: VERDICT.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {c.detail}
                    </span>
                    <span style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)" }}>
                      {c.status}
                    </span>
                  </li>
                ))}
            </ul>
          </section>
        ))}

        {/* Remedies with copy buttons */}
        {report && report.remedies.length > 0 ? (
          <section
            style={{
              background: VERDICT.surface,
              border: `1px solid ${VERDICT.border}`,
              borderRadius: RADIUS.card,
              padding: 18,
            }}
          >
            <h2 style={{ margin: "0 0 12px", fontSize: 14, color: VERDICT.text, letterSpacing: 1 }}>install commands</h2>
            <ul role="list" style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 10 }}>
              {report.remedies.map((r, i) => {
                const idx = r.indexOf(":");
                const name = idx > 0 ? r.slice(0, idx) : "";
                const cmd = idx > 0 ? r.slice(idx + 1).trim() : r;
                return (
                  <li key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                    <span style={{ minWidth: 110, color: VERDICT.inferred, fontSize: 12 }}>{name}</span>
                    <code
                      style={{
                        flex: 1,
                        background: VERDICT.surfaceInset,
                        border: `1px solid ${VERDICT.borderSubtle}`,
                        borderRadius: RADIUS.tile,
                        padding: "6px 10px",
                        fontSize: 12,
                        color: VERDICT.text,
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                      }}
                    >
                      {cmd}
                    </code>
                    <CopyButton text={cmd} />
                  </li>
                );
              })}
            </ul>
          </section>
        ) : null}
      </div>
    </main>
  );
}
