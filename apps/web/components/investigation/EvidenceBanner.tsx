// EvidenceBanner — the sticky "what am I looking at?" strip atop the dashboard.
//
// Presentational: takes the EvidenceMeta derived from the audit stream (see
// lib/evidence-meta.ts) and renders evidence name · type · size · SHA-256 (with
// copy) · case id. Returns null until a case_open has streamed, so it cleanly
// hides before a run connects. Uses the verdict-ui design tokens to match the
// rest of the dark dashboard.

"use client";

import { useState } from "react";

import type { EvidenceMeta } from "@/lib/evidence-meta";
import { GROTESK, MONO, VERDICT } from "@/lib/verdict-ui";

type Props = {
  meta: EvidenceMeta | null;
};

function shortHash(hash: string): string {
  if (hash.length <= 20) return hash;
  return `${hash.slice(0, 12)}…${hash.slice(-6)}`;
}

export function EvidenceBanner({ meta }: Props) {
  const [copied, setCopied] = useState(false);

  if (!meta) return null;

  const sha = meta.sha256;

  const handleCopy = async () => {
    if (!sha || typeof navigator === "undefined" || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(sha);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard blocked (insecure context / denied permission) — non-fatal.
    }
  };

  const dot = <span aria-hidden>{"·"}</span>;

  return (
    <section
      aria-label="evidence under investigation"
      style={{
        position: "sticky",
        top: 0,
        zIndex: 20,
        marginBottom: 16,
        background: "rgba(22,19,24,0.92)",
        backdropFilter: "blur(6px)",
        WebkitBackdropFilter: "blur(6px)",
        border: `1px solid ${VERDICT.border}`,
        borderLeft: `3px solid ${VERDICT.accentPurple}`,
        borderRadius: 12,
        padding: "12px 18px",
        fontFamily: MONO,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            fontFamily: GROTESK,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 2,
            color: VERDICT.accentPurpleLight,
          }}
        >
          EVIDENCE
        </span>
        <span
          style={{
            fontSize: 16,
            fontWeight: 700,
            color: VERDICT.text,
            wordBreak: "break-all",
          }}
        >
          {meta.name ?? meta.path}
        </span>
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          flexWrap: "wrap",
          marginTop: 6,
          fontSize: 12,
          color: VERDICT.muted,
        }}
      >
        <span
          style={{
            textTransform: "uppercase",
            letterSpacing: 1,
            color: VERDICT.inferred,
          }}
        >
          {meta.evidenceType}
        </span>

        {meta.sizeHuman ? (
          <>
            {dot}
            <span>{meta.sizeHuman}</span>
          </>
        ) : null}

        {sha ? (
          <>
            {dot}
            <span>sha256 {shortHash(sha)}</span>
            <button
              type="button"
              onClick={handleCopy}
              aria-label="copy full SHA-256 to clipboard"
              style={{
                background: "transparent",
                border: `1px solid ${VERDICT.border}`,
                borderRadius: 6,
                color: copied ? VERDICT.confirmed : VERDICT.muted,
                fontFamily: MONO,
                fontSize: 11,
                padding: "1px 8px",
                cursor: "pointer",
              }}
            >
              {copied ? "copied" : "copy"}
            </button>
          </>
        ) : null}

        {meta.caseId ? (
          <>
            {dot}
            <span>case {meta.caseId.slice(0, 8)}</span>
          </>
        ) : null}
      </div>
    </section>
  );
}
