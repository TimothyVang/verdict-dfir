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

interface N8nInfo {
  configured: boolean;
  url: string;
  email: string | null;
  password: string | null;
  reachable: boolean;
}

function CredRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked — value is visible to copy by hand */
    }
  };
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
        padding: "8px 0",
        borderBottom: `1px solid ${VERDICT.borderSubtle}`,
      }}
    >
      <span
        style={{
          fontFamily: GROTESK,
          fontSize: 12,
          letterSpacing: 1.5,
          textTransform: "uppercase",
          color: VERDICT.muted,
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <code
        style={{
          fontFamily: MONO,
          fontSize: 13,
          color: VERDICT.text,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          flex: 1,
          textAlign: "right",
        }}
      >
        {value}
      </code>
      <button
        type="button"
        onClick={copy}
        style={{
          flexShrink: 0,
          background: "transparent",
          border: `1px solid ${copied ? VERDICT.confirmed : VERDICT.border}`,
          color: copied ? VERDICT.confirmed : VERDICT.muted,
          borderRadius: RADIUS.pill,
          padding: "3px 10px",
          fontFamily: MONO,
          fontSize: 11,
          cursor: "pointer",
        }}
      >
        {copied ? "copied ✓" : "copy"}
      </button>
    </div>
  );
}

/**
 * N8nAccessCard — surfaces the n8n owner credentials that setup-n8n.py
 * provisions, so an investigator can open the automation portal. n8n 2.x
 * mandates an owner login (no no-auth mode), so the dashboard shows the
 * generated creds + a one-click open. The session is long-lived (set at
 * container start), so it's a one-time login in practice.
 */
export function N8nAccessCard() {
  const [info, setInfo] = useState<N8nInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/n8n")
      .then((r) => r.json())
      .then((d: N8nInfo) => {
        if (!cancelled) setInfo(d);
      })
      .catch(() => {
        /* leave null — card hides */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!info) return null;

  const dot = info.reachable ? VERDICT.confirmed : VERDICT.mutedDark;

  return (
    <Surface>
      <SectionHeading
        right={
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span
              aria-hidden
              style={{ width: 7, height: 7, borderRadius: "50%", background: dot }}
            />
            {info.reachable ? "online" : "offline"}
          </span>
        }
      >
        n8n automation portal
      </SectionHeading>

      {info.configured ? (
        <>
          <div style={{ marginTop: 2 }}>
            {info.email && <CredRow label="email" value={info.email} />}
            {info.password && <CredRow label="password" value={info.password} />}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 14 }}>
            <a
              href={info.url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                background: `${VERDICT.accentPurple}26`,
                border: `1px solid ${VERDICT.accentPurple}`,
                color: VERDICT.accentPurpleLight,
                borderRadius: RADIUS.pill,
                padding: "8px 16px",
                fontFamily: MONO,
                fontSize: 13,
                fontWeight: 700,
                textDecoration: "none",
              }}
            >
              Open n8n ↗
            </a>
            <span style={{ fontFamily: GROTESK, fontSize: 12, color: VERDICT.mutedDark, lineHeight: 1.4 }}>
              n8n 2.x requires a login; these creds open the canvas (long-lived session).
            </span>
          </div>
        </>
      ) : (
        <div style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.muted, lineHeight: 1.6, marginTop: 4 }}>
          Not provisioned yet. Run{" "}
          <code style={{ color: VERDICT.accentPurpleLight }}>python3 scripts/setup-n8n.py</code>{" "}
          to create the owner + deploy the workflow.
        </div>
      )}
    </Surface>
  );
}

export default N8nAccessCard;
