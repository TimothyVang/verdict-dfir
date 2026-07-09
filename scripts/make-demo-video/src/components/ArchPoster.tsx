import React from "react";
import { AbsoluteFill } from "remotion";
import { C, MONO, SERIF, GROTESK } from "./shared/editorial";
import { Grain, Vignette } from "./shared/Grain";

// Standalone architecture POSTER — a still (not a film beat). Replaces the old
// box-and-arrows diagram whose absolute-positioned labels collided. Everything
// here is flow layout (flex column + CSS grid + gaps), so text can never
// overlap regardless of length. Content is verbatim from docs/architecture.md.
//
// Render:  npx remotion still src/Root.tsx ArchPoster <out>.png --scale=1

const POSTER_W = 1680;
const PAD = 96;

type Tone = string;

interface Boundary {
  no: string;
  name: string;
  tone: Tone;
  body: React.ReactNode;
  note?: string;
}

function Pills({ items }: { items: string[] }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
      {items.map((t) => (
        <span
          key={t}
          style={{
            fontFamily: MONO,
            fontSize: 16,
            letterSpacing: 0.3,
            color: C.ink,
            border: `1px solid ${C.hairline}`,
            background: "rgba(236,230,218,0.03)",
            borderRadius: 4,
            padding: "5px 11px",
            whiteSpace: "nowrap",
          }}
        >
          {t}
        </span>
      ))}
    </div>
  );
}

function Mono({ children, color = C.inkMuted }: { children: React.ReactNode; color?: string }) {
  return (
    <span style={{ fontFamily: MONO, fontSize: 17, lineHeight: 1.5, letterSpacing: 0.3, color }}>
      {children}
    </span>
  );
}

const BOUNDARIES: Boundary[] = [
  {
    no: "00",
    name: "Evidence Vault",
    tone: C.confirmed,
    body: <Mono color={C.ink}>.E01 · .dd · memory · pcap&nbsp;&nbsp;—&nbsp;&nbsp;mounted read-only</Mono>,
    note: "SHA-256 at case_open · the original is never mutated",
  },
  {
    no: "01",
    name: "SIFT Tool Subprocesses",
    tone: C.inkMuted,
    body: <Pills items={["Volatility 3", "Hayabusa", "Chainsaw", "YARA-X", "Velociraptor", "Sleuth Kit", "tshark"]} />,
    note: "AGPL/GPL tools run as subprocesses, never linked — license-clean",
  },
  {
    no: "02",
    name: "Two Typed MCP Servers",
    tone: C.accent,
    body: (
      <div style={{ display: "flex", gap: 38, flexWrap: "wrap" }}>
        <Mono color={C.ink}>
          <b style={{ color: C.accent }}>findevil-mcp</b>&nbsp;· 32 Rust DFIR tools
        </Mono>
        <Mono color={C.ink}>
          <b style={{ color: C.accent }}>findevil-agent-mcp</b>&nbsp;· 14 Python crypto / ACH
        </Mono>
      </div>
    ),
    note: "typed in, typed out · hashes every output · no execute_shell",
  },
  {
    no: "03",
    name: "Claude Code Agent Loop",
    tone: C.accent,
    body: (
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <PoolTag label="Pool A" sub="persistence" tone={C.inferred} />
          <PoolTag label="Pool B" sub="exfil" tone={C.hypothesis} />
          <Mono>→ detect_contradictions → verify_finding → judge → correlate</Mono>
        </div>
      </div>
    ),
    note: "supervisor + two subagents · every Finding cites a tool_call_id",
  },
  {
    no: "04",
    name: "Cryptographic Custody",
    tone: C.accent,
    body: (
      <Mono color={C.ink}>
        hash-chained audit&nbsp;<span style={{ color: C.inkFaint }}>(prev_hash)</span>&nbsp; →&nbsp;
        Merkle root&nbsp; →&nbsp; signed manifest
      </Mono>
    ),
    note: "tamper one byte and verify fails · supports FRE 902(14) · checks offline",
  },
  {
    no: "05",
    name: "Presentation",
    tone: C.accent,
    body: (
      <Mono color={C.ink}>
        Claude Code terminal&nbsp;<span style={{ color: C.inkFaint }}>(primary UX)</span>&nbsp;·&nbsp;
        Next.js dashboard&nbsp;<span style={{ color: C.inkFaint }}>localhost:3000, read-only</span>
      </Mono>
    ),
    note: "signed verdict.json + REPORT.pdf — provable, not just claimed",
  },
];

function PoolTag({ label, sub, tone }: { label: string; sub: string; tone: string }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "baseline",
        gap: 7,
        fontFamily: MONO,
        fontSize: 16,
        border: `1px solid ${tone}`,
        color: tone,
        borderRadius: 4,
        padding: "5px 11px",
        whiteSpace: "nowrap",
      }}
    >
      <b>{label}</b>
      <span style={{ color: C.inkMuted, fontSize: 14 }}>{sub}</span>
    </span>
  );
}

export function ArchPoster() {
  return (
    <AbsoluteFill style={{ backgroundColor: C.paper, color: C.ink }}>
      <AbsoluteFill
        style={{
          padding: PAD,
          display: "flex",
          justifyContent: "center",
        }}
      >
        <div style={{ width: POSTER_W, height: "100%", display: "flex", flexDirection: "column" }}>
          {/* Running furniture — top */}
          <Row between>
            <Furniture>VERDICT — Case №1492</Furniture>
            <Furniture>A Forensic Case File</Furniture>
          </Row>
          <Hair thick />

          {/* Masthead */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 40, alignItems: "end", margin: "30px 0 8px" }}>
            <div>
              <div
                style={{
                  fontFamily: GROTESK,
                  fontSize: 18,
                  fontWeight: 600,
                  letterSpacing: 3,
                  textTransform: "uppercase",
                  color: C.accent,
                }}
              >
                SANS Find Evil! 2026 · Direct Agent Extension
              </div>
              <div style={{ fontFamily: SERIF, fontWeight: 600, fontSize: 78, lineHeight: 0.98, letterSpacing: -1.5, marginTop: 12, color: C.ink }}>
                Architecture &amp;<br />
                <span style={{ fontStyle: "italic", fontWeight: 400 }}>chain of custody.</span>
              </div>
            </div>
            <Stamp />
          </div>
          <div style={{ fontFamily: SERIF, fontStyle: "italic", fontSize: 24, color: C.inkMuted, marginTop: 14, marginBottom: 22 }}>
            Claude Code <span style={{ color: C.ink }}>is</span> the engine — evidence crosses each boundary only through a typed tool that hashes its own output.
          </div>
          <Hair />

          {/* The boundary stack — flow column, hairline-separated, distributed
              to fill the page height. No overlaps possible (grid + flex, gaps). */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "space-between", margin: "14px 0" }}>
            {BOUNDARIES.map((b, i) => (
              <div
                key={b.no}
                style={{
                  display: "grid",
                  gridTemplateColumns: "78px 360px 1fr",
                  columnGap: 28,
                  alignItems: "start",
                  padding: "16px 0",
                  borderBottom: i === BOUNDARIES.length - 1 ? "none" : `1px solid ${C.hairline}`,
                }}
              >
                {/* ordinal + tone tick */}
                <div style={{ display: "flex", alignItems: "stretch", gap: 16, minHeight: 56 }}>
                  <div style={{ width: 4, background: b.tone, borderRadius: 2 }} />
                  <span style={{ fontFamily: MONO, fontSize: 34, fontWeight: 700, color: C.inkFaint, letterSpacing: 0.5 }}>
                    {b.no}
                  </span>
                </div>

                {/* name + note */}
                <div>
                  <div style={{ fontFamily: SERIF, fontSize: 33, fontWeight: 600, lineHeight: 1.02, letterSpacing: -0.4, color: C.ink }}>
                    {b.name}
                  </div>
                  {b.note && (
                    <div style={{ fontFamily: SERIF, fontStyle: "italic", fontSize: 17.5, lineHeight: 1.3, color: C.inkMuted, marginTop: 8 }}>
                      {b.note}
                    </div>
                  )}
                </div>

                {/* content */}
                <div style={{ alignSelf: "center" }}>{b.body}</div>
              </div>
            ))}
          </div>

          <Hair thick />
          {/* Footer thesis / the spine ends */}
          <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 28, alignItems: "center", marginTop: 22 }}>
            <SpineCap color={C.confirmed}>EVIDENCE IN</SpineCap>
            <div style={{ fontFamily: SERIF, fontStyle: "italic", fontSize: 21, color: C.inkMuted, textAlign: "center", lineHeight: 1.3 }}>
              The guardrails are <span style={{ color: C.ink }}>architectural</span>, not just prompted — the narrow, typed,
              read-only surface <span style={{ color: C.ink }}>is</span> the security.
            </div>
            <SpineCap color={C.confirmed} align="right">SIGNED VERDICT OUT</SpineCap>
          </div>
        </div>
      </AbsoluteFill>
      <Vignette />
      <Grain />
    </AbsoluteFill>
  );
}

function Row({ children, between }: { children: React.ReactNode; between?: boolean }) {
  return <div style={{ display: "flex", justifyContent: between ? "space-between" : "flex-start", alignItems: "baseline" }}>{children}</div>;
}

function Furniture({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontFamily: GROTESK, fontSize: 15, fontWeight: 600, letterSpacing: 3, textTransform: "uppercase", color: C.inkMuted }}>
      {children}
    </span>
  );
}

function Hair({ thick }: { thick?: boolean }) {
  return <div style={{ height: thick ? 2 : 1, background: C.hairline, marginTop: 10 }} />;
}

function Stamp() {
  return (
    <div
      style={{
        border: `2px solid ${C.alert}`,
        borderRadius: 6,
        padding: "14px 18px",
        transform: "rotate(-2deg)",
        color: C.alert,
        fontFamily: MONO,
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: 30, fontWeight: 700, letterSpacing: 1, lineHeight: 1 }}>46 TYPED</div>
      <div style={{ fontSize: 30, fontWeight: 700, letterSpacing: 1, lineHeight: 1.1 }}>READ-ONLY TOOLS</div>
      <div style={{ fontSize: 14, letterSpacing: 2, marginTop: 6, color: C.inkMuted }}>NO EXECUTE_SHELL</div>
    </div>
  );
}

function SpineCap({ children, color, align }: { children: React.ReactNode; color: string; align?: "right" }) {
  return (
    <span
      style={{
        fontFamily: MONO,
        fontSize: 15,
        fontWeight: 700,
        letterSpacing: 3,
        textTransform: "uppercase",
        color,
        textAlign: align,
      }}
    >
      {children}
    </span>
  );
}
