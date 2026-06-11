import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, CONFIDENCE_TONE, GROTESK, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import {
  EvidenceTag,
  Kicker,
  KineticHeadline,
  PullQuote,
  RedactionReveal,
  RuleLine,
  Stamp,
} from "./shared/editorial-ui";

// Beat 4 — "Two theories, one host." A magazine debate spread: Pool A
// (persistence-biased → INFERRED) and Pool B (exfil-biased → HYPOTHESIS) argued
// as two editorial columns with serif sub-heads and mono evidence lines. The
// conflicting tool_call_ids meet in a redacted CONFLICT callout (C.alert), then
// the judge's credibility-weighted merge lands as a letterpress Stamp.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

interface Argument {
  hand: string;
  pool: string;
  bias: string;
  tier: "INFERRED" | "HYPOTHESIS";
  thesis: string;
  evidence: string[];
  weight: string;
}

const POOL_A: Argument = {
  hand: "For the prosecution",
  pool: "Pool A",
  bias: "Persistence-biased",
  tier: "INFERRED",
  thesis: "svchost32 was dropped for persistence — a Run key pins it to every boot.",
  evidence: [
    "registry_query  HKLM\\…\\Run\\svchost32 present",
    "prefetch_parse  svchost32.exe .pf recovered",
    "amcache        catalog entry exists",
  ],
  weight: "0.72",
};

const POOL_B: Argument = {
  hand: "For the defense",
  pool: "Pool B",
  bias: "Exfil-biased",
  tier: "HYPOTHESIS",
  thesis: "svchost32 looks like a stock Windows component installed by a routine update.",
  evidence: [
    "hayabusa_scan  no sigma hits on svchost32",
    "mft_timeline   created alongside OS files",
    "zeek_summary   no network IOC observed",
  ],
  weight: "0.41",
};

function ArgumentColumn({ arg, frame, delay, align }: { arg: Argument; frame: number; delay: number; align: "left" | "right" }) {
  const tone = CONFIDENCE_TONE[arg.tier];
  const op = interpolate(frame - delay, [0, 16], [0, 1], clampOpts);
  const tx = interpolate(frame - delay, [0, 20], [align === "left" ? -26 : 26, 0], { ...clampOpts });
  return (
    <div style={{ opacity: op, transform: `translateX(${tx}px)`, textAlign: align }}>
      <div style={{ display: "flex", justifyContent: align === "left" ? "flex-start" : "flex-end", alignItems: "baseline", gap: 14 }}>
        <span style={{ ...labelStyle, color: tone }}>{arg.pool}</span>
        <span style={{ ...labelStyle, color: C.inkMuted }}>· {arg.bias}</span>
      </div>
      <div style={{ fontFamily: SERIF, fontStyle: "italic", fontSize: 17, color: C.inkFaint, marginTop: 4 }}>
        {arg.hand}
      </div>
      <div style={{ marginTop: 20 }}>
        <RuleLine frame={frame} delay={delay + 8} color={C.hairline} />
      </div>
      <div style={{
        fontFamily: SERIF, fontWeight: 600, fontSize: 33, lineHeight: 1.18, letterSpacing: -0.5,
        color: C.ink, marginTop: 24,
      }}>
        {arg.thesis}
      </div>
      <div style={{ marginTop: 26, display: "flex", flexDirection: "column", gap: 11, alignItems: align === "left" ? "flex-start" : "flex-end" }}>
        {arg.evidence.map((line, i) => {
          const ld = delay + 26 + i * 12;
          const lop = interpolate(frame - ld, [0, 12], [0, 1], clampOpts);
          return (
            <div key={i} style={{ fontFamily: MONO, fontSize: 15, color: C.inkMuted, opacity: lop, letterSpacing: 0.2 }}>
              {line}
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 28, display: "flex", justifyContent: align === "left" ? "flex-start" : "flex-end" }}>
        <EvidenceTag label={`Read as ${arg.tier.toLowerCase()}`} tier={arg.tier} frame={frame} delay={delay + 64} />
      </div>
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  fontFamily: GROTESK,
  fontSize: 17,
  fontWeight: 600,
  letterSpacing: 4,
  textTransform: "uppercase",
};

export function ContradictionScene() {
  const frame = useCurrentFrame();

  // Beat pacing across the 60s budget: title -> two arguments stagger in ->
  // the conflict redaction lifts -> the judge stamps the resolution.
  const poolAD = 30;
  const poolBD = 70;
  const conflictD = 470;
  const judgeD = 760;

  return (
    <Scene page={5} caption="Competing hypotheses · illustrative reconstruction">
      {/* Masthead — the debate framing */}
      <div style={{ position: "absolute", left: MARGIN, top: 150, width: 1100 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>Analysis of Competing Hypotheses</Kicker>
        <div style={{ marginTop: 14 }}>
          <KineticHeadline text="Two theories," frame={frame} delay={18} size={88} />
          <KineticHeadline text="one host." frame={frame} delay={30} size={88} italic />
        </div>
      </div>
      <div style={{ position: "absolute", right: MARGIN, top: 168, width: 360, textAlign: "right" }}>
        <PullQuote frame={frame} delay={42} size={23} color={C.inkMuted} style={{ fontStyle: "italic", fontWeight: 500 }}>
          Same evidence. Opposing priors. Two pools argue the host before the judge weighs them.
        </PullQuote>
      </div>

      {/* The debate spread — two argued columns flanking the central spine */}
      <div style={{ position: "absolute", left: MARGIN, top: 380, width: 690 }}>
        <ArgumentColumn arg={POOL_A} frame={frame} delay={poolAD} align="left" />
      </div>

      {/* Central spine — the contested record */}
      <div style={{ position: "absolute", left: 928, top: 392, bottom: 130, width: 1, background: C.hairline }} />

      <div style={{ position: "absolute", right: MARGIN, top: 380, width: 690 }}>
        <ArgumentColumn arg={POOL_B} frame={frame} delay={poolBD} align="right" />
      </div>

      {/* CONFLICT callout — the contradiction the two columns can't both hold */}
      <div style={{ position: "absolute", left: MARGIN, right: MARGIN, top: 768 }}>
        <RuleLine frame={frame} delay={conflictD - 14} color={C.alert} thickness={2} />
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginTop: 22, gap: 40 }}>
          <div style={{ maxWidth: 760 }}>
            <div style={{
              fontFamily: MONO, fontSize: 15, letterSpacing: 4, textTransform: "uppercase", color: C.alert,
              opacity: interpolate(frame - conflictD, [0, 12], [0, 1], clampOpts),
            }}>
              kind = contradiction · detect_contradictions
            </div>
            <div style={{ marginTop: 16, fontFamily: SERIF, fontSize: 30, fontWeight: 600, lineHeight: 1.25, color: C.ink }}>
              <span style={{ opacity: interpolate(frame - conflictD - 6, [0, 12], [0, 1], clampOpts) }}>
                The host can&rsquo;t be both. &ldquo;Run key present&rdquo; and{" "}
              </span>
              <RedactionReveal frame={frame} delay={conflictD + 30} color={C.alert} style={{ fontStyle: "italic" }}>
                &ldquo;born with the OS&rdquo;
              </RedactionReveal>
              <span style={{ opacity: interpolate(frame - conflictD - 6, [0, 12], [0, 1], clampOpts) }}>
                {" "}cannot both be true.
              </span>
            </div>
            <div style={{ marginTop: 18, display: "flex", gap: 36, fontFamily: MONO, fontSize: 14, color: C.inkFaint, opacity: interpolate(frame - conflictD - 40, [0, 14], [0, 1], clampOpts) }}>
              <span>A cites <span style={{ color: C.alert }}>tci_reg_00c2a1</span></span>
              <span>B cites <span style={{ color: C.alert }}>tci_mft_009f44</span></span>
            </div>
          </div>

          {/* The judge's resolution — credibility-weighted merge, stamped */}
          <div style={{ minWidth: 460, textAlign: "right" }}>
            <div style={{
              fontFamily: MONO, fontSize: 14, letterSpacing: 3, textTransform: "uppercase", color: C.inkMuted,
              opacity: interpolate(frame - judgeD, [0, 14], [0, 1], clampOpts),
            }}>
              judge_findings · weight A {POOL_A.weight} › weight B {POOL_B.weight}
            </div>
            <div style={{ marginTop: 18, display: "flex", justifyContent: "flex-end" }}>
              <Stamp
                label="Inferred · malicious persistence"
                frame={frame}
                delay={judgeD + 16}
                color={C.inferred}
                rotate={-5}
                size={24}
              />
            </div>
            <div style={{
              marginTop: 18, fontFamily: MONO, fontSize: 14, color: C.inkMuted, lineHeight: 1.7,
              opacity: interpolate(frame - judgeD - 30, [0, 14], [0, 1], clampOpts),
            }}>
              T1547.001 · the heavier prior carries
            </div>
          </div>
        </div>
      </div>
    </Scene>
  );
}
