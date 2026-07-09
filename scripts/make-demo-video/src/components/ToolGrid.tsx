import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine, Stamp } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 4 — "The toolbox." VERDICT's 45 forensic tools as a grouped instrument
// tray: four plain-English questions, each a GROTESK header + a count badge that
// counts up (mirrors FleetScene's big-numeral reveal) + a wrapped row of MONO
// tool-name chips. Groups reveal left→right; chips stagger in with spring. The
// thesis — every tool answers one question, and not one can run a shell — lands
// mid-beat under a "NO SHELL" stamp set against the chip wall.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

interface ToolGroup {
  question: string;
  count: number;
  tools: string[];
}

// The 45-tool surface, verbatim: 32 Rust DFIR tools + 13 Python crypto/ACH
// tools, regrouped by the question each answers.
const GROUPS: ToolGroup[] = [
  {
    question: "What ran on this machine?",
    count: 19,
    tools: [
      "case_open",
      "disk_mount",
      "disk_extract_artifacts",
      "disk_unmount",
      "prefetch_parse",
      "mft_timeline",
      "usnjrnl_query",
      "registry_query",
      "browser_history",
      "ez_parse",
      "plaso_parse",
      "indx_parse",
      "oe_dbx_parse",
      "vol_pslist",
      "vol_psscan",
      "vol_psxview",
      "vol_malfind",
      "vol_run",
      "mac_triage",
    ],
  },
  {
    question: "What did the system log?",
    count: 8,
    tools: [
      "evtx_query",
      "hayabusa_scan",
      "sysmon_network_query",
      "vel_collect",
      "journalctl_query",
      "login_accounting",
      "ausearch",
      "cloud_audit",
    ],
  },
  {
    question: "What left over the network?",
    count: 5,
    tools: ["pcap_triage", "zeek_summary", "suricata_eve", "nfdump_query", "yara_scan"],
  },
  {
    question: "Can we prove it?",
    count: 13,
    tools: [
      "audit_append",
      "audit_verify",
      "manifest_finalize",
      "manifest_verify",
      "verify_finding",
      "detect_contradictions",
      "judge_findings",
      "correlate_findings",
      "memory_remember",
      "memory_recall",
      "pool_handoff",
      "expert_miss_capture",
      "accuracy_compare",
      "find_ai_signatures",
    ],
  },
];

// Count-up numeral — mirrors the FleetScene big-numeral feel: a spring-driven
// climb from 0 to the group's tool count, settling at the badge value.
function CountBadge({ target, delay, tone }: { target: number; delay: number; tone: string }) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const s = spring({ frame: frame - delay, fps, config: { damping: 18, stiffness: 90, mass: 0.9 } });
  const value = Math.round(s * target);
  const ty = interpolate(frame - delay, [0, 16], [14, 0], clampOpts);
  const op = interpolate(frame - delay, [0, 12], [0, 1], clampOpts);
  return (
    <span
      style={{
        opacity: op,
        transform: `translateY(${ty}px)`,
        fontFamily: SERIF,
        fontWeight: 900,
        fontSize: 64,
        lineHeight: 0.9,
        letterSpacing: -2,
        color: tone,
        display: "inline-block",
      }}
    >
      {value}
    </span>
  );
}

// A single tool-name chip: small rounded surface, hairline border, mono label.
function ToolChip({ name, delay, tone }: { name: string; delay: number; tone: string }) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const s = spring({ frame: frame - delay, fps, config: { damping: 17, stiffness: 130 } });
  const op = interpolate(frame - delay, [0, 10], [0, 1], clampOpts);
  return (
    <span
      style={{
        opacity: op,
        transform: `translateY(${(1 - s) * 10}px)`,
        display: "inline-block",
        fontFamily: MONO,
        fontSize: 20,
        letterSpacing: 0.3,
        color: tone,
        background: C.surface,
        border: `1px solid ${C.hairline}`,
        borderRadius: 8,
        padding: "8px 14px",
        whiteSpace: "nowrap",
      }}
    >
      {name}
    </span>
  );
}

export function ToolGrid() {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Masthead + thesis reveals spread across the full beat.
  const sd = (raw: number) => spread(raw, 0, 100, durationInFrames, 24, 200);

  // Group reveal cadence (left→right): one group lands every ~step of the beat.
  const groupDelay = (i: number) => spread(20 + i * 18, 20, 74, durationInFrames, 40, 200);

  // The "NO SHELL" emphasis lands mid-beat, after the chips have populated.
  const stampDelay = spread(70, 0, 100, durationInFrames, 24, 200);

  const groupTone = (i: number) => (i === GROUPS.length - 1 ? C.confirmed : C.ink);

  return (
    <Scene page={4} caption="The tools" total={10}>
      {/* Left column — the story */}
      <div style={{ position: "absolute", left: MARGIN, top: 168, width: 560 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          Exhibit D · Inside the SANS SIFT Workstation
        </Kicker>
        <div style={{ marginTop: 18 }}>
          <KineticHeadline text="Forty-five" frame={frame} delay={sd(6)} size={92} />
          <KineticHeadline text="tools." frame={frame} delay={sd(11)} size={92} />
          <KineticHeadline text="Zero shells." frame={frame} delay={sd(16)} size={92} italic color={C.alert} />
        </div>
        <div style={{ marginTop: 28, marginBottom: 28 }}>
          <RuleLine frame={frame} delay={sd(24)} width={140} color={C.alert} thickness={2} />
        </div>

        <PullQuote frame={frame} delay={sd(30)} size={34} color={C.inkMuted} style={{ maxWidth: 520, lineHeight: 1.18 }}>
          Each answers one question. Not one&nbsp;can run a shell command.
        </PullQuote>

        {/* The thesis emphasis — a "NO SHELL" stamp against the chip wall */}
        <div style={{ marginTop: 56, display: "flex", alignItems: "center", gap: 26 }}>
          <Stamp label="No Shell" frame={frame} delay={stampDelay} color={C.alert} rotate={-7} size={30} />
          <div
            style={{
              fontFamily: MONO,
              fontSize: 15,
              color: C.inkMuted,
              lineHeight: 1.7,
              letterSpacing: 0.5,
              opacity: interpolate(frame - stampDelay - 8, [0, 16], [0, 1], clampOpts),
            }}
          >
            no <span style={{ color: C.alert }}>execute_shell</span><br />
            the attack surface stays narrow
          </div>
        </div>
      </div>

      {/* Right column — the four grouped bands of chips */}
      <div style={{ position: "absolute", left: 720, right: MARGIN, top: 176 }}>
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 14,
          }}
        >
          <span>Exhibit D-1 — Tool Surface</span>
          <span style={{ color: C.inkFaint }}>32 rust · 13 python · 45 typed</span>
        </div>
        <RuleLine frame={frame} delay={sd(20)} color={C.hairline} />

        <div style={{ marginTop: 22, display: "flex", flexDirection: "column", gap: 22 }}>
          {GROUPS.map((group, gi) => {
            const gd = groupDelay(gi);
            const op = interpolate(frame - gd, [0, 14], [0, 1], clampOpts);
            const tx = interpolate(frame - gd, [0, 18], [26, 0], clampOpts);
            const tone = groupTone(gi);
            return (
              <div key={group.question} style={{ opacity: op, transform: `translateX(${tx}px)` }}>
                {/* Band header — the plain-English question + count-up badge */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    justifyContent: "space-between",
                    gap: 24,
                    marginBottom: 12,
                  }}
                >
                  <span
                    style={{
                      fontFamily: GROTESK,
                      fontSize: 25,
                      fontWeight: 600,
                      letterSpacing: 0.2,
                      color: tone,
                    }}
                  >
                    {group.question}
                  </span>
                  <span style={{ display: "flex", alignItems: "baseline", gap: 10, flexShrink: 0 }}>
                    <CountBadge target={group.count} delay={gd + 4} tone={tone} />
                    <span
                      style={{
                        fontFamily: GROTESK,
                        fontSize: 13,
                        fontWeight: 600,
                        letterSpacing: 3,
                        textTransform: "uppercase",
                        color: C.inkMuted,
                      }}
                    >
                      tools
                    </span>
                  </span>
                </div>

                {/* Wrapped row of MONO tool-name chips */}
                <div style={{ display: "flex", flexWrap: "wrap", gap: 9 }}>
                  {group.tools.map((tool, ti) => {
                    const chipDelay = gd + 12 + ti * 4;
                    return <ToolChip key={tool} name={tool} delay={chipDelay} tone={C.inkMuted} />;
                  })}
                </div>

                {/* Hairline between bands */}
                {gi < GROUPS.length - 1 && (
                  <div style={{ marginTop: 22 }}>
                    <RuleLine frame={frame} delay={gd + 10} color={C.hairline} />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Closing tally under the tray */}
        <div style={{ marginTop: 26 }}>
          <RuleLine frame={frame} delay={sd(88)} color={C.hairline} thickness={2} />
        </div>
        <div
          style={{
            marginTop: 16,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
            fontFamily: MONO,
            fontSize: 15,
            letterSpacing: 2,
            textTransform: "uppercase",
            opacity: interpolate(frame - sd(92), [0, 16], [0, 1], clampOpts),
          }}
        >
          <span style={{ color: C.inkMuted }}>Four questions · forty-five answers</span>
          <span style={{ color: C.alert }}>Zero shells</span>
        </div>
      </div>
    </Scene>
  );
}
