import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine, Stamp } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 6 — "Twenty-two hosts." The fleet as a forensic contact sheet: 22 host
// tiles in a tight editorial index (flagged = alert, clean = confirmed tone,
// running/queued = muted) with mono host ids, beside a stat sidebar of
// oversized v2 editorial numerals and a signed note. Replaces the old GitHub-dark
// grid + rounded-card rollup.

const FINDING_COUNTS = [3, 1, 0, 2, 1, 4, 0, 1, 2, 0, 3, 1, 0, 1, 2, 0, 1, 3, 0, 0, 0, 0];

type HostStatus = "flagged" | "clean" | "running" | "queued";
interface Host {
  id: number;
  name: string;
  status: HostStatus;
  findings: number;
}

const HOSTS: Host[] = Array.from({ length: 22 }, (_, i) => {
  const findings = FINDING_COUNTS[i] ?? 0;
  const rawStatus = i < 18 ? "done" : i < 20 ? "running" : "queued";
  const status: HostStatus =
    rawStatus === "done" ? (findings > 0 ? "flagged" : "clean") : (rawStatus as HostStatus);
  return { id: i + 1, name: `HOST-${String(i + 1).padStart(3, "0")}`, status, findings };
});

const STATUS_TONE: Record<HostStatus, string> = {
  flagged: C.alert,
  clean: C.confirmed,
  running: C.inkMuted,
  queued: C.inkFaint,
};

// The fleet rollup of record — stated totals, preserved verbatim from the case.
const STATS: { value: string; label: string; tone: string }[] = [
  { value: "22", label: "Hosts investigated", tone: C.ink },
  { value: "24", label: "Total findings", tone: C.alert },
  { value: "11", label: "Confirmed", tone: C.confirmed },
  { value: "08", label: "Inferred", tone: C.inferred },
  { value: "05", label: "Hypothesis", tone: C.hypothesis },
];

export function FleetScene() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();
  const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

  // Spread the host fan-out across the full 50s beat so the index fills in step
  // with the narration instead of completing in the first few seconds.
  const hostDelay = (id: number) => spread(70 + id * 4, 74, 158, durationInFrames, 60, 220);
  const statD = (i: number) => spread(96 + i * 6, 96, 130, durationInFrames, 60, 220);
  const sealD = spread(132, 96, 132, durationInFrames, 60, 220);

  return (
    <Scene page={9} caption="Fleet · 84 GB">
      {/* Masthead — kicker + kinetic headline */}
      <div style={{ position: "absolute", left: MARGIN, top: 132, width: 1000 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>
          Fleet · 84 GB · one command
        </Kicker>
        <div style={{ marginTop: 14 }}>
          <KineticHeadline text="Twenty-two hosts." frame={frame} delay={20} size={92} />
        </div>
      </div>

      {/* Left — the contact sheet / host index */}
      <div style={{ position: "absolute", left: MARGIN, top: 290, width: 960 }}>
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
          <span>Exhibit F — Host Index</span>
          <span style={{ color: C.inkFaint }}>memory images · 22 of 22</span>
        </div>
        <RuleLine frame={frame} delay={44} color={C.hairline} />

        <div
          style={{
            marginTop: 18,
            display: "grid",
            gridTemplateColumns: "repeat(6, 1fr)",
            columnGap: 2,
            rowGap: 2,
            borderTop: `1px solid ${C.hairline}`,
            borderLeft: `1px solid ${C.hairline}`,
          }}
        >
          {HOSTS.map((host) => {
            const delay = hostDelay(host.id);
            const s = spring({ frame: frame - delay, fps, config: { damping: 16, stiffness: 120 } });
            const op = interpolate(frame - delay, [0, 12], [0, 1], clampOpts);
            const tone = STATUS_TONE[host.status];
            const isFlagged = host.status === "flagged";
            const meta =
              host.status === "flagged"
                ? `${host.findings} ${host.findings === 1 ? "finding" : "findings"}`
                : host.status === "clean"
                  ? "clean"
                  : host.status === "running"
                    ? "running"
                    : "queued";
            return (
              <div
                key={host.id}
                style={{
                  opacity: op,
                  transform: `translateY(${(1 - s) * 8}px)`,
                  borderRight: `1px solid ${C.hairline}`,
                  borderBottom: `1px solid ${C.hairline}`,
                  background: isFlagged ? `${C.alert}10` : "transparent",
                  padding: "16px 16px 14px",
                  minHeight: 86,
                  position: "relative",
                }}
              >
                {/* flagged corner tick — the redaction-margin flag */}
                {isFlagged && (
                  <div
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: 3,
                      bottom: 0,
                      background: C.alert,
                    }}
                  />
                )}
                <div
                  style={{
                    fontFamily: MONO,
                    fontSize: 15,
                    fontWeight: 700,
                    letterSpacing: 0.5,
                    color: host.status === "queued" ? C.inkFaint : C.ink,
                  }}
                >
                  {host.name}
                </div>
                <div
                  style={{
                    fontFamily: isFlagged ? SERIF : MONO,
                    fontStyle: isFlagged ? "italic" : "normal",
                    fontSize: isFlagged ? 19 : 13,
                    fontWeight: isFlagged ? 600 : 400,
                    color: tone,
                    marginTop: 8,
                    letterSpacing: isFlagged ? -0.3 : 1,
                  }}
                >
                  {meta}
                </div>
              </div>
            );
          })}
        </div>

        {/* legend strip */}
        <div
          style={{
            marginTop: 18,
            display: "flex",
            gap: 30,
            fontFamily: GROTESK,
            fontSize: 13,
            letterSpacing: 2,
            textTransform: "uppercase",
            color: C.inkMuted,
            opacity: interpolate(frame - 60, [0, 16], [0, 1], clampOpts),
          }}
        >
          <LegendDot tone={C.alert} label="Flagged · 9" />
          <LegendDot tone={C.confirmed} label="Clean · 13" />
          <LegendDot tone={C.inkMuted} label="Running" />
          <LegendDot tone={C.inkFaint} label="Queued" />
        </div>
      </div>

      {/* Right — the stat sidebar: oversized v2 editorial numerals of record */}
      <div style={{ position: "absolute", right: MARGIN, top: 290, width: 470 }}>
        <div
          style={{
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 16,
          }}
        >
          Fleet Rollup of Record
        </div>
        <RuleLine frame={frame} delay={80} color={C.hairline} />

        {STATS.map((stat, i) => {
          const d = statD(i);
          const op = interpolate(frame - d, [0, 14], [0, 1], clampOpts);
          const ty = interpolate(frame - d, [0, 16], [16, 0], clampOpts);
          const big = i === 0;
          return (
            <div
              key={stat.label}
              style={{
                opacity: op,
                transform: `translateY(${ty}px)`,
                display: "flex",
                alignItems: "baseline",
                justifyContent: "space-between",
                gap: 20,
                padding: big ? "22px 0 18px" : "13px 0",
                borderBottom: `1px solid ${C.hairline}`,
              }}
            >
              <span
                style={{
                  fontFamily: SERIF,
                  fontWeight: 900,
                  fontSize: big ? 96 : 58,
                  lineHeight: 0.9,
                  letterSpacing: -2,
                  color: stat.tone,
                }}
              >
                {stat.value}
              </span>
              <span
                style={{
                  fontFamily: GROTESK,
                  fontSize: 14,
                  fontWeight: 600,
                  letterSpacing: 3,
                  textTransform: "uppercase",
                  color: C.inkMuted,
                  textAlign: "right",
                  maxWidth: 180,
                }}
              >
                {stat.label}
              </span>
            </div>
          );
        })}

        {/* secondary tallies */}
        <div
          style={{
            marginTop: 22,
            display: "flex",
            gap: 36,
            opacity: interpolate(frame - statD(5), [0, 16], [0, 1], clampOpts),
          }}
        >
          <Tally value="9" label="hosts with IOC" tone={C.alert} />
          <Tally value="13" label="clean" tone={C.confirmed} />
        </div>

        {/* signed note + seal */}
        <div style={{ marginTop: 40, display: "flex", alignItems: "center", gap: 24 }}>
          <Stamp label="Signed · manifest" frame={frame} delay={sealD} color={C.confirmed} rotate={-6} size={22} />
          <div
            style={{
              fontFamily: MONO,
              fontSize: 13,
              color: C.inkMuted,
              lineHeight: 1.7,
              opacity: interpolate(frame - sealD - 10, [0, 16], [0, 1], clampOpts),
            }}
          >
            manifest_verify ✓<br />
            one signed run · verifiable offline
          </div>
        </div>
      </div>

      {/* a single editorial pull-quote anchoring the spread */}
      <div style={{ position: "absolute", left: MARGIN, bottom: 110, width: 880 }}>
        <PullQuote frame={frame} delay={spread(120, 96, 130, durationInFrames, 60, 220)} size={30} color={C.inkMuted}>
          84&nbsp;GB of memory images. One command. Crash-resilient progress, checkpointed —
          and every host accounted for under one signature.
        </PullQuote>
      </div>
    </Scene>
  );
}

function LegendDot({ tone, label }: { tone: string; label: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 9 }}>
      <span style={{ width: 8, height: 8, background: tone, display: "inline-block" }} />
      {label}
    </span>
  );
}

function Tally({ value, label, tone }: { value: string; label: string; tone: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
      <span style={{ fontFamily: SERIF, fontWeight: 900, fontSize: 40, lineHeight: 1, letterSpacing: -1, color: tone }}>
        {value}
      </span>
      <span
        style={{
          fontFamily: GROTESK,
          fontSize: 12,
          fontWeight: 600,
          letterSpacing: 2,
          textTransform: "uppercase",
          color: C.inkMuted,
        }}
      >
        {label}
      </span>
    </div>
  );
}
