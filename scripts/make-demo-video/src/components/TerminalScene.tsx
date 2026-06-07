import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";

// Beat 3 (marquee) — "The host that lied." The pslist/psscan divergence is
// presented as a marked-up forensic EXHIBIT, not a generic terminal: an
// editorial headline + pull-quote on the left, a process-reconciliation
// exhibit table on the right with the unlinked rows flagged in the margin.

interface Row { pid: string; image: string; view: string; flag?: string; alert?: boolean }
const ROWS: Row[] = [
  { pid: "0604", image: "services.exe", view: "pslist + psscan" },
  { pid: "1492", image: "svchost.exe", view: "pslist + psscan" },
  { pid: "1492", image: "svchost.exe", view: "psscan only", flag: "unlinked", alert: true },
  { pid: "3044", image: "explorer.exe", view: "psscan only", flag: "hidden", alert: true },
];

export function TerminalScene(_props?: { title?: string; subtitle?: string; accentColor?: string }) {
  const frame = useCurrentFrame();
  const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

  return (
    <Scene page={3} caption="Single-host · memory">
      {/* Left column — the story */}
      <div style={{ position: "absolute", left: MARGIN, top: 210, width: 760 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>Exhibit A · Memory Image</Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="The host" frame={frame} delay={20} size={104} />
          <KineticHeadline text="that lied." frame={frame} delay={32} size={104} italic />
        </div>
        <div style={{ marginTop: 30, marginBottom: 26 }}>
          <RuleLine frame={frame} delay={44} width={120} color={C.alert} thickness={2} />
        </div>
        <PullQuote frame={frame} delay={300} size={36} color={C.ink} style={{ maxWidth: 700 }}>
          Two processes the active list swears aren&rsquo;t there — recovered intact from pool
          memory. That divergence is the textbook&nbsp;DKOM signature.
        </PullQuote>
        <div style={{ marginTop: 34, display: "flex", alignItems: "center", gap: 18 }}>
          <EvidenceTag label="T1014 Rootkit" tier="CONFIRMED" frame={frame} delay={620} />
          <span style={{ fontFamily: MONO, fontSize: 14, color: C.inkFaint }}>tci_psscan_00a7f3</span>
        </div>
      </div>

      {/* Right column — the exhibit table */}
      <div style={{ position: "absolute", right: MARGIN, top: 220, width: 740 }}>
        <div style={{ fontFamily: MONO, fontSize: 14, letterSpacing: 3, textTransform: "uppercase", color: C.inkMuted, marginBottom: 14 }}>
          Exhibit A-1 — Process Reconciliation
        </div>
        <RuleLine frame={frame} delay={70} color={C.hairline} />
        {/* header */}
        <div style={{ display: "grid", gridTemplateColumns: "90px 1fr 220px", fontFamily: MONO, fontSize: 15, color: C.inkFaint, padding: "12px 0", letterSpacing: 1 }}>
          <span>PID</span><span>IMAGE</span><span>RECOVERED VIEW</span>
        </div>
        <RuleLine frame={frame} delay={78} color={C.hairline} />
        {ROWS.map((r, i) => {
          const d = 92 + i * 26;
          const op = interpolate(frame - d, [0, 12], [0, 1], clampOpts);
          const tone = r.alert ? C.alert : C.ink;
          return (
            <div key={i} style={{ opacity: op }}>
              <div style={{ display: "grid", gridTemplateColumns: "90px 1fr 220px", alignItems: "center", fontFamily: MONO, fontSize: 19, color: tone, padding: "16px 0" }}>
                <span>{r.pid}</span>
                <span>{r.image}</span>
                <span style={{ position: "relative" }}>
                  {r.view}
                  {r.flag && (
                    <span style={{ position: "absolute", left: 200, whiteSpace: "nowrap", fontFamily: SERIF, fontStyle: "italic", fontSize: 18, color: C.alert }}>
                      ← {r.flag}
                    </span>
                  )}
                </span>
              </div>
              {i < ROWS.length - 1 && <div style={{ height: 1, background: C.hairline, opacity: 0.5 }} />}
            </div>
          );
        })}
        <RuleLine frame={frame} delay={200} color={C.hairline} />
        <div style={{ fontFamily: MONO, fontSize: 17, color: C.inkMuted, marginTop: 16, letterSpacing: 1, opacity: interpolate(frame - 210, [0, 14], [0, 1], clampOpts) }}>
          pslist <span style={{ color: C.ink }}>32</span> &nbsp;·&nbsp; psscan <span style={{ color: C.ink }}>35</span> &nbsp;·&nbsp; divergence <span style={{ color: C.alert }}>3</span>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 15, color: C.confirmed, marginTop: 18, opacity: interpolate(frame - 540, [0, 14], [0, 1], clampOpts) }}>
          verify_finding ✓ &nbsp;hash match &nbsp;— promoted to CONFIRMED
        </div>
      </div>
    </Scene>
  );
}
