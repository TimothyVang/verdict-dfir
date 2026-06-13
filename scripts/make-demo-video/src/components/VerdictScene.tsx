import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine, Stamp } from "./shared/editorial-ui";

// Beat 8 — "The verdict." The signed disposition as a case file: a huge serif
// SUSPICIOUS, the findings of record as a forensic exhibit, and the signature
// as a wax-seal stamp. Replaces the old self-score scene.

interface Finding { id: string; title: string; detail: string; tech: string; tier: string }
const FINDINGS: Finding[] = [
  { id: "F-001", title: "DKOM rootkit", detail: "pid 1492 + 3044 unlinked from the live process list", tech: "T1014", tier: "CONFIRMED" },
  { id: "F-002", title: "Run-key persistence", detail: "HKLM\\…\\Run\\svchost32 → unsigned binary", tech: "T1547.001", tier: "INFERRED" },
];

export function VerdictScene() {
  const frame = useCurrentFrame();
  const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

  return (
    <Scene page={8} caption="Signed verdict">
      {/* Left — the disposition */}
      <div style={{ position: "absolute", left: MARGIN, top: 230, width: 760 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>Disposition</Kicker>
        <div style={{ marginTop: 14 }}>
          <KineticHeadline text="The verdict." frame={frame} delay={20} size={96} />
        </div>
        <div style={{ marginTop: 24, overflow: "hidden" }}>
          <div style={{
            fontFamily: SERIF, fontWeight: 900, fontSize: 124, lineHeight: 1, color: C.alert, letterSpacing: -3,
            clipPath: `inset(0 ${(1 - interpolate(frame - 40, [0, 24], [0, 1], { ...clampOpts })) * 100}% 0 0)`,
          }}>
            Suspicious
          </div>
        </div>
        <PullQuote frame={frame} delay={70} size={34} color={C.inkMuted} style={{ marginTop: 24, maxWidth: 680 }}>
          One confirmed finding with a MITRE technique. Treat it as a positive — and escalate.
        </PullQuote>
      </div>

      {/* Right — findings of record + the seal */}
      <div style={{ position: "absolute", right: MARGIN, top: 240, width: 720 }}>
        <div style={{ fontFamily: MONO, fontSize: 14, letterSpacing: 3, textTransform: "uppercase", color: C.inkMuted, marginBottom: 14 }}>
          Findings of Record
        </div>
        <RuleLine frame={frame} delay={60} color={C.hairline} />
        {FINDINGS.map((f, i) => {
          const d = 80 + i * 30;
          const op = interpolate(frame - d, [0, 14], [0, 1], clampOpts);
          return (
            <div key={f.id} style={{ opacity: op, padding: "22px 0" }}>
              <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 18 }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: 16 }}>
                  <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkFaint }}>{f.id}</span>
                  <span style={{ fontFamily: SERIF, fontSize: 34, fontWeight: 600, color: C.ink }}>{f.title}</span>
                </div>
                <EvidenceTag label={f.tech} tier={f.tier} frame={frame} delay={d + 6} />
              </div>
              <div style={{ fontFamily: MONO, fontSize: 15, color: C.inkMuted, marginTop: 8 }}>{f.detail}</div>
              {i < FINDINGS.length - 1 && <div style={{ height: 1, background: C.hairline, opacity: 0.5, marginTop: 22 }} />}
            </div>
          );
        })}
        <RuleLine frame={frame} delay={150} color={C.hairline} />

        {/* The seal */}
        <div style={{ marginTop: 36, display: "flex", alignItems: "center", gap: 28 }}>
          <Stamp label="Signed · manifest" frame={frame} delay={200} color={C.confirmed} rotate={-6} size={26} />
          <div style={{ fontFamily: MONO, fontSize: 14, color: C.inkMuted, lineHeight: 1.7, opacity: interpolate(frame - 215, [0, 14], [0, 1], clampOpts) }}>
            merkle d1e4bc7a906f2c38<br />
            chain OK · verifiable offline, years from now
          </div>
        </div>
      </div>
    </Scene>
  );
}
