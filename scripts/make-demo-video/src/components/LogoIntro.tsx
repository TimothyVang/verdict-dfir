import React from "react";
import { useCurrentFrame } from "remotion";
import { C, MARGIN, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine, Stamp } from "./shared/editorial-ui";

// Beat 1 — cold open masthead. A forensic case file opening, not a dev-tool
// splash: editorial logotype in Fraunces, a serif pull-line, a CASE OPENED
// stamp, and the epistemic spine (CONFIRMED > INFERRED > HYPOTHESIS) as tags.
export function LogoIntro() {
  const frame = useCurrentFrame();
  return (
    <Scene page={1} caption="Cold open">
      <div style={{ position: "absolute", left: MARGIN, top: 250, right: MARGIN }}>
        <Kicker frame={frame} delay={8}>Digital Forensics · Incident Response</Kicker>
        <div style={{ marginTop: 18, marginBottom: 18 }}>
          <RuleLine frame={frame} delay={14} width={360} color={C.accent} thickness={2} />
        </div>
        <KineticHeadline text="VERDICT" frame={frame} delay={20} size={300} weight={900} style={{ letterSpacing: -6 }} />
        <div style={{ marginTop: 12, maxWidth: 1000 }}>
          <PullQuote frame={frame} delay={48} size={48} color={C.inkMuted}>
            <span style={{ fontStyle: "italic" }}>Proof,</span> at machine speed.
          </PullQuote>
        </div>
      </div>

      {/* Asymmetric stamp, upper-right */}
      <div style={{ position: "absolute", right: MARGIN + 30, top: 300 }}>
        <Stamp label="Case Opened" frame={frame} delay={72} color={C.alert} rotate={-9} size={34} />
      </div>

      {/* The epistemic spine, sitting above the lower rule */}
      <div style={{ position: "absolute", left: MARGIN, bottom: 110, display: "flex", alignItems: "center", gap: 16 }}>
        <span style={{ fontFamily: SERIF, fontSize: 22, color: C.inkFaint, fontStyle: "italic", marginRight: 6 }}>the discipline —</span>
        <EvidenceTag label="Confirmed" tier="CONFIRMED" frame={frame} delay={92} />
        <span style={{ color: C.inkFaint }}>›</span>
        <EvidenceTag label="Inferred" tier="INFERRED" frame={frame} delay={100} />
        <span style={{ color: C.inkFaint }}>›</span>
        <EvidenceTag label="Hypothesis" tier="HYPOTHESIS" frame={frame} delay={108} />
      </div>
    </Scene>
  );
}
