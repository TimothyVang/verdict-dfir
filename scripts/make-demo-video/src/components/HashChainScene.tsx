import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { C, MARGIN, MONO, SERIF } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { EvidenceTag, Kicker, KineticHeadline, PullQuote, RuleLine, Stamp } from "./shared/editorial-ui";

// Beat 5 — "Admissible." The hash chain rendered as a provenance LEDGER of
// record: each audit record is a ledger row (kind in Fraunces, prev→hash in
// mono, a tier tag) separated by hairline rules. To the side, the rs_merkle
// root, the sigstore seal, the FRE 902(14) line as a legal-exhibit pull-quote,
// and a small mono manifest_verify exhibit. Real hashes preserved from prior.

interface Record {
  kind: string;
  hash: string;
  prevHash: string;
  tier?: string;
}

const LEDGER: Record[] = [
  { kind: "case_open", hash: "9b57a2f3c841e609", prevHash: "00000000" },
  { kind: "tool_call", hash: "e3b0c44298fc1c14", prevHash: "9b57a2f3" },
  { kind: "finding", hash: "4a7d1e9c03b2f581", prevHash: "e3b0c442", tier: "INFERRED" },
  { kind: "verify_finding", hash: "8c3f0bde7a214e90", prevHash: "4a7d1e9c", tier: "CONFIRMED" },
  { kind: "correlate", hash: "2f6a8d01c943b7e5", prevHash: "8c3f0bde" },
  { kind: "manifest_finalize", hash: "d1e4bc7a906f2c38", prevHash: "2f6a8d01" },
];

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

export function HashChainScene() {
  const frame = useCurrentFrame();

  return (
    <Scene page={7} caption="Chain of custody">
      {/* Left column — the ledger of record */}
      <div style={{ position: "absolute", left: MARGIN, top: 150, width: 940 }}>
        <Kicker frame={frame} delay={10} color={C.accent}>
          Exhibit E · Ledger of Record
        </Kicker>
        <div style={{ marginTop: 14 }}>
          <KineticHeadline text="Admissible." frame={frame} delay={20} size={104} italic />
        </div>
        <div style={{ marginTop: 22, marginBottom: 28 }}>
          <RuleLine frame={frame} delay={42} width={120} color={C.accent} thickness={2} />
        </div>

        {/* Ledger header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 280px 150px",
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 2,
            textTransform: "uppercase",
            color: C.inkFaint,
            paddingBottom: 12,
            opacity: interpolate(frame - 58, [0, 12], [0, 1], clampOpts),
          }}
        >
          <span>Record</span>
          <span>prev → hash</span>
          <span style={{ textAlign: "right" }}>Tier</span>
        </div>
        <RuleLine frame={frame} delay={62} color={C.hairline} />

        {LEDGER.map((r, i) => {
          const d = 80 + i * 24;
          const op = interpolate(frame - d, [0, 12], [0, 1], clampOpts);
          const ty = interpolate(frame - d, [0, 14], [10, 0], clampOpts);
          const isFinal = r.kind === "manifest_finalize";
          return (
            <div key={r.kind} style={{ opacity: op, transform: `translateY(${ty}px)` }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 280px 150px",
                  alignItems: "center",
                  padding: "18px 0",
                }}
              >
                <span
                  style={{
                    fontFamily: SERIF,
                    fontWeight: isFinal ? 900 : 600,
                    fontSize: 32,
                    letterSpacing: -0.5,
                    color: isFinal ? C.ink : C.ink,
                  }}
                >
                  {r.kind}
                </span>
                <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkMuted }}>
                  <span style={{ color: C.inkFaint }}>{r.prevHash}</span>
                  <span style={{ color: C.inkFaint, margin: "0 8px" }}>→</span>
                  <span style={{ color: isFinal ? C.accent : C.ink }}>{r.hash}</span>
                </span>
                <span style={{ justifySelf: "end" }}>
                  {r.tier ? (
                    <EvidenceTag label={r.tier} tier={r.tier} frame={frame} delay={d + 6} />
                  ) : (
                    <span style={{ fontFamily: MONO, fontSize: 14, color: C.inkFaint, letterSpacing: 2 }}>
                      ledger
                    </span>
                  )}
                </span>
              </div>
              {i < LEDGER.length - 1 && (
                <div style={{ height: 1, background: C.hairline, opacity: 0.55 }} />
              )}
            </div>
          );
        })}
        <RuleLine frame={frame} delay={236} color={C.hairline} thickness={2} />
        <div
          style={{
            fontFamily: MONO,
            fontSize: 15,
            color: C.inkMuted,
            marginTop: 16,
            letterSpacing: 1,
            opacity: interpolate(frame - 250, [0, 16], [0, 1], clampOpts),
          }}
        >
          6 records · append-only · each <span style={{ color: C.ink }}>prev_hash</span> links the line before
          it
        </div>
      </div>

      {/* Right column — the attestation: merkle, seal, FRE exhibit */}
      <div style={{ position: "absolute", right: MARGIN, top: 156, width: 540 }}>
        <div
          style={{
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 12,
            opacity: interpolate(frame - 300, [0, 14], [0, 1], clampOpts),
          }}
        >
          Three Tiers of Custody
        </div>
        <RuleLine frame={frame} delay={310} color={C.hairline} />

        {/* Tier ledger: prev_hash → merkle → sigstore */}
        <div style={{ paddingTop: 18 }}>
          {[
            { n: "I", name: "audit prev_hash", note: "append-only hash chain" },
            { n: "II", name: "rs_merkle root", note: "f7a3c9e2b1d04… · 6 leaves · SHA-256" },
            { n: "III", name: "sigstore Rekor", note: "rekor.sigstore.dev / 24922385" },
          ].map((t, i) => {
            const d = 330 + i * 26;
            const op = interpolate(frame - d, [0, 14], [0, 1], clampOpts);
            return (
              <div
                key={t.n}
                style={{ opacity: op, display: "flex", alignItems: "baseline", gap: 18, padding: "14px 0" }}
              >
                <span style={{ fontFamily: SERIF, fontStyle: "italic", fontSize: 26, color: C.accent, width: 44 }}>
                  {t.n}
                </span>
                <div>
                  <div style={{ fontFamily: MONO, fontSize: 18, color: C.ink }}>{t.name}</div>
                  <div style={{ fontFamily: MONO, fontSize: 13, color: C.inkMuted, marginTop: 4 }}>{t.note}</div>
                </div>
              </div>
            );
          })}
        </div>
        <RuleLine frame={frame} delay={420} color={C.hairline} />

        {/* The seal */}
        <div style={{ marginTop: 30, display: "flex", alignItems: "center", gap: 24 }}>
          <Stamp label="Signed · sigstore" frame={frame} delay={460} color={C.confirmed} rotate={-6} size={24} />
          <div
            style={{
              fontFamily: MONO,
              fontSize: 13,
              color: C.inkMuted,
              lineHeight: 1.7,
              opacity: interpolate(frame - 478, [0, 14], [0, 1], clampOpts),
            }}
          >
            merkle d1e4bc7a906f2c38
            <br />
            verifiable offline, years from now
          </div>
        </div>

        {/* FRE 902(14) — treated as a legal-exhibit pull-quote */}
        <div style={{ marginTop: 34 }}>
          <RuleLine frame={frame} delay={520} width={80} color={C.accent} thickness={2} />
          <PullQuote frame={frame} delay={540} size={27} color={C.ink} style={{ marginTop: 16, maxWidth: 520 }}>
            Self-authenticating under <span style={{ fontStyle: "italic" }}>FRE&nbsp;902(14)</span> — a court
            verifies this manifest from the transparency log, no expert witness required.
          </PullQuote>
        </div>
      </div>

      {/* manifest_verify exhibit — bottom mono band spanning the lower gutter */}
      <div
        style={{
          position: "absolute",
          left: MARGIN,
          bottom: 96,
          width: 940,
          opacity: interpolate(frame - 600, [0, 16], [0, 1], clampOpts),
        }}
      >
        <div
          style={{
            fontFamily: MONO,
            fontSize: 13,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 12,
          }}
        >
          Exhibit E-1 — manifest_verify (offline)
        </div>
        <RuleLine frame={frame} delay={612} color={C.hairline} />
        <div style={{ fontFamily: MONO, fontSize: 15, lineHeight: 1.95, paddingTop: 14 }}>
          <div style={{ color: C.inkMuted }}>
            $ <span style={{ color: C.ink }}>uv run python -m findevil_agent_mcp.server manifest_verify</span>
          </div>
          {[
            { k: "chain", v: "OK" },
            { k: "merkle_root", v: "d1e4bc7a906f2c38" },
            { k: "sigstore", v: "VERIFIED (rekor.sigstore.dev/24922385)" },
          ].map((line, i) => {
            const op = interpolate(frame - (640 + i * 18), [0, 12], [0, 1], clampOpts);
            return (
              <div key={line.k} style={{ opacity: op, color: C.confirmed }}>
                {line.k.padEnd(13, " ")}
                {line.v}
              </div>
            );
          })}
          <div style={{ color: C.inkMuted, opacity: interpolate(frame - 700, [0, 12], [0, 1], clampOpts) }}>
            records 6 · findings 2 · <span style={{ color: C.confirmed }}>CONFIRMED 1</span>
          </div>
        </div>
      </div>
    </Scene>
  );
}
