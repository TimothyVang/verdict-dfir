import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { C, GROTESK, MARGIN, MONO } from "./shared/editorial";
import { Scene } from "./shared/Scene";
import { Kicker, KineticHeadline, PullQuote, RuleLine } from "./shared/editorial-ui";
import { spread } from "./shared/pacing";

// Beat 3 — "How a case moves." The centerpiece animated flow diagram: a glowing
// evidence token travels left-to-right through the investigation pipeline along
// hairline connectors, and each node springs in as the token arrives. The split
// branches visibly into Pool A + Pool B then re-merges into the judge. Built as
// crisp SVG, mirroring ClusterScene's coordinate-mapping approach.

const clampOpts = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

type Tint = "neutral" | "alert" | "confirmed";

interface FlowNode {
  id: string;
  label: string;
  sub: string;
  x: number; // center x in svg coords
  y: number; // center y in svg coords
  w: number;
  tint?: Tint;
}

// SVG plotting box. The diagram occupies the right ~62% of the canvas.
const SVG_W = 1140;
const SVG_H = 720;
const NODE_H = 70;

// Three vertical lanes for the serpentine + split.
const LANE_MID = 250; // single-track rows (case_open, tools, judge, manifest)
const LANE_TOP = 150; // Pool A
const LANE_BOT = 350; // Pool B

// Node geometry. The token visits these centers in order; the split is the only
// place two nodes share a step (Pool A + Pool B in parallel), so the ordered
// travel list re-merges at the tools node.
const NODES: Record<string, FlowNode> = {
  evidence: { id: "evidence", label: "Evidence", sub: ".E01 · .mem · .evtx", x: 130, y: LANE_MID, w: 200 },
  caseOpen: { id: "caseOpen", label: "case_open", sub: "locked · read-only", x: 420, y: LANE_MID, w: 230 },
  poolA: { id: "poolA", label: "Pool A", sub: "persistence", x: 760, y: LANE_TOP, w: 210 },
  poolB: { id: "poolB", label: "Pool B", sub: "exfil", x: 760, y: LANE_BOT, w: 210 },
  tools: { id: "tools", label: "45 typed tools", sub: "schema-checked · hashed output", x: 1010, y: LANE_MID, w: 240 },
  contradictions: { id: "contradictions", label: "Contradictions flagged", sub: "detect_contradictions", x: 700, y: 520, w: 290, tint: "alert" },
  verify: { id: "verify", label: "Verify vs raw output", sub: "verify_finding", x: 360, y: 520, w: 270 },
  judge: { id: "judge", label: "Judge · weigh", sub: "credibility merge", x: 360, y: 650, w: 250 },
  manifest: { id: "manifest", label: "Signed manifest", sub: "signer tier · finalize", x: 760, y: 650, w: 240, tint: "confirmed" },
};

// The ordered travel path of the evidence token, by node id. The split branches
// to Pool A then Pool B (the token visits both), then re-merges into tools.
const TOKEN_ORDER: string[] = [
  "evidence",
  "caseOpen",
  "poolA",
  "poolB",
  "tools",
  "contradictions",
  "verify",
  "judge",
  "manifest",
];

// Hairline connectors (drawn under the token). Branch + re-merge edges are
// listed explicitly so the split visibly forks and rejoins.
interface Edge {
  from: string;
  to: string;
}
const EDGES: Edge[] = [
  { from: "evidence", to: "caseOpen" },
  { from: "caseOpen", to: "poolA" },
  { from: "caseOpen", to: "poolB" },
  { from: "poolA", to: "tools" },
  { from: "poolB", to: "tools" },
  { from: "tools", to: "contradictions" },
  { from: "contradictions", to: "verify" },
  { from: "verify", to: "judge" },
  { from: "judge", to: "manifest" },
];

function tintColor(tint?: Tint): string {
  if (tint === "alert") return C.alert;
  if (tint === "confirmed") return C.confirmed;
  return C.ink;
}

// Anchor on a node's perimeter pointed toward a target point — keeps connectors
// touching box edges rather than centers.
function edgeAnchor(node: FlowNode, tx: number, ty: number): { x: number; y: number } {
  const halfW = node.w / 2;
  const halfH = NODE_H / 2;
  const dx = tx - node.x;
  const dy = ty - node.y;
  if (dx === 0 && dy === 0) return { x: node.x, y: node.y };
  const scaleX = dx !== 0 ? halfW / Math.abs(dx) : Infinity;
  const scaleY = dy !== 0 ? halfH / Math.abs(dy) : Infinity;
  const t = Math.min(scaleX, scaleY);
  return { x: node.x + dx * t, y: node.y + dy * t };
}

export function CaseProgression() {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  // Spread the masthead reveals across the beat.
  const sd = (raw: number) => spread(raw, 0, 100, durationInFrames, 24, 200);

  // Token travel: marches across the whole ordered path over the beat budget,
  // holding briefly at the end. p in [0,1] across TOKEN_ORDER segments.
  const travelStart = 50;
  const travelEnd = Math.max(travelStart + 30, durationInFrames - 150);
  const p = interpolate(frame, [travelStart, travelEnd], [0, 1], clampOpts);

  const segments = TOKEN_ORDER.length - 1;
  const segFloat = p * segments;
  const segIdx = Math.min(segments - 1, Math.floor(segFloat));
  const segFrac = segFloat - segIdx;
  const fromNode = NODES[TOKEN_ORDER[segIdx]];
  const toNode = NODES[TOKEN_ORDER[segIdx + 1]];
  const tokenX = interpolate(segFrac, [0, 1], [fromNode.x, toNode.x]);
  const tokenY = interpolate(segFrac, [0, 1], [fromNode.y, toNode.y]);

  // A node "arrives" (springs in) just before the token reaches it. Arrival
  // fraction = node's index / segments along the ordered march.
  const arrivalFrame = (nodeId: string): number => {
    const idx = TOKEN_ORDER.indexOf(nodeId);
    if (idx <= 0) return travelStart - 8;
    const frac = (idx - 0.45) / segments;
    return travelStart + frac * (travelEnd - travelStart);
  };

  return (
    <Scene page={3} caption="How it works" total={10}>
      {/* Left column — the story */}
      <div style={{ position: "absolute", left: MARGIN, top: 188, width: 540 }}>
        <Kicker frame={frame} delay={sd(2)} color={C.accent}>
          Exhibit C · Chain of Reasoning
        </Kicker>
        <div style={{ marginTop: 16 }}>
          <KineticHeadline text="How a case" frame={frame} delay={sd(6)} size={92} />
          <KineticHeadline text="moves." frame={frame} delay={sd(12)} size={92} italic />
        </div>
        <div style={{ marginTop: 30, marginBottom: 34 }}>
          <RuleLine frame={frame} delay={sd(20)} width={140} color={C.accent} thickness={2} />
        </div>

        <PullQuote frame={frame} delay={sd(30)} size={40} color={C.ink} style={{ maxWidth: 500 }}>
          Locked evidence in. Two teams.&nbsp;
          <span style={{ color: C.confirmed }}>Cross-checked findings out.</span>
        </PullQuote>

        <div
          style={{
            marginTop: 40,
            fontFamily: MONO,
            fontSize: 14,
            letterSpacing: 1,
            lineHeight: 1.8,
            color: C.inkFaint,
            opacity: interpolate(frame - sd(50), [0, 16], [0, 1], clampOpts),
          }}
        >
          read left&nbsp;→&nbsp;right · the evidence travels<br />
          every step cites a tool_call_id
        </div>
      </div>

      {/* Right column — the animated flow diagram */}
      <div style={{ position: "absolute", right: MARGIN - 6, top: 196, width: SVG_W }}>
        <div
          style={{
            fontFamily: MONO,
            fontSize: 14,
            letterSpacing: 3,
            textTransform: "uppercase",
            color: C.inkMuted,
            marginBottom: 12,
          }}
        >
          Exhibit C-1 — Investigation Pipeline
        </div>
        <RuleLine frame={frame} delay={sd(24)} color={C.hairline} />

        <svg width={SVG_W} height={SVG_H} style={{ display: "block", marginTop: 6, overflow: "visible" }}>
          <defs>
            <marker
              id="cp-arrow"
              markerWidth="9"
              markerHeight="9"
              refX="7"
              refY="4.5"
              orient="auto"
              markerUnits="userSpaceOnUse"
            >
              <path d="M0,0 L8,4.5 L0,9 Z" fill={C.inkFaint} />
            </marker>
          </defs>

          {/* Connectors — hairlines with small arrowheads, drawn under nodes */}
          {EDGES.map((edge, i) => {
            const a = NODES[edge.from];
            const b = NODES[edge.to];
            const start = edgeAnchor(a, b.x, b.y);
            const end = edgeAnchor(b, a.x, a.y);
            const drawn = arrivalFrame(edge.to);
            const op = interpolate(frame - (drawn - 10), [0, 14], [0, 1], clampOpts);
            return (
              <line
                key={i}
                x1={start.x}
                y1={start.y}
                x2={end.x}
                y2={end.y}
                stroke={C.hairline}
                strokeWidth={1.5}
                opacity={op}
                markerEnd="url(#cp-arrow)"
              />
            );
          })}

          {/* Split bracket label — sits between case_open and the two pools */}
          {(() => {
            const op = interpolate(frame - (arrivalFrame("poolA") - 12), [0, 16], [0, 1], clampOpts);
            return (
              <text
                x={590}
                y={LANE_MID - 96}
                textAnchor="middle"
                fontFamily={GROTESK}
                fontSize={13}
                fontWeight={600}
                letterSpacing={3}
                fill={C.accent}
                opacity={op}
                style={{ textTransform: "uppercase" } as React.CSSProperties}
              >
                split · two parallel pools
              </text>
            );
          })()}

          {/* Re-merge label — under the pools, into the tools node */}
          {(() => {
            const op = interpolate(frame - (arrivalFrame("tools") - 10), [0, 16], [0, 1], clampOpts);
            return (
              <text
                x={905}
                y={LANE_MID + 96}
                textAnchor="middle"
                fontFamily={GROTESK}
                fontSize={13}
                fontWeight={600}
                letterSpacing={3}
                fill={C.inkMuted}
                opacity={op}
                style={{ textTransform: "uppercase" } as React.CSSProperties}
              >
                re-merge
              </text>
            );
          })()}

          {/* Nodes — rounded rects that spring in as the token arrives */}
          {Object.values(NODES).map((node) => {
            const d = arrivalFrame(node.id);
            const s = spring({ frame: frame - d, fps, config: { damping: 15, stiffness: 130 } });
            const op = interpolate(frame - d, [0, 12], [0, 1], clampOpts);
            const scale = 0.86 + s * 0.14;
            const tone = tintColor(node.tint);
            const stroke = node.tint ? `${tone}99` : C.hairline;
            const fill = node.tint ? `${tone}12` : C.surface;
            const labelColor = node.tint ? tone : C.ink;
            const rx = node.x - node.w / 2;
            const ry = node.y - NODE_H / 2;
            return (
              <g
                key={node.id}
                opacity={op}
                transform={`translate(${node.x} ${node.y}) scale(${scale}) translate(${-node.x} ${-node.y})`}
              >
                <rect
                  x={rx}
                  y={ry}
                  width={node.w}
                  height={NODE_H}
                  rx={8}
                  ry={8}
                  fill={fill}
                  stroke={stroke}
                  strokeWidth={1}
                />
                <text
                  x={node.x}
                  y={node.y - 5}
                  textAnchor="middle"
                  fontFamily={GROTESK}
                  fontSize={20}
                  fontWeight={600}
                  letterSpacing={0.3}
                  fill={labelColor}
                >
                  {node.label}
                </text>
                <text
                  x={node.x}
                  y={node.y + 18}
                  textAnchor="middle"
                  fontFamily={MONO}
                  fontSize={13}
                  letterSpacing={0.5}
                  fill={C.inkMuted}
                >
                  {node.sub}
                </text>
              </g>
            );
          })}

          {/* The traveling evidence token — glowing accent dot */}
          {(() => {
            const visible = interpolate(frame - travelStart, [0, 8], [0, 1], clampOpts);
            const pulse = 1 + 0.18 * Math.sin((frame / fps) * 6);
            return (
              <g opacity={visible}>
                <circle cx={tokenX} cy={tokenY} r={20 * pulse} fill={C.accent} opacity={0.16} />
                <circle cx={tokenX} cy={tokenY} r={12 * pulse} fill={C.accent} opacity={0.3} />
                <circle cx={tokenX} cy={tokenY} r={6.5} fill={C.accent} />
                <circle cx={tokenX} cy={tokenY} r={2.6} fill={C.ink} />
              </g>
            );
          })()}
        </svg>

        {/* Footer read-direction note under the diagram */}
        <RuleLine frame={frame} delay={sd(90)} color={C.hairline} style={{ marginTop: 4 }} />
        <div
          style={{
            marginTop: 14,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
            fontFamily: MONO,
            fontSize: 14,
            letterSpacing: 2,
            textTransform: "uppercase",
            opacity: interpolate(frame - sd(94), [0, 16], [0, 1], clampOpts),
          }}
        >
          <span style={{ color: C.inkMuted }}>Evidence in</span>
          <span style={{ color: C.alert }}>Contradictions surfaced</span>
          <span style={{ color: C.confirmed }}>Signed verdict out</span>
        </div>
      </div>
    </Scene>
  );
}
