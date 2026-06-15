import { type Beat } from "./beats-data";

// FeatureDeepDives — one chapter per standout feature, each framed by a real
// captured clip (the genuine footage already in public/ui/). The footage is the
// substance; the editorial frame and copy are the only thing the film draws.
// See scripts/make-demo-video/CAPTURE.md for how the clips were recorded.
export const DEEPDIVE_BEATS: Beat[] = [
  {
    number: 1,
    scene: "concept",
    title: "Five features, shown working",
    startS: 0,
    endS: 18,
    rubric: "Deep dive",
    accentColor: "#9b59b6",
    kicker: "Feature deep dive",
    headline: "Five features — shown actually working",
    body:
      "Not slides. Each of these is a real screen recording of VERDICT running: finding replay, two pools that argue on the record, the live dashboard, the offline tamper check, and the typed tool surface underneath it all.",
    narration:
      "Let's go past the pitch and look at five features actually running — not slides, real recordings. Finding replay, two pools that argue on the record, the live dashboard, the offline tamper check, and the typed tool surface holding it all up.",
  },
  {
    number: 2,
    scene: "exhibit",
    title: "Evidence replay, on camera",
    startS: 18,
    endS: 52,
    rubric: "The verifier",
    accentColor: "#6f93b8",
    kicker: "Feature 01 — the verifier",
    headline: "Findings replay before they count",
    body:
      "Every Finding is checked against current-case tool output before the judge can rely on it.",
    points: [
      "Each Finding carries a cited tool_call_id",
      "Verifier evidence must match the replayed output hash",
      "Unverified leads stay out of the final verdict",
    ],
    exhibit: {
      src: "ui/terminal-investigation.mp4",
      label: "verdict · investigate evidence/ — live terminal",
      objectFit: "contain",
      playbackRate: 0.42,
    },
    narration:
      "Feature one: the verifier. Every finding is replayed against current-case tool output before it's allowed into the report. It has to cite a tool call, its replay hash has to match, and unverified leads stay out of the final verdict. The point is simple: the report is evidence-bound, not vibes-bound.",
  },
  {
    number: 3,
    scene: "exhibit",
    title: "They disagree — out loud",
    startS: 52,
    endS: 62.1,
    rubric: "Competing hypotheses",
    accentColor: "#d6452f",
    kicker: "Feature 02 — competing hypotheses",
    headline: "Two theories, argued on the record",
    body:
      "Two pools work the same SRL-2018 host from opposite priors — persistence versus exfiltration — and disagree.",
    points: [
      "detect_contradictions surfaces every clash as its own record",
      "Each shows Pool A's claim against Pool B's",
      "A credibility-weighted judge reconciles it — on the record",
    ],
    exhibit: {
      src: "ui/F-contradiction.mp4",
      label: "detect_contradictions · Pool A vs Pool B → judge",
      objectFit: "contain",
      playbackRate: 1,
    },
    narration:
      "Two pools read the same host from opposite priors and disagree. Every clash is logged, then reconciled on the record.",
  },
  {
    number: 4,
    scene: "exhibit",
    title: "Watch it work",
    startS: 62.1,
    endS: 94.1,
    rubric: "The dashboard",
    accentColor: "#9b59b6",
    kicker: "Feature 03 — the dashboard",
    headline: "The whole case, live",
    body:
      "You are not staring at a spinner. Findings land as they are vetted, tagged by how sure the agent is.",
    points: [
      "Findings appear tagged confirmed, inferred, or hypothesis",
      "The pipeline rail lights up stage by stage",
      "Every finding links back to its exact tool call",
    ],
    exhibit: {
      src: "ui/dashboard-live.mp4",
      label: "localhost:3000 · live case dashboard",
      objectFit: "cover",
      playbackRate: 1,
    },
    narration:
      "Feature three: the dashboard. While it works, you watch it work. Findings land as they're vetted, each tagged confirmed, inferred, or hypothesis so you always know how sure it is. The pipeline lights up stage by stage, a timeline builds itself, and every finding links straight back to the exact tool call behind it.",
  },
  {
    number: 5,
    scene: "exhibit",
    title: "Tamper-evident, provably",
    startS: 94.1,
    endS: 128.1,
    rubric: "Chain of custody",
    accentColor: "#6f93b8",
    kicker: "Feature 04 — chain of custody",
    headline: "Don't trust it — verify it",
    body:
      "The case is sealed into a hash-chained, Merkle-rooted manifest you can check offline.",
    points: [
      "The verifier passes on the sealed case",
      "We flip one byte in the audit log",
      "It fails — and names the exact broken record",
    ],
    exhibit: {
      src: "ui/manifest-tamper.mp4",
      label: "trace-finding · offline manifest verify",
      objectFit: "contain",
      playbackRate: 1,
    },
    narration:
      "Feature four: chain of custody. The whole case is sealed into a hash-chained, Merkle-rooted manifest, verifiable offline with zero dependencies. Watch the verifier pass. Now I flip a single byte in the audit log and run it again — it fails, and it names the exact record that broke. The verdict isn't something to trust. It's a sealed artifact anyone can check.",
  },
  {
    number: 6,
    scene: "tools",
    title: "No shell, ever",
    startS: 128.1,
    endS: 154.1,
    rubric: "The tools",
    accentColor: "#c79a4a",
    narration:
      "And feature five is the one you don't see flashing on screen, but it underpins all the rest: the tool surface. Forty-three typed tools — thirty-one in Rust, twelve in Python — and not a single one can run an arbitrary command. There is no shell to hijack. That boundary is what lets the agent be fast without ever being dangerous.",
  },
  {
    number: 7,
    scene: "outro",
    title: "All of it, open source",
    startS: 154.1,
    endS: 170.1,
    rubric: "Open source",
    accentColor: "#9b59b6",
    narration:
      "Every one of those features is in the open-source repo, with the same receipts you just watched. Point it at supported evidence and see it for yourself.",
  },
];
