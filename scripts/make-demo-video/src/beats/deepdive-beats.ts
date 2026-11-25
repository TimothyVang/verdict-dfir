import { type Beat } from "./beats-data";

// FeatureDeepDives — one chapter per standout feature, each framed by a real
// captured clip (the genuine footage already in public/ui/). The footage is the
// substance; the editorial frame and copy are the only thing the film draws.
// See scripts/make-demo-video/CAPTURE.md for how the clips were recorded.
export const DEEPDIVE_BEATS: Beat[] = [
  {
    number: 1,
    scene: "concept",
    title: "Four features, shown working",
    startS: 0,
    endS: 16,
    rubric: "Deep dive",
    accentColor: "#4D5DFF",
    kicker: "Feature deep dive",
    headline: "Four features — shown actually working",
    body:
      "Not slides. Each of these is a real screen recording of VERDICT running: the self-correcting verifier, the live dashboard, the offline tamper check, and the typed tool surface underneath it all.",
    narration:
      "Let's go past the pitch and look at four features actually running — not slides, real recordings. The self-correcting verifier, the live dashboard, the offline tamper check, and the typed tool surface holding it all up.",
  },
  {
    number: 2,
    scene: "exhibit",
    title: "Self-correction, on camera",
    startS: 16,
    endS: 40,
    rubric: "The verifier",
    accentColor: "#4D5DFF",
    kicker: "Feature 01 — the verifier",
    headline: "It catches its own mistakes",
    body:
      "Every Finding is replayed before it counts. Here we sabotage one on purpose to prove the verifier is awake.",
    points: [
      "A finding's replay comes back wrong",
      "VERDICT throws it out and re-runs the tool",
      "It recovers clean — the verdict is unchanged",
    ],
    exhibit: {
      src: "ui/terminal-investigation.mp4",
      label: "verdict · investigate evidence/ — live terminal",
      objectFit: "contain",
      playbackRate: 1,
    },
    narration:
      "Feature one: the verifier. Every finding is replayed against the raw tool output before it's allowed into the report. To prove that's real, we sabotage one finding on purpose. Watch — its replay comes back wrong, so VERDICT throws it out, re-runs the tool, and recovers it clean. It catches its own mistake, on camera, and the verdict stands.",
  },
  {
    number: 3,
    scene: "exhibit",
    title: "Watch it work",
    startS: 40,
    endS: 63,
    rubric: "The dashboard",
    accentColor: "#4D5DFF",
    kicker: "Feature 02 — the dashboard",
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
      "Feature two: the dashboard. While it works, you watch it work. Findings land as they're vetted, each tagged confirmed, inferred, or hypothesis so you always know how sure it is. The pipeline lights up stage by stage, a timeline builds itself, and every finding links straight back to the exact tool call behind it.",
  },
  {
    number: 4,
    scene: "exhibit",
    title: "Tamper-evident, provably",
    startS: 63,
    endS: 90,
    rubric: "Chain of custody",
    accentColor: "#4D5DFF",
    kicker: "Feature 03 — chain of custody",
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
      "Feature three: chain of custody. The whole case is sealed into a hash-chained, Merkle-rooted manifest, verifiable offline with zero dependencies. Watch the verifier pass. Now I flip a single byte in the audit log and run it again — it fails, and it names the exact record that broke. The verdict isn't something to trust. It's a sealed artifact anyone can check.",
  },
  {
    number: 5,
    scene: "tools",
    title: "No shell, ever",
    startS: 90,
    endS: 113,
    rubric: "The tools",
    accentColor: "#FFD76A",
    narration:
      "And feature four is the one you don't see flashing on screen, but it underpins all the rest: the tool surface. A narrow typed catalog spans Rust forensic tools and Python crypto-analysis helpers, and not a single one can run an arbitrary command. There is no shell to hijack. That boundary is what lets the agent be fast without ever being dangerous.",
  },
  {
    number: 6,
    scene: "outro",
    title: "All of it, open source",
    startS: 113,
    endS: 123,
    rubric: "Open source",
    accentColor: "#4D5DFF",
    narration:
      "Every one of those features is in the open-source repo, with the same receipts you just watched. Point it at supported evidence and see it for yourself.",
  },
];
