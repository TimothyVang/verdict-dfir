// Which scene component renders a beat. The original FindEvilDemo beats omit
// `scene` and are dispatched by `number` (see Beat.tsx). The additional videos
// (explainer, deep-dives, quickstart, contributor call) set `scene` so they can
// reuse the same data-driven scenes without colliding with beat numbers.
export type SceneKind =
  | "concept"
  | "exhibit"
  | "tools"
  | "arch"
  | "outro"
  | "logo"
  | "title";

// A real captured clip framed as a forensic EXHIBIT (see ExhibitVideo.tsx).
export interface Exhibit {
  src: string;
  label: string;
  objectFit?: "cover" | "contain";
  playbackRate?: number;
  startFrom?: number;
}

export interface Beat {
  number: number;
  title: string;
  startS: number;
  endS: number;
  rubric: string;
  narration: string;
  accentColor: string;
  // --- Optional, used only by the additional videos -----------------------
  scene?: SceneKind;
  kicker?: string;
  headline?: string;
  body?: string;
  points?: string[];
  command?: string;
  exhibit?: Exhibit;
  caption?: string;
}

// 10 beats — newcomer-first product walkthrough.
// Narration is the canonical voiceover source (read by the TTS scripts).
// startS/endS are fixed scene slots; the TTS step speed-fits each beat's audio
// to its slot, so a conversational rewrite stays in sync without re-timing.
export const BEATS: Beat[] = [
  {
    number: 1,
    title: "What VERDICT is",
    startS: 0,
    endS: 29,
    rubric: "Cold open",
    accentColor: "#4D5DFF",
    narration:
      "Here's the problem every forensics analyst knows. A machine gets popped, and now you've got to work out exactly what the attacker did — and prove it. By hand, that's days. So I pointed VERDICT at a real NIST hacking-case disk and let it run. A few minutes later: a suspicious verdict, tool-cited findings, and an explicit coverage manifest saying what it did and did not parse. Every supported finding has a receipt you can verify offline. It does the grind for you, and you don't just get answers — you get answers you can prove.",
  },
  {
    number: 2,
    title: "It starts in Claude Code",
    startS: 29,
    endS: 60,
    rubric: "How to run it",
    accentColor: "#4D5DFF",
    narration:
      "And running it is honestly simple. VERDICT lives inside Claude Code — the AI assistant right in your terminal. You type one line: investigate, then supported evidence — a disk image, an event log, a packet capture, or a snapshot of the machine's memory. That's the whole command. Now watch this part closely — we sabotage one finding on purpose, to prove the verifier is awake. Midway through, its replay comes back wrong, so it throws the finding out — re-runs the tool, recovers it clean. It catches the mistake, on camera.",
  },
  {
    number: 3,
    title: "How the case progresses",
    startS: 60,
    endS: 92,
    rubric: "How it works",
    accentColor: "#73D9C2",
    narration:
      "So what's it actually doing under the hood? First it locks the evidence — a read-only copy, so the original is never touched. That matters if this ends up in court. Then it splits into two teams of agents, working the same evidence from opposite angles. Each one runs real forensic tools and writes up what it finds. Anywhere they disagree, that conflict gets flagged out loud — not quietly smoothed over. And before anything makes the report, every finding is checked back against the raw tool output.",
  },
  {
    number: 4,
    title: "The toolbox",
    startS: 92,
    endS: 120,
    rubric: "The tools",
    accentColor: "#FFD76A",
    narration:
      "And it's not guessing. It's driving a narrow typed tool surface — real forensic tools in Rust, plus Python tools for crypto and analysis — right inside the SANS SIFT Workstation. And the key design choice: not one of them can run arbitrary commands, so it can't be tricked into going rogue. Each tool answers one plain question. What ran on this machine? What did the system quietly log? What left over the network? And — can we prove it?",
  },
  {
    number: 5,
    title: "Two investigators",
    startS: 120,
    endS: 146,
    rubric: "Competing hypotheses",
    accentColor: "#FF6257",
    narration:
      "So why two teams? One assumes the attacker broke in to stick around and dig in. The other assumes they came to grab data and get out. Same evidence, opposite theories. Now, a single analyst tends to lock onto their first hunch and run with it. VERDICT makes both sides argue it out on the record, shows you exactly where they clash, and only then calls it. You get to see the reasoning — not just a verdict handed down.",
  },
  {
    number: 6,
    title: "Watch it live",
    startS: 146,
    endS: 172,
    rubric: "The dashboard",
    accentColor: "#4D5DFF",
    narration:
      "And while it works, you're not just staring at a spinner. This is the live dashboard. Findings and leads appear as they are vetted — tagged confirmed, inferred, or hypothesis, so you always know how sure it is. A timeline builds itself, the pipeline lights up stage by stage, and every finding links straight back to the exact tool call behind it. Nothing hidden, nothing hand-waved.",
  },
  {
    number: 7,
    title: "Proof you can take to court",
    startS: 172,
    endS: 203,
    rubric: "Chain of custody",
    accentColor: "#4D5DFF",
    narration:
      "And here's the part I think really sets it apart. Every action is locked into a tamper-evident chain — hashed, Merkle-rooted, verifiable offline. Strong enough to back a courtroom self-authentication claim. But you don't have to take my word for it. Watch: the verifier passes. Now I flip a single byte in the audit log and run it again — it fails, and it names the exact record that broke. So the verdict isn't something you have to trust. It's a sealed artifact anyone can check.",
  },
  {
    number: 8,
    title: "Then your team takes over",
    startS: 203,
    endS: 219,
    rubric: "Handoff",
    accentColor: "#73D9C2",
    narration:
      "And once the verdict's signed, VERDICT stops. It doesn't act on its own — it hands your team a clean, signed case, and they decide what happens next. That's the whole idea: an orchestrator that takes the friction out of the grind, not an autonomous responder.",
  },
  {
    number: 9,
    title: "From one host to the fleet",
    startS: 219,
    endS: 252,
    rubric: "Scale",
    accentColor: "#FFD76A",
    narration:
      "And one machine is really just the demo. A real breach touches dozens of them. So I turned VERDICT loose on a twenty-two-host enterprise, host by host. Across that whole fleet it caught six machines running the exact same admin tool at the exact same second. That's not normal — that's an attacker sweeping laterally — and it surfaced it as a lead for an analyst to confirm. And on a separate case, one that does have a published answer key, it hit five out of five expected findings — a hundred percent recall, and the score is reproducible offline.",
  },
  {
    number: 10,
    title: "Get the receipts",
    startS: 252,
    endS: 275,
    rubric: "Signed verdict",
    accentColor: "#4D5DFF",
    narration:
      "And at the end, you get the one thing that actually matters — a signed verdict. And an honest one. It only ever says three things: suspicious, indeterminate, or no evil found in what we looked at. It never promises more than it can back up. VERDICT is open source and ready today. Point it at supported evidence — minutes instead of days, with a receipt for every single finding.",
  },
];

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;
// Total runtime is the last beat's end — keeps Root.tsx in sync after re-timing.
export const TOTAL_FRAMES = BEATS[BEATS.length - 1].endS * FPS;
