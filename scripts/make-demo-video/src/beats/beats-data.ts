export interface Beat {
  number: number;
  title: string;
  startS: number;
  endS: number;
  rubric: string;
  narration: string;
  accentColor: string;
}

// 10 beats — newcomer-first product walkthrough.
// Narration is the canonical voiceover source (read by make-demo-video-tts.py).
// startS/endS are re-timed to each beat's measured audio + a short breath
// (hybrid pacing — no dead air). Durations below are in sync with the generated
// public/audio/beat_NN.mp3 files (measured 2026-06-11).
export const BEATS: Beat[] = [
  {
    number: 1,
    title: "What VERDICT is",
    startS: 0,
    endS: 29,
    rubric: "Cold open",
    accentColor: "#9b59b6",
    narration:
      "Every security team has the same nightmare: someone breaks into a computer, and now you have to prove exactly what they did, fast. By hand, that's days of forensic work. VERDICT ran a real NIST reference disk, end to end, in minutes: nine findings, eight of them confirmed, verdict, suspicious. And it signed every one. It's an AI agent that investigates the evidence for you, so you don't just get answers, you get answers you can prove.",
  },
  {
    number: 2,
    title: "It starts in Claude Code",
    startS: 29,
    endS: 60,
    rubric: "How to run it",
    accentColor: "#6f93b8",
    narration:
      "And it's surprisingly simple to run. VERDICT lives inside Claude Code, the A.I. assistant in your terminal. You type one line: investigate, followed by the evidence, a hard-drive image, or a snapshot of a computer's memory. That's the whole command. And watch closely while it runs: midway through, its verifier replays a finding, the hashes don't match, and it rejects it. Throws it back, re-runs the tool, recovers it clean. It catches its own mistakes, on camera.",
  },
  {
    number: 3,
    title: "How the case progresses",
    startS: 60,
    endS: 92,
    rubric: "How it works",
    accentColor: "#7fae6e",
    narration:
      "So what's it actually doing? First it makes a locked, read-only copy of the evidence, so the original is never touched, which matters if this ends up in court. Then it splits into two separate teams of agents that investigate from opposite angles. Each runs real forensic tools and writes up what it finds. Wherever the two disagree, that conflict is flagged out loud, not swept away. Finally, every finding is double-checked against the raw tool output before it makes the report.",
  },
  {
    number: 4,
    title: "The toolbox",
    startS: 92,
    endS: 120,
    rubric: "The tools",
    accentColor: "#c79a4a",
    narration:
      "The agent isn't guessing. It runs thirty-two real forensic tools, twenty written in Rust and twelve in Python, the same kind professionals use. And by design, not one of them can run arbitrary commands on your system, so it can't be tricked into going rogue. Each tool answers one plain question: What programs ran on this machine? What did the system quietly log? What left over the network? And, can we prove it?",
  },
  {
    number: 5,
    title: "Two investigators",
    startS: 120,
    endS: 146,
    rubric: "Competing hypotheses",
    accentColor: "#d6452f",
    narration:
      "Why two teams? One assumes the attacker broke in to stay and dig in. The other assumes they came to steal data and leave. Same evidence, opposite theories. A single analyst tends to lock onto their first guess. VERDICT forces both sides to argue on the record, shows you where they disagree, and only then decides. You see the reasoning, not just a conclusion handed down.",
  },
  {
    number: 6,
    title: "Watch it live",
    startS: 146,
    endS: 172,
    rubric: "The dashboard",
    accentColor: "#9b59b6",
    narration:
      "And while it runs, you're not staring at a blank screen. This is the live dashboard. Each finding appears the moment it's proven, tagged confirmed, inferred, or hypothesis, so you always know how sure the agent is. A timeline builds itself, the pipeline lights up stage by stage, and every finding links straight back to the exact tool call behind it. Nothing hidden, nothing hand-waved.",
  },
  {
    number: 7,
    title: "Proof you can take to court",
    startS: 172,
    endS: 203,
    rubric: "Chain of custody",
    accentColor: "#6f93b8",
    narration:
      "Here's what really sets it apart. Every action is locked into a tamper-evident chain, sealed with a cryptographic signature, strong enough to back a courtroom self-authentication claim. And you don't have to take that on trust. Watch: the verifier passes. Now we flip a single byte in the audit log and run it again. It fails, and names the exact record that broke. The verdict isn't a claim you have to trust. It's a sealed artifact you can check.",
  },
  {
    number: 8,
    title: "Then your team takes over",
    startS: 203,
    endS: 219,
    rubric: "Handoff",
    accentColor: "#7fae6e",
    narration:
      "And the moment the verdict is signed, VERDICT hands it to the workflows your team already uses: a Slack alert, a ticket, an indicator pushed out to your defenses. The agent investigates. Your analysts decide what happens next.",
  },
  {
    number: 9,
    title: "From one host to the fleet",
    startS: 219,
    endS: 252,
    rubric: "Scale",
    accentColor: "#c79a4a",
    narration:
      "One computer is just the demo. A real breach touches dozens of machines. VERDICT investigated twenty-two hosts, eighty-four gigabytes of evidence, from a single command. Across that fleet it flagged six hosts that ran the same admin tool at the exact same second. That's not natural system behavior, that's an attacker's sweep, and it surfaced it as a hypothesis for the analyst to confirm. And against a published answer key, it found five out of five expected findings. One hundred percent recall.",
  },
  {
    number: 10,
    title: "Get the receipts",
    startS: 252,
    endS: 275,
    rubric: "Signed verdict",
    accentColor: "#9b59b6",
    narration:
      "And at the end you get the one artifact that matters: a signed verdict, and an honest one. It only ever says three things: suspicious, indeterminate, or no evil found in what was examined. Never a promise it can't keep. VERDICT is open source and ready today. Point it at your evidence: minutes instead of days, with a receipt for every finding.",
  },
];

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;
// Total runtime is the last beat's end — keeps Root.tsx in sync after re-timing.
export const TOTAL_FRAMES = BEATS[BEATS.length - 1].endS * FPS;
