import { type Beat } from "./beats-data";

// EducationalExplainer — "What VERDICT is and why you can trust it." A calm,
// concept-first walkthrough for someone who has never seen the tool. Narration
// is the canonical voiceover (read by the TTS step); on-screen text is the
// concise headline/points. Every claim is scoped to the product guardrails
// (CLAUDE.md): NO_EVIL is never a clean bill of health, no tool runs arbitrary
// commands, and every finding is tool-cited and verified.
export const EXPLAINER_BEATS: Beat[] = [
  {
    number: 1,
    scene: "logo",
    title: "VERDICT",
    startS: 0,
    endS: 9,
    rubric: "Explainer",
    accentColor: "#4D5DFF",
    narration:
      "Let's talk about what VERDICT actually is — and why its answers are ones you can prove, not just ones you have to trust.",
  },
  {
    number: 2,
    scene: "concept",
    title: "A DFIR agent that shows its work",
    startS: 9,
    endS: 36,
    rubric: "What it is",
    accentColor: "#4D5DFF",
    kicker: "What it is",
    headline: "A DFIR agent that shows its work",
    body:
      "VERDICT is a digital-forensics and incident-response agent that runs inside Claude Code. You point it at supported evidence — a disk image, an event log, a packet capture, a memory snapshot — and it investigates, like an analyst would, but at machine speed.",
    points: [
      "Runs in your terminal, on evidence you already have",
      "Drives real forensic tools — it does not guess",
      "Ends with a signed, verifiable case file",
    ],
    narration:
      "VERDICT is a forensics and incident-response agent that lives inside Claude Code, the AI assistant in your terminal. You point it at evidence you already have — a disk image, an event log, a packet capture, a snapshot of memory — and it investigates the way an analyst would, only faster. It drives real forensic tools, it doesn't guess, and it ends every case with a signed file you can verify.",
  },
  {
    number: 3,
    scene: "concept",
    title: "Case, Findings, Verdict",
    startS: 36,
    endS: 63,
    rubric: "The core loop",
    accentColor: "#4D5DFF",
    kicker: "The core loop",
    headline: "Case → Findings → Verdict",
    body:
      "Every investigation follows the same shape. VERDICT opens a Case over the evidence, gathers Findings from the tools, verifies each one against the raw output, and only then reaches a Verdict.",
    points: [
      "A Case binds the work to specific evidence",
      "Each Finding cites the exact tool call behind it",
      "Every Finding is verified before it counts",
    ],
    narration:
      "Every investigation has the same shape. VERDICT opens a Case bound to the evidence. It gathers Findings by running tools. Each Finding has to cite the exact tool call that produced it — a receipt. Then every Finding is replayed and verified against the raw output before it's allowed to count. Only after that does it reach a Verdict. Nothing skips the receipt, and nothing skips the check.",
  },
  {
    number: 4,
    scene: "tools",
    title: "The tool surface",
    startS: 63,
    endS: 89,
    rubric: "The tools",
    accentColor: "#FFD76A",
    narration:
      "What it's driving is a typed tool surface: Rust forensic tools plus Python helpers for crypto and analysis. And here's the load-bearing design choice. Not one of these tools can run an arbitrary command. There is no shell. Each one answers a single, narrow question, so the agent can be fast without ever being tricked into going off the rails.",
  },
  {
    number: 5,
    scene: "concept",
    title: "Proof you can verify offline",
    startS: 89,
    endS: 118,
    rubric: "Chain of custody",
    accentColor: "#4D5DFF",
    kicker: "Chain of custody",
    headline: "A receipt for every claim",
    body:
      "The evidence is read-only and the audit log is append-only and hash-chained. The whole case is sealed into a signed manifest — and you can verify that seal offline, with no network and no trust in us.",
    points: [
      "Evidence is never modified — read-only throughout",
      "Every action is hashed into a tamper-evident chain",
      "Flip one byte and the verifier names the broken record",
    ],
    narration:
      "Because every finding carries a receipt, the whole case becomes checkable. The evidence is read-only — the original is never touched. Every action is hashed into an append-only chain and sealed in a signed manifest. And you can verify that manifest offline, years later, with no network and no trust in us. Tamper with a single byte and the verifier fails and tells you exactly which record broke.",
  },
  {
    number: 6,
    scene: "concept",
    title: "Three words, scoped honestly",
    startS: 118,
    endS: 147,
    rubric: "Verdict words",
    accentColor: "#FF6257",
    kicker: "What the verdict means",
    headline: "Three words — and what they don't say",
    body:
      "VERDICT only ever says one of three things, and it never promises more than the evidence supports.",
    points: [
      "SUSPICIOUS — reportable evidence was found",
      "INDETERMINATE — leads or limited coverage prevent a call",
      "NO_EVIL — nothing reportable in the artifacts examined",
    ],
    narration:
      "And the verdict itself is deliberately humble. It only ever says one of three things. Suspicious means it found reportable evidence. Indeterminate means leads, or limited coverage, stop it from making a clean call. And no-evil means nothing reportable in the artifacts it actually examined — which is not the same as saying the machine is clean. That honesty is the whole point.",
  },
  {
    number: 7,
    scene: "outro",
    title: "Get the receipts",
    startS: 147,
    endS: 158,
    rubric: "Open source",
    accentColor: "#4D5DFF",
    narration:
      "VERDICT is open source and ready today. Point it at supported evidence and you get answers in minutes instead of days — with a receipt for every single one.",
  },
];
