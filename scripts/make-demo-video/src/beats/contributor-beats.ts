import { type Beat } from "./beats-data";

// ContributorCall — "Help build VERDICT." Recruits open-source contributors:
// what it is in one line, why it matters, the load-bearing invariants from
// CONTRIBUTING.md, and the on-ramp. The invariants are quoted accurately — they
// are the product's security story and must not be softened.
export const CONTRIBUTOR_BEATS: Beat[] = [
  {
    number: 1,
    scene: "logo",
    title: "VERDICT",
    startS: 0,
    endS: 12,
    rubric: "Contribute",
    accentColor: "#4D5DFF",
    narration:
      "VERDICT is open source, and it's built to be built on. If forensics, Rust, Python, or trustworthy AI is your thing — here's how to jump in.",
  },
  {
    number: 2,
    scene: "concept",
    title: "Why help build it",
    startS: 12,
    endS: 40,
    rubric: "Why",
    accentColor: "#4D5DFF",
    kicker: "Why contribute",
    headline: "Forensics tooling, in the open",
    body:
      "VERDICT does the grind of an investigation and proves its work. Every new tool, fixture, and check makes that proof cover more of the real world — and the architecture is designed so contributions can't quietly weaken the safety story.",
    points: [
      "Real DFIR work, not a toy — disk, memory, network, cloud",
      "Rust, Python, and a TypeScript dashboard",
      "Guardrails are enforced in code, so it's safe to extend",
    ],
    narration:
      "Why help? Because VERDICT does the grind of a real investigation and then proves its work — and every tool, fixture, and check you add makes that proof reach further. It spans disk, memory, network, and cloud. It's Rust, Python, and a TypeScript dashboard. And the safety guardrails are enforced in code, not by convention, so you can extend it without quietly breaking what makes it trustworthy.",
  },
  {
    number: 3,
    scene: "concept",
    title: "The invariants",
    startS: 40,
    endS: 70,
    rubric: "Non-negotiables",
    accentColor: "#FF6257",
    kicker: "The non-negotiables",
    headline: "Four lines that never move",
    body:
      "These are load-bearing. A change that breaks one of them won't be merged — they are the whole security story.",
    points: [
      "No execute_shell tool — ever",
      "Every Finding cites a valid tool_call_id",
      "Evidence is read-only; the audit log is append-only and hash-chained",
      "Claude Code is the orchestrator — no hidden autonomous runtime",
    ],
    narration:
      "Before you write a line, know the four rules that never move. There is never a shell tool — nothing that runs an arbitrary command. Every finding must cite a real tool-call id. Evidence stays read-only, and the audit log is append-only and hash-chained. And Claude Code is the orchestrator — no hidden autonomous runtime sneaks back in. Break one of these and the change won't merge, because these four lines are the security story.",
  },
  {
    number: 4,
    scene: "concept",
    title: "Get started",
    startS: 70,
    endS: 94,
    rubric: "On-ramp",
    accentColor: "#73D9C2",
    kicker: "The on-ramp",
    headline: "Clone, set up, pick an issue",
    body:
      "Branch off master, use Conventional Commits, and open a PR with the template. Good first issues and issue templates are waiting in the repo.",
    command:
      "git clone https://github.com/TimothyVang/verdict-dfir\nbash scripts/setup\nbash scripts/run-all-smokes.sh   # mirrors CI before you push",
    narration:
      "Getting started is the easy part. Clone the repo, run setup, and run all the smokes — that one command mirrors what continuous integration will check, so you get a green light before you ever push. Branch off master, write Conventional Commits, and open a pull request with the template. There are good first issues and issue templates already waiting for you.",
  },
  {
    number: 5,
    scene: "concept",
    title: "Two bars to clear",
    startS: 94,
    endS: 121,
    rubric: "Done means proven",
    accentColor: "#4D5DFF",
    kicker: "What 'done' means",
    headline: "Smokes predict CI — a live run proves it",
    body:
      "Passing smokes tell you the wiring is right. The real gate is a live investigation that produces a verifiable manifest.",
    points: [
      "Fast bar — run-all-smokes mirrors L0 and L1",
      "Real bar — scripts/verdict on real evidence",
      "An honest INDETERMINATE on thin evidence is a pass",
    ],
    narration:
      "One more thing worth knowing: there are two bars. The fast one is the smokes — they predict what CI will say. The real one is a live investigation: point VERDICT at real evidence and confirm the manifest verifies. And here's the culture — an honest indeterminate on thin evidence is a pass. We'd rather the tool say it isn't sure than overclaim. Hold that line and you'll fit right in.",
  },
  {
    number: 6,
    scene: "outro",
    title: "Come build it",
    startS: 121,
    endS: 132,
    rubric: "Join in",
    accentColor: "#4D5DFF",
    narration:
      "That's the invitation. The repo's open, the issues are tagged, and the guardrails have your back. Come help build forensics tooling people can actually trust.",
  },
];
