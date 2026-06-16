import { type Beat } from "./beats-data";

// FeatureDeepDives — a detailed, criteria-aligned walkthrough. Each feature is a
// real screen recording (public/ui/*.mp4); concept/tools/arch/outro beats are
// code-rendered. Slots are sized to each line's narration and exhibit clips are
// retimed (playbackRate = clip_len / slot_len) so the picture keeps moving
// instead of holding a frozen frame — paired with the lower pacing.holdFrames.
//
// Mapped to the six judged criteria in agent-config/JUDGING.md. Beat 4 is
// criterion 1 (autonomous execution / self-correction) shown live in the
// Claude Code terminal — the cascading tiebreaker. Its clip,
// ui/self-correction.mp4, is a fresh fullscreen capture dropped in before the
// full render (see scripts/make-demo-video/CAPTURE.md).
export const DEEPDIVE_BEATS: Beat[] = [
  {
    number: 1,
    scene: "concept",
    title: "Shown working, with receipts",
    startS: 0,
    endS: 22,
    rubric: "Cold open",
    accentColor: "#9b59b6",
    kicker: "VERDICT · feature deep dive",
    headline: "Shown working — with receipts",
    body:
      "Five real recordings of the tool running on genuine evidence — judged the way this competition asks: every claim traceable to the tool call that produced it.",
    narration:
      "This is VERDICT — a forensics agent that doesn't just find evil, it proves it. Nothing here is a slide. Every screen is a real recording of the tool running on genuine evidence, and judged the way this competition asks: can you trace every claim back to the tool call that produced it.",
  },
  {
    number: 2,
    scene: "concept",
    title: "Proof is the hard part",
    startS: 22,
    endS: 45,
    rubric: "Why it exists",
    accentColor: "#6f93b8",
    kicker: "Why it exists",
    headline: "Proof is the hard part",
    body:
      "Finding a clue is easy. Proving exactly what an attacker did, well enough to hold up later, is days of manual work across disk, memory, and logs.",
    narration:
      "A machine gets compromised, and now you have to reconstruct exactly what the attacker did — and prove it well enough to hold up later. By hand that's days across disk, memory, and logs. VERDICT does that grind in minutes, and never asks you to take its word.",
  },
  {
    number: 3,
    scene: "exhibit",
    title: "It starts in Claude Code",
    startS: 45,
    endS: 76,
    rubric: "One command",
    accentColor: "#6f93b8",
    kicker: "One command",
    headline: "It starts in Claude Code",
    body:
      "Type investigate, point it at evidence. It opens a case, fingerprints the evidence read-only, and drives typed tools one call at a time.",
    points: [
      "case_open fingerprints the evidence with SHA-256, read-only",
      "Real tools: registry, prefetch, event logs, memory",
      "Every call recorded with its own tool_call_id",
    ],
    command: "verdict investigate evidence/",
    exhibit: {
      src: "ui/terminal-investigation.mp4",
      label: "verdict · investigate evidence/ — live terminal",
      objectFit: "contain",
      playbackRate: 0.46,
    },
    narration:
      "It starts with one line inside Claude Code: investigate, pointed at evidence — a disk image, a memory capture, an event log, a packet capture. Watch the terminal. The first thing it does is open a case and fingerprint the evidence with a SHA-256, read-only, so the original is never touched. Then it drives real forensic tools — registry, prefetch, event logs, memory — one typed call at a time, each recorded with its own id. Nothing happens off the books.",
  },
  {
    number: 4,
    scene: "exhibit",
    title: "It self-corrects, live",
    startS: 76,
    endS: 118,
    rubric: "Criterion 1 · autonomous execution",
    accentColor: "#d6452f",
    kicker: "Criterion 1 · autonomous execution",
    headline: "It self-corrects, live — for real",
    body:
      "A genuine tool failure, named in the log and handled without a human: narrow, continue, and when failures stack up, escalate to an honest partial verdict. Organic, not staged — fault_injection is zero.",
    points: [
      "registry_query fails: hive truncated, header too small",
      "course_correction: narrow scope, continue other lanes",
      "heartbeat escalates → honest INDETERMINATE / partial verdict",
    ],
    exhibit: {
      src: "ui/self-correction.mp4",
      label: "Claude Code · organic course_correction (fault_injection=0)",
      objectFit: "contain",
      playbackRate: 1,
    },
    narration:
      "Now the part that matters most, and the one this competition weighs first: it self-corrects, live, in the terminal — and it does it for real. Here it hits a genuinely broken artifact, a truncated registry hive; the log says, hive truncated, header too small. It doesn't silently retry, and it doesn't fake a result. It writes a named course-correction, narrows scope, and moves on to the lanes it can still run. When the failures stack up, a heartbeat check escalates, and it seals an honest, partial verdict over only what it could actually examine. This is an organic failure — fault injection is zero — not a staged stumble with a suspiciously clean recovery.",
  },
  {
    number: 5,
    scene: "concept",
    title: "Findings replay before they count",
    startS: 118,
    endS: 149,
    rubric: "Criterion 2 · accuracy & honesty",
    accentColor: "#7fae6e",
    kicker: "Criterion 2 · accuracy & honesty",
    headline: "Findings replay before they count",
    body:
      "A finding can't enter the report until the verifier re-runs its cited tool call and the output hash matches. Claims are labeled by confidence — and overclaims are owned, not hidden.",
    points: [
      "Each finding cites a current-case tool_call_id",
      "Verifier replays it; hash mismatch → downgrade or drop",
      "Labeled CONFIRMED / INFERRED / HYPOTHESIS",
      "Caught hallucinations documented — honesty over perfection",
    ],
    narration:
      "Feature one: the verifier. Most agents will happily hand you a confident, wrong answer. VERDICT won't let a finding into the report until it's replayed — it has to cite a tool call from this case, and the verifier re-runs that call and compares the output hash. If it doesn't match, the finding is downgraded or dropped. Every claim is labeled by how sure it is: confirmed, inferred, or hypothesis. And when it overclaims, it says so — like the memory-process near-miss we caught and wrote up. Honesty over perfection.",
  },
  {
    number: 6,
    scene: "exhibit",
    title: "They disagree — on the record",
    startS: 149,
    endS: 177,
    rubric: "Two investigators",
    accentColor: "#d6452f",
    kicker: "Feature 02 · competing hypotheses",
    headline: "They disagree — on the record",
    body:
      "Two pools work the same host from opposite priors. Every clash is logged and reconciled by a credibility-weighted judge.",
    points: [
      "Pool A: persistence · Pool B: exfiltration",
      "detect_contradictions logs each clash as its own record",
      "A credibility-weighted judge reconciles it, on the record",
    ],
    exhibit: {
      src: "ui/F-contradiction.mp4",
      label: "detect_contradictions · Pool A vs Pool B → judge",
      objectFit: "contain",
      playbackRate: 0.36,
    },
    narration:
      "Feature two: two investigators, not one. Two pools work the same host from opposite priors — one expects persistence, the other exfiltration. A lone analyst locks onto their first theory; these two argue it out. Every place they clash, detect_contradictions logs it as its own record, and a credibility-weighted judge reconciles it on the record — so you see the reasoning, not just a verdict.",
  },
  {
    number: 7,
    scene: "exhibit",
    title: "The whole case, live",
    startS: 177,
    endS: 203,
    rubric: "The dashboard",
    accentColor: "#9b59b6",
    kicker: "Feature 03 · the dashboard",
    headline: "The whole case, live",
    body:
      "Findings appear as they're vetted, tagged by confidence; the pipeline lights up and every finding links to its exact tool call.",
    points: [
      "Tagged confirmed / inferred / hypothesis as they land",
      "Pipeline rail plus a self-building timeline",
      "Click any finding → its exact tool call",
    ],
    exhibit: {
      src: "ui/dashboard-live.mp4",
      label: "localhost:3000 · live case dashboard",
      objectFit: "cover",
      playbackRate: 1,
    },
    narration:
      "Feature three: you watch it work. You're not staring at a spinner — findings appear the moment they're vetted, each tagged confirmed, inferred, or hypothesis, so you always know how sure it is. The pipeline lights up stage by stage, a timeline assembles itself, and every finding links straight back to the exact tool call behind it.",
  },
  {
    number: 8,
    scene: "concept",
    title: "Depth beats breadth",
    startS: 203,
    endS: 238,
    rubric: "Criterion 3 · breadth & depth",
    accentColor: "#c79a4a",
    kicker: "Criterion 3 · breadth & depth",
    headline: "Depth beats breadth",
    body:
      "Every case writes a coverage manifest, so partial coverage is never sold as clean. Execution claims must corroborate across at least two artifact classes.",
    points: [
      "coverage_manifest: parsed / failed / unsupported / not-supplied",
      "Execution claims require ≥2 artifact classes",
      "One deep cross-artifact chain beats a dozen shallow queries",
    ],
    narration:
      "Depth beats breadth here. Every case writes a coverage manifest — each artifact class marked parsed, failed, unsupported, or not supplied, so partial coverage is never sold as clean. And an execution claim has to corroborate across at least two artifact classes. One deep chain across disk, memory, and logs outscores a dozen shallow log queries.",
  },
  {
    number: 9,
    scene: "exhibit",
    title: "Don't trust it — verify it",
    startS: 238,
    endS: 269,
    rubric: "Criterion 5 · audit trail",
    accentColor: "#6f93b8",
    kicker: "Criterion 5 · audit trail",
    headline: "Don't trust it — verify it",
    body:
      "Any finding traces to a tool-call id, to its output hash, into a signed Merkle-rooted manifest you can check offline. Flip one byte and it fails — by name.",
    points: [
      "Finding → tool_call_id → output hash → Merkle root → signature",
      "manifest_verify passes offline, zero dependencies",
      "One flipped byte → fails, names the broken record",
    ],
    exhibit: {
      src: "ui/manifest-tamper.mp4",
      label: "trace-finding · offline manifest verify",
      objectFit: "contain",
      playbackRate: 0.54,
    },
    narration:
      "Feature four: don't trust it — verify it. Pick any finding: it traces to a tool-call id, to that call's output hash, into a Merkle-rooted, signed manifest. Watch manifest-verify pass offline. Now I flip a single byte in the audit log and run it again — it fails, and it names the exact record that broke. The verdict isn't something you have to believe. It's a tamper-evident artifact anyone can re-check, years from now, without trusting us.",
  },
  {
    number: 10,
    scene: "tools",
    title: "No shell, ever",
    startS: 269,
    endS: 302,
    rubric: "Criterion 4 · constraints",
    accentColor: "#c79a4a",
    kicker: "Criterion 4 · constraints",
    headline: "No shell, ever",
    narration:
      "Feature five holds up all the rest: the tool surface. Forty-three typed tools — thirty-one in Rust, twelve in Python — and not one of them can run an arbitrary command. No execute-shell, no path traversal, every call schema-validated, and the bypass attempts live in the test suite. The guardrail here is architectural — built into the types — not a polite instruction in a prompt.",
  },
  {
    number: 11,
    scene: "arch",
    title: "The architecture",
    startS: 302,
    endS: 337,
    rubric: "How it connects",
    accentColor: "#9b59b6",
    kicker: "How it connects",
    headline: "The architecture",
    narration:
      "Here's how it fits together. Claude Code is the agent. It drives two purpose-built MCP servers — the typed tool surface — which run real forensic tooling inside the SANS SIFT workstation, against a read-only evidence vault. Findings flow through the verifier and the judge, into a signed manifest and the analyst report. Each box is a trust boundary, and the guardrails that matter are architectural — enforced by schemas and hashes, not just by asking the model nicely.",
  },
  {
    number: 12,
    scene: "concept",
    title: "Receipts at scale",
    startS: 337,
    endS: 372,
    rubric: "On real cases",
    accentColor: "#7fae6e",
    kicker: "On real cases",
    headline: "Receipts at scale",
    body:
      "Real evidence, real numbers — and an honest scope when it can't prove something.",
    points: [
      "NIST hacking-case disk: SUSPICIOUS, 8 tool-cited findings",
      "22-host fleet: 6 machines, same admin tool, same second — lateral-movement lead",
      "Published-key case: 5 of 5 expected findings, reproducible offline",
    ],
    narration:
      "And it works on real cases. On the NIST hacking-case disk it returned suspicious with eight tool-cited findings. Turned loose on a twenty-two-host enterprise, host by host, it caught six machines running the same admin tool at the same second — lateral movement, surfaced as a lead. On a case with a published answer key it hit five of five expected findings, a score you can reproduce offline. And when it can't prove something, it scopes down and says so.",
  },
  {
    number: 13,
    scene: "outro",
    title: "All of it, open source",
    startS: 372,
    endS: 396,
    rubric: "Criterion 6 · usability",
    accentColor: "#9b59b6",
    kicker: "Criterion 6 · usability",
    headline: "All of it, open source",
    narration:
      "Clone the repo, run scripts find-evil, and you're in a working investigation in under five minutes; adding a new tool follows one reference file. It's Apache-licensed and open. VERDICT only ever says three things — suspicious, indeterminate, or no evil found in what it examined — and never more than it can back up. Point it at supported evidence, and see it for yourself.",
  },
];
