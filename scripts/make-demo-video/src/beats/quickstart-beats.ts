import { type Beat } from "./beats-data";

// Quickstart — install and first run, end to end. Commands shown match the
// canonical paths in CLAUDE.md / QUICKSTART.md exactly: `bash scripts/setup`
// then `scripts/verdict <evidence>`, with outputs under tmp/auto-runs/<case-id>/.
export const QUICKSTART_BEATS: Beat[] = [
  {
    number: 1,
    scene: "logo",
    title: "VERDICT",
    startS: 0,
    endS: 8,
    rubric: "Quickstart",
    accentColor: "#73D9C2",
    narration:
      "Here's the whole thing, start to finish — from a fresh checkout to a signed verdict, in two commands.",
  },
  {
    number: 2,
    scene: "concept",
    title: "Set it up once",
    startS: 8,
    endS: 27,
    rubric: "Step 1 — setup",
    accentColor: "#73D9C2",
    kicker: "Step 1 — setup",
    headline: "One command to set up",
    body:
      "From the repo root. Setup builds the Rust tool server, syncs the Python environment, installs the helper tooling, and runs a preflight doctor so you know you're ready.",
    command: "bash scripts/setup",
    narration:
      "Step one, run once. From the repo root, type bash scripts setup. That builds the Rust tool server, syncs the Python environment, installs the supported helper tooling, and runs a preflight doctor so you know everything's in place before you start.",
  },
  {
    number: 3,
    scene: "concept",
    title: "Point it at evidence",
    startS: 27,
    endS: 52,
    rubric: "Step 2 — run",
    accentColor: "#4D5DFF",
    kicker: "Step 2 — run a case",
    headline: "Point it at evidence",
    body:
      "One line. Give it a path to supported evidence — a disk image, an event log, a packet capture, a memory snapshot — and it opens a Case and runs the whole pipeline.",
    command: "scripts/verdict <path-to-evidence>\nscripts/verdict --sift <path>   # full disk-image parity",
    narration:
      "Step two, the actual investigation. Type scripts verdict and a path to supported evidence — a disk image, an event log, a packet capture, a memory image. That's the whole command. It opens a Case and runs the full pipeline. If your evidence is reachable inside the SANS SIFT workstation, add dash dash sift for full disk-image parity.",
  },
  {
    number: 4,
    scene: "concept",
    title: "What you get back",
    startS: 52,
    endS: 81,
    rubric: "The outputs",
    accentColor: "#FFD76A",
    kicker: "The outputs",
    headline: "What lands when it finishes",
    body:
      "Everything drops under tmp/auto-runs/<case-id>/. The run is only complete when the manifest verifies.",
    points: [
      "verdict.json — the scoped verdict and tool-cited findings",
      "manifest_verify.json — must report overall: true",
      "REPORT.html and REPORT.pdf — the analyst report",
      "audit.jsonl — the hash-chained custody record",
    ],
    narration:
      "When it finishes, everything lands under tmp, auto-runs, your case id. You get verdict-dot-json with the scoped verdict and every tool-cited finding. You get the analyst report as H-T-M-L and P-D-F. And you get the audit log and a manifest. One rule: the run is only really done when manifest-verify reports overall true. If it doesn't, the custody is invalid, and VERDICT tells you so instead of pretending.",
  },
  {
    number: 5,
    scene: "concept",
    title: "Or drive it interactively",
    startS: 81,
    endS: 97,
    rubric: "Interactive",
    accentColor: "#4D5DFF",
    kicker: "Interactive mode",
    headline: "Prefer to drive it by hand?",
    body:
      "Open Claude Code and ask in plain language — same pipeline, same receipts.",
    command: "claude\n# then:\n/verdict <path-to-evidence>\ninvestigate <path-to-evidence>",
    narration:
      "Prefer to work interactively? Just open Claude Code and type slash verdict, or simply say investigate and the path. Same pipeline, same receipts — you're just driving it in conversation instead of one shot.",
  },
  {
    number: 6,
    scene: "outro",
    title: "That's the whole loop",
    startS: 97,
    endS: 107,
    rubric: "Done",
    accentColor: "#73D9C2",
    narration:
      "That's the whole loop — setup once, point it at evidence, read the signed result. Open source, and ready to run today.",
  },
];
