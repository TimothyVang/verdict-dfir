export interface Beat {
  number: number;
  title: string;
  startS: number;
  endS: number;
  rubric: string;
  narration: string;
  accentColor: string;
}

// 9 beats from docs/demo-script-a2.md — 300s total
export const BEATS: Beat[] = [
  {
    number: 1,
    title: "Cold open + problem framing",
    startS: 0,
    endS: 25,
    rubric: "Stakes",
    accentColor: "#e74c3c",
    narration:
      "Modern attackers move at machine speed — the median ransomware dwell time is now measured in hours, not days. The SANS Find Evil hackathon asks: can an agent reproduce a forensic investigator's work fast enough to keep up — and prove what it did. Our submission says yes, and gives the analyst a sigstore-backed signature on every finding, verifiable offline.",
  },
  {
    number: 2,
    title: "Architecture",
    startS: 25,
    endS: 50,
    rubric: "Criterion 4 — Constraints",
    accentColor: "#3498db",
    narration:
      "Five trust boundaries. Evidence vault — read-only. SIFT tools as subprocesses, never linked, so we stay license-clean for AGPL code. Two MCP servers — Rust for forensic tools, Python for the crypto chain. Claude Code as the orchestrator. Every Finding cites a tool-call ID; every tool call hashes its output. There is no execute_shell tool — by design.",
  },
  {
    number: 3,
    title: "Single-host investigation",
    startS: 50,
    endS: 95,
    rubric: "Criteria 1, 2, 5",
    accentColor: "#2ecc71",
    narration:
      "One command. Tesla-mode. The agent opens the case, hashes the image, walks the active process list with Volatility pslist, then signature-scans EPROCESS pool memory with psscan — and the two disagree. That divergence is the textbook DKOM rootkit signature. The agent labels the finding INFERRED because two tool outputs corroborate it. It will not label this CONFIRMED until the verifier re-runs both calls and matches the original hashes. That distinction is non-negotiable.",
  },
  {
    number: 4,
    title: "Live ACH disagreement",
    startS: 95,
    endS: 155,
    rubric: "Criteria 1, 2",
    accentColor: "#f39c12",
    narration:
      "Heuer's Analysis of Competing Hypotheses, applied at agent architecture. Two pools investigate the same evidence with opposing priors. They will disagree — and that disagreement is not a bug. We surface it before reconciliation, named, in the audit trail. The judge merges with credibility weighting. The analyst sees both arguments and the reconciliation. No consensus-seeking single agent can give them that.",
  },
  {
    number: 5,
    title: "Crypto chain-of-custody",
    startS: 155,
    endS: 190,
    rubric: "Criteria 4, 5",
    accentColor: "#9b59b6",
    narration:
      "Every audit record, every tool output, every Finding — all hash-chained. At investigation end, we Merkle-tree the chain and sign the root with sigstore, whose Rekor transparency log records the signature as an independent third party. This supports a Federal Rule of Evidence 902-14 self-authenticating-evidence claim. A judge in a literal court can verify this submission's integrity from the manifest alone, three years from now, without trusting us.",
  },
  {
    number: 6,
    title: "22-host fleet investigation",
    startS: 190,
    endS: 240,
    rubric: "Criterion 3 — Breadth/Depth",
    accentColor: "#1abc9c",
    narration:
      "Single-host is the demo; fleet investigation is the use case. Twenty-two memory images, eighty-four gigabytes total, investigated end-to-end with one command. The orchestrator persists progress after every host so a crash doesn't cost you the run. Every host gets its own signed manifest; the fleet rollup adds cross-host correlation on top.",
  },
  {
    number: 7,
    title: "Cross-host APT signal",
    startS: 240,
    endS: 270,
    rubric: "Criteria 3, 6",
    accentColor: "#e67e22",
    narration:
      "This is what makes fleet correlation worth the cost. Six hosts ran Autoruns at the exact same second — that is not natural system behavior, that is a PsExec sweep or an SCCM push. Four different hosts ran rubyw — Ruby for Windows isn't enterprise tooling. These are correlations no single-host investigation would surface. The agent surfaces them as HYPOTHESIS and names the threshold. The analyst confirms.",
  },
  {
    number: 8,
    title: "Tiebreaker — self-score chip",
    startS: 270,
    endS: 290,
    rubric: "Criteria 1, 5",
    accentColor: "#e74c3c",
    narration:
      "The agent self-scores against the SANS rubric and writes that grade into the audit chain — before manifest_finalize. So the score itself is signed by the same sigstore signature and rooted in the same Merkle tree as every other finding. Judges grep one line, see the agent's own assessment of how it did, and know we couldn't have revised it after the fact.",
  },
  {
    number: 9,
    title: "Outro — repo URL + license",
    startS: 290,
    endS: 300,
    rubric: "",
    accentColor: "#2c3e50",
    narration:
      "Source is open. License is Apache-2.0. Build is green. Cut evidence in. Get a signed verdict out. Thank you.",
  },
];

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;
export const TOTAL_FRAMES = 300 * FPS; // 9000
