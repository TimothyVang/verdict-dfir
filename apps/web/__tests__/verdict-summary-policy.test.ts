import { describe, expect, it } from "vitest";

import {
  buildVerdictSummaryLine,
  deriveVerdictWord,
  summarizeVerdictCaveats,
  type FindingTally,
} from "@/lib/verdict-summary-policy";

const emptyTally: FindingTally = {
  confirmed: 0,
  inferred: 0,
  hypothesis: 0,
  total: 0,
};

describe("verdict summary policy", () => {
  it("renders NO_EVIL as scoped examined-artifact language, never clean/safe", () => {
    const caveats = ["unsupported samples: 2", "not supplied: 1"];
    const line = buildVerdictSummaryLine("NO EVIL", emptyTally, "case.evtx", caveats);

    expect(line).toContain("No reportable findings in examined artifacts");
    expect(line).toContain("scope caveats");
    expect(line.toLowerCase()).not.toContain("clean");
    expect(line.toLowerCase()).not.toContain("safe");
  });

  it("extracts coverage, verifier, and QA caveats from verdict.json", () => {
    const caveats = summarizeVerdictCaveats({
      verdict: "NO_EVIL",
      coverage_manifest: {
        summary: {
          unsupported: 1,
          unsupported_sample_count: 2,
          failed: 1,
          not_supplied: 3,
          attack_blind_spot_count: 4,
          status_counts: { partial: 1 },
        },
      },
      rejected_finding_leads: [{ finding_id: "f-rejected" }],
      analysis_limitations: ["network telemetry not supplied"],
      report_qa: { status: "WARN" },
    });

    expect(caveats).toEqual([
      "unsupported samples: 2",
      "failed parser lanes: 1",
      "partial parser lanes: 1",
      "not supplied: 3",
      "ATT&CK blind spots: 4",
      "verifier-rejected leads: 1",
      "analysis limitations: 1",
      "QA: WARN",
    ]);
  });

  it("prefers signed verdict.json over live-stream derivation", () => {
    expect(
      deriveVerdictWord(
        "NO_EVIL",
        { confirmed: 1, inferred: 0, hypothesis: 0, total: 1 },
        true,
      ),
    ).toBe("NO EVIL");
  });
});
