export type VerdictWord = "SUSPICIOUS" | "INDETERMINATE" | "NO EVIL" | "INVESTIGATING";

export interface FindingTally {
  confirmed: number;
  inferred: number;
  hypothesis: number;
  total: number;
}

interface CoverageSummary {
  unsupported?: number;
  unsupported_sample_count?: number;
  failed?: number;
  not_supplied?: number;
  attack_blind_spot_count?: number;
  status_counts?: Record<string, number>;
}

interface CoverageManifest {
  summary?: CoverageSummary;
}

export interface VerdictPayload {
  verdict?: string;
  coverage_manifest?: CoverageManifest;
  rejected_finding_leads?: unknown[];
  analysis_limitations?: unknown[];
  report_qa?: {
    status?: string;
    packet_state?: string;
  };
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function intValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : 0;
}

export function deriveVerdictWord(
  authVerdict: string | null | undefined,
  tally: FindingTally,
  manifestDone: boolean,
): VerdictWord {
  const authoritative = (authVerdict ?? "").toUpperCase().replace(/_/g, " ");
  if (authoritative.includes("SUSPICIOUS")) return "SUSPICIOUS";
  if (authoritative.includes("INDETERMINATE")) return "INDETERMINATE";
  if (authoritative.includes("NO EVIL")) return "NO EVIL";
  if (tally.confirmed > 0) return "SUSPICIOUS";
  if (tally.inferred > 0 || tally.hypothesis > 0) return "INDETERMINATE";
  if (manifestDone) return "NO EVIL";
  return "INVESTIGATING";
}

export function summarizeVerdictCaveats(payload: VerdictPayload | null | undefined): string[] {
  if (!payload) return [];
  const summary = payload.coverage_manifest?.summary ?? {};
  const statusCounts = summary.status_counts ?? {};
  const caveats: string[] = [];

  const unsupportedSamples = intValue(summary.unsupported_sample_count);
  const unsupportedRows = intValue(summary.unsupported);
  if (unsupportedSamples > 0) {
    caveats.push(`unsupported samples: ${unsupportedSamples}`);
  } else if (unsupportedRows > 0) {
    caveats.push(`unsupported artifact rows: ${unsupportedRows}`);
  }

  const failed = intValue(summary.failed);
  if (failed > 0) caveats.push(`failed parser lanes: ${failed}`);

  const partial = intValue(statusCounts.partial);
  if (partial > 0) caveats.push(`partial parser lanes: ${partial}`);

  const notSupplied = intValue(summary.not_supplied);
  if (notSupplied > 0) caveats.push(`not supplied: ${notSupplied}`);

  const blindSpots = intValue(summary.attack_blind_spot_count);
  if (blindSpots > 0) caveats.push(`ATT&CK blind spots: ${blindSpots}`);

  const rejectedLeads = Array.isArray(payload.rejected_finding_leads)
    ? payload.rejected_finding_leads.length
    : 0;
  if (rejectedLeads > 0) caveats.push(`verifier-rejected leads: ${rejectedLeads}`);

  const limitations = Array.isArray(payload.analysis_limitations)
    ? payload.analysis_limitations.length
    : 0;
  if (limitations > 0) caveats.push(`analysis limitations: ${limitations}`);

  const qaStatus = String(payload.report_qa?.status ?? "").toUpperCase();
  if (qaStatus && qaStatus !== "PASS") caveats.push(`QA: ${qaStatus}`);

  return caveats;
}

export function buildVerdictSummaryLine(
  verdict: VerdictWord,
  tally: FindingTally,
  evidenceName?: string,
  caveats: string[] = [],
): string {
  const subject = evidenceName ?? "the evidence";
  if (verdict === "SUSPICIOUS") {
    return (
      `${plural(tally.confirmed, "confirmed finding")}` +
      (tally.inferred ? ` and ${plural(tally.inferred, "inferred lead")}` : "") +
      ` on ${subject}.`
    );
  }
  if (verdict === "INVESTIGATING") {
    return `${plural(tally.total, "finding")} so far; ${subject} is still being processed.`;
  }
  if (verdict === "INDETERMINATE") {
    return `${plural(tally.inferred + tally.hypothesis, "lead")} on ${subject}; corroboration or scope closure is still needed.`;
  }
  return caveats.length > 0
    ? `No reportable findings in examined artifacts for ${subject}; review the scope caveats below.`
    : `No reportable findings in examined artifacts for ${subject}.`;
}
