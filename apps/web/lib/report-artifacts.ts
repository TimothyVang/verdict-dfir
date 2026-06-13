export const REPORT_ARTIFACTS = [
  { name: "REPORT.pdf", label: "PDF report" },
  { name: "REPORT.html", label: "HTML report" },
  { name: "REPORT.md", label: "Markdown report" },
  { name: "REPORT-internal.pdf", label: "internal QA PDF" },
  { name: "REPORT-internal.html", label: "internal QA HTML" },
  { name: "REPORT-internal.md", label: "internal QA packet" },
  { name: "verdict.json", label: "verdict.json" },
  { name: "coverage_manifest.json", label: "coverage manifest" },
  { name: "evidence_inventory.json", label: "evidence inventory" },
  { name: "run.manifest.json", label: "manifest (signed)" },
  { name: "manifest_verify.json", label: "manifest verify" },
  { name: "expert_signoff.json", label: "expert signoff" },
  { name: "expert_signoff_manifest_link.json", label: "signoff manifest link" },
  { name: "customer_release_gate.final.json", label: "customer release gate" },
  { name: "timeline.json", label: "timeline.json" },
  { name: "timeline.csv", label: "timeline.csv" },
  { name: "grounding.json", label: "grounding.json" },
] as const;

export const REPORT_ARTIFACT_NAMES: ReadonlySet<string> = new Set(
  REPORT_ARTIFACTS.map((artifact) => artifact.name),
);

export const REPORT_ARTIFACT_LABELS: Readonly<Record<string, string>> =
  Object.freeze(
    Object.fromEntries(
      REPORT_ARTIFACTS.map((artifact) => [artifact.name, artifact.label]),
    ),
  );
