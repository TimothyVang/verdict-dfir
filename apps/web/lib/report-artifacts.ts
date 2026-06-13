export const REPORT_ARTIFACTS = [
  { name: "REPORT.pdf", label: "PDF report" },
  { name: "REPORT.new.pdf", label: "PDF report (new)" },
  { name: "REPORT.html", label: "HTML report" },
  { name: "REPORT.md", label: "Markdown report" },
  { name: "REPORT-internal.pdf", label: "internal QA PDF" },
  { name: "REPORT-internal.new.pdf", label: "internal QA PDF (new)" },
  { name: "REPORT-internal.html", label: "internal QA HTML" },
  { name: "REPORT-internal.md", label: "internal QA packet" },
  { name: "verdict.json", label: "verdict.json" },
  { name: "coverage_manifest.json", label: "coverage manifest" },
  { name: "evidence_inventory.json", label: "evidence inventory" },
  { name: "audit.jsonl", label: "audit chain" },
  { name: "run.manifest.json", label: "manifest (signed)" },
  { name: "manifest_verify.json", label: "manifest verify" },
  { name: "expert_signoff.json", label: "expert signoff" },
  { name: "expert_signoff_manifest_link.json", label: "signoff manifest link" },
  { name: "customer_release_gate.final.json", label: "customer release gate" },
  { name: "disk_artifact_summary.json", label: "disk artifact summary" },
  { name: "psscan.json", label: "psscan process view" },
  { name: "psxview.json", label: "psxview cross-check" },
  { name: "malfind.json", label: "malfind output" },
  { name: "malware_triage.json", label: "malware triage" },
  { name: "timeline.json", label: "timeline.json" },
  { name: "timeline.csv", label: "timeline.csv" },
  { name: "automation.json", label: "automation summary" },
  { name: "self-score.json", label: "self score" },
  { name: "recall-score.json", label: "recall score" },
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
