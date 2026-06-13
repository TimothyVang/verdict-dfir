import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  REPORT_ARTIFACT_LABELS,
  REPORT_ARTIFACT_NAMES,
  REPORT_ARTIFACTS,
} from "@/lib/report-artifacts";

describe("report artifact registry", () => {
  it("exposes the reviewer sidecars needed to audit scope and release gates", () => {
    expect(REPORT_ARTIFACT_NAMES.has("coverage_manifest.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("evidence_inventory.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("audit.jsonl")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("REPORT.new.pdf")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("REPORT-internal.md")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("REPORT-internal.new.pdf")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("expert_signoff.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("expert_signoff_manifest_link.json")).toBe(
      true,
    );
    expect(REPORT_ARTIFACT_NAMES.has("customer_release_gate.final.json")).toBe(
      true,
    );
  });

  it("exposes common parser-summary sidecars produced by finished runs", () => {
    expect(REPORT_ARTIFACT_NAMES.has("disk_artifact_summary.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("psscan.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("psxview.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("malfind.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("malware_triage.json")).toBe(true);
    expect(REPORT_ARTIFACT_NAMES.has("automation.json")).toBe(true);
  });

  it("keeps artifact names as case-dir basenames", () => {
    for (const artifact of REPORT_ARTIFACTS) {
      expect(path.basename(artifact.name)).toBe(artifact.name);
      expect(artifact.name).not.toContain("\\");
      expect(artifact.name).not.toContain("/");
    }
  });

  it("labels the reviewer sidecars in dashboard language", () => {
    expect(REPORT_ARTIFACT_LABELS["coverage_manifest.json"]).toBe(
      "coverage manifest",
    );
    expect(REPORT_ARTIFACT_LABELS["evidence_inventory.json"]).toBe(
      "evidence inventory",
    );
    expect(REPORT_ARTIFACT_LABELS["audit.jsonl"]).toBe("audit chain");
    expect(REPORT_ARTIFACT_LABELS["REPORT-internal.md"]).toBe(
      "internal QA packet",
    );
    expect(REPORT_ARTIFACT_LABELS["REPORT.new.pdf"]).toBe("PDF report (new)");
    expect(REPORT_ARTIFACT_LABELS["REPORT-internal.new.pdf"]).toBe(
      "internal QA PDF (new)",
    );
    expect(REPORT_ARTIFACT_LABELS["expert_signoff.json"]).toBe(
      "expert signoff",
    );
    expect(REPORT_ARTIFACT_LABELS["customer_release_gate.final.json"]).toBe(
      "customer release gate",
    );
  });
});
