/** Planned commands (later build phases). They fail clearly rather than pretending. */

function planned(name: string, phase: string, detail: string): number {
  console.error(`caseforge ${name}: not yet implemented (${phase}).`)
  console.error(`  ${detail}`)
  return 3
}

export const gatewayStart = (): number =>
  planned("gateway start", "Phase 3", "LiteLLM universal gateway is planned; see configs/llm-gateway.litellm.yaml.")

export const benchmarkRun = (): number =>
  planned("benchmark run", "Phase 14", "Benchmark + provider-capability tests are planned.")

export const ocr = (): number =>
  planned("ocr", "Phase 11", "OCR router is planned; see configs/ocr-profiles.yaml.")

export const ingest = (): number =>
  planned("ingest", "Phase 12", "Rust ingest core (crates/caseforge-ingest) is planned.")
