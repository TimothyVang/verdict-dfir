/**
 * caseforge run record — evidenced `used_fallback`.
 *
 * m27 residual: `used_fallback` was asserted for a run but recorded in no
 * custody artifact, so `caseforge verify` could not attest it and the claim had
 * to be retracted. The honest contract:
 *
 *   - The RUNTIME (the `verdict`/opencode engine, or caseforge's own
 *     deterministic EVTX auto-runner) is the source of truth for whether a
 *     fallback path produced the sealed run. caseforge READS that value from the
 *     runtime run result — it never synthesizes it.
 *   - caseforge records the read value in its own run artifact
 *     (`caseforge_run.json`) alongside the sealed custody files, so `verify` can
 *     surface it. When no runtime run result exists and caseforge did not itself
 *     select a fallback path, `used_fallback` is recorded as `null` (unknown) —
 *     never defaulted to `false`.
 */
import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"

/** caseforge-owned run record file written into the sealed run directory. */
export const CASEFORGE_RUN_RECORD = "caseforge_run.json"

/** Runtime-emitted run result file caseforge reads `used_fallback` from. */
export const RUNTIME_RUN_RESULT = "run_result.json"

export type UsedFallbackSource = "runtime_run_result" | "caseforge_orchestration" | "unknown"

export interface CaseforgeRunRecord {
  generated_by: "caseforge"
  /** true/false read from a runtime run result; null when genuinely unknown. */
  used_fallback: boolean | null
  used_fallback_source: UsedFallbackSource
  runtime_run_result_present: boolean
  note: string
}

/**
 * Extract `used_fallback` from an arbitrary runtime run-result object. Returns
 * the boolean only when it is literally a boolean; otherwise `null`. Never
 * coerces strings/numbers and never invents a value.
 */
export function readUsedFallback(result: unknown): boolean | null {
  if (!result || typeof result !== "object") return null
  const v = (result as Record<string, unknown>).used_fallback
  return typeof v === "boolean" ? v : null
}

/** Read the runtime-emitted run result JSON (undefined if absent/unreadable). */
export async function readRuntimeRunResult(runDir: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(join(runDir, RUNTIME_RUN_RESULT), "utf8"))
  } catch {
    return undefined
  }
}

/** Read caseforge's own run record (undefined if absent/unreadable). */
export async function readCaseforgeRun(runDir: string): Promise<CaseforgeRunRecord | undefined> {
  try {
    return JSON.parse(await readFile(join(runDir, CASEFORGE_RUN_RECORD), "utf8")) as CaseforgeRunRecord
  } catch {
    return undefined
  }
}

/** Persist caseforge's run record into the run directory; returns what was written. */
export async function writeCaseforgeRun(runDir: string, record: CaseforgeRunRecord): Promise<CaseforgeRunRecord> {
  await writeFile(join(runDir, CASEFORGE_RUN_RECORD), JSON.stringify(record, null, 2) + "\n")
  return record
}

export interface AssembleRunRecordInput {
  /** The runtime-emitted run result object, if any (authoritative). */
  runtimeResult?: unknown
  /**
   * caseforge's own first-party knowledge that it selected the deterministic
   * fallback path (control-flow fact, not a guess). Used only when the runtime
   * emitted no usable `used_fallback`.
   */
  engineUsedFallback?: boolean | null
}

/**
 * Build a run record, sourcing `used_fallback` in priority order:
 *   1. the runtime run result (authoritative for the agent/cloud path),
 *   2. caseforge's own control-flow decision (deterministic-engine fallback),
 *   3. unknown (`null`) — never a synthesized `false`.
 */
export function assembleRunRecord(input: AssembleRunRecordInput): CaseforgeRunRecord {
  const runtimePresent = input.runtimeResult !== undefined
  const fromRuntime = readUsedFallback(input.runtimeResult)
  if (fromRuntime !== null) {
    return {
      generated_by: "caseforge",
      used_fallback: fromRuntime,
      used_fallback_source: "runtime_run_result",
      runtime_run_result_present: true,
      note: "used_fallback read from the runtime run result.",
    }
  }
  if (typeof input.engineUsedFallback === "boolean") {
    return {
      generated_by: "caseforge",
      used_fallback: input.engineUsedFallback,
      used_fallback_source: "caseforge_orchestration",
      runtime_run_result_present: runtimePresent,
      note: "used_fallback recorded from caseforge's own path selection (no runtime run result emitted the field).",
    }
  }
  return {
    generated_by: "caseforge",
    used_fallback: null,
    used_fallback_source: "unknown",
    runtime_run_result_present: runtimePresent,
    note: "used_fallback unknown — no runtime run result emitted the field and caseforge did not itself select a fallback path.",
  }
}

/**
 * Attest `used_fallback` for a run directory: prefer caseforge's recorded run
 * artifact; otherwise derive live from the runtime run result. Read-only —
 * surfaces evidence, never synthesizes.
 */
export async function attestUsedFallback(runDir: string): Promise<CaseforgeRunRecord> {
  const recorded = await readCaseforgeRun(runDir)
  if (recorded) return recorded
  const runtimeResult = await readRuntimeRunResult(runDir)
  return assembleRunRecord({ runtimeResult })
}
