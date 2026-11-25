import { createHash } from "node:crypto"

export type CoverageStatus = "complete" | "partial" | "unknown"

export type ArtifactClass =
  | "memory"
  | "disk"
  | "evtx"
  | "network"
  | "registry"
  | "malware"
  | "linux"
  | "custody"
  | "meta"

export interface CoverageDeclaration {
  scope: string
  status: CoverageStatus
  total_count?: number
  returned_count?: number
  next_offset?: number | null
}

export interface AnalysisProfile {
  engine: string
  version: string
  mode: "deterministic" | "interactive" | "agent"
  parameters?: Record<string, unknown>
}

export interface EvidenceRecord<T = Record<string, unknown>> {
  schema_version: 1
  evidence_id: string
  seq: number
  prev_hash: string | null
  recorded_at: string
  tool: string
  artifact_class: ArtifactClass
  parameters: Record<string, unknown>
  analysis_profile: AnalysisProfile | null
  normalized_result: T
  raw_result: unknown | null
  coverage: CoverageDeclaration
  limitations: string[]
}

export interface RetainedEvidenceRef {
  kind: "retained-evidence"
  evidence_id: string
}

export interface EvidenceFileRef {
  kind: "evidence-file"
  path: string
  evidence_id?: string
}

export type EvidenceSource = RetainedEvidenceRef | EvidenceFileRef | EvidenceRecord

export interface EvidenceSummary {
  parent_evidence_id: string
  tool: string
  artifact_class: ArtifactClass
  coverage: CoverageDeclaration
  limitations: string[]
  collections: Record<string, number>
  preview: Record<string, unknown>
}

export type ErrorCode =
  | "invalid_request"
  | "evidence_integrity_mismatch"
  | "citation_rejected"
  | "forensic_rule_violation"
  | "stale_revision"
  | "privacy_violation"
  | "provider_unavailable"

export interface DiagnosticPayload {
  error: {
    code: ErrorCode
    message: string
    details?: Record<string, unknown>
    remediation?: {
      action: string
    }
    recovery?: {
      kind: "inspect_input_contract" | "inspect_timeout_state" | "reread_revision" | "supply_corroboration"
      operation?: string
    }
  }
}

export class VerdictMcpError extends Error {
  readonly code: ErrorCode
  readonly details?: Record<string, unknown>
  readonly remediation?: { action: string }
  readonly recovery?: DiagnosticPayload["error"]["recovery"]

  constructor(
    code: ErrorCode,
    message: string,
    opts?: {
      details?: Record<string, unknown>
      remediation?: { action: string }
      recovery?: DiagnosticPayload["error"]["recovery"]
    },
  ) {
    super(message)
    this.name = "VerdictMcpError"
    this.code = code
    this.details = opts?.details
    this.remediation = opts?.remediation
    this.recovery = opts?.recovery
  }

  toDiagnostic(): DiagnosticPayload {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
        ...(this.remediation ? { remediation: this.remediation } : {}),
        ...(this.recovery ? { recovery: this.recovery } : {}),
      },
    }
  }
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`
  }
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
  const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
  return `{${pairs.join(",")}}`
}

export function computeEvidenceId(payload: {
  tool: string
  artifact_class: ArtifactClass
  parameters: Record<string, unknown>
  analysis_profile: AnalysisProfile | null
  normalized_result: unknown
  coverage: CoverageDeclaration
  limitations: string[]
}): string {
  const digest = createHash("sha256").update(canonicalJson(payload)).digest("hex")
  return `ev_${digest.slice(0, 32)}`
}

export function verifyEvidenceDigest(record: EvidenceRecord): boolean {
  if (record.schema_version !== 1 || !("analysis_profile" in record)) {
    return false
  }
  const expected = computeEvidenceId({
    tool: record.tool,
    artifact_class: record.artifact_class,
    parameters: record.parameters,
    analysis_profile: record.analysis_profile,
    normalized_result: record.normalized_result,
    coverage: record.coverage,
    limitations: record.limitations,
  })
  return record.evidence_id === expected
}

export function isValidIsoTimestamp(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(value)) {
    return false
  }
  return !Number.isNaN(Date.parse(value))
}
