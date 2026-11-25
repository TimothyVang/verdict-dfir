import { createHash } from "node:crypto"
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"
import {
  AnalysisProfile,
  ArtifactClass,
  canonicalJson,
  computeEvidenceId,
  CoverageDeclaration,
  EvidenceRecord,
  EvidenceSource,
  EvidenceSummary,
  VerdictMcpError,
  verifyEvidenceDigest,
} from "./evidence.js"

export interface RetainEvidenceInput<T = Record<string, unknown>> {
  tool: string
  artifact_class: ArtifactClass
  parameters: Record<string, unknown>
  analysis_profile: AnalysisProfile | null
  normalized_result: T
  raw_result?: unknown | null
  coverage: CoverageDeclaration
  limitations?: string[]
  recorded_at?: string
}

export interface AnalysisViewQuery {
  kind: "summary" | "collection"
  collection?: string
  offset?: number
  limit?: number
  fields?: string[]
  filter_key?: string
  filter_contains?: string
}

export interface EvidenceBundle {
  schema_version: 1
  bundle_id: string
  exported_at: string
  record_count: number
  chain_head_hash: string | null
  records: EvidenceRecord[]
}

export class EvidenceLedger {
  private readonly records = new Map<string, EvidenceRecord>()
  private readonly ordered: EvidenceRecord[] = []
  private readonly auditPath: string | null
  private readonly onRetain: ((record: EvidenceRecord) => void) | null
  private lastHash: string | null = null

  constructor(opts?: { auditPath?: string; onRetain?: (record: EvidenceRecord) => void }) {
    this.auditPath = opts?.auditPath ?? null
    this.onRetain = opts?.onRetain ?? null
  }

  retain<T extends Record<string, unknown>>(input: RetainEvidenceInput<T>): EvidenceRecord<T> {
    const limitations = [...(input.limitations ?? [])]
    const evidence_id = computeEvidenceId({
      tool: input.tool,
      artifact_class: input.artifact_class,
      parameters: input.parameters,
      analysis_profile: input.analysis_profile,
      normalized_result: input.normalized_result,
      coverage: input.coverage,
      limitations,
    })

    const record: EvidenceRecord<T> = {
      schema_version: 1,
      evidence_id,
      seq: this.ordered.length + 1,
      prev_hash: this.lastHash,
      recorded_at: input.recorded_at ?? new Date().toISOString(),
      tool: input.tool,
      artifact_class: input.artifact_class,
      parameters: input.parameters,
      analysis_profile: input.analysis_profile,
      normalized_result: input.normalized_result,
      raw_result: input.raw_result ?? null,
      coverage: input.coverage,
      limitations,
    }

    const line = canonicalJson(record)
    const lineHash = createHash("sha256").update(line).digest("hex")
    this.lastHash = lineHash
    this.records.set(record.evidence_id, record)
    this.ordered.push(record)

    if (this.auditPath) {
      mkdirSync(dirname(this.auditPath), { recursive: true })
      appendFileSync(this.auditPath, `${line}\n`, "utf8")
    }
    if (this.onRetain) {
      this.onRetain(record)
    }
    return record
  }

  has(evidenceId: string): boolean {
    return this.records.has(evidenceId)
  }

  get(evidenceId: string): EvidenceRecord | undefined {
    return this.records.get(evidenceId)
  }

  list(): EvidenceRecord[] {
    return [...this.ordered]
  }

  chainHeadHash(): string | null {
    return this.lastHash
  }

  resolve(source: EvidenceSource): EvidenceRecord {
    if ("kind" in source && source.kind === "retained-evidence") {
      const found = this.records.get(source.evidence_id)
      if (!found) {
        throw new VerdictMcpError(
          "evidence_integrity_mismatch",
          `Retained evidence '${source.evidence_id}' not found in current session ledger.`,
          {
            details: { reason: "missing", evidence_id: source.evidence_id },
            remediation: {
              action: "Import the exported evidence bundle or supply the complete inline Evidence record.",
            },
          },
        )
      }
      return found
    }

    if ("kind" in source && source.kind === "evidence-file") {
      if (!existsSync(source.path)) {
        throw new VerdictMcpError(
          "evidence_integrity_mismatch",
          `Evidence file not found: ${source.path}`,
          { details: { reason: "file_missing", path: source.path } },
        )
      }
      const parsed = JSON.parse(readFileSync(source.path, "utf8")) as EvidenceBundle | EvidenceRecord
      const candidate =
        "records" in parsed && Array.isArray(parsed.records)
          ? source.evidence_id
            ? parsed.records.find((r) => r.evidence_id === source.evidence_id)
            : parsed.records.length === 1
              ? parsed.records[0]
              : undefined
          : (parsed as EvidenceRecord)

      if (!candidate) {
        throw new VerdictMcpError(
          "evidence_integrity_mismatch",
          `Could not select a unique Evidence record from ${source.path}`,
          { details: { reason: "missing", path: source.path, evidence_id: source.evidence_id } },
        )
      }
      if (!verifyEvidenceDigest(candidate)) {
        throw new VerdictMcpError(
          "evidence_integrity_mismatch",
          `Evidence digest mismatch for '${candidate.evidence_id}' in ${source.path}`,
          { details: { reason: "digest_mismatch", evidence_id: candidate.evidence_id } },
        )
      }
      return candidate
    }

    const inline = source as EvidenceRecord
    if (!verifyEvidenceDigest(inline)) {
      throw new VerdictMcpError(
        "evidence_integrity_mismatch",
        `Inline Evidence record '${inline.evidence_id}' failed SHA-256 digest verification.`,
        { details: { reason: "digest_mismatch", evidence_id: inline.evidence_id } },
      )
    }
    return inline
  }

  summarize(record: EvidenceRecord): EvidenceSummary {
    const collections: Record<string, number> = {}
    const preview: Record<string, unknown> = {}

    for (const [k, v] of Object.entries(record.normalized_result)) {
      if (Array.isArray(v)) {
        collections[k] = v.length
        preview[k] = v.slice(0, 3)
      } else if (v === null || typeof v !== "object") {
        preview[k] = v
      }
    }

    return {
      parent_evidence_id: record.evidence_id,
      tool: record.tool,
      artifact_class: record.artifact_class,
      coverage: record.coverage,
      limitations: record.limitations,
      collections,
      preview,
    }
  }

  inspectView(source: EvidenceSource, view: AnalysisViewQuery): Record<string, unknown> {
    const parent = this.resolve(source)
    if (view.kind === "summary") {
      return {
        parent_evidence_id: parent.evidence_id,
        source_coverage: parent.coverage,
        summary: this.summarize(parent),
      }
    }

    const collectionName = view.collection
    if (!collectionName) {
      throw new VerdictMcpError("invalid_request", "view.collection is required when view.kind is 'collection'.", {
        recovery: { kind: "inspect_input_contract", operation: "inspect_analysis_view" },
      })
    }

    const rawCollection = parent.normalized_result[collectionName]
    if (!Array.isArray(rawCollection)) {
      throw new VerdictMcpError(
        "invalid_request",
        `Collection '${collectionName}' does not exist as an array on parent Evidence '${parent.evidence_id}'.`,
        {
          details: {
            available_collections: Object.keys(parent.normalized_result).filter((k) =>
              Array.isArray(parent.normalized_result[k]),
            ),
          },
          recovery: { kind: "inspect_input_contract", operation: "inspect_analysis_view" },
        },
      )
    }

    let indexed = rawCollection.map((item, source_index) => ({ source_index, item }))
    if (view.filter_key && view.filter_contains !== undefined) {
      const needle = view.filter_contains.toLowerCase()
      indexed = indexed.filter(({ item }) => {
        if (!item || typeof item !== "object") return false
        const val = (item as Record<string, unknown>)[view.filter_key!]
        return val !== undefined && String(val).toLowerCase().includes(needle)
      })
    }

    const offset = Math.max(0, view.offset ?? 0)
    const limit = Math.max(1, Math.min(250, view.limit ?? 32))
    const slice = indexed.slice(offset, offset + limit)

    const items = slice.map(({ source_index, item }) => {
      if (!view.fields || view.fields.length === 0 || !item || typeof item !== "object") {
        return { source_index, value: item }
      }
      const picked: Record<string, unknown> = { source_index }
      for (const f of view.fields) {
        picked[f] = (item as Record<string, unknown>)[f]
      }
      return picked
    })

    const nextOffset = offset + items.length < indexed.length ? offset + items.length : null
    return {
      parent_evidence_id: parent.evidence_id,
      collection: collectionName,
      source_coverage: parent.coverage,
      page_coverage: {
        matched_count: indexed.length,
        offset,
        returned_count: items.length,
        exhausted: nextOffset === null,
        next_offset: nextOffset,
      },
      limitations: parent.limitations,
      items,
    }
  }

  verifyAuditChain(): { ok: boolean; checked: number; error?: string } {
    let expectedPrev: string | null = null
    for (let i = 0; i < this.ordered.length; i++) {
      const rec = this.ordered[i]!
      if (rec.prev_hash !== expectedPrev) {
        return {
          ok: false,
          checked: i,
          error: `Audit chain broken at seq ${rec.seq}: expected prev_hash=${expectedPrev}, got ${rec.prev_hash}`,
        }
      }
      if (!verifyEvidenceDigest(rec)) {
        return {
          ok: false,
          checked: i,
          error: `Evidence digest mismatch at seq ${rec.seq} (${rec.evidence_id})`,
        }
      }
      expectedPrev = createHash("sha256").update(canonicalJson(rec)).digest("hex")
    }
    return { ok: true, checked: this.ordered.length }
  }

  exportBundle(outputPath?: string): EvidenceBundle {
    const records = this.list()
    const exported_at = new Date().toISOString()
    const bundle_id = `bndl_${createHash("sha256")
      .update(canonicalJson({ records: records.map((r) => r.evidence_id), head: this.lastHash }))
      .digest("hex")
      .slice(0, 24)}`
    const bundle: EvidenceBundle = {
      schema_version: 1,
      bundle_id,
      exported_at,
      record_count: records.length,
      chain_head_hash: this.lastHash,
      records,
    }
    if (outputPath) {
      mkdirSync(dirname(outputPath), { recursive: true })
      writeFileSync(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8")
    }
    return bundle
  }

  importBundle(bundle: EvidenceBundle): { imported: number } {
    if (bundle.schema_version !== 1 || !Array.isArray(bundle.records)) {
      throw new VerdictMcpError("invalid_request", "Unsupported or malformed evidence bundle.")
    }
    for (const rec of bundle.records) {
      if (!verifyEvidenceDigest(rec)) {
        throw new VerdictMcpError(
          "evidence_integrity_mismatch",
          `Bundle import aborted: record '${rec.evidence_id}' failed SHA-256 verification.`,
          { details: { reason: "digest_mismatch", evidence_id: rec.evidence_id } },
        )
      }
    }
    let imported = 0
    for (const rec of bundle.records) {
      if (!this.records.has(rec.evidence_id)) {
        this.records.set(rec.evidence_id, rec)
        this.ordered.push(rec)
        imported++
      }
    }
    return { imported }
  }
}
