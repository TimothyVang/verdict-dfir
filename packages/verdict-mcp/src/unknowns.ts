import { createHash } from "node:crypto"
import { VerdictMcpError } from "./evidence.js"
import { EvidenceLedger } from "./ledger.js"

export type UnknownStatus = "open" | "resolved" | "unresolvable"

export interface UnknownRecord {
  unknown_id: string
  revision: number
  question: string
  required_authority: string
  status: UnknownStatus
  supporting_evidence_ids: string[]
  contradicting_evidence_ids: string[]
  resolution_note?: string
  updated_at: string
}

export class UnknownsRegistry {
  private readonly items = new Map<string, UnknownRecord>()

  record(
    ledger: EvidenceLedger,
    input: {
      question: string
      required_authority: string
      supporting_evidence_ids?: string[]
      contradicting_evidence_ids?: string[]
    },
  ): UnknownRecord {
    const supporting = input.supporting_evidence_ids ?? []
    const contradicting = input.contradicting_evidence_ids ?? []
    for (const id of [...supporting, ...contradicting]) {
      if (!ledger.has(id)) {
        throw new VerdictMcpError(
          "citation_rejected",
          `Unknown references nonexistent evidence_id '${id}'.`,
          { details: { missing_evidence_id: id } },
        )
      }
    }

    const unknown_id = `unk_${createHash("sha256")
      .update(`${input.question}|${input.required_authority}|${this.items.size}`)
      .digest("hex")
      .slice(0, 16)}`

    const rec: UnknownRecord = {
      unknown_id,
      revision: 1,
      question: input.question,
      required_authority: input.required_authority,
      status: "open",
      supporting_evidence_ids: [...supporting],
      contradicting_evidence_ids: [...contradicting],
      updated_at: new Date().toISOString(),
    }
    this.items.set(unknown_id, rec)
    return rec
  }

  update(
    ledger: EvidenceLedger,
    input: {
      unknown_id: string
      expected_revision: number
      status?: UnknownStatus
      supporting_evidence_ids?: string[]
      contradicting_evidence_ids?: string[]
      resolution_note?: string
    },
  ): UnknownRecord {
    const existing = this.items.get(input.unknown_id)
    if (!existing) {
      throw new VerdictMcpError("invalid_request", `Unknown '${input.unknown_id}' not found.`)
    }
    if (existing.revision !== input.expected_revision) {
      throw new VerdictMcpError(
        "stale_revision",
        `Stale revision for '${input.unknown_id}': expected ${input.expected_revision}, current is ${existing.revision}.`,
        {
          details: { current_revision: existing.revision, expected_revision: input.expected_revision },
          remediation: { action: "Reread the unknown record and retry with the current revision." },
          recovery: { kind: "reread_revision", operation: "update_unknown" },
        },
      )
    }

    const supporting = input.supporting_evidence_ids ?? existing.supporting_evidence_ids
    const contradicting = input.contradicting_evidence_ids ?? existing.contradicting_evidence_ids
    for (const id of [...supporting, ...contradicting]) {
      if (!ledger.has(id)) {
        throw new VerdictMcpError(
          "citation_rejected",
          `Unknown update references nonexistent evidence_id '${id}'.`,
          { details: { missing_evidence_id: id } },
        )
      }
    }

    const nextStatus = input.status ?? existing.status
    if (nextStatus === "resolved" && supporting.length === 0) {
      throw new VerdictMcpError(
        "forensic_rule_violation",
        "Cannot resolve an unknown without at least one verified supporting evidence_id.",
        {
          remediation: { action: "Cite qualifying observed evidence_ids before marking status='resolved'." },
          recovery: { kind: "supply_corroboration", operation: "update_unknown" },
        },
      )
    }

    const updated: UnknownRecord = {
      ...existing,
      revision: existing.revision + 1,
      status: nextStatus,
      supporting_evidence_ids: [...supporting],
      contradicting_evidence_ids: [...contradicting],
      resolution_note: input.resolution_note ?? existing.resolution_note,
      updated_at: new Date().toISOString(),
    }
    this.items.set(updated.unknown_id, updated)
    return updated
  }

  list(): UnknownRecord[] {
    return [...this.items.values()]
  }

  openCount(): number {
    return this.list().filter((u) => u.status === "open").length
  }
}
