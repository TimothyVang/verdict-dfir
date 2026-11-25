import { createHash } from "node:crypto"
import { ArtifactClass, isValidIsoTimestamp, VerdictMcpError } from "./evidence.js"
import { EvidenceLedger } from "./ledger.js"
import { UnknownsRegistry } from "./unknowns.js"

export type FindingStatus = "proposed" | "confirmed" | "inferred" | "refuted" | "uncertain"
export type VerdictWord = "SUSPICIOUS" | "INDETERMINATE" | "NO_EVIL"

export interface ChallengeRecord {
  challenged_at: string
  challenger: string
  counter_hypothesis: string
  counter_evidence_refs: string[]
  outcome: FindingStatus
  notes: string
}

export interface ForensicFinding {
  finding_id: string
  title: string
  claim: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  status: FindingStatus
  mitre_techniques: string[]
  evidence_refs: string[]
  artifact_classes: ArtifactClass[]
  event_timestamp: string | null
  timestamp_warning?: string
  caveats_acknowledged: string[]
  challenges: ChallengeRecord[]
  recorded_at: string
}

export interface RecordFindingInput {
  title: string
  claim: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  status?: FindingStatus
  mitre_techniques?: string[]
  evidence_refs: string[]
  event_timestamp?: string | null
  caveats_acknowledged?: string[]
  requires_corroboration?: boolean
}

export class FindingsStore {
  private readonly findings = new Map<string, ForensicFinding>()

  record(ledger: EvidenceLedger, input: RecordFindingInput): ForensicFinding {
    if (!Array.isArray(input.evidence_refs) || input.evidence_refs.length === 0) {
      throw new VerdictMcpError(
        "citation_rejected",
        "Every forensic finding must cite at least one verified evidence_id in evidence_refs.",
        {
          remediation: { action: "Run a forensic tool and cite its returned evidence_id." },
          recovery: { kind: "supply_corroboration", operation: "record_finding" },
        },
      )
    }

    const citedRecords = input.evidence_refs.map((id) => {
      const rec = ledger.get(id)
      if (!rec) {
        throw new VerdictMcpError(
          "citation_rejected",
          `Fabricated or unknown evidence citation '${id}' rejected at API boundary.`,
          {
            details: { missing_evidence_id: id },
            remediation: { action: "Cite only evidence_ids recorded in the append-only session ledger." },
            recovery: { kind: "supply_corroboration", operation: "record_finding" },
          },
        )
      }
      return rec
    })

    const artifactClasses = [...new Set(citedRecords.map((r) => r.artifact_class))]
    const caveats = [...(input.caveats_acknowledged ?? [])]
    const requestedStatus: FindingStatus = input.status ?? "proposed"

    // VERDICT schema rule: Amcache citation requires explicit LastModified != execution caveat
    const citesAmcache = citedRecords.some((r) => /amcache/i.test(r.tool) || /amcache/i.test(JSON.stringify(r.parameters)))
    if (citesAmcache && requestedStatus === "confirmed") {
      const acknowledged = caveats.some((c) => /amcache|lastmodified|existence|not execution/i.test(c))
      if (!acknowledged) {
        throw new VerdictMcpError(
          "forensic_rule_violation",
          "Amcache proves file presence/LastModified metadata, not execution. Acknowledge the Amcache caveat in caveats_acknowledged before confirming.",
          {
            details: { rule: "amcache_caveat_required" },
            remediation: {
              action: "Add 'Amcache LastModified does not prove execution' to caveats_acknowledged or corroborate with execution artifacts (Prefetch/EVTX/memory).",
            },
            recovery: { kind: "supply_corroboration", operation: "record_finding" },
          },
        )
      }
    }

    // VERDICT schema rule: Confirmed findings require >= 2 distinct artifact classes unless explicitly opted out
    const requireCorroboration = input.requires_corroboration ?? true
    if (requestedStatus === "confirmed" && requireCorroboration && artifactClasses.length < 2) {
      throw new VerdictMcpError(
        "forensic_rule_violation",
        `Cannot mark finding as 'confirmed' with only ${artifactClasses.length} artifact class (${artifactClasses.join(", ")}). Corroborate across >= 2 distinct artifact classes or record as 'inferred'.`,
        {
          details: { artifact_classes: artifactClasses, required_classes: 2 },
          remediation: {
            action: "Corroborate with a second artifact class (e.g., EVTX + Disk/Registry/Memory/Network) or submit with status='inferred'.",
          },
          recovery: { kind: "supply_corroboration", operation: "record_finding" },
        },
      )
    }

    // Mulder rule: validate ISO-8601 timestamps; auto-nullify fabricated/malformed ones
    let eventTimestamp: string | null = null
    let timestampWarning: string | undefined
    if (input.event_timestamp) {
      if (isValidIsoTimestamp(input.event_timestamp)) {
        eventTimestamp = input.event_timestamp
      } else {
        eventTimestamp = null
        timestampWarning = `Malformed non-ISO-8601 timestamp '${input.event_timestamp}' auto-nullified at API boundary.`
      }
    }

    const finding_id = `fnd_${createHash("sha256")
      .update(`${input.title}|${input.evidence_refs.join(",")}|${this.findings.size}`)
      .digest("hex")
      .slice(0, 16)}`

    const finding: ForensicFinding = {
      finding_id,
      title: input.title,
      claim: input.claim,
      severity: input.severity,
      status: requestedStatus,
      mitre_techniques: [...(input.mitre_techniques ?? [])],
      evidence_refs: [...input.evidence_refs],
      artifact_classes: artifactClasses,
      event_timestamp: eventTimestamp,
      ...(timestampWarning ? { timestamp_warning: timestampWarning } : {}),
      caveats_acknowledged: caveats,
      challenges: [],
      recorded_at: new Date().toISOString(),
    }

    this.findings.set(finding_id, finding)
    return finding
  }

  challenge(
    ledger: EvidenceLedger,
    input: {
      finding_id: string
      challenger: string
      counter_hypothesis: string
      counter_evidence_refs?: string[]
      outcome: FindingStatus
      notes: string
    },
  ): ForensicFinding {
    const existing = this.findings.get(input.finding_id)
    if (!existing) {
      throw new VerdictMcpError("invalid_request", `Finding '${input.finding_id}' not found.`)
    }
    const counterRefs = input.counter_evidence_refs ?? []
    for (const id of counterRefs) {
      if (!ledger.has(id)) {
        throw new VerdictMcpError(
          "citation_rejected",
          `Challenge cites nonexistent counter evidence_id '${id}'.`,
          { details: { missing_evidence_id: id } },
        )
      }
    }
    const challenge: ChallengeRecord = {
      challenged_at: new Date().toISOString(),
      challenger: input.challenger,
      counter_hypothesis: input.counter_hypothesis,
      counter_evidence_refs: [...counterRefs],
      outcome: input.outcome,
      notes: input.notes,
    }
    const updated: ForensicFinding = {
      ...existing,
      status: input.outcome,
      challenges: [...existing.challenges, challenge],
    }
    this.findings.set(updated.finding_id, updated)
    return updated
  }

  list(): ForensicFinding[] {
    return [...this.findings.values()]
  }

  computeCaseVerdict(ledger: EvidenceLedger, unknowns: UnknownsRegistry): {
    verdict: VerdictWord
    basis: string
    confirmed_count: number
    inferred_count: number
    refuted_count: number
    open_unknowns: number
    audit_chain_ok: boolean
  } {
    const all = this.list()
    const confirmed = all.filter((f) => f.status === "confirmed")
    const inferred = all.filter((f) => f.status === "inferred")
    const refuted = all.filter((f) => f.status === "refuted")
    const openUnknowns = unknowns.openCount()
    const chain = ledger.verifyAuditChain()
    const records = ledger.list()

    const hasSuspicious = confirmed.some((f) => f.severity !== "info") || inferred.some((f) => f.severity === "critical" || f.severity === "high")
    const anyIncompleteCoverage = records.some((r) => r.coverage.status !== "complete")

    let verdict: VerdictWord
    let basis: string

    if (!chain.ok) {
      verdict = "INDETERMINATE"
      basis = `Audit chain integrity failed: ${chain.error}`
    } else if (hasSuspicious) {
      verdict = "SUSPICIOUS"
      basis = `${confirmed.length} confirmed and ${inferred.length} inferred reportable finding(s) backed by verified evidence.`
    } else if (records.length === 0 || openUnknowns > 0 || anyIncompleteCoverage) {
      verdict = "INDETERMINATE"
      basis = `Coverage is bounded or unresolved (${records.length} evidence records, ${openUnknowns} open unknowns, incomplete_coverage=${anyIncompleteCoverage}); cannot issue NO_EVIL.`
    } else {
      verdict = "NO_EVIL"
      basis = `No reportable findings across ${records.length} completely examined evidence record(s). Scoped strictly to examined artifacts.`
    }

    return {
      verdict,
      basis,
      confirmed_count: confirmed.length,
      inferred_count: inferred.length,
      refuted_count: refuted.length,
      open_unknowns: openUnknowns,
      audit_chain_ok: chain.ok,
    }
  }
}
