/**
 * VERDICT verdict.json ingestion + findings custody check.
 *
 * The VERDICT toolkit emits a rich verdict.json whose findings each carry a
 * `tool_call_id` (required — its verifier vetoes if absent) and the verifier's
 * replay result (`replay_matched`). caseforge ingests those real findings and
 * enforces the default security rule independently of the LLM: every reported
 * finding must be cited (tool_call_id or a hash-chained audit record) and, when
 * the verifier replayed it, the replay must have matched. Uncited or
 * replay-failed findings are flagged.
 */
import { createHash } from "node:crypto"
import { readFile } from "node:fs/promises"
import { join } from "node:path"

export interface VerdictFinding {
  finding_id?: string
  tool_call_id?: string
  confidence?: string
  description?: string
  verdict?: string
  replay_matched?: boolean
  replay_record_sha256?: string
  replay_actual_sha256?: string
  citation_kind?: string
  audit_seq?: number
  audit_record_sha256?: string
  [k: string]: unknown
}

export interface VerdictDoc {
  verdict?: string
  case_id?: string
  findings?: VerdictFinding[]
  [k: string]: unknown
}

/** Read and parse a run's verdict.json (undefined if absent/unreadable). */
export async function readVerdict(runDir: string): Promise<VerdictDoc | undefined> {
  try {
    return JSON.parse(await readFile(join(runDir, "verdict.json"), "utf8")) as VerdictDoc
  } catch {
    return undefined
  }
}

export interface FindingCustody {
  finding_id: string
  cited: boolean
  citation: "tool_call" | "audit_record" | "none"
  replayVerified: boolean | null // null = verifier did not replay this finding
  reason: string
}

export interface FindingsCustodyReport {
  total: number
  cited: number
  uncited: number
  replayVerified: number
  replayFailed: number
  ok: boolean
  findings: FindingCustody[]
}

/** The three scoped verdict words to recover from the agent's messages. */
const VERDICT_WORDS = ["SUSPICIOUS", "INDETERMINATE", "NO_EVIL"] as const

export interface AssembledVerdict extends VerdictDoc {
  findings: VerdictFinding[]
  evidence_path?: string
  case_completeness: { generated_by_caseforge: true; note: string }
  generated_by: "caseforge"
  generated_at: string
}

type AuditLogEntry = {
  kind?: string
  seq?: number
  line_index: number
  line_sha256: string
  payload?: Record<string, unknown>
}

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex")
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value))
}

function hasToolCitation(f: VerdictFinding): boolean {
  return typeof f.tool_call_id === "string" && f.tool_call_id.trim() !== ""
}

function hasAuditRecordCitation(f: VerdictFinding): boolean {
  return (
    f.citation_kind === "audit_record" &&
    typeof f.audit_seq === "number" &&
    typeof f.audit_record_sha256 === "string" &&
    /^[a-f0-9]{64}$/i.test(f.audit_record_sha256)
  )
}

function citationKind(f: VerdictFinding): FindingCustody["citation"] {
  if (hasToolCitation(f)) return "tool_call"
  if (hasAuditRecordCitation(f)) return "audit_record"
  return "none"
}

function acceptedCitation(f: VerdictFinding): boolean {
  return citationKind(f) !== "none"
}

function pushEvtx1102Finding(
  findings: VerdictFinding[],
  entry: AuditLogEntry,
  args: Record<string, unknown>,
  toolName: string,
  rawRow: Record<string, unknown>,
  rowIndex: number,
): void {
  const eventId = Number(rawRow.event_id)
  if (eventId !== 1102) return
  const recordId = rawRow.record_id
  const ts = typeof rawRow.ts === "string" ? rawRow.ts : undefined
  const channel = typeof rawRow.channel === "string" ? rawRow.channel : "Security"
  const seq = entry.seq ?? entry.line_index
  const recordSuffix = typeof recordId === "string" || typeof recordId === "number" ? String(recordId) : String(rowIndex + 1)
  const when = ts ? ` at ${ts}` : ""
  findings.push({
    finding_id: `evtx-1102-${seq}-${recordSuffix}`,
    verdict: "SUSPICIOUS",
    confidence: "INFERRED",
    description: `${channel} audit log cleared (Event ID 1102)${when}; record_id=${recordSuffix}.`,
    citation_kind: "audit_record",
    audit_seq: seq,
    audit_record_sha256: entry.line_sha256,
    tool_name: toolName,
    case_id: typeof args.case_id === "string" ? args.case_id : undefined,
    evidence_path: typeof args.evtx_path === "string" ? args.evtx_path : undefined,
    event_id: eventId,
    channel,
    record_id: recordId,
    ts,
  })
}

function deriveEvtxFindings(entries: AuditLogEntry[]): VerdictFinding[] {
  const findings: VerdictFinding[] = []
  for (const entry of entries) {
    const payload = entry.payload
    const toolName = typeof payload?.tool_name === "string" ? payload.tool_name : ""
    if (!toolName.includes("evtx_query")) continue

    const args = isRecord(payload?.arguments) ? payload.arguments : {}
    // Prefer structured output_summary.rows; also accept payload.output.rows.
    const summaryObj = isRecord(payload?.output_summary) ? payload.output_summary : undefined
    const outputObj = isRecord(payload?.output) ? payload.output : undefined
    const rows = Array.isArray(summaryObj?.rows)
      ? summaryObj.rows
      : Array.isArray(outputObj?.rows)
        ? outputObj.rows
        : []
    rows.forEach((rawRow, rowIndex) => {
      if (!isRecord(rawRow)) return
      pushEvtx1102Finding(findings, entry, args, toolName, rawRow, rowIndex)
    })
  }
  return findings
}

/**
 * Best-effort assemble a verdict.json from a sealed run's audit.jsonl.
 *
 * The toolkit's authoritative verdict.json is produced only by its own
 * auto-runner. For agent-driven runs, caseforge reconstructs a DERIVED report
 * from the hash-chained audit log: case metadata from `case_open`, findings
 * merged by `finding_id` across the chain (keeping only CITED findings so the
 * report never fails its own custody check), and the scoped verdict word from
 * the agent's final messages. Clearly marked as caseforge-derived, not
 * authoritative.
 */
export async function assembleVerdictFromAudit(runDir: string): Promise<AssembledVerdict | undefined> {
  let text: string
  try {
    text = await readFile(join(runDir, "audit.jsonl"), "utf8")
  } catch {
    return undefined
  }
  const entries: AuditLogEntry[] = []
  for (const [lineIndex, line] of text.split("\n").entries()) {
    const l = line.trim()
    if (!l) continue
    try {
      const parsed = JSON.parse(l) as { kind?: string; seq?: unknown; payload?: unknown }
      entries.push({
        kind: parsed.kind,
        seq: typeof parsed.seq === "number" ? parsed.seq : undefined,
        line_index: lineIndex,
        line_sha256: sha256(l),
        payload: isRecord(parsed.payload) ? parsed.payload : undefined,
      })
    } catch {
      /* skip malformed line */
    }
  }

  // Case metadata from case_open.
  let case_id: string | undefined
  let evidence_path: string | undefined
  for (const e of entries) {
    const out = isRecord(e.payload?.output) ? e.payload.output : undefined
    const args = isRecord(e.payload?.arguments) ? e.payload.arguments : undefined
    if (e.payload?.tool_name === "case_open") {
      case_id = (out?.id as string) ?? (out?.case_id as string) ?? case_id
      evidence_path = (out?.evidence_path as string) ?? (args?.image_path as string) ?? evidence_path
    }
    case_id = (args?.case_id as string) ?? case_id
    evidence_path = (args?.evtx_path as string) ?? evidence_path
  }

  // Merge findings by finding_id across the whole chain (partial + rich copies).
  const merged = new Map<string, VerdictFinding>()
  const walk = (o: unknown): void => {
    if (!o || typeof o !== "object") return
    if (Array.isArray(o)) {
      o.forEach(walk)
      return
    }
    const r = o as Record<string, unknown>
    if (typeof r.finding_id === "string") {
      const k = r.finding_id
      const p = merged.get(k) ?? { finding_id: k }
      merged.set(k, {
        finding_id: k,
        tool_call_id: p.tool_call_id ?? (r.tool_call_id as string) ?? undefined,
        confidence: p.confidence ?? (r.confidence as string) ?? undefined,
        description: p.description ?? (r.description as string) ?? undefined,
        replay_matched: p.replay_matched ?? (r.replay_matched as boolean) ?? undefined,
        replay_record_sha256:
          p.replay_record_sha256 ?? (r.replay_record_sha256 as string) ?? (r.output_sha256 as string) ?? undefined,
        citation_kind: p.citation_kind ?? (r.citation_kind as string) ?? undefined,
        audit_seq: p.audit_seq ?? (r.audit_seq as number) ?? undefined,
        audit_record_sha256: p.audit_record_sha256 ?? (r.audit_record_sha256 as string) ?? undefined,
      })
    }
    for (const v of Object.values(r)) walk(v)
  }
  for (const e of entries) walk(e.payload)
  for (const f of deriveEvtxFindings(entries)) {
    if (!merged.has(f.finding_id!)) merged.set(f.finding_id!, f)
  }
  const findings = [...merged.values()].filter(acceptedCitation)

  // Scoped verdict word — last occurrence in the agent's messages.
  const msgs = entries.filter((e) => e.kind === "agent_message").map((e) => JSON.stringify(e.payload))
  let verdict: string | undefined
  for (let i = msgs.length - 1; i >= 0 && !verdict; i--) {
    verdict = VERDICT_WORDS.find((w) => msgs[i]!.includes(w))
  }
  if (!verdict) verdict = findings.some((f) => f.verdict === "SUSPICIOUS") ? "SUSPICIOUS" : findings.length ? "INDETERMINATE" : "NO_EVIL"

  return {
    case_id,
    evidence_path,
    verdict,
    findings,
    case_completeness: {
      generated_by_caseforge: true,
      note: "Derived from audit.jsonl by caseforge; not the toolkit's authoritative verdict.json.",
    },
    generated_by: "caseforge",
    generated_at: new Date().toISOString(),
  }
}

/** A finding is anchored (must be tool-cited) unless it is a HYPOTHESIS. */
function isAnchored(f: VerdictFinding): boolean {
  const c = (f.confidence ?? "").toUpperCase()
  return c === "CONFIRMED" || c === "INFERRED"
}

/**
 * Verify the custody of every finding in a run's verdict.json using the
 * toolkit's own signals. `ok` is true only when no anchored finding is uncited
 * and no replayed finding failed its replay.
 */
export function checkFindingsCustody(doc: VerdictDoc | undefined): FindingsCustodyReport {
  const findings = doc?.findings ?? []
  const results: FindingCustody[] = findings.map((f, i) => {
    const id = f.finding_id ?? `#${i}`
    const citation = citationKind(f)
    const cited = citation !== "none"
    const replayVerified = typeof f.replay_matched === "boolean" ? f.replay_matched : null
    let reason = "ok"
    if (isAnchored(f) && !cited) reason = "anchored finding is uncited (no tool_call_id or audit_record citation) — vetoed"
    else if (replayVerified === false) reason = "verifier replay did not match — custody failed"
    else if (!cited) reason = "unanchored (hypothesis) — no citation required"
    return { finding_id: id, cited, citation, replayVerified, reason }
  })
  const uncitedAnchored = results.some((r, i) => isAnchored(findings[i]!) && !r.cited)
  const replayFailed = results.some((r) => r.replayVerified === false)
  return {
    total: results.length,
    cited: results.filter((r) => r.cited).length,
    uncited: results.filter((r) => !r.cited).length,
    replayVerified: results.filter((r) => r.replayVerified === true).length,
    replayFailed: results.filter((r) => r.replayVerified === false).length,
    ok: !uncitedAnchored && !replayFailed,
    findings: results,
  }
}
