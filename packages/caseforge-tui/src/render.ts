import type { CaseView, CoverageRow, AuditRecord } from "./load.js"
import type { FindingCustody } from "@verdict/caseforge-sdk"
import type { RunEntry } from "./picker.js"

const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"
const DIM = "\x1b[2m"
const rgb = (r: number, g: number, b: number): string => `\x1b[38;2;${r};${g};${b}m`
const SEAFOAM = rgb(115, 217, 194)
const BUTTER = rgb(255, 215, 106)
const COBALT = rgb(120, 140, 255)
const CORAL = rgb(255, 98, 87)
const LILAC = rgb(184, 168, 255)

function tierColor(c?: string): string {
  const t = (c ?? "").toUpperCase()
  if (t === "CONFIRMED") return SEAFOAM
  if (t === "INFERRED") return BUTTER
  return COBALT
}
function verdictColor(v?: string): string {
  const w = (v ?? "").toUpperCase()
  if (w === "SUSPICIOUS") return CORAL
  if (w === "NO_EVIL") return SEAFOAM
  return BUTTER
}
function light(ok: boolean | undefined): string {
  if (ok === true) return `${SEAFOAM}●${RESET}`
  if (ok === false) return `${CORAL}●${RESET}`
  return `${DIM}○${RESET}`
}
function mark(b?: boolean): string {
  if (b === true) return `${SEAFOAM}✓${RESET}`
  if (b === false) return `${DIM}–${RESET}`
  return `${DIM}?${RESET}`
}
const NOT_PRODUCED = `${DIM}not produced by this run${RESET}`

export function renderHeader(v: CaseView): string {
  const verd = v.verdict?.verdict ?? "(no verdict.json)"
  return [
    `${LILAC}${BOLD}VERDICT · caseforge workbench${RESET}   ${DIM}read-only · presentation only${RESET}`,
    `${BOLD}${verdictColor(v.verdict?.verdict)}${verd}${RESET}   ${DIM}case ${v.verdict?.case_id ?? v.runDir}${RESET}`,
    `custody:  recorded ${light(v.recordedManifestOverall)} manifest_verify   |   re-verified now ${light(v.validation.custodyValid)} ${DIM}(${v.validation.status})${RESET}`,
    `${DIM}${v.validation.detail}${RESET}`,
  ].join("\n")
}

function custodyOf(report: CaseView["custody"], fid?: string): FindingCustody | undefined {
  if (!report || !fid) return undefined
  return report.findings.find((f) => f.finding_id === fid)
}

export function renderFindings(v: CaseView, selected?: number, focused = true): string {
  const focus = focused ? `${LILAC}▸${RESET} ` : ""
  const head = `${focus}${LILAC}${BOLD}FINDINGS${RESET}`
  const findings = v.verdict?.findings ?? []
  if (findings.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const rows = findings.map((f, i) => {
    const conf = (f.confidence ?? "?").toString()
    const tech = (f["mitre_technique"] as string | undefined) ?? (f["named_technique"] as string | undefined) ?? "unmapped"
    const desc = ((f.description ?? "") as string).slice(0, 64)
    const cust = custodyOf(v.custody, f.finding_id)
    const custStr = cust
      ? `${cust.cited ? SEAFOAM + "cited" : CORAL + "UNCITED"}${RESET} ${DIM}tool_call_id ${f.tool_call_id ?? "?"}${RESET}`
      : `${DIM}tool_call_id ${f.tool_call_id ?? "?"}${RESET}`
    const arrow = i === selected ? `${LILAC}▶${RESET}` : " "
    return [
      `${arrow} ${tierColor(conf)}●${RESET} ${BOLD}${tech}${RESET} ${DIM}${conf}${RESET}`,
      `      ${desc}`,
      `      ${custStr}`,
    ].join("\n")
  })
  return `${head}\n${rows.join("\n")}`
}

/** Full detail for one finding: complete (untruncated) description, custody
 * citation status, tool_call_id, output_sha256, and the matching audit.jsonl
 * record. Honest degradation: when a finding is absent (no verdict / index out
 * of range) or uncited, it shows a "not produced"/"not cited" state instead of
 * fabricating a tool_call_id or output hash. */
export function renderFindingDetail(v: CaseView, index: number): string {
  const head = `${LILAC}${BOLD}FINDING DETAIL${RESET}`
  const findings = v.verdict?.findings ?? []
  const f = findings[index]
  if (!f) return `${head}\n  ${NOT_PRODUCED}`

  const fid = f.finding_id ?? "?"
  const conf = (f.confidence ?? "?").toString()
  const tech = (f["mitre_technique"] as string | undefined) ?? (f["named_technique"] as string | undefined) ?? "unmapped"
  const desc = ((f.description ?? "") as string) || `${DIM}(no description)${RESET}`

  const tcid = typeof f.tool_call_id === "string" && f.tool_call_id.trim() !== "" ? f.tool_call_id : undefined
  const sha = typeof f["output_sha256"] === "string" && (f["output_sha256"] as string).trim() !== "" ? (f["output_sha256"] as string) : undefined
  const cust = custodyOf(v.custody, f.finding_id)

  const citeStatus = cust
    ? cust.cited
      ? `${SEAFOAM}cited${RESET}`
      : `${CORAL}not cited${RESET}`
    : tcid
      ? `${SEAFOAM}cited${RESET}`
      : `${CORAL}not cited${RESET}`
  const reason = cust && cust.reason ? ` ${DIM}— ${cust.reason}${RESET}` : ""

  const tcLine = tcid
    ? `${DIM}tool_call_id${RESET}  ${tcid}`
    : `${DIM}tool_call_id${RESET}  ${CORAL}not cited${RESET}`
  const shaLine = sha
    ? `${DIM}output_sha256${RESET} ${sha}`
    : `${DIM}output_sha256${RESET} ${NOT_PRODUCED}`

  const rec = tcid ? v.audit.find((r) => r.tool_call_id === tcid) : undefined
  const auditLine = rec
    ? `${DIM}audit record${RESET}  #${rec.seq ?? "?"} ${rec.kind ?? "?"} ${DIM}${rec.ts ?? ""}${RESET}`
    : `${DIM}audit record${RESET}  ${DIM}no matching audit.jsonl record${RESET}`

  return [
    head,
    `  ${tierColor(conf)}●${RESET} ${BOLD}${tech}${RESET} ${DIM}${conf}${RESET}  ${DIM}${fid}${RESET}`,
    `  ${desc}`,
    ``,
    `  custody  ${citeStatus}${reason}`,
    `  ${tcLine}`,
    `  ${shaLine}`,
    `  ${auditLine}`,
  ].join("\n")
}

export function renderCoverage(v: CaseView, selected?: number, focused = false): string {
  const focus = focused ? `${LILAC}▸${RESET} ` : ""
  const head = `${focus}${LILAC}${BOLD}COVERAGE${RESET}`
  if (v.coverage.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const rows = v.coverage.map((c: CoverageRow, i) => {
    const arrow = i === selected && focused ? `${LILAC}▶${RESET}` : " "
    return `${arrow} ${c.artifact_class.padEnd(14)} avail ${mark(c.available)}  attempted ${mark(c.attempted)}  parsed ${mark(c.parsed)}`
  })
  return `${head}\n${rows.join("\n")}`
}

/** Full detail for one coverage row. Honest degradation when missing. */
export function renderCoverageDetail(v: CaseView, index: number): string {
  const head = `${LILAC}${BOLD}COVERAGE DETAIL${RESET}`
  if (v.coverage.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const c = v.coverage[index]
  if (!c) return `${head}\n  ${NOT_PRODUCED}`
  const cls = c.artifact_class || "?"
  const yn = (b?: boolean): string =>
    b === true ? `${SEAFOAM}yes${RESET}` : b === false ? `${CORAL}no${RESET}` : `${DIM}unknown${RESET}`
  return [
    head,
    `  class      ${BOLD}${cls}${RESET}`,
    `  available  ${yn(c.available)}`,
    `  attempted  ${yn(c.attempted)}`,
    `  parsed     ${yn(c.parsed)}`,
    `  supported  ${yn(c.supported)}`,
  ].join("\n")
}

export function renderAudit(v: CaseView): string {
  const head = `${LILAC}${BOLD}AUDIT TAIL${RESET}`
  if (v.audit.length === 0) return `${head}\n  ${DIM}no audit.jsonl records${RESET}`
  const chain = v.chainOk ? `${SEAFOAM}chain linkage OK${RESET}` : `${CORAL}chain linkage BROKEN${RESET}`
  const tail = v.audit
    .slice(-5)
    .map((r: AuditRecord) => `  ${DIM}#${r.seq ?? "?"}${RESET} ${(r.kind ?? "?").padEnd(20)} ${DIM}${r.ts ?? ""}${RESET}`)
  return `${head}  ${DIM}${v.audit.length} records ·${RESET} ${chain}\n${tail.join("\n")}`
}

export function renderTimeline(v: CaseView, selected?: number, focused = false): string {
  const focus = focused ? `${LILAC}▸${RESET} ` : ""
  const head = `${focus}${LILAC}${BOLD}TIMELINE${RESET}`
  if (v.timeline.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const rows = v.timeline.slice(0, 8).map((e, i) => {
    const arrow = i === selected && focused ? `${LILAC}▶${RESET}` : " "
    return `${arrow} ${tierColor(e.confidence)}●${RESET} ${DIM}${e.ts ?? "?"}${RESET} ${BOLD}${e.technique ?? "-"}${RESET} ${(e.summary ?? "").slice(0, 48)}`
  })
  const more = v.timeline.length > 8 ? `\n  ${DIM}… ${v.timeline.length - 8} more events${RESET}` : ""
  return `${head}  ${DIM}${v.timeline.length} events${RESET}\n${rows.join("\n")}${more}`
}

/** Full detail for one timeline event. Honest degradation when the index is
 * out of range or the timeline was not produced. */
export function renderTimelineDetail(v: CaseView, index: number): string {
  const head = `${LILAC}${BOLD}TIMELINE DETAIL${RESET}`
  if (v.timeline.length === 0) return `${head}\n  ${NOT_PRODUCED}`
  const e = v.timeline[index]
  if (!e) return `${head}\n  ${NOT_PRODUCED}`
  const conf = e.confidence ?? "?"
  const tech = e.technique ?? "unmapped"
  const ts = e.ts ?? `${DIM}(no timestamp)${RESET}`
  const sig = e.significance ?? `${DIM}not produced${RESET}`
  const summary = (e.summary && e.summary.trim() !== "" ? e.summary : undefined) ?? `${DIM}(no summary)${RESET}`
  return [
    head,
    `  ${tierColor(conf)}●${RESET} ${BOLD}${tech}${RESET} ${DIM}${conf}${RESET}`,
    `  time         ${ts}`,
    `  significance ${sig}`,
    `  summary`,
    `    ${summary}`,
  ].join("\n")
}

export function renderPicker(entries: RunEntry[], cursor?: number): string {
  const head = `${LILAC}${BOLD}CASES${RESET}`
  if (entries.length === 0) return `${head}\n  ${DIM}no run directories found${RESET}`
  const rows = entries.map((e, i) => {
    const l = e.status === "complete" && e.custodyValid ? SEAFOAM : e.status === "custody-invalid" ? CORAL : BUTTER
    const sel = i === cursor
    const arrow = sel ? `${LILAC}▶${RESET}` : " "
    const label = sel ? `${BOLD}${e.status.padEnd(16)}${RESET}` : e.status.padEnd(16)
    const warn = e.chainOk ? "" : ` ${CORAL}⚠ chain${RESET}`
    return `${arrow} ${DIM}${String(i + 1).padStart(2)}${RESET} ${l}●${RESET} ${label} ${DIM}${e.dir}${RESET}${warn}`
  })
  return `${head}  ${DIM}${entries.length}${RESET}\n${rows.join("\n")}`
}

export function renderFooter(
  view: "picker" | "case" | "detail" | "timeline-detail" | "coverage-detail",
): string {
  if (view === "picker") return `${DIM}↑↓ move · enter open · q quit${RESET}`
  if (view === "case")
    return `${DIM}tab panel (findings/timeline/coverage) · ↑↓ move · enter detail · q back${RESET}`
  return `${DIM}q back · ctrl-c quit${RESET}`
}

export function renderCustodyBanner(v: CaseView): string {
  if (v.validation.custodyValid && v.chainOk) return ""
  const msgs: string[] = []
  if (!v.validation.custodyValid) msgs.push("manifest seal not verified")
  if (!v.chainOk && v.audit.length > 0) msgs.push("audit chain linkage broken")
  return `${CORAL}${BOLD}⚠ CUSTODY NOT VERIFIED${RESET} ${DIM}— ${msgs.join("; ")}; findings below are not backed by valid custody${RESET}`
}

export function renderScreen(
  v: CaseView,
  selectedFinding?: number,
  selectedTimeline?: number,
  panel: "findings" | "timeline" | "coverage" = "findings",
  selectedCoverage?: number,
): string {
  return [
    renderHeader(v),
    renderCustodyBanner(v),
    renderFindings(v, selectedFinding, panel === "findings"),
    renderTimeline(v, selectedTimeline, panel === "timeline"),
    renderCoverage(v, selectedCoverage, panel === "coverage"),
    renderAudit(v),
  ]
    .filter((s) => s.length > 0)
    .join("\n\n")
}
