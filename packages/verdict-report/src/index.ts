import { createHash } from "node:crypto"
import { mkdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import type { EvidenceBundle, ForensicFinding, UnknownRecord, VerdictWord } from "@verdict/mcp"

export interface CaseReportInput {
  case_id: string
  verdict: VerdictWord
  basis: string
  audit_chain_ok: boolean
  bundle: EvidenceBundle
  findings: ForensicFinding[]
  unknowns: UnknownRecord[]
}

function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
}

function buildEvidenceChainSvg(input: CaseReportInput): string {
  const records = input.bundle.records.slice(0, 8)
  const findings = input.findings.slice(0, 8)
  const height = Math.max(160, Math.max(records.length, findings.length, 1) * 46 + 40)
  const recCoords = new Map<string, { x: number; y: number }>()

  const recNodes = records
    .map((r, i) => {
      const y = 30 + i * 44
      recCoords.set(r.evidence_id, { x: 260, y: y + 16 })
      return `<rect x="20" y="${y}" width="240" height="32" rx="6" fill="#1e293b" stroke="#475569"/>
      <text x="30" y="${y + 20}" fill="#e2e8f0" font-size="11" font-family="monospace">${esc(r.tool)} (${esc(r.artifact_class)})</text>`
    })
    .join("\n")

  const edges: string[] = []
  const fndNodes = findings
    .map((f, i) => {
      const y = 30 + i * 44
      const fill = f.status === "confirmed" ? "#7f1d1d" : f.status === "refuted" ? "#1e293b" : "#78350f"
      const stroke = f.status === "confirmed" ? "#ef4444" : f.status === "refuted" ? "#64748b" : "#f59e0b"
      for (const ref of f.evidence_refs) {
        const src = recCoords.get(ref)
        if (src) {
          edges.push(
            `<line x1="${src.x}" y1="${src.y}" x2="460" y2="${y + 16}" stroke="#64748b" stroke-width="1.5" stroke-dasharray="4 2"/>`,
          )
        }
      }
      return `<rect x="460" y="${y}" width="280" height="32" rx="6" fill="${fill}" stroke="${stroke}"/>
      <text x="470" y="${y + 20}" fill="#f8fafc" font-size="11" font-family="sans-serif">${esc(f.title.slice(0, 34))} [${esc(f.status)}]</text>`
    })
    .join("\n")

  return `<svg viewBox="0 0 760 ${height}" width="100%" style="max-width:760px;background:#0f172a;border-radius:8px;border:1px solid #334155">
  ${edges.join("\n")}
  ${recNodes}
  ${fndNodes}
</svg>`
}

export function generateHtmlReport(input: CaseReportInput): string {
  const verdictColor =
    input.verdict === "SUSPICIOUS" ? "#ef4444" : input.verdict === "NO_EVIL" ? "#10b981" : "#f59e0b"

  const findingsRows =
    input.findings.length === 0
      ? `<tr><td colspan="6" style="color:#94a3b8">No findings recorded.</td></tr>`
      : input.findings
          .map(
            (f) => `<tr>
            <td><strong>${esc(f.title)}</strong><br><small>${esc(f.claim)}</small></td>
            <td><span class="pill">${esc(f.severity)}</span></td>
            <td><span class="pill">${esc(f.status)}</span></td>
            <td><code>${esc(f.mitre_techniques.join(", ") || "—")}</code></td>
            <td><code>${esc(f.evidence_refs.join(", "))}</code></td>
            <td>${f.challenges.length} challenge(s)</td>
          </tr>`,
          )
          .join("\n")

  const timelineRows = input.bundle.records
    .map(
      (r) => `<tr>
      <td><code>#${r.seq}</code></td>
      <td><code>${esc(r.recorded_at)}</code></td>
      <td><code>${esc(r.tool)}</code></td>
      <td>${esc(r.artifact_class)}</td>
      <td>${esc(r.coverage.status)}</td>
      <td><code>${esc(r.evidence_id)}</code></td>
    </tr>`,
    )
    .join("\n")

  const unknownRows =
    input.unknowns.length === 0
      ? `<tr><td colspan="4" style="color:#94a3b8">No unknowns recorded.</td></tr>`
      : input.unknowns
          .map(
            (u) => `<tr>
            <td>${esc(u.question)}</td>
            <td>${esc(u.required_authority)}</td>
            <td><span class="pill">${esc(u.status)}</span></td>
            <td>rev ${u.revision}</td>
          </tr>`,
          )
          .join("\n")

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VERDICT Case Report — ${esc(input.case_id)}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #020617; color: #e2e8f0; margin: 0; padding: 24px; line-height: 1.5; }
  .wrap { max-width: 1100px; margin: 0 auto; }
  .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 10px; padding: 18px 20px; margin-bottom: 18px; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; font-weight: 700; color: #fff; background: ${verdictColor}; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 6px; background: #1e293b; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  th { color: #94a3b8; font-weight: 600; }
  code { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; color: #93c5fd; }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1 style="margin:0 0 8px">VERDICT Forensic Report — ${esc(input.case_id)}</h1>
    <p><span class="badge">${esc(input.verdict)}</span> &nbsp; Audit Chain: <strong>${input.audit_chain_ok ? "VERIFIED" : "BROKEN"}</strong> &nbsp; Bundle: <code>${esc(input.bundle.bundle_id)}</code></p>
    <p style="color:#cbd5e1">${esc(input.basis)}</p>
  </div>

  <div class="card">
    <h2>Evidence Chain Graph (Deterministic)</h2>
    ${buildEvidenceChainSvg(input)}
  </div>

  <div class="card">
    <h2>Findings &amp; Skeptic Review (${input.findings.length})</h2>
    <table>
      <thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>MITRE</th><th>Cited Evidence</th><th>Skeptic</th></tr></thead>
      <tbody>${findingsRows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Open &amp; Resolved Unknowns (${input.unknowns.length})</h2>
    <table>
      <thead><tr><th>Question</th><th>Required Authority</th><th>Status</th><th>Rev</th></tr></thead>
      <tbody>${unknownRows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Hash-Chained Audit Super-Timeline (${input.bundle.records.length} records)</h2>
    <table>
      <thead><tr><th>Seq</th><th>Recorded At</th><th>Tool</th><th>Class</th><th>Coverage</th><th>Evidence ID</th></tr></thead>
      <tbody>${timelineRows}</tbody>
    </table>
  </div>
</div>
</body>
</html>
`
}

export function generateStixBundle(input: CaseReportInput): Record<string, unknown> {
  const now = new Date().toISOString()
  const objects = input.findings.map((f) => {
    const idHash = createHash("sha256").update(f.finding_id).digest("hex").slice(0, 32)
    const uuid = `${idHash.slice(0, 8)}-${idHash.slice(8, 12)}-4${idHash.slice(13, 16)}-8${idHash.slice(17, 20)}-${idHash.slice(20, 32)}`
    return {
      type: "report",
      spec_version: "2.1",
      id: `report--${uuid}`,
      created: f.recorded_at || now,
      modified: now,
      name: f.title,
      description: `${f.claim} (status=${f.status}, refs=${f.evidence_refs.join(",")})`,
      report_types: ["threat-report"],
      published: f.recorded_at || now,
      labels: [f.severity, f.status, ...f.mitre_techniques],
      object_refs: [],
    }
  })

  return {
    type: "bundle",
    id: `bundle--00000000-0000-4000-8000-${createHash("sha256").update(input.case_id).digest("hex").slice(0, 12)}`,
    objects,
  }
}

export function generateAttackNavigatorLayer(input: CaseReportInput): Record<string, unknown> {
  const techniqueCounts = new Map<string, { score: number; comments: string[] }>()
  for (const f of input.findings) {
    if (f.status === "refuted") continue
    for (const tech of f.mitre_techniques) {
      const prev = techniqueCounts.get(tech) ?? { score: 0, comments: [] }
      prev.score += f.status === "confirmed" ? 100 : 50
      prev.comments.push(`${f.title} (${f.status})`)
      techniqueCounts.set(tech, prev)
    }
  }

  return {
    name: `VERDICT — ${input.case_id}`,
    versions: { attack: "15", navigator: "4.9.5", layer: "4.5" },
    domain: "enterprise-attack",
    description: `VERDICT case ${input.case_id} (${input.verdict})`,
    techniques: [...techniqueCounts.entries()].map(([techniqueID, meta]) => ({
      techniqueID,
      score: Math.min(100, meta.score),
      comment: meta.comments.join("; "),
      enabled: true,
    })),
  }
}

export function writeCaseReportPack(input: CaseReportInput, outDir: string): {
  htmlPath: string
  stixPath: string
  navigatorPath: string
} {
  mkdirSync(outDir, { recursive: true })
  const htmlPath = join(outDir, `${input.case_id}.report.html`)
  const stixPath = join(outDir, `${input.case_id}.stix.json`)
  const navigatorPath = join(outDir, `${input.case_id}.attack-navigator.json`)
  writeFileSync(htmlPath, generateHtmlReport(input), "utf8")
  writeFileSync(stixPath, `${JSON.stringify(generateStixBundle(input), null, 2)}\n`, "utf8")
  writeFileSync(navigatorPath, `${JSON.stringify(generateAttackNavigatorLayer(input), null, 2)}\n`, "utf8")
  return { htmlPath, stixPath, navigatorPath }
}
