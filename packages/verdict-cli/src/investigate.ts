import { existsSync, mkdirSync } from "node:fs"
import { join, resolve } from "node:path"
import {
  DEFAULT_PRIVACY_MODE,
  decideModel,
  type EvidenceClass,
  type PrivacyMode,
} from "@verdict/caseforge-sdk"
import {
  VerdictMcpSession,
  type IntakeItem,
  type LinuxArtifactHit,
  type BinaryTriageResult,
} from "@verdict/mcp"
import { writeCaseReportPack } from "@verdict/report"

export interface InvestigateOptions {
  evidencePath: string
  outDir: string
  caseId: string
  repoRoot: string
  privacy?: PrivacyMode
  evidenceClass?: EvidenceClass
}

export interface InvestigateSummary {
  case_id: string
  evidence_path: string
  out_dir: string
  privacy_mode: PrivacyMode
  evidence_class: EvidenceClass
  verdict: string
  basis: string
  audit_chain_ok: boolean
  evidence_records: number
  findings_count: number
  open_unknowns: number
  artifacts: {
    audit_log: string
    evidence_bundle: string
    html_report: string
    stix_bundle: string
    attack_navigator: string
  }
}

/**
 * End-to-end 5-phase deterministic DFIR pipeline:
 * 1. Catalog (verdict_intake + DAIR)
 * 2. Extract (Linux dead-disk + execution-free binary triage, auto-FTS5 indexed)
 * 3. Correlate (multi-class finding construction obeying >=2 artifact-class gate)
 * 4. Challenge (DAIR phase check + Skeptic baseline + explicit unknowns)
 * 5. Report & Bundle (hash-chained audit.jsonl, evidence-bundle.json, HTML+SVG, STIX 2.1, ATT&CK Navigator)
 */
export function runInvestigatePipeline(opts: InvestigateOptions): InvestigateSummary {
  const privacy = opts.privacy ?? DEFAULT_PRIVACY_MODE
  const evidenceClass = opts.evidenceClass ?? "sensitive"

  // Enforce CaseForge fail-closed privacy policy before touching evidence
  const localCheck = decideModel({ id: "deterministic/local-engine", location: "local" }, {
    mode: privacy,
    evidenceClass,
    redacted: privacy === "redacted-cloud",
  })
  if (!localCheck.allowed) {
    throw new Error(`Privacy policy denied execution: ${localCheck.reason}`)
  }

  const absEvidence = resolve(opts.evidencePath)
  const absOut = resolve(opts.outDir)
  mkdirSync(absOut, { recursive: true })
  const auditPath = join(absOut, "audit.jsonl")

  const session = new VerdictMcpSession({ repoRoot: opts.repoRoot, auditPath })

  // Phase 1: Catalog
  session.callTool("conduct_assess", {})
  const intakeRes = session.callTool("verdict_intake", { path: absEvidence, detail: "complete" })
  if (intakeRes.isError) {
    throw new Error(`Intake failed: ${intakeRes.content[0]?.text ?? "unknown error"}`)
  }
  const intakeRec = intakeRes.structuredContent as {
    evidence_id: string
    normalized_result: { items: IntakeItem[]; class_counts: Record<string, number> }
  }
  const items = intakeRec.normalized_result.items ?? []

  // Phase 2: Extract (Linux dead-disk if Linux rootfs markers present; binary triage on malware/executables)
  let linuxRecId: string | null = null
  let linuxHits: LinuxArtifactHit[] = []
  if (existsSync(join(absEvidence, "etc")) || existsSync(join(absEvidence, "var"))) {
    const lx = session.callTool("triage_linux_disk", { rootfs: absEvidence, detail: "complete" })
    if (!lx.isError && lx.structuredContent) {
      const parsed = lx.structuredContent as { evidence_id: string; normalized_result: { hits: LinuxArtifactHit[] } }
      linuxRecId = parsed.evidence_id
      linuxHits = parsed.normalized_result.hits ?? []
    }
  }

  const binEvidenceIds: string[] = []
  const suspiciousBinaries: Array<{ id: string; result: BinaryTriageResult }> = []
  for (const item of items.filter((i) => i.artifact_class === "malware").slice(0, 10)) {
    const full = items.length === 1 && !existsSync(join(absEvidence, item.logical_path)) ? absEvidence : join(absEvidence, item.logical_path)
    if (!existsSync(full)) continue
    const bt = session.callTool("triage_binary", { path: full, detail: "complete" })
    if (!bt.isError && bt.structuredContent) {
      const parsed = bt.structuredContent as { evidence_id: string; normalized_result: BinaryTriageResult }
      binEvidenceIds.push(parsed.evidence_id)
      if (parsed.normalized_result.likely_packed_or_encrypted || parsed.normalized_result.suspicious_strings.length > 0) {
        suspiciousBinaries.push({ id: parsed.evidence_id, result: parsed.normalized_result })
      }
    }
  }

  // Phase 3: Correlate
  const highLinux = linuxHits.filter((h) => h.severity === "high")
  if (highLinux.length > 0 && suspiciousBinaries.length > 0 && linuxRecId) {
    // >=2 distinct artifact classes (linux + malware) -> eligible for confirmed status!
    const f = session.callTool("record_finding", {
      title: "Corroborated Linux persistence and suspicious executable",
      claim: `Detected ${highLinux.length} high-severity Linux persistence/auth hit(s) corroborated by ${suspiciousBinaries.length} suspicious binary artifact(s).`,
      severity: "high",
      status: "confirmed",
      mitre_techniques: ["T1053.003", "T1543.002", "T1574.006"],
      evidence_refs: [linuxRecId, suspiciousBinaries[0]!.id],
    })
    if (!f.isError && f.structuredContent && "finding_id" in f.structuredContent) {
      const fid = String(f.structuredContent.finding_id)
      session.callTool("challenge_finding", {
        finding_id: fid,
        challenger: "verdict-skeptic-deterministic",
        counter_hypothesis: "Benign administrative script or test fixture without corroborating execution",
        outcome: "confirmed",
        notes: "Independent evidence exists across both Linux persistence configuration and binary artifact classes.",
      })
    }
  } else if (highLinux.length > 0 && linuxRecId) {
    const f = session.callTool("record_finding", {
      title: "High-severity Linux persistence or webshell indicator",
      claim: `Detected ${highLinux.length} high-severity Linux artifact hit(s): ${highLinux.map((h) => h.category).slice(0, 4).join(", ")}.`,
      severity: "high",
      status: "inferred",
      mitre_techniques: ["T1053.003", "T1505.003"],
      evidence_refs: [linuxRecId],
    })
    if (!f.isError && f.structuredContent && "finding_id" in f.structuredContent) {
      const fid = String(f.structuredContent.finding_id)
      session.callTool("challenge_finding", {
        finding_id: fid,
        challenger: "verdict-skeptic-deterministic",
        counter_hypothesis: "Single-class disk configuration without runtime/memory confirmation",
        outcome: "inferred",
        notes: "Remains inferred pending second artifact class corroboration (memory/network/auth timeline).",
      })
    }
  } else if (suspiciousBinaries.length > 0) {
    const b = suspiciousBinaries[0]!
    const f = session.callTool("record_finding", {
      title: `Suspicious ${b.result.format} binary artifact`,
      claim: `Binary ${b.result.path} exhibits entropy=${b.result.shannon_entropy} and ${b.result.suspicious_strings.length} suspicious string indicator(s).`,
      severity: "medium",
      status: "inferred",
      mitre_techniques: ["T1027"],
      evidence_refs: [b.id],
    })
    if (!f.isError && f.structuredContent && "finding_id" in f.structuredContent) {
      const fid = String(f.structuredContent.finding_id)
      session.callTool("challenge_finding", {
        finding_id: fid,
        challenger: "verdict-skeptic-deterministic",
        counter_hypothesis: "Packed or dual-use legitimate binary",
        outcome: "inferred",
        notes: "Requires second artifact class or deep RE (morluto/rea) to confirm malicious execution.",
      })
    }
  }

  // Record explicit unknown if only 1 artifact class was observed
  const classes = new Set(session.ledger.list().map((r) => r.artifact_class))
  if (classes.size < 2) {
    session.callTool("record_unknown", {
      question: "Are there corroborating artifacts in memory, EVTX, or network captures?",
      required_authority: "Second independent artifact class (memory dump, EVTX, or PCAP)",
      supporting_evidence_ids: [intakeRec.evidence_id],
    })
  }

  // Phase 4/5: Final DAIR assessment, verdict summary, bundle & report pack
  session.callTool("conduct_assess", {})
  const summary = session.findings.computeCaseVerdict(session.ledger, session.unknowns)
  const bundlePath = join(absOut, "evidence-bundle.json")
  const bundle = session.ledger.exportBundle(bundlePath)

  const written = writeCaseReportPack(
    {
      case_id: opts.caseId,
      verdict: summary.verdict,
      basis: summary.basis,
      audit_chain_ok: summary.audit_chain_ok,
      bundle,
      findings: session.findings.list(),
      unknowns: session.unknowns.list(),
    },
    absOut,
  )

  return {
    case_id: opts.caseId,
    evidence_path: absEvidence,
    out_dir: absOut,
    privacy_mode: privacy,
    evidence_class: evidenceClass,
    verdict: summary.verdict,
    basis: summary.basis,
    audit_chain_ok: summary.audit_chain_ok,
    evidence_records: bundle.record_count,
    findings_count: session.findings.list().length,
    open_unknowns: summary.open_unknowns,
    artifacts: {
      audit_log: auditPath,
      evidence_bundle: bundlePath,
      html_report: written.htmlPath,
      stix_bundle: written.stixPath,
      attack_navigator: written.navigatorPath,
    },
  }
}
