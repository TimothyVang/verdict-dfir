import { VerdictMcpError } from "./evidence.js"
import { FindingsStore } from "./findings.js"
import { EvidenceLedger } from "./ledger.js"
import { UnknownsRegistry } from "./unknowns.js"

export type InvestigationPhase = "Catalog" | "Extract" | "Correlate" | "Challenge" | "Report"

export interface CuriosityProbe {
  probe_id: string
  dair_assessment_seq: number
  rationale: string
  target: string
  recorded_at: string
}

export interface DairAssessment {
  assessment_seq: number
  phase: InvestigationPhase
  priority_tools: string[]
  curiosity_budget: number
  curiosity_spent: number
  coverage_audit: {
    observed_classes: string[]
    applicable_unused_tools: string[]
    open_unknowns: number
    unchallenged_findings: number
  }
  rationale: string
}

/**
 * TRUDI-inspired DAIR phase director + bounded curiosity budget gate.
 * Emits the next bounded work order from sealed session state and tracks
 * off-plan read-only curiosity probes so exploration stays auditable and finite.
 */
export class DairDirector {
  private assessmentSeq = 0
  private activeBudget = 0
  private readonly probes: CuriosityProbe[] = []

  assess(ledger: EvidenceLedger, findings: FindingsStore, unknowns: UnknownsRegistry): DairAssessment {
    this.assessmentSeq++
    const records = ledger.list()
    const allFindings = findings.list()
    const openUnknowns = unknowns.openCount()
    const observedClasses = [...new Set(records.map((r) => r.artifact_class))]
    const usedTools = new Set(records.map((r) => r.tool))
    const unchallenged = allFindings.filter((f) => f.challenges.length === 0 && f.status !== "refuted").length

    const applicableUnused: string[] = []
    if (!usedTools.has("verdict_intake")) applicableUnused.push("verdict_intake")
    if (observedClasses.includes("linux") && !usedTools.has("triage_linux_disk")) {
      applicableUnused.push("triage_linux_disk")
    }
    if (observedClasses.includes("malware") && !usedTools.has("triage_binary")) {
      applicableUnused.push("triage_binary")
    }
    if (records.length > 0 && !usedTools.has("search_evidence")) {
      applicableUnused.push("search_evidence")
    }

    let phase: InvestigationPhase
    let priorityTools: string[]
    let budget = 0
    let rationale: string

    if (records.length === 0) {
      phase = "Catalog"
      priorityTools = ["verdict_intake", "verdict_doctor"]
      budget = 0
      rationale = "No evidence cataloged yet; run verdict_intake to hash and classify artifacts."
    } else if (applicableUnused.length > 0 && allFindings.length === 0) {
      phase = "Extract"
      priorityTools = applicableUnused.slice(0, 3)
      budget = 1
      rationale = "Catalog complete; run applicable typed extractors and index artifacts."
    } else if (allFindings.length === 0 || (observedClasses.length < 2 && openUnknowns > 0)) {
      phase = "Correlate"
      priorityTools = ["search_evidence", "inspect_analysis_view", "record_finding", "record_unknown"]
      budget = 2
      rationale = "Correlate across >=2 artifact classes before confirming findings; track gaps with record_unknown."
    } else if (unchallenged > 0) {
      phase = "Challenge"
      priorityTools = ["challenge_finding", "update_unknown"]
      budget = 1
      rationale = `${unchallenged} finding(s) have not undergone adversarial Skeptic review; run challenge_finding before reporting.`
    } else {
      phase = "Report"
      priorityTools = ["verdict_summary", "export_evidence_bundle"]
      budget = 0
      rationale = "All findings challenged and coverage audited; ready for verdict_summary and bundle/HTML export."
    }

    this.activeBudget = budget
    return {
      assessment_seq: this.assessmentSeq,
      phase,
      priority_tools: priorityTools,
      curiosity_budget: budget,
      curiosity_spent: 0,
      coverage_audit: {
        observed_classes: observedClasses,
        applicable_unused_tools: applicableUnused,
        open_unknowns: openUnknowns,
        unchallenged_findings: unchallenged,
      },
      rationale,
    }
  }

  recordCuriosityProbe(rationale: string, target: string): CuriosityProbe {
    if (!rationale.trim()) {
      throw new VerdictMcpError(
        "forensic_rule_violation",
        "A curiosity_probe must declare a non-empty rationale explaining the hunch and falsification criterion.",
        { details: { gate: "curiosity_budget" } },
      )
    }
    if (this.assessmentSeq === 0 || this.activeBudget <= 0) {
      throw new VerdictMcpError(
        "forensic_rule_violation",
        "No curiosity budget granted by active conduct_assess. Run conduct_assess to receive an exploratory allowance.",
        { details: { gate: "curiosity_budget", active_budget: this.activeBudget } },
      )
    }
    const spent = this.probes.filter((p) => p.dair_assessment_seq === this.assessmentSeq).length
    if (spent >= this.activeBudget) {
      throw new VerdictMcpError(
        "forensic_rule_violation",
        `Curiosity budget (${this.activeBudget}) exhausted for conduct_assess #${this.assessmentSeq}. Call conduct_assess to refresh or advance phase.`,
        { details: { gate: "curiosity_budget", spent, budget: this.activeBudget } },
      )
    }
    const probe: CuriosityProbe = {
      probe_id: `probe_${this.assessmentSeq}_${spent + 1}`,
      dair_assessment_seq: this.assessmentSeq,
      rationale: rationale.trim(),
      target,
      recorded_at: new Date().toISOString(),
    }
    this.probes.push(probe)
    return probe
  }

  listProbes(): CuriosityProbe[] {
    return [...this.probes]
  }
}
