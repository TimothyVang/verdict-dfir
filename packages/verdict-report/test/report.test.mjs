import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"

import { EvidenceLedger, FindingsStore, UnknownsRegistry } from "@verdict/mcp"
import { generateAttackNavigatorLayer, generateHtmlReport, generateStixBundle, writeCaseReportPack } from "../dist/src/index.js"

test("P3 verdict-report generates static HTML with SVG Evidence Chain, STIX 2.1, and ATT&CK Navigator", () => {
  const ledger = new EvidenceLedger()
  const findings = new FindingsStore()
  const unknowns = new UnknownsRegistry()

  const r1 = ledger.retain({
    tool: "evtx_query",
    artifact_class: "evtx",
    parameters: { event_id: 4688 },
    analysis_profile: null,
    normalized_result: { hits: [{ proc: "scvhost.exe" }] },
    coverage: { scope: "security.evtx", status: "complete" },
  })
  const r2 = ledger.retain({
    tool: "mft_timeline",
    artifact_class: "disk",
    parameters: { path: "C:\\Temp\\scvhost.exe" },
    analysis_profile: null,
    normalized_result: { entries: [{ file: "scvhost.exe" }] },
    coverage: { scope: "mft", status: "complete" },
  })
  findings.record(ledger, {
    title: "Masqueraded svchost binary",
    claim: "scvhost.exe spawned from cmd.exe and present in C:\\Temp",
    severity: "high",
    status: "confirmed",
    mitre_techniques: ["T1036.005"],
    evidence_refs: [r1.evidence_id, r2.evidence_id],
  })

  const summary = findings.computeCaseVerdict(ledger, unknowns)
  const input = {
    case_id: "case-001",
    verdict: summary.verdict,
    basis: summary.basis,
    audit_chain_ok: summary.audit_chain_ok,
    bundle: ledger.exportBundle(),
    findings: findings.list(),
    unknowns: unknowns.list(),
  }

  const html = generateHtmlReport(input)
  assert.match(html, /SUSPICIOUS/)
  assert.match(html, /<svg viewBox=/)
  assert.match(html, /T1036\.005/)

  const stix = generateStixBundle(input)
  assert.equal(stix.type, "bundle")
  assert.equal(stix.objects.length, 1)

  const nav = generateAttackNavigatorLayer(input)
  assert.equal(nav.domain, "enterprise-attack")
  assert.equal(nav.techniques[0].techniqueID, "T1036.005")

  const dir = mkdtempSync(join(tmpdir(), "verdict-report-"))
  try {
    const out = writeCaseReportPack(input, dir)
    assert.ok(existsSync(out.htmlPath))
    assert.ok(existsSync(out.stixPath))
    assert.ok(existsSync(out.navigatorPath))
    assert.match(readFileSync(out.htmlPath, "utf8"), /VERDICT Forensic Report/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
