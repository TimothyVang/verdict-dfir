import assert from "node:assert/strict"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"

import {
  EvidenceLedger,
  FindingsStore,
  runIntake,
  UnknownsRegistry,
  VerdictMcpError,
  VerdictMcpSession,
} from "../dist/src/index.js"

test("EvidenceLedger retains canonical digest, pages via inspect_analysis_view, and rejects tampering", () => {
  const ledger = new EvidenceLedger()
  const rec = ledger.retain({
    tool: "evtx_query",
    artifact_class: "evtx",
    parameters: { event_id: 4688 },
    analysis_profile: { engine: "findevil-mcp", version: "1.0.0", mode: "deterministic" },
    normalized_result: {
      events: [
        { id: 1, proc: "cmd.exe" },
        { id: 2, proc: "powershell.exe" },
        { id: 3, proc: "svchost.exe" },
      ],
    },
    coverage: { scope: "security-evtx", status: "complete", total_count: 3, returned_count: 3 },
    limitations: [],
  })

  assert.match(rec.evidence_id, /^ev_[a-f0-9]{32}$/)
  assert.equal(ledger.verifyAuditChain().ok, true)

  const page = ledger.inspectView(
    { kind: "retained-evidence", evidence_id: rec.evidence_id },
    { kind: "collection", collection: "events", offset: 1, limit: 1, fields: ["proc"] },
  )
  assert.equal(page.parent_evidence_id, rec.evidence_id)
  assert.deepEqual(page.items, [{ source_index: 1, proc: "powershell.exe" }])
  assert.equal(page.page_coverage.next_offset, 2)

  // Tamper with inline record and verify rejection
  const tampered = structuredClone(rec)
  tampered.normalized_result.events[0].proc = "benign.exe"
  assert.throws(() => ledger.resolve(tampered), (err) => err instanceof VerdictMcpError && err.code === "evidence_integrity_mismatch")
})

test("FindingsStore enforces Mulder citation gate, VERDICT >=2-class rule, Amcache caveat, and SIFT++ skeptic challenge", () => {
  const ledger = new EvidenceLedger()
  const unknowns = new UnknownsRegistry()
  const findings = new FindingsStore()

  // 1. Fabricated citation rejected at API boundary
  assert.throws(
    () =>
      findings.record(ledger, {
        title: "Fake lateral movement",
        claim: "Fabricated claim",
        severity: "high",
        evidence_refs: ["ev_00000000000000000000000000000000"],
      }),
    (err) => err instanceof VerdictMcpError && err.code === "citation_rejected",
  )

  const evtxRec = ledger.retain({
    tool: "evtx_query",
    artifact_class: "evtx",
    parameters: { channel: "Security" },
    analysis_profile: null,
    normalized_result: { hits: [{ event_id: 4688, cmd: "scvhost.exe" }] },
    coverage: { scope: "security.evtx", status: "complete" },
  })

  // 2. Single artifact class cannot be marked confirmed
  assert.throws(
    () =>
      findings.record(ledger, {
        title: "Masquerade binary",
        claim: "scvhost.exe launched by cmd.exe",
        severity: "high",
        status: "confirmed",
        evidence_refs: [evtxRec.evidence_id],
      }),
    (err) => err instanceof VerdictMcpError && err.code === "forensic_rule_violation",
  )

  // 3. Amcache without caveat acknowledgment rejected when confirmed
  const amcacheRec = ledger.retain({
    tool: "amcache_parse",
    artifact_class: "registry",
    parameters: { hive: "Amcache.hve" },
    analysis_profile: null,
    normalized_result: { entries: [{ path: "C:\\Temp\\scvhost.exe" }] },
    coverage: { scope: "amcache", status: "complete" },
  })
  assert.throws(
    () =>
      findings.record(ledger, {
        title: "Masquerade binary",
        claim: "scvhost.exe executed",
        severity: "high",
        status: "confirmed",
        evidence_refs: [evtxRec.evidence_id, amcacheRec.evidence_id],
      }),
    (err) => err instanceof VerdictMcpError && err.code === "forensic_rule_violation",
  )

  // 4. With >=2 classes + Amcache caveat acknowledged, finding succeeds; bad timestamp auto-nullified
  const f = findings.record(ledger, {
    title: "Masquerade binary",
    claim: "scvhost.exe present and spawned from cmd.exe",
    severity: "high",
    status: "confirmed",
    mitre_techniques: ["T1036.005"],
    evidence_refs: [evtxRec.evidence_id, amcacheRec.evidence_id],
    event_timestamp: "yesterday-ish",
    caveats_acknowledged: ["Amcache LastModified does not prove execution; execution corroborated by EVTX 4688."],
  })
  assert.equal(f.event_timestamp, null)
  assert.ok(f.timestamp_warning)
  assert.equal(findings.computeCaseVerdict(ledger, unknowns).verdict, "SUSPICIOUS")

  // 5. Skeptic challenge refutes finding -> verdict drops to NO_EVIL (since all records have complete coverage & 0 open unknowns)
  const refuted = findings.challenge(ledger, {
    finding_id: f.finding_id,
    challenger: "skeptic",
    counter_hypothesis: "Authorized IT script",
    outcome: "refuted",
    notes: "Signed internal utility",
  })
  assert.equal(refuted.status, "refuted")
  assert.equal(findings.computeCaseVerdict(ledger, unknowns).verdict, "NO_EVIL")
})

test("UnknownsRegistry enforces optimistic revisions and evidence-backed resolution", () => {
  const ledger = new EvidenceLedger()
  const unknowns = new UnknownsRegistry()
  const u = unknowns.record(ledger, {
    question: "Did attacker pivot to DC01?",
    required_authority: "DC01 Security.evtx",
  })

  // Cannot resolve without evidence
  assert.throws(
    () => unknowns.update(ledger, { unknown_id: u.unknown_id, expected_revision: 1, status: "resolved" }),
    (err) => err instanceof VerdictMcpError && err.code === "forensic_rule_violation",
  )

  const rec = ledger.retain({
    tool: "evtx_query",
    artifact_class: "evtx",
    parameters: { host: "DC01" },
    analysis_profile: null,
    normalized_result: { hits: [] },
    coverage: { scope: "dc01-security", status: "complete" },
  })
  const resolved = unknowns.update(ledger, {
    unknown_id: u.unknown_id,
    expected_revision: 1,
    status: "resolved",
    supporting_evidence_ids: [rec.evidence_id],
    resolution_note: "No 4624/4648 logon observed from compromised account.",
  })
  assert.equal(resolved.revision, 2)
  assert.equal(resolved.status, "resolved")

  // Stale revision rejected
  assert.throws(
    () => unknowns.update(ledger, { unknown_id: u.unknown_id, expected_revision: 1, status: "open" }),
    (err) => err instanceof VerdictMcpError && err.code === "stale_revision",
  )
})

test("VerdictMcpSession handles JSON-RPC initialize, tools/list, and intake -> view round-trip", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-intake-"))
  try {
    writeFileSync(join(dir, "Security.evtx"), "synthetic-evtx-bytes")
    writeFileSync(join(dir, "capture.pcap"), "synthetic-pcap-bytes")

    const session = new VerdictMcpSession()
    const init = session.handleJsonRpc({ jsonrpc: "2.0", id: 1, method: "initialize" })
    assert.equal(init.result.serverInfo.name, "verdict-mcp")

    const list = session.handleJsonRpc({ jsonrpc: "2.0", id: 2, method: "tools/list" })
    assert.ok(list.result.tools.length >= 9)

    const intakeResp = session.handleJsonRpc({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "verdict_intake", arguments: { path: dir, detail: "summary" } },
    })
    assert.equal(intakeResp.result.isError, undefined)
    const parentId = intakeResp.result.structuredContent.normalized_result.parent_evidence_id
    assert.match(parentId, /^ev_/)

    const viewResp = session.handleJsonRpc({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "inspect_analysis_view",
        arguments: {
          source: { kind: "retained-evidence", evidence_id: parentId },
          view: { kind: "collection", collection: "items", filter_key: "artifact_class", filter_contains: "evtx" },
        },
      },
    })
    assert.equal(viewResp.result.structuredContent.items.length, 1)
    assert.equal(viewResp.result.structuredContent.items[0].value.logical_path, "Security.evtx")
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
