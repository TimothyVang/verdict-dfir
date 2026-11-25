import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const __dirname = dirname(fileURLToPath(import.meta.url))
const CLI = resolve(__dirname, "..", "dist", "src", "cli.js")

test("verdict doctor --json reports zero-install readiness and probes", () => {
  const out = execFileSync("node", [CLI, "doctor", "--json"], { encoding: "utf8" })
  const parsed = JSON.parse(out)
  assert.equal(parsed.ready_zero_install, true)
  assert.ok(Array.isArray(parsed.probes) && parsed.probes.length > 0)
})

test("verdict models enforces CaseForge fail-closed privacy routing", () => {
  const out = execFileSync("node", [CLI, "models", "--privacy", "local-only", "--evidence", "sensitive", "--json"], {
    encoding: "utf8",
  })
  const parsed = JSON.parse(out)
  const cloud = parsed.models.filter((m) => m.location === "cloud")
  const local = parsed.models.filter((m) => m.location === "local")
  assert.ok(cloud.every((m) => m.decision.allowed === false))
  assert.ok(local.every((m) => m.decision.allowed === true))
})

test("verdict intake --json emits canonical REA summary and exports authenticated bundle", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-cli-"))
  try {
    writeFileSync(join(dir, "SYSTEM"), "hive")
    const bundlePath = join(dir, "bundle.json")
    const out = execFileSync("node", [CLI, "intake", dir, "--evidence-output", bundlePath, "--json"], {
      encoding: "utf8",
    })
    const parsed = JSON.parse(out)
    assert.equal(parsed.detail, "summary")
    assert.match(parsed.normalized_result.parent_evidence_id, /^ev_/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("verdict investigate runs full 5-phase pipeline and emits confirmed verdict + HTML/STIX/ATT&CK pack", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-inv-"))
  const outDir = join(dir, "out")
  const evDir = join(dir, "evidence")
  try {
    mkdirSync(join(evDir, "etc"), { recursive: true })
    writeFileSync(join(evDir, "etc", "ld.so.preload"), "/tmp/libhide.so\n")
    writeFileSync(
      join(evDir, "implant.elf"),
      Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.from("VirtualAlloc http://c2.evil/ping")]),
    )

    const out = execFileSync("node", [CLI, "investigate", evDir, "--out-dir", outDir, "--case-id", "inv-001", "--json"], {
      encoding: "utf8",
    })
    const parsed = JSON.parse(out)
    assert.equal(parsed.verdict, "SUSPICIOUS")
    assert.equal(parsed.audit_chain_ok, true)
    assert.equal(parsed.findings_count, 1)
    assert.ok(existsSync(parsed.artifacts.audit_log))
    assert.ok(existsSync(parsed.artifacts.evidence_bundle))
    assert.ok(existsSync(parsed.artifacts.html_report))
    assert.ok(existsSync(parsed.artifacts.stix_bundle))
    assert.ok(existsSync(parsed.artifacts.attack_navigator))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test("verdict setup --apply backs up existing config, registers MCP server, and copies skill hermetically", () => {
  const fakeHome = mkdtempSync(join(tmpdir(), "verdict-home-"))
  try {
    const claudeCfg = join(fakeHome, ".claude.json")
    writeFileSync(claudeCfg, JSON.stringify({ mcpServers: { existing: { command: "echo" } } }, null, 2))

    const out = execFileSync("node", [CLI, "setup", "--client", "claude", "--apply", "--home", fakeHome], {
      encoding: "utf8",
    })
    const parsed = JSON.parse(out)
    assert.equal(parsed.mode, "applied")
    assert.equal(parsed.actions.length, 1)
    assert.ok(parsed.actions[0].backup_path && existsSync(parsed.actions[0].backup_path))
    assert.ok(existsSync(join(parsed.actions[0].skill_dest, "SKILL.md")))

    const updated = JSON.parse(readFileSync(claudeCfg, "utf8"))
    assert.ok(updated.mcpServers.existing)
    assert.equal(updated.mcpServers.verdict.command, "node")
  } finally {
    rmSync(fakeHome, { recursive: true, force: true })
  }
})
