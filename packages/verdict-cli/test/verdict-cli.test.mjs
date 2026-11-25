import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
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
