#!/usr/bin/env node
import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import {
  DEFAULT_PRIVACY_MODE,
  decideModel,
  validateRun,
  readVerdict,
  checkFindingsCustody,
  type EvidenceClass,
  type ModelCandidate,
  type PrivacyMode,
} from "@verdict/caseforge-sdk"
import { EvidenceLedger, runDoctor, runIntake, startStdioServer, type EvidenceBundle } from "@verdict/mcp"
import { writeCaseReportPack } from "@verdict/report"
import { runInvestigatePipeline } from "./investigate.js"
import { runSetup, type SetupClient } from "./setup.js"
const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(__dirname, "..", "..", "..", "..")

const DEFAULT_MODELS: ModelCandidate[] = [
  { id: "local-vllm/qwen3", location: "local" },
  { id: "local-ollama/gpt-oss", location: "local" },
  { id: "anthropic/claude-opus", location: "cloud" },
  { id: "openai/gpt-5", location: "cloud" },
]

function flagValue(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name)
  if (idx === -1 || idx + 1 >= args.length) return undefined
  return args[idx + 1]
}

function printHelp(): void {
  console.log(`VERDICT — REA for DFIR (Unified Monorepo CLI)

Usage:
  verdict doctor [--json]
  verdict setup [--client claude|cursor|codex|all] [--apply] [--home <dir>] [--json]
  verdict models [--privacy local-only|redacted-cloud|cloud-ok] [--evidence sensitive|synthetic|public] [--json]
  verdict intake <path> [--detail summary|complete] [--evidence-output <file>] [--json]
  verdict investigate <evidence-path> --out-dir <dir> [--case-id <id>] [--privacy local-only|redacted-cloud|cloud-ok] [--evidence sensitive|synthetic|public] [--json]
  verdict report <bundle.json> --out-dir <dir> [--case-id <id>] [--json]
  verdict verify <run-dir> [--json]
  verdict serve [--audit-log <file>]
`)
}

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv
  const asJson = rest.includes("--json")

  if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") {
    printHelp()
    return
  }

  switch (cmd) {
    case "doctor": {
      const report = runDoctor(REPO_ROOT)
      if (asJson) {
        console.log(JSON.stringify(report, null, 2))
        return
      }
      console.log(`VERDICT Doctor (repo: ${report.repo_root})`)
      for (const p of report.probes) {
        const mark = p.available ? "[OK]" : "[--]"
        console.log(`  ${mark} [${p.category}] ${p.name} — ${p.location ?? p.note}`)
      }
      return
    }

    case "setup": {
      const client = (flagValue(rest, "--client") ?? "all") as SetupClient
      const apply = rest.includes("--apply")
      const homeDir = flagValue(rest, "--home")
      const res = runSetup({ repoRoot: REPO_ROOT, client, apply, homeDir })
      console.log(JSON.stringify(res, null, 2))
      return
    }

    case "investigate": {
      const evidencePath = rest.find((a) => !a.startsWith("-"))
      const outDir = flagValue(rest, "--out-dir")
      if (!evidencePath || !outDir) {
        console.error("error: verdict investigate requires <evidence-path> --out-dir <dir>")
        process.exit(2)
      }
      const caseId = flagValue(rest, "--case-id") ?? "case"
      const privacy = (flagValue(rest, "--privacy") ?? DEFAULT_PRIVACY_MODE) as PrivacyMode
      const evidenceClass = (flagValue(rest, "--evidence") ?? "sensitive") as EvidenceClass
      const summary = runInvestigatePipeline({
        evidencePath,
        outDir,
        caseId,
        repoRoot: REPO_ROOT,
        privacy,
        evidenceClass,
      })
      console.log(JSON.stringify(summary, null, 2))
      return
    }

    case "models": {
      const privacy = (flagValue(rest, "--privacy") ?? DEFAULT_PRIVACY_MODE) as PrivacyMode
      const evidence = (flagValue(rest, "--evidence") ?? "sensitive") as EvidenceClass
      const rows = DEFAULT_MODELS.map((m) => ({
        model: m.id,
        location: m.location,
        decision: decideModel(m, { mode: privacy, evidenceClass: evidence, redacted: privacy === "redacted-cloud" }),
      }))
      if (asJson) {
        console.log(JSON.stringify({ privacy, evidence, models: rows }, null, 2))
        return
      }
      console.log(`Privacy mode: ${privacy} | Evidence class: ${evidence}`)
      for (const r of rows) {
        const tag = r.decision.allowed ? "[allow]" : "[deny] "
        console.log(`  ${tag} ${r.model} (${r.location}) — ${r.decision.reason}`)
      }
      return
    }

    case "intake": {
      const target = rest.find((a) => !a.startsWith("-"))
      if (!target) {
        console.error("error: verdict intake requires <path>")
        process.exit(2)
      }
      const ledger = new EvidenceLedger()
      const rec = runIntake(ledger, target)
      const outPath = flagValue(rest, "--evidence-output")
      if (outPath) {
        ledger.exportBundle(resolve(outPath))
      }
      const detail = flagValue(rest, "--detail") === "complete" ? "complete" : "summary"
      const output = detail === "complete" ? rec : { detail: "summary", normalized_result: ledger.summarize(rec) }
      console.log(JSON.stringify(output, null, 2))
      return
    }

    case "report": {
      const bundleFile = rest.find((a) => !a.startsWith("-"))
      const outDir = flagValue(rest, "--out-dir")
      if (!bundleFile || !outDir) {
        console.error("error: verdict report requires <bundle.json> --out-dir <dir>")
        process.exit(2)
      }
      const caseId = flagValue(rest, "--case-id") ?? "case"
      const bundle = JSON.parse(readFileSync(resolve(bundleFile), "utf8")) as EvidenceBundle
      const ledger = new EvidenceLedger()
      ledger.importBundle(bundle)
      const chain = ledger.verifyAuditChain()
      const written = writeCaseReportPack(
        {
          case_id: caseId,
          verdict: "INDETERMINATE",
          basis: `Generated from authenticated bundle ${bundle.bundle_id} (${bundle.record_count} records).`,
          audit_chain_ok: chain.ok,
          bundle,
          findings: [],
          unknowns: [],
        },
        resolve(outDir),
      )
      console.log(JSON.stringify(written, null, 2))
      return
    }

    case "verify": {
      const runDir = rest.find((a) => !a.startsWith("-"))
      if (!runDir) {
        console.error("error: verdict verify requires <run-dir>")
        process.exit(2)
      }
      const absDir = resolve(runDir)
      const validation = await validateRun(absDir)
      const custody = checkFindingsCustody(await readVerdict(absDir))
      const payload = { run_dir: absDir, validation, custody }
      if (asJson) {
        console.log(JSON.stringify(payload, null, 2))
      } else {
        console.log(`VERDICT Verify: ${absDir}`)
        console.log(`  Status: ${validation.status}`)
        console.log(`  Findings custody ok: ${custody.ok}`)
      }
      if (validation.status !== "complete" || !custody.ok) {
        process.exit(1)
      }
      return
    }

    case "serve": {
      const auditPath = flagValue(rest, "--audit-log")
      startStdioServer({ repoRoot: REPO_ROOT, auditPath })
      return
    }

    default:
      console.error(`Unknown command: ${cmd}`)
      printHelp()
      process.exit(2)
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
