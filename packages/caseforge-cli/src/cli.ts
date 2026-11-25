#!/usr/bin/env node
/**
 * caseforge — headless DFIR agentic core CLI.
 *
 *   caseforge doctor
 *   caseforge auth status | login | logout
 *   caseforge models            [--privacy MODE] [--evidence CLASS]
 *   caseforge investigate <evidence-path> [--privacy MODE] [--evidence CLASS] [--route ID] [--command NAME]
 *   caseforge verify <run-dir>
 *   caseforge fleet [run-dir ...] [--socket <path>] [--attach <path>]   (multiplexer)
 *   caseforge gateway start | benchmark run | ocr <case-id> | ingest <path>   (planned)
 */
import type { EvidenceClass, PrivacyMode } from "@verdict/caseforge-sdk"
import { doctor } from "./commands/doctor.js"
import { auth } from "./commands/auth.js"
import { models } from "./commands/models.js"
import { investigate } from "./commands/investigate.js"
import { verify } from "./commands/verify.js"
import { gatewayStart, benchmarkRun, ocr, ingest } from "./commands/stubs.js"
import { launchTui } from "@verdict/caseforge-tui"
import { fleet } from "./commands/fleet.js"

interface Parsed {
  positionals: string[]
  flags: Record<string, string | boolean>
}

function parseArgs(argv: string[]): Parsed {
  const positionals: string[] = []
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (a.startsWith("--")) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next
        i++
      } else flags[key] = true
    } else positionals.push(a)
  }
  return { positionals, flags }
}

function usage(): void {
  console.log(`caseforge — headless DFIR agentic core

  doctor                          check environment + config prerequisites
  auth status|login|logout         manage ChatGPT / SuperGrok subscription OAuth
  models [--privacy M] [--evidence C]   list routes and privacy permissions
  investigate <evidence-path>     run a privacy-gated DFIR investigation
      [--privacy local-only|redacted-cloud|cloud-ok] [--evidence synthetic|public|approved|sensitive]
      [--route ID] [--command triage|disk|memory|evtx|network|...] [--cloud-ack]
  verify <run-dir>                validate VERDICT run artifacts + custody
  tui [run-dir]                                             read-only workbench
  gateway start | benchmark run | ocr <id> | ingest <path>   (planned)

privacy defaults to local-only; evidence defaults to sensitive (fail-closed).`)
}

async function main(): Promise<number> {
  const { positionals, flags } = parseArgs(process.argv.slice(2))
  const cmd = positionals[0]
  const rest = positionals.slice(1)
  const privacy = typeof flags.privacy === "string" ? (flags.privacy as PrivacyMode) : undefined
  const evidence = typeof flags.evidence === "string" ? (flags.evidence as EvidenceClass) : undefined

  switch (cmd) {
    case "doctor":
      return doctor({ route: typeof flags.route === "string" ? flags.route : undefined })
    case "auth":
      return auth(rest, flags)
    case "models":
      return models({ privacy, evidence })
    case "investigate":
      return investigate(rest[0], {
        privacy,
        evidence,
        route: typeof flags.route === "string" ? flags.route : undefined,
        command: typeof flags.command === "string" ? flags.command : undefined,
        runDir: typeof flags["run-dir"] === "string" ? (flags["run-dir"] as string) : undefined,
        noVerify: flags["no-verify"] === true,
        cloudAck: flags["cloud-ack"] === true,
      })
    case "tui":
      return await launchTui(positionals[1])
    case "fleet":
      return fleet(process.argv.slice(3))
    case "verify":
      return verify(rest)
    case "gateway":
      return rest[0] === "start" ? gatewayStart() : (usage(), 2)
    case "benchmark":
      return rest[0] === "run" ? benchmarkRun() : (usage(), 2)
    case "ocr":
      return ocr()
    case "ingest":
      return ingest()
    case undefined:
    case "help":
    case "--help":
    case "-h":
      usage()
      return 0
    default:
      console.error(`unknown command: ${cmd}`)
      usage()
      return 2
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err?.stack ?? String(err))
    process.exit(1)
  },
)
