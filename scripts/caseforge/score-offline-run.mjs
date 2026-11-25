#!/usr/bin/env node
/**
 * score-offline-run — grade a sealed VERDICT run against the DFIR scorecard oracle.
 *
 * This is the automated grader the offline battery lacked: it reads a run's
 * verdict.json, diffs the elevated MITRE techniques / CVEs against the per-case
 * ground truth in fixtures/dfir-scorecard/ground-truth.json, and emits
 * HIT / PARTIAL / MISS per technique plus a numeric score.
 *
 * It ALSO reports llm_provenance — whether gpt-oss:20b (the opencode agent) actually
 * authored the run, or whether caseforge fell back to the deterministic find_evil_auto
 * engine. A passing technique score does NOT by itself prove the LLM did anything; the
 * provenance field is what distinguishes "the LLM passed offline" from "the engine floor
 * passed". Callers that specifically test the LLM must gate on provenance, not just score.
 *
 * Pure: no network, no LLM, no external deps. Importable (scoreRun/…) and runnable as CLI.
 */
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const HERE = dirname(fileURLToPath(import.meta.url))
export const DEFAULT_GROUND_TRUTH = join(HERE, "..", "fixtures", "dfir-scorecard", "ground-truth.json")

const T_CODE = /\bT\d{4}(?:\.\d{3})?\b/g
const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi

/** Collect every MITRE technique the run actually elevated (observed_techniques + findings). */
export function collectObservedTechniques(verdict) {
  const set = new Set()
  const ac = verdict.attack_coverage || {}
  for (const t of ac.observed_techniques || []) if (t) set.add(String(t).toUpperCase())
  for (const tgt of ac.targets || []) {
    // only count as "observed" when a finding was elevated, not blind_spot / covered_no_finding
    if (tgt?.technique_id && /finding|elevat|confirm|observ/i.test(String(tgt.status || ""))) {
      set.add(String(tgt.technique_id).toUpperCase())
    }
  }
  for (const f of verdict.findings || []) {
    for (const key of ["technique_id", "technique", "mitre", "techniques", "attack_technique"]) {
      const v = f?.[key]
      if (Array.isArray(v)) v.forEach((x) => x && set.add(String(x).toUpperCase()))
      else if (v) String(v).match(T_CODE)?.forEach((x) => set.add(x.toUpperCase()))
    }
    const blob = JSON.stringify(f || {})
    blob.match(T_CODE)?.forEach((x) => set.add(x.toUpperCase()))
  }
  return set
}

/** Collect every CVE the run cited (attack_story targets, findings, or anywhere nested). */
export function collectCves(verdict) {
  const set = new Set()
  const add = (s) => String(s).match(CVE)?.forEach((c) => set.add(c.toUpperCase()))
  for (const tgt of verdict.attack_story?.targets || []) (tgt.cves || []).forEach(add)
  for (const f of verdict.findings || []) add(JSON.stringify(f || {}))
  if (Array.isArray(verdict.cves)) verdict.cves.forEach(add)
  return set
}

/** Did the signal at least get parsed (event ids in timeline / evtx summary), short of a finding? */
function signalSeen(verdict, evtxEntry) {
  const hay = JSON.stringify({
    t: verdict.normalized_timeline || verdict.timeline_summary || {},
    e: verdict.evtx_summary || {},
    inv: verdict.evidence_inventory || {},
    cov: verdict.attack_coverage?.targets || [],
  })
  return (evtxEntry.event_ids || []).some((eid) => hay.includes(String(eid)))
}

/**
 * Provenance: did the LLM agent author this run, or did the deterministic engine?
 * The deterministic runner stamps agent="find-evil-auto MVP"; the LLM path leaves opencode
 * agent tool_calls and does not carry that agent id.
 */
export function detectProvenance(verdict) {
  const agent = String(verdict.agent || "").toLowerCase()
  const toolCalls = Array.isArray(verdict.tool_calls) ? verdict.tool_calls.length : 0
  if (/find-evil-auto|findevil-auto|auto[- ]?runner|deterministic/.test(agent)) {
    return { llm: false, kind: "deterministic-fallback", agent: verdict.agent ?? null, tool_calls: toolCalls }
  }
  if (/verdict|opencode|gpt-oss|agent|llm/.test(agent)) {
    return { llm: true, kind: "llm-agent", agent: verdict.agent ?? null, tool_calls: toolCalls }
  }
  return { llm: null, kind: "unknown", agent: verdict.agent ?? null, tool_calls: toolCalls }
}

/** Grade one run's verdict.json for a named case against the oracle. */
export function scoreRun(verdict, caseGroundTruth) {
  const observed = collectObservedTechniques(verdict)
  const cves = collectCves(verdict)
  const techniques = []
  let hit = 0,
    partial = 0,
    miss = 0

  const expectedTechs = new Map()
  for (const [file, entry] of Object.entries(caseGroundTruth.evtx || {})) {
    for (const t of entry.techniques || []) if (!expectedTechs.has(t)) expectedTechs.set(t, { file, entry })
  }
  for (const [tech, { entry }] of expectedTechs) {
    let status
    if (observed.has(tech.toUpperCase())) {
      status = "HIT"
      hit++
    } else if (signalSeen(verdict, entry)) {
      status = "PARTIAL"
      partial++
    } else {
      status = "MISS"
      miss++
    }
    techniques.push({ technique: tech, status })
  }

  const cveResults = []
  for (const [, entry] of Object.entries(caseGroundTruth.evtx || {})) {
    for (const c of entry.cves || []) {
      const got = cves.has(c.toUpperCase())
      cveResults.push({ cve: c, status: got ? "HIT" : "MISS" })
    }
  }
  const cveHit = cveResults.filter((c) => c.status === "HIT").length

  const totalExpected = expectedTechs.size + cveResults.length
  const totalHit = hit + cveHit
  return {
    verdict: verdict.verdict ?? null,
    expected_verdict_band: caseGroundTruth.expected_verdict_band ?? null,
    llm_provenance: detectProvenance(verdict),
    techniques,
    cves: cveResults,
    tally: { hit, partial, miss, cve_hit: cveHit, cve_total: cveResults.length },
    score: totalExpected === 0 ? 1 : totalHit / totalExpected,
    total_expected: totalExpected,
    total_hit: totalHit,
  }
}

export function loadGroundTruth(path = DEFAULT_GROUND_TRUTH) {
  return JSON.parse(readFileSync(path, "utf8"))
}

function parseArgs(argv) {
  const args = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === "--case") args.case = argv[++i]
    else if (a === "--ground-truth") args.groundTruth = argv[++i]
    else if (a === "--require-llm") args.requireLlm = true
    else if (a === "--min-score") args.minScore = Number(argv[++i])
    else args._.push(a)
  }
  return args
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  const verdictPath = args._[0]
  if (!verdictPath || !args.case) {
    console.error("usage: score-offline-run.mjs <verdict.json> --case <name> [--ground-truth <path>] [--require-llm] [--min-score <0..1>]")
    process.exit(2)
  }
  const gt = loadGroundTruth(args.groundTruth)
  const caseGt = gt.cases?.[args.case]
  if (!caseGt) {
    console.error(`unknown case '${args.case}'. known: ${Object.keys(gt.cases || {}).join(", ")}`)
    process.exit(2)
  }
  const verdict = JSON.parse(readFileSync(verdictPath, "utf8"))
  const r = scoreRun(verdict, caseGt)

  console.log(`case:            ${args.case}`)
  console.log(`verdict:         ${r.verdict}  (expected band ${r.expected_verdict_band})`)
  console.log(`llm_provenance:  ${r.llm_provenance.kind}  (agent=${r.llm_provenance.agent}, tool_calls=${r.llm_provenance.tool_calls})`)
  for (const t of r.techniques) console.log(`  ${t.status.padEnd(7)} ${t.technique}`)
  for (const c of r.cves) console.log(`  ${c.status.padEnd(7)} ${c.cve}`)
  console.log(`score:           ${r.total_hit}/${r.total_expected} = ${(r.score * 100).toFixed(0)}%`)

  let failed = false
  if (args.minScore != null && r.score < args.minScore) {
    console.error(`FAIL: score ${(r.score * 100).toFixed(0)}% < required ${(args.minScore * 100).toFixed(0)}%`)
    failed = true
  }
  if (args.requireLlm && r.llm_provenance.llm !== true) {
    console.error(`FAIL: --require-llm set but provenance is '${r.llm_provenance.kind}' (LLM did not author this run)`)
    failed = true
  }
  console.log(JSON.stringify({ case: args.case, ...r }))
  process.exit(failed ? 1 : 0)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
