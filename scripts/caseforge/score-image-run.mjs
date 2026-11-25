#!/usr/bin/env node
/**
 * score-image-run — multi-axis grader for a sealed VERDICT run against a per-artifact
 * forensic-image oracle (dfir-image-oracle/v1).
 *
 * Extends the offline EVTX grader (score-offline-run.mjs) to the richer image case. Scores four
 * axes, each bound to fields the producer verdict.json actually emits (verified against real
 * runs), plus an AI-degree detector and the honest llm_provenance control:
 *   1. MITRE elevation      — expected techniques (alias-aware) vs structured observed fields
 *   2. IOC recovery         — planted IOC recall over only the categories the verdict emits
 *   3. Chain reconstruction — oracle stages joined to attack_story.attack_chain[] by
 *                             technique+phase; coverage + adjacent-pair ordering concordance
 *   4. Verdict band         — scoped verdict vs expected
 *   + AI-degree             — none | AI-present | AI-orchestrated, from documented Tier-1
 *                             integration-artifact signatures (not writing style)
 *
 * Pure: no network, no LLM, no external deps. Importable and runnable as CLI.
 *
 * Notes vs the shipped grader: technique/CVE collection uses STRUCTURED fields (not a stringify
 * of narrative text, which over-counts), and CVEs are read from attack_story.attack_chain[].cves
 * + findings[].cves (the shipped collectCves read a non-existent attack_story.targets).
 */
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { detectProvenance } from "./score-offline-run.mjs"

const T_CODE = /\bT\d{4}(?:\.\d{3})?\b/i
const IOC_TYPE_TO_CATEGORY = {
  service: "services",
  process: "processes",
  account: "accounts",
  host: "hosts",
  file: "file_paths",
  ip: "ip_addresses",
}

const norm = (s) => String(s ?? "").trim().toLowerCase()
const basename = (s) => norm(s).split(/[\\/]/).pop()

// ---- observed evidence, from STRUCTURED fields only ----

export function observedTechniques(verdict) {
  const set = new Set()
  const add = (t) => {
    const m = String(t ?? "").match(T_CODE)
    if (m) set.add(m[0].toUpperCase())
  }
  for (const t of verdict.attack_coverage?.observed_techniques ?? []) add(t)
  for (const f of verdict.findings ?? []) add(f?.mitre_technique)
  for (const s of verdict.attack_story?.attack_chain ?? []) add(s?.mitre_technique)
  return set
}

export function observedCves(verdict) {
  const set = new Set()
  const add = (c) => c && set.add(String(c).toUpperCase())
  for (const f of verdict.findings ?? []) (f?.cves ?? []).forEach(add)
  for (const s of verdict.attack_story?.attack_chain ?? []) (s?.cves ?? []).forEach(add)
  return set
}

// ---- AI-degree: documented Tier-1 integration-artifact signatures ----

const AI_SIGNATURES = {
  provider_key: /sk-ant-api03|T3BlbkFJ|\bsk-[A-Za-z0-9]{20,}\b|AIzaSy[A-Za-z0-9_-]{20,}/,
  local_llm: /\.ollama[\\/]|\.lmstudio|llama\.cpp|\bgguf\b|generativelanguage\.googleapis/i,
  prompts_as_code: /return only commands|prompts?[- ]as[- ]code|without markdown|you are a[n]? [\w\s-]{0,40}(assistant|model|cybersecurity)/i,
  llm_api_traffic: /api\.openai\.com|api\.anthropic\.com|huggingface\.co\/.*inference/i,
}
const AI_ORCHESTRATION = /model context protocol|\bMCP\b[\w\s-]{0,20}(server|orchestrat)|thousands of requests? per second|agentic operator/i

export function detectAiDegree(verdict) {
  // explicit producer field wins if present (future-proofing)
  const declared = verdict.ai_assessment?.degree
  if (declared) return { degree: declared, indicators: verdict.ai_assessment?.indicators ?? [], source: "declared" }

  const hay = JSON.stringify({
    findings: verdict.findings ?? [],
    file_paths: verdict.indicators?.file_paths ?? [],
    urls: verdict.indicators?.urls ?? [],
    domains: verdict.indicators?.domains ?? [],
    story: verdict.attack_story ?? {},
  })
  const indicators = Object.entries(AI_SIGNATURES)
    .filter(([, re]) => re.test(hay))
    .map(([name]) => name)
  const orchestrated = AI_ORCHESTRATION.test(hay)
  const degree = orchestrated ? "AI-orchestrated" : indicators.length ? "AI-present" : "none"
  return { degree, indicators, source: "inferred" }
}

// ---- the four axes ----

function scoreMitre(verdict, oracle) {
  const observed = observedTechniques(verdict)
  const cvesSeen = observedCves(verdict)
  const results = []
  let techHit = 0
  for (const stage of oracle.attack_chain ?? []) {
    const t = stage.technique ?? {}
    const aliases = (t.aliases?.length ? t.aliases : [t.attack_id]).map((x) => String(x).toUpperCase())
    const hit = aliases.some((a) => observed.has(a))
    if (hit) techHit++
    results.push({ technique: t.attack_id, status: hit ? "HIT" : "MISS" })
  }
  const cveResults = []
  let cveHit = 0
  for (const stage of oracle.attack_chain ?? []) {
    for (const c of stage.cves ?? []) {
      const hit = cvesSeen.has(String(c).toUpperCase())
      if (hit) cveHit++
      cveResults.push({ cve: c, status: hit ? "HIT" : "MISS" })
    }
  }
  const totalTech = (oracle.attack_chain ?? []).length
  const totalCve = cveResults.length
  return {
    techniques: results,
    cves: cveResults,
    tech_recall: totalTech ? techHit / totalTech : 1,
    cve_recall: totalCve ? cveHit / totalCve : 1,
    total: totalTech + totalCve,
    hit: techHit + cveHit,
  }
}

function expectedIocs(oracle) {
  const unscored = new Set(oracle.unscored_ioc_types ?? [])
  const out = []
  for (const stage of oracle.attack_chain ?? []) {
    for (const a of stage.artifacts ?? []) {
      const ioc = a.ioc
      if (!ioc || unscored.has(ioc.type)) continue
      out.push({ artifact_id: a.artifact_id, type: ioc.type, value: ioc.value })
    }
  }
  return out
}

function scoreIocs(verdict, oracle) {
  const ind = verdict.indicators ?? {}
  const results = []
  let hit = 0
  const unscoredPlanted = []
  const unscored = new Set(oracle.unscored_ioc_types ?? [])
  for (const stage of oracle.attack_chain ?? []) {
    for (const a of stage.artifacts ?? []) {
      if (a.ioc && unscored.has(a.ioc.type)) unscoredPlanted.push({ artifact_id: a.artifact_id, type: a.ioc.type })
    }
  }
  for (const exp of expectedIocs(oracle)) {
    const category = IOC_TYPE_TO_CATEGORY[exp.type]
    const emitted = (ind[category] ?? []).map(norm)
    const want = norm(exp.value)
    const found =
      emitted.includes(want) ||
      // file/process are basename-vs-fullpath ambiguous; also try basename match
      ((exp.type === "file" || exp.type === "process") && emitted.some((e) => basename(e) === basename(exp.value)))
    if (found) hit++
    results.push({ artifact_id: exp.artifact_id, type: exp.type, value: exp.value, status: found ? "RECOVERED" : "MISS" })
  }
  return {
    results,
    recall: results.length ? hit / results.length : 1,
    total: results.length,
    hit,
    // precision needs a fully-labeled benign IOC baseline the producer does not emit — deferred.
    precision: null,
    unscored_planted: unscoredPlanted,
  }
}

function techMatch(oracleStage, runStage) {
  const t = oracleStage.technique ?? {}
  const aliases = (t.aliases?.length ? t.aliases : [t.attack_id]).map((x) => String(x).toUpperCase())
  const runTech = String(runStage.mitre_technique ?? "").toUpperCase()
  const sameTech = aliases.includes(runTech)
  const samePhase = norm(oracleStage.phase) === norm(runStage.phase)
  return sameTech && samePhase
}

function scoreChain(verdict, oracle) {
  const oracleStages = [...(oracle.attack_chain ?? [])].sort((a, b) => (a.chain_order ?? 0) - (b.chain_order ?? 0))
  const runStages = verdict.attack_story?.attack_chain ?? []
  const matches = [] // {oracleOrder, runOrder}
  for (const os of oracleStages) {
    const rs = runStages.find((r) => techMatch(os, r))
    matches.push({ oracle_order: os.chain_order, phase: os.phase, technique: os.technique?.attack_id, matched: !!rs, run_order: rs?.order ?? null })
  }
  const matched = matches.filter((m) => m.matched)
  const coverage = oracleStages.length ? matched.length / oracleStages.length : 1
  // ordering: adjacent-pair concordance over matched stages (does the run preserve the sequence?)
  let concordant = 0
  let pairs = 0
  for (let i = 1; i < matched.length; i++) {
    pairs++
    if ((matched[i].run_order ?? 0) > (matched[i - 1].run_order ?? 0)) concordant++
  }
  const ordering = pairs ? concordant / pairs : 1
  return { stages: matches, coverage, ordering, matched: matched.length, total: oracleStages.length }
}

export function scoreImageRun(verdict, oracle) {
  const mitre = scoreMitre(verdict, oracle)
  const iocs = scoreIocs(verdict, oracle)
  const chain = scoreChain(verdict, oracle)
  const ai = detectAiDegree(verdict)
  const provenance = detectProvenance(verdict)
  const verdictBand = {
    got: verdict.verdict ?? null,
    expected: oracle.expected_verdict_band ?? null,
    match: (verdict.verdict ?? null) === (oracle.expected_verdict_band ?? null),
  }
  const aiMatch = oracle.expected_ai_degree ? ai.degree === oracle.expected_ai_degree : null
  return {
    case: oracle.case ?? null,
    axes: {
      mitre: { recall: (mitre.total ? mitre.hit / mitre.total : 1), ...mitre },
      ioc_recovery: iocs,
      chain_reconstruction: chain,
      verdict_band: verdictBand,
    },
    ai_degree: { ...ai, expected: oracle.expected_ai_degree ?? null, match: aiMatch },
    llm_provenance: provenance,
  }
}

export function loadOracle(path) {
  return JSON.parse(readFileSync(path, "utf8"))
}

function main() {
  const argv = process.argv.slice(2)
  const verdictPath = argv.find((a) => !a.startsWith("--"))
  const oracleFlag = argv.indexOf("--oracle")
  const requireLlm = argv.includes("--require-llm")
  if (!verdictPath || oracleFlag < 0) {
    console.error("usage: score-image-run.mjs <verdict.json> --oracle <ground-truth.json> [--require-llm]")
    process.exit(2)
  }
  const verdict = JSON.parse(readFileSync(verdictPath, "utf8"))
  const oracle = loadOracle(argv[oracleFlag + 1])
  const r = scoreImageRun(verdict, oracle)
  const pct = (x) => `${Math.round((x ?? 0) * 100)}%`
  console.log(`case:            ${r.case}`)
  console.log(`MITRE:           ${pct(r.axes.mitre.recall)} (${r.axes.mitre.hit}/${r.axes.mitre.total})`)
  console.log(`IOC recovery:    recall ${pct(r.axes.ioc_recovery.recall)} (${r.axes.ioc_recovery.hit}/${r.axes.ioc_recovery.total}); unscored ${r.axes.ioc_recovery.unscored_planted.length}`)
  console.log(`chain:           coverage ${pct(r.axes.chain_reconstruction.coverage)}, ordering ${pct(r.axes.chain_reconstruction.ordering)}`)
  console.log(`verdict band:    ${r.axes.verdict_band.got} vs ${r.axes.verdict_band.expected} — ${r.axes.verdict_band.match ? "match" : "MISMATCH"}`)
  console.log(`AI-degree:       ${r.ai_degree.degree} [${r.ai_degree.indicators.join(", ")}]${r.ai_degree.expected ? ` (expected ${r.ai_degree.expected})` : ""}`)
  console.log(`llm_provenance:  ${r.llm_provenance.kind}`)
  console.log(JSON.stringify({ case: r.case, ...r }))
  if (requireLlm && r.llm_provenance.llm !== true) {
    console.error(`FAIL: --require-llm set but provenance is '${r.llm_provenance.kind}'`)
    process.exit(1)
  }
  process.exit(0)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
