export const meta = {
  name: 'judging-readiness-audit',
  description: 'Audit this VERDICT submission against the official June-2026 Find Evil! Judge Pack (read-only)',
  whenToUse: 'Before the hackathon deadline, to score the 6 judging criteria (1-5 stars, Judge Pack anchors) + Stage-One deliverables and surface the highest-leverage gaps to fix.',
  phases: [
    { title: 'Inventory', detail: 'Appendix-A Stage-One checks against the PUBLIC remote + viability flags' },
    { title: 'Score', detail: 'score each of the 6 Stage-Two criteria 1-5 stars with cited evidence' },
    { title: 'Verify', detail: 'adversarially refute each criterion score' },
    { title: 'Runtime', detail: 'three-claim trace + live-test gate on the newest existing run' },
    { title: 'Synthesize', detail: 'scorecard + winning-edge brief to tmp/judging-audit/' },
  ],
}

// Grounded in the official judge documents (read 2026-06-12): FindEvil_Judge_Pack.pdf
// (Appendix A Stage-One prompt, Appendix B judge-assist prompt), Judge QuickReference,
// Submission Self-Check, Judge Survival Scratchpad (~4,000-entrant field).
// Judges score 1-5 stars, equal weight, with a CASCADING TIEBREAKER in criteria order
// below; they judge the repo AS IT STOOD June 15, 11:45 PM EDT (the public remote, not a
// local tree); the three-claim trace is non-negotiable; staged self-correction is "the
// predictable gaming vector"; documented caught hallucinations count FOR the team.

// ---------- shared schema fragments ----------
const EVIDENCE = {
  type: 'object',
  additionalProperties: false,
  properties: {
    claim: { type: 'string' },
    path: { type: 'string' },
    lines: { type: 'string', description: 'e.g. "59-83" or "n/a"' },
    kind: { type: 'string', enum: ['code-enforced', 'runtime-demonstrated', 'doc-only'] },
  },
  required: ['claim', 'path', 'lines', 'kind'],
}
const GAP = {
  type: 'object',
  additionalProperties: false,
  properties: {
    gap: { type: 'string' },
    severity: { type: 'string', enum: ['blocker', 'major', 'minor'] },
    fix: { type: 'string', description: 'concrete, one-line remediation' },
  },
  required: ['gap', 'severity', 'fix'],
}

// ---------- the six Stage-Two criteria, in OFFICIAL TIEBREAK ORDER ----------
const CRITERIA = [
  { key: 'autonomous_execution', name: 'Autonomous Execution Quality',
    ask: 'Does the agent reason about next steps, handle failures, and self-correct in REAL TIME?',
    starAnchors: '1 = fixed pipeline (tool, output, next tool regardless of what came back) or a scripted retry; 3 = reacts to failures (retries with adjusted parameters, pivots tools), ONE genuine self-correction, but the overall plan is static; 5 = visibly reasons — forms a hypothesis, picks tools to test it, recognizes when results do not add up, re-sequences the investigation mid-run, full arc in the logs ("you would trust its next move at 3 AM"). FIRST in the tiebreak cascade — this criterion decides prizes.',
    anchors: 'agent-config/HEARTBEAT.md; services/agent_mcp/findevil_agent_mcp/tools/detect_contradictions.py; .../verify_finding.py; agent-config/AGENTS.md (ACH, Pool A vs B); course_correction records emitted by scripts/find_evil_auto.py; agent-config/PLAYBOOK.md; audit.jsonl files under docs/sample-run/ and tmp/auto-runs/',
    knownGap: 'STAGED SELF-CORRECTION SCREEN: the Judge Pack calls a contrived error with an instant clean fix "the predictable gaming vector". docs/sample-run/fault-injection-redispatch and the verifier_hash_mismatch_once mode are BY NAME injected conditions — verify they are honestly labeled as harness/fault-injection tests and are NOT presented as the submission\'s self-correction evidence; then look for a NATURAL correction arc (genuine tool error -> adjusted parameters -> recovery -> re-sequenced plan) in a real run\'s audit.jsonl. Separately: HEARTBEAT escalation ("2 consecutive failures -> terminate") is documented but no enforcement found in find_evil_auto.py.' },
  { key: 'ir_accuracy', name: 'IR Accuracy',
    ask: 'Are findings correct? Hallucinations caught/flagged? CONFIRMED distinguished from inferences?',
    starAnchors: '1 = findings do not trace to tool executions, or an UNFLAGGED hallucination found, or confirmed evidence blended with inference; 3 = findings trace cleanly, CONFIRMED vs INFERRED labeled, but the accuracy report is thin (vague about false positives, no test methodology); 5 = every claim traces, labeling is rigorous, and the accuracy report is genuinely self-critical — SPECIFIC false positives, SPECIFIC misses, SPECIFIC hallucinations caught during testing, methodology described ("would survive opposing counsel"). THE ASYMMETRY: hallucinations the team caught and documented count FOR them ("Honesty valued over perfection"); confident wrong answers get zero partial credit. SECOND in the tiebreak cascade.',
    anchors: 'agent-config/SOUL.md (CONFIRMED>INFERRED>HYPOTHESIS); docs/accuracy-report.md (must name specific FPs/misses/caught hallucinations + methodology + an evidence-integrity section); docs/false-positives.md; services/agent_mcp/findevil_agent_mcp/tools/correlate_findings.py (>=2-artifact rule); agent-config/expert-rules.json (execution-needs-2-classes blocker); .../verify_finding.py (replay); agent-config/GROUNDING.md',
    knownGap: 'expert-rules.json is metadata; runtime enforcement not visible. Amcache-alone downgrade lives in unread services/agent/. Accuracy report must be checked for SPECIFICS, not just existence — thin reports anchor at 3 stars.' },
  { key: 'breadth_depth', name: 'Breadth and Depth of Analysis',
    ask: 'How much case data can it handle (disk, memory, logs, network, remote endpoints) and how DEEP does it go on each? Depth on fewer types beats shallow coverage of many; cross-source correlation (e.g. disk vs memory discrepancy detection) is a DEPTH signal.',
    anchors: 'agent-config/TOOLS.md (20 Rust + 12 Python); agent-config/PLAYBOOK.md (per-evidence-type sequences); agent-config/AGENTS.md (Pool A persistence / Pool B exfil); agent-config/MEMORY.md (artifact caveats); services/agent/findevil_agent/playbook.py (TOOL_SEQUENCES); fleet correlation (scripts/fleet_correlate.py, docs/using/fleet-analysis.md)',
    knownGap: 'Raw disk is custody-only without manual mount; no browser/cloud/mobile/OT coverage.' },
  { key: 'constraint_impl', name: 'Constraint Implementation',
    ask: 'Are guardrails ARCHITECTURAL or prompt-based? An MCP server that only exposes typed, read-only functions (the agent physically cannot run destructive commands) is architectural; a system prompt instructing the model to be careful is prompt-based. Where are boundaries enforced, and WERE THEY TESTED FOR BYPASS? If anything is prompt-based, did the team test and document what happens when the model ignores the restriction? Is original evidence protected by design, with all processing on copies?',
    anchors: 'agent-config/TOOLS.md (no execute_shell); services/mcp/src/tools/mod.rs; services/mcp/src/server.rs (JSON-RPC schema validation, read-only annotations); services/mcp/src/tools/vel_collect.rs (arg-key validation blocks flag injection); docs/architecture.md (trust boundaries 0-5, marked)',
    knownGap: 'No visible adversarial bypass tests (path traversal, shell injection, symlink). The Judge Pack asks the bypass question LITERALLY — untested boundaries cap this criterion.' },
  { key: 'audit_trail', name: 'Audit Trail Quality',
    ask: 'Can a judge trace ANY finding back to the specific tool execution that produced it? Are logs structured, timestamped, and COMPLETE for the architecture type — multi-agent builds need agent-to-agent message logs (Pool A/B handoffs), single-agent builds need token usage, persistent loops need iteration traces? Could another analyst reconstruct the case from logs alone? Does log content match what the demo video shows ("must function as depicted in the video")?',
    anchors: 'services/agent_mcp/findevil_agent_mcp/tools/audit_append.py (hash chain, prev_hash); .../manifest_finalize.py (rs_merkle + sigstore/ed25519); .../manifest_verify.py (offline verify); agent-config/expert-rules.json (tool_call_id required); docs/cryptographic-attestation.md (FRE 902(14)); docs/sample-run/*/audit.jsonl (pool_handoff records, timestamps)',
    knownGap: 'Merkle recompute path hard to read; Hermes memory ledger is separate from the Merkle tree. Verify pool A/B agent-to-agent records are actually visible in COMMITTED sample logs (Appendix A Check 10).' },
  { key: 'usability_docs', name: 'Usability and Documentation',
    ask: 'Can another practitioner deploy and build on this? Could they deploy it from the README today? Is the architecture documented well enough for community extension (winning code goes back into the open-source Protocol SIFT toolset)?',
    anchors: 'README.md; QUICKSTART.md; scripts/install.sh; scripts/setup; docs/onboarding.md; agent-config/*; CLAUDE.md; SUBMISSION_COMPLIANCE.md; docs/using/',
    knownGap: 'Gated SANS SIFT OVA download is a friction point; verify troubleshooting docs exist (docs/troubleshooting.md).' },
]

const SCORE_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    criterion: { type: 'string' },
    score: { type: 'integer', minimum: 1, maximum: 5 },
    rationale: { type: 'string' },
    evidence: { type: 'array', items: EVIDENCE, minItems: 1 },
    gaps: { type: 'array', items: GAP },
    winningEdge: { type: 'string', description: 'what about this criterion could differentiate us toward 1st, or "" if none' },
  },
  required: ['criterion', 'score', 'rationale', 'evidence', 'gaps', 'winningEdge'],
}
const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    criterion: { type: 'string' },
    refutations: { type: 'array', items: { type: 'string' }, description: 'where the score is over-claimed, esp. doc-only passed off as enforced' },
    adjustedScore: { type: 'integer', minimum: 1, maximum: 5 },
    adjustmentReason: { type: 'string' },
  },
  required: ['criterion', 'refutations', 'adjustedScore', 'adjustmentReason'],
}

// ========================= PHASE 1: INVENTORY =========================
phase('Inventory')
const REQS_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    requirements: { type: 'array', items: {
      type: 'object', additionalProperties: false,
      properties: {
        requirement: { type: 'string' },
        status: { type: 'string', enum: ['present', 'partial', 'missing'] },
        path: { type: 'string' },
        gap: { type: 'string' },
        severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'none'] },
      },
      required: ['requirement', 'status', 'path', 'gap', 'severity'],
    } },
  },
  required: ['requirements'],
}
const STAGE_ONE_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    pass: { type: 'boolean' },
    reasons: { type: 'array', items: { type: 'string' } },
    risks: { type: 'array', items: { type: 'string' } },
  },
  required: ['pass', 'reasons', 'risks'],
}

const [requirements, stageOne] = await parallel([
  () => agent(
    `You are running the Find Evil! Stage-One qualification checks (Judge Pack Appendix A) against this submission. ONE FAIL on checks 1-10 means elimination. Judges see the PUBLIC remote github.com/TimothyVang/verdict-dfir as it stood at the June 15, 11:45 PM EDT deadline — so check the REMOTE state (use read-only "gh repo view", "gh api repos/TimothyVang/verdict-dfir/...", "gh release view v-submit --repo TimothyVang/verdict-dfir") and note where the local tree diverges from it. Read-only; do not edit or push. The checks, each becoming one requirements[] entry:\n` +
    `(1) repo public, loads without auth; (2) LICENSE at root is MIT or Apache-2.0 AND GitHub detects it in the About badge (licenseInfo non-null); (3) README has real setup instructions (prereqs, install steps, how to run); (4) demo video <=5 min, hosted on YouTube/Vimeo/Youku and publicly visible, linked from Devpost AND README, screencast of live terminal execution with narration showing >=1 self-correction sequence — a GitHub release asset ALONE does not satisfy the hosting rule; the README/SUBMISSION_COMPLIANCE must surface the hosted URL; (5) architecture diagram showing agent + SIFT tools + MCP servers + evidence sources + output pipeline, naming which of the 4 patterns (Direct Agent Extension / Custom MCP Server / Multi-Agent Framework / Alternative Agentic IDE) and marking trust boundaries, distinguishing prompt-based vs architectural guardrails; (6) written project description (Devpost story format — cannot verify Devpost from here: mark partial with gap "verify on Devpost" unless a committed copy exists); (7) evidence dataset documentation (what tested on, source, what the agent found — docs/DATASET.md); (8) accuracy report addressing false positives, missed artifacts, hallucinated claims found in testing, AND an evidence-integrity section (how the architecture prevents evidence modification); missing the evidence-integrity section entirely = FAIL; (9) try-it-out instructions a judge can follow locally with dependencies documented, free and unrestricted through end of judging; (10) agent execution logs IN THE REPO, structured + timestamped; VERDICT is multi-agent so agent-to-agent message logs (Pool A/B handoff records) must be visible in committed logs (docs/sample-run/*/audit.jsonl); spot-check one finding traces to its tool execution.\n` +
    `Plus LOG-VS-VIDEO CONSISTENCY: the project "must function as depicted in the video" — compare the demo beats (docs/demo-script-a2.md or scripts/make-demo-video/) against committed logs/runs; any video claim not reproducible from logs is a "major" gap.\n` +
    `Open every file you cite. severity "blocker" = would fail Stage One.`,
    { label: 'inventory:appendix-a', phase: 'Inventory', schema: REQS_SCHEMA }
  ),
  () => agent(
    `You are checking Find Evil! STAGE-ONE viability + the Appendix-A integrity flags (checks 11-12; flags, not verdicts) for this repo, READ-ONLY. (a) Theme fit: extends Protocol SIFT autonomous IR on SIFT/Linux with Claude Code as the PRIMARY engine, not a bolt-on; (b) the three mandatory Project Requirements, each a FLOOR on its criterion: self-correction without human intervention, accuracy validation with findings traceable to specific artifacts/files/offsets/log entries, analytical reasoning presented as a structured investigative narrative rather than a raw execution log; (c) DQ flags: thin LLM wrapper with no agentic behavior? no real case data analyzed? dependent on proprietary tools/paid services a judge cannot access (SANS-gated SIFT OVA counts only if there is a no-VM fallback — check docs/using/whole-case-local-run.md)? (d) deadline scope: does any headline claim or the demo depend on commits AFTER June 15 23:45 EDT, or on local-only work not pushed to the public verdict-dfir remote (check: the demo-video refresh on feat/find-evil-live-launcher, unmerged to master)? Read CLAUDE.md, docs/architecture.md, README.md, agent-config/SOUL.md, agent-config/AGENTS.md, docs/sample-run/README.md, SUBMISSION_COMPLIANCE.md. Return pass + concrete reasons + every risk worth flagging.`,
    { label: 'inventory:viability', phase: 'Inventory', schema: STAGE_ONE_SCHEMA }
  ),
])

// ============= PHASE 2+3: SCORE -> VERIFY (pipeline) + PHASE 4 runtime in parallel =============
phase('Score')
const scorePromise = pipeline(
  CRITERIA,
  // stage 1: score
  (c) => agent(
    `Score the Find Evil! Stage-Two criterion **${c.name}** for this repo, READ-ONLY, on the judges' 1-5 STAR scale. The judge's question: "${c.ask}". Official star anchors${c.starAnchors ? `: ${c.starAnchors}` : ' follow the generic scale'}. Calibration (Judge Pack): 5 = best in a ~4,000-entrant pool and engagement-ready; 3 = competent, unremarkable; 1 = barely addressed; most teams run the same Claude Code + MCP + SIFT stack, so polish clusters and the real spread is guardrail architecture, accuracy honesty, and log quality. DO NOT default to 4. Known evidence anchors (verify them, do not take on faith): ${c.anchors}. Known suspected gap to test: ${c.knownGap}. For each piece of evidence you cite, OPEN the file, give path + line range, and tag its kind: "code-enforced" (the guarantee is in compiled/executed code), "runtime-demonstrated" (an actual run artifact under docs/sample-run, tmp/auto-runs or out/auto-runs shows it happening), or "doc-only" (only asserted in markdown/config, no enforcing code located). Scoring discipline: a criterion backed mostly by doc-only evidence caps at 3 stars; 4-5 requires code-enforced or runtime-demonstrated evidence. List concrete gaps with severity + a one-line fix. State the single highest-leverage thing about this criterion that could push us toward 1st place (winningEdge), or "" if none.`,
    { label: `score:${c.key}`, phase: 'Score', schema: SCORE_SCHEMA }
  ),
  // stage 2: adversarial verify
  (scored, c) => agent(
    `Adversarially REFUTE this 1-5 star score for the Find Evil! criterion **${c.name}**, acting as the most skeptical judge on the panel. Default to skepticism. Open every file:line the scorer cited and check the claim actually holds THERE — especially evidence tagged "doc-only" or "code-enforced": confirm the code really enforces it (e.g. expert-rules.json blockers need enforcing code; a markdown invariant is not enforcement; an unread services/agent/ path is not proof). Penalize traceability claims that cannot be followed end to end, self-correction evidence whose triggering error looks injected rather than natural (the "staged self-correction" gaming vector), and any reliance on the demo video (the least trustworthy artifact). Here is the scorer's output as JSON: ${JSON.stringify(scored)}. Return refutations (empty if the score holds), an adjustedScore (lower than the original only if you found over-claiming; never raise it), and a one-line adjustmentReason.`,
    { label: `verify:${c.key}`, phase: 'Verify', schema: VERDICT_SCHEMA }
  ).then((v) => ({ ...c, scored, verdict: v }))
)

// ========================= PHASE 4: RUNTIME EVIDENCE =========================
const TRACE_ITEM = {
  type: 'object', additionalProperties: false,
  properties: {
    source: { type: 'string', description: 'run dir or sample-run case the finding came from' },
    finding: { type: 'string' },
    toolCallId: { type: 'string' },
    auditLine: { type: 'string', description: 'audit.jsonl path + line number where the tool execution lives, or "not found"' },
    verdict: { type: 'string', enum: ['supported', 'unsupported', 'could-not-locate'] },
  },
  required: ['source', 'finding', 'toolCallId', 'auditLine', 'verdict'],
}
const RUNTIME_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    runFound: { type: 'boolean' },
    runPath: { type: 'string' },
    manifestOverall: { type: 'boolean' },
    allFindingsCiteToolCallId: { type: 'boolean' },
    verdictWord: { type: 'string' },
    verdictHonestAboutCoverage: { type: 'boolean' },
    threeClaimTrace: { type: 'array', items: TRACE_ITEM, minItems: 3, description: 'the judges\' non-negotiable check, executed exactly as they will' },
    threeClaimTracePass: { type: 'boolean', description: 'false if ANY trace item is not "supported" — that is an automatic blocker ("a submission that fails the trace is done")' },
    naturalSelfCorrectionFound: { type: 'boolean', description: 'a genuine (non-injected) error -> adjusted parameters -> recovery arc located in a real run audit.jsonl' },
    selfCorrectionNote: { type: 'string' },
    selfScorePresent: { type: 'boolean' },
    recallPercent: { type: 'integer' },
    liveTestGatePass: { type: 'boolean' },
    note: { type: 'string' },
  },
  required: ['runFound', 'runPath', 'manifestOverall', 'allFindingsCiteToolCallId', 'verdictWord', 'verdictHonestAboutCoverage', 'threeClaimTrace', 'threeClaimTracePass', 'naturalSelfCorrectionFound', 'selfCorrectionNote', 'selfScorePresent', 'recallPercent', 'liveTestGatePass', 'note'],
}
const runtimePromise = (async () => {
  phase('Runtime')
  return agent(
    `READ-ONLY: assess whether REAL completed runs back the runtime-heavy criteria, and execute the judges' THREE-CLAIM TRACE exactly as the Judge Pack prescribes. (1) Glob tmp/auto-runs/*/ and out/auto-runs/*/ ; pick the newest dir with verdict.json; grade it against VERDICT's 4-point live-test gate: pipeline ran past case_open (non-empty audit.jsonl tool chain); EVERY entry in verdict.json findings[] cites a tool_call_id; manifest_verify.json overall == true (read the file); the verdict word is honest about coverage. (2) THREE-CLAIM TRACE: pick 3 findings — at least one from the newest run and at least one from the flagship committed case under docs/sample-run/ (judges only see committed logs) — and for each, locate the SPECIFIC tool execution in the corresponding audit.jsonl that produced it (match the tool_call_id, quote path + line number). Mark each supported / unsupported / could-not-locate. ANY non-supported item makes threeClaimTracePass=false — the Judge Pack says a submission that fails the trace is done. (3) SELF-CORRECTION: search the real runs' audit.jsonl (NOT the fault-injection sample, which is an injected condition) for a natural correction arc: genuine tool error -> adjusted parameters/pivoted tool -> recovery, or a re-sequenced plan; report what you found in selfCorrectionNote. (4) Report self-score.json presence and recall-score.json recall_percent if present (else -1). If NO run dir with verdict.json exists, set runFound=false and note the strongest remaining move is to capture a fresh real run — but do NOT run anything yourself.`,
    { label: 'runtime:trace+gate', phase: 'Runtime', schema: RUNTIME_SCHEMA }
  )
})()

const [verified, runtime] = await Promise.all([scorePromise, runtimePromise])
const scored = verified.filter(Boolean)

// ========================= PHASE 5: SYNTHESIZE =========================
phase('Synthesize')
const SCORECARD_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    stageOnePass: { type: 'boolean' },
    perCriterion: { type: 'array', items: {
      type: 'object', additionalProperties: false,
      properties: { criterion: { type: 'string' }, stars: { type: 'integer', minimum: 1, maximum: 5 }, why: { type: 'string' } },
      required: ['criterion', 'stars', 'why'],
    } },
    totalOutOf30: { type: 'integer' },
    normalizedPercent: { type: 'integer' },
    deliverableBlockers: { type: 'array', items: { type: 'string' } },
    prioritizedGaps: { type: 'array', items: {
      type: 'object', additionalProperties: false,
      properties: { gap: { type: 'string' }, severity: { type: 'string' }, hurtsCriterion: { type: 'string' }, fix: { type: 'string' } },
      required: ['gap', 'severity', 'hurtsCriterion', 'fix'],
    } },
    winningEdge: { type: 'array', items: { type: 'string' }, description: 'existing differentiators that already point toward 1st' },
    topMovesToWin: { type: 'array', items: { type: 'string' }, minItems: 2, maxItems: 4, description: 'highest-leverage moves to convert "passes" into "wins 1st"' },
    reportPath: { type: 'string' },
  },
  required: ['stageOnePass', 'perCriterion', 'totalOutOf30', 'normalizedPercent', 'deliverableBlockers', 'prioritizedGaps', 'winningEdge', 'topMovesToWin', 'reportPath'],
}
const scorecard = await agent(
  `You are the synthesizer for a Find Evil! 1st-place readiness audit, judged per the official June-2026 Judge Pack: six criteria, 1-5 stars, equal weight, CASCADING TIEBREAKER in this order — Autonomous Execution Quality, IR Accuracy, Breadth & Depth, Constraint Implementation, Audit Trail Quality, Usability & Docs (near the top of a ~4,000-entrant pool, precision on the first two decides prizes). Combine these inputs and WRITE a markdown report, then return the scorecard JSON.\n\n` +
  `APPENDIX-A STAGE-ONE CHECKS: ${JSON.stringify(requirements)}\n\n` +
  `VIABILITY + INTEGRITY FLAGS: ${JSON.stringify(stageOne)}\n\n` +
  `SIX VERIFIED CRITERIA in tiebreak order (each has the scorer output + the adversarial verdict; USE verdict.adjustedScore as the stars of record): ${JSON.stringify(scored.map((s) => ({ criterion: s.name, scored: s.scored, verdict: s.verdict })))}\n\n` +
  `RUNTIME GATE + THREE-CLAIM TRACE: ${JSON.stringify(runtime)}\n\n` +
  `Compute totalOutOf30 = sum of the six adjusted star scores; normalizedPercent = round(total/30*100). Build prioritizedGaps ordered Stage-One blockers first, then by TIEBREAK ORDER of the criterion each gap hurts (an Autonomous-Execution gap outranks an Audit-Trail gap at equal severity), deduped across criteria. deliverableBlockers = any Appendix-A check at severity blocker (a failed three-claim trace is ALWAYS a blocker; a video not hosted on YouTube/Vimeo/Youku, a missing evidence-integrity section, or undetectable license are hard Stage-One gates — surface them loudly). winningEdge = differentiators already present (e.g. cryptographic chain of custody / FRE 902(14) offline verification; narrow typed tool surface with NO execute_shell as an ARCHITECTURAL constraint; ACH competing-hypotheses Pool A/B topology; >=2-artifact corroboration rule; documented caught-hallucination honesty, which the rules explicitly reward). topMovesToWin = the 2-4 highest-leverage moves ranked by tiebreak impact; if no NATURAL self-correction arc was found in real runs, elevating one into a committed sample run is almost certainly move #1, because Criterion 1 is the tiebreaker and staged corrections are discounted.\n\n` +
  `Write the report to tmp/judging-audit/judging-readiness-report.md (create the dir; this is scratch, not repo source) with sections: Verdict (are we 1st-place ready in a ~4,000 pool? one honest paragraph, tiebreaker read included), Stage-One (Appendix-A table), Scorecard table (criterion | stars/5 | evidence kind summary), Three-claim trace results, Prioritized gaps, Winning-edge brief, Top moves to win. Also write tmp/judging-audit/scorecard.json with the returned object. Set reportPath to the markdown path. Be honest and calibrated — this is for us, not the judges.`,
  { label: 'synthesize', phase: 'Synthesize', schema: SCORECARD_SCHEMA }
)

log(`Readiness: ${scorecard.normalizedPercent}% (${scorecard.totalOutOf30}/30 stars). Report: ${scorecard.reportPath}`)
return scorecard
