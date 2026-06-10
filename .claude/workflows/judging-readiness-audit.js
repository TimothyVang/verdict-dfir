export const meta = {
  name: 'judging-readiness-audit',
  description: 'Audit this VERDICT submission against the SANS Find Evil! 1st-place criteria (read-only)',
  whenToUse: 'Before the hackathon deadline, to score the 6 judging criteria + submission deliverables and surface the highest-leverage gaps to fix.',
  phases: [
    { title: 'Inventory', detail: 'submission deliverables + Stage-One viability' },
    { title: 'Score', detail: 'score each of the 6 Stage-Two criteria with cited evidence' },
    { title: 'Verify', detail: 'adversarially refute each criterion score' },
    { title: 'Runtime', detail: 'grade the newest existing run vs the live-test gate' },
    { title: 'Synthesize', detail: 'scorecard + winning-edge brief to tmp/judging-audit/' },
  ],
}

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

// ---------- the six Stage-Two criteria with known evidence anchors ----------
const CRITERIA = [
  { key: 'autonomous_execution', name: 'Autonomous Execution Quality',
    ask: 'Does the agent reason about next steps, handle failures, and self-correct in REAL TIME?',
    anchors: 'agent-config/HEARTBEAT.md; services/agent_mcp/findevil_agent_mcp/tools/detect_contradictions.py; .../verify_finding.py; agent-config/AGENTS.md (ACH, Pool A vs B); course_correction records emitted by scripts/find_evil_auto.py; agent-config/PLAYBOOK.md',
    knownGap: 'HEARTBEAT escalation ("2 consecutive failures -> terminate") is documented but no enforcement found in find_evil_auto.py.' },
  { key: 'ir_accuracy', name: 'IR Accuracy',
    ask: 'Are findings correct? Hallucinations caught/flagged? CONFIRMED distinguished from inferences?',
    anchors: 'agent-config/SOUL.md (CONFIRMED>INFERRED>HYPOTHESIS); services/agent_mcp/findevil_agent_mcp/tools/correlate_findings.py (>=2-artifact rule); agent-config/expert-rules.json (execution-needs-2-classes blocker); .../verify_finding.py (replay); agent-config/GROUNDING.md',
    knownGap: 'expert-rules.json is metadata; runtime enforcement not visible. Amcache-alone downgrade lives in unread services/agent/.' },
  { key: 'breadth_depth', name: 'Breadth and Depth of Analysis',
    ask: 'How much case data can it handle? Depth on fewer types beats shallow coverage of many.',
    anchors: 'agent-config/TOOLS.md (19 Rust + 12 Python); agent-config/PLAYBOOK.md (per-evidence-type sequences); agent-config/AGENTS.md (Pool A persistence / Pool B exfil); agent-config/MEMORY.md (artifact caveats); services/agent/findevil_agent/playbook.py (TOOL_SEQUENCES)',
    knownGap: 'Raw disk is custody-only without manual mount; no browser/cloud/mobile/OT coverage.' },
  { key: 'constraint_impl', name: 'Constraint Implementation',
    ask: 'Are guardrails ARCHITECTURAL or prompt-based? Where are boundaries enforced; were they tested for bypass?',
    anchors: 'agent-config/TOOLS.md (no execute_shell); services/mcp/src/tools/mod.rs; services/mcp/src/server.rs (JSON-RPC schema validation, read-only annotations); services/mcp/src/tools/vel_collect.rs (arg-key validation blocks flag injection)',
    knownGap: 'No visible adversarial bypass tests (path traversal, shell injection, symlink).' },
  { key: 'audit_trail', name: 'Audit Trail Quality',
    ask: 'Can a judge trace ANY finding back to the specific tool execution that produced it?',
    anchors: 'services/agent_mcp/findevil_agent_mcp/tools/audit_append.py (hash chain, prev_hash); .../manifest_finalize.py (rs_merkle + sigstore); .../manifest_verify.py (offline verify); agent-config/expert-rules.json (tool_call_id required); docs/cryptographic-attestation.md (FRE 902(14))',
    knownGap: 'Merkle recompute path hard to read; Hermes memory ledger is separate from the Merkle tree.' },
  { key: 'usability_docs', name: 'Usability and Documentation',
    ask: 'Can another practitioner deploy and build on this?',
    anchors: 'README.md; QUICKSTART.md; scripts/install.sh; scripts/setup; docs/onboarding.md; agent-config/*; CLAUDE.md; SUBMISSION_COMPLIANCE.md',
    knownGap: 'No troubleshooting/FAQ; gated SANS SIFT OVA download is a friction point.' },
]

const SCORE_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    criterion: { type: 'string' },
    score: { type: 'integer', minimum: 0, maximum: 10 },
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
    adjustedScore: { type: 'integer', minimum: 0, maximum: 10 },
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
    `You are auditing the SANS "Find Evil!" hackathon submission in this repo for SUBMISSION-DELIVERABLE compliance (read-only; do not edit). For EACH required deliverable verify it actually exists and is substantive (open the file). Deliverables: (1) public repo with MIT/Apache-2.0 LICENSE at root; (2) README with setup instructions; (3) text description of features; (4) demo video <5min, live terminal screencast w/ audio narration showing >=1 self-correction sequence; (5) architecture diagram (agent, SIFT tools, MCP servers, evidence sources, output pipeline); (6) evidence dataset documentation (what it was tested on, source, what it found); (7) accuracy report (false positives, missed artifacts, hallucinations found in testing); (8) agent execution logs (structured, timestamped, every finding traceable to the tool execution that produced it); (9) judge-facing compliance checklist; (10) README documents how a judge runs it locally against provided evidence. Known anchors to verify: LICENSE, README.md, QUICKSTART.md, SUBMISSION_COMPLIANCE.md, docs/architecture.md, docs/DATASET.md, docs/reports/2026-04-26-srl2018-dc-investigation.{pdf,html,md}, docs/find-evil-demo.mp4, docs/demo-script-a2.md, out/auto-runs/<case>/audit.jsonl, docs/false-positives.md. For the video and the accuracy report, judge QUALITY against the requirement (e.g. does the demo script actually contain a self-correction beat? does the accuracy report actually admit false positives/misses?). Mark a missing blocker (e.g. no public Devpost/GitHub URL, no real video, license not Apache/MIT) as severity "blocker".`,
    { label: 'inventory:deliverables', phase: 'Inventory', schema: REQS_SCHEMA }
  ),
  () => agent(
    `You are checking STAGE-ONE viability (pass/fail) for the SANS "Find Evil!" hackathon: does this submission (a) reasonably fit the theme — extend Protocol SIFT's AUTONOMOUS incident-response capability; (b) use an agentic framework (Claude Code) as the PRIMARY execution engine, not a bolt-on; (c) run on Linux / SIFT Workstation; and (d) demonstrate the three mandatory capabilities — self-correction (agent detects & resolves its own errors without a human), accuracy validation (every finding traceable to specific artifacts/files/offsets/log entries), and analytical reasoning (output is a structured investigative narrative, not a raw execution log)? Read CLAUDE.md, docs/architecture.md, README.md, agent-config/SOUL.md, agent-config/AGENTS.md, and the report under docs/reports/. Return pass plus concrete reasons and any viability risks.`,
    { label: 'inventory:stage-one', phase: 'Inventory', schema: STAGE_ONE_SCHEMA }
  ),
])

// ============= PHASE 2+3: SCORE -> VERIFY (pipeline) + PHASE 4 runtime in parallel =============
phase('Score')
const scorePromise = pipeline(
  CRITERIA,
  // stage 1: score
  (c) => agent(
    `Score the SANS "Find Evil!" Stage-Two judging criterion **${c.name}** for this repo, 0-10, READ-ONLY. The judge's question: "${c.ask}". Known evidence anchors (verify them, do not take on faith): ${c.anchors}. Known suspected gap to test: ${c.knownGap}. For each piece of evidence you cite, OPEN the file, give path + line range, and tag its kind: "code-enforced" (the guarantee is in compiled/executed code), "runtime-demonstrated" (an actual run artifact under tmp/auto-runs or out/auto-runs shows it happening), or "doc-only" (only asserted in markdown/config, no enforcing code located). Scoring discipline: a criterion backed mostly by doc-only evidence caps around 6/10; 8+ requires code-enforced or runtime-demonstrated evidence. List concrete gaps with severity + a one-line fix. State the single highest-leverage thing about this criterion that could push us toward 1st place (winningEdge), or "" if none. The six criteria are equally weighted, so be calibrated, not generous.`,
    { label: `score:${c.key}`, phase: 'Score', schema: SCORE_SCHEMA }
  ),
  // stage 2: adversarial verify
  (scored, c) => agent(
    `Adversarially REFUTE this score for the SANS criterion **${c.name}**. Default to skepticism. Open every file:line the scorer cited and check the claim actually holds THERE — especially any evidence tagged "doc-only" or "code-enforced": confirm the code really enforces it (e.g. expert-rules.json blockers need enforcing code; a markdown invariant is not enforcement; an unread services/agent/ path is not proof). Penalize traceability claims that can't be followed end to end. Here is the scorer's output as JSON: ${JSON.stringify(scored)}. Return refutations (empty if the score holds), an adjustedScore (lower than the original only if you found over-claiming; never raise it), and a one-line adjustmentReason.`,
    { label: `verify:${c.key}`, phase: 'Verify', schema: VERDICT_SCHEMA }
  ).then((v) => ({ ...c, scored, verdict: v }))
)

// ========================= PHASE 4: RUNTIME EVIDENCE =========================
const RUNTIME_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    runFound: { type: 'boolean' },
    runPath: { type: 'string' },
    manifestOverall: { type: 'boolean' },
    allFindingsCiteToolCallId: { type: 'boolean' },
    verdictWord: { type: 'string' },
    verdictHonestAboutCoverage: { type: 'boolean' },
    selfScorePresent: { type: 'boolean' },
    recallPercent: { type: 'integer' },
    liveTestGatePass: { type: 'boolean' },
    note: { type: 'string' },
  },
  required: ['runFound', 'runPath', 'manifestOverall', 'allFindingsCiteToolCallId', 'verdictWord', 'verdictHonestAboutCoverage', 'selfScorePresent', 'recallPercent', 'liveTestGatePass', 'note'],
}
const runtimePromise = (async () => {
  phase('Runtime')
  return agent(
    `READ-ONLY: assess whether a REAL completed run exists to back the runtime-heavy criteria. Glob tmp/auto-runs/*/ and out/auto-runs/*/ ; pick the newest dir that has verdict.json. Then grade it against VERDICT's 4-point live-test gate: (1) pipeline ran past case_open (non-empty audit.jsonl tool chain); (2) EVERY entry in verdict.json.findings[] cites a tool_call_id; (3) manifest_verify.json.overall == true (read that file); (4) the verdict word is honest about coverage (INDETERMINATE/NO_EVIL must not over-claim on limited coverage). Also report self-score.json presence and recall-score.json recall_percent if present (else -1). If NO run dir with verdict.json exists, set runFound=false and note that the strongest remaining move is to run "scripts/verdict evidence/rocba-cdrive.e01" to generate fresh runtime evidence — but do NOT run anything yourself.`,
    { label: 'runtime:gate', phase: 'Runtime', schema: RUNTIME_SCHEMA }
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
      properties: { criterion: { type: 'string' }, score: { type: 'integer' }, why: { type: 'string' } },
      required: ['criterion', 'score', 'why'],
    } },
    totalOutOf60: { type: 'integer' },
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
  required: ['stageOnePass', 'perCriterion', 'totalOutOf60', 'normalizedPercent', 'deliverableBlockers', 'prioritizedGaps', 'winningEdge', 'topMovesToWin', 'reportPath'],
}
const scorecard = await agent(
  `You are the synthesizer for a SANS "Find Evil!" 1st-place readiness audit. Combine these inputs and WRITE a markdown report, then return the scorecard JSON.\n\n` +
  `SUBMISSION DELIVERABLES: ${JSON.stringify(requirements)}\n\n` +
  `STAGE-ONE VIABILITY: ${JSON.stringify(stageOne)}\n\n` +
  `SIX VERIFIED CRITERIA (each has the scorer output + the adversarial verdict; USE verdict.adjustedScore as the score of record): ${JSON.stringify(scored.map((s) => ({ criterion: s.name, scored: s.scored, verdict: s.verdict })))}\n\n` +
  `RUNTIME GATE: ${JSON.stringify(runtime)}\n\n` +
  `Compute totalOutOf60 = sum of the six adjustedScores (equal weight); normalizedPercent = round(total/60*100). Build prioritizedGaps ordered blocker -> major -> minor, each tagged with the criterion it hurts and a concrete fix, deduped across criteria. deliverableBlockers = any submission deliverable with status missing/partial at severity blocker (a public repo URL, a real <5min narrated video showing self-correction, and an Apache/MIT license are hard Stage-One gates — surface them loudly if weak). winningEdge = the differentiators already present (e.g. cryptographic chain of custody / FRE 902(14); narrow typed tool surface with NO execute_shell as an ARCHITECTURAL constraint; ACH competing-hypotheses topology; >=2-artifact corroboration rule). topMovesToWin = the 2-4 highest-leverage moves; if the runtime gate found no fresh run, the #1 move is almost certainly to capture a real live run (scripts/verdict evidence/rocba-cdrive.e01) because a read-only audit can only confirm docs+code, and judges reward demonstrated runtime self-correction.\n\n` +
  `Write the report to tmp/judging-audit/judging-readiness-report.md (create the dir; this is scratch, not repo source) with sections: Verdict (are we 1st-place ready? one paragraph), Stage-One, Scorecard table (criterion | score/10 | evidence kind summary), Submission deliverables checklist, Prioritized gaps, Winning-edge brief, Top moves to win. Also write tmp/judging-audit/scorecard.json with the returned object. Set reportPath to the markdown path. Be honest and calibrated — this is for us, not the judges.`,
  { label: 'synthesize', phase: 'Synthesize', schema: SCORECARD_SCHEMA }
)

log(`Readiness: ${scorecard.normalizedPercent}% (${scorecard.totalOutOf60}/60). Report: ${scorecard.reportPath}`)
return scorecard
