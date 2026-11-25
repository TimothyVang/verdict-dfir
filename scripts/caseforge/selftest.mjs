#!/usr/bin/env node
/**
 * caseforge self-test — asserts the model-independent MVP guarantees:
 *  - privacy router respects mode (local-only blocks cloud; cloud-ok gates on class)
 *  - invalid findings are rejected (no evidence / bad hash)
 *  - route config keeps ChatGPT OAuth distinct from OpenAI API keys
 *  - missing VERDICT artifacts => run incomplete
 *  - failed manifest verification => custody-invalid
 *  - citation custody: unknown tool_call_id / mismatched hash => not verified
 */
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync, rmSync, statSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { fileURLToPath } from "node:url"
import {
  decideModel,
  validateFinding,
  validateRun,
  loadAudit,
  verifyCitations,
  assembleVerdictFromAudit,
  checkFindingsCustody,
  REQUIRED_ARTIFACTS,
} from "../packages/caseforge-sdk/dist/src/index.js"
import { scoreRun, detectProvenance, loadGroundTruth } from "./score-offline-run.mjs"
import { scoreImageRun, detectAiDegree, loadOracle } from "./score-image-run.mjs"

let pass = 0,
  fail = 0
const ok = (name, cond) => (cond ? (pass++, console.log(`  PASS ${name}`)) : (fail++, console.log(`  FAIL ${name}`)))

const local = { id: "local-ollama", location: "local" }
const cloud = { id: "openai", location: "cloud" }

console.log("privacy router:")
ok("local-only blocks cloud", decideModel(cloud, { mode: "local-only" }).allowed === false)
ok("local-only allows local", decideModel(local, { mode: "local-only" }).allowed === true)
ok("cloud-ok allows synthetic cloud", decideModel(cloud, { mode: "cloud-ok", evidenceClass: "synthetic" }).allowed === true)
ok("cloud-ok blocks sensitive cloud", decideModel(cloud, { mode: "cloud-ok", evidenceClass: "sensitive" }).allowed === false)
ok("redacted-cloud needs redaction", decideModel(cloud, { mode: "redacted-cloud" }).allowed === false)
ok("redacted-cloud allows when redacted", decideModel(cloud, { mode: "redacted-cloud", redacted: true }).allowed === true)
ok("default fail-closed (unknown class, cloud-ok) blocks", decideModel(cloud, { mode: "cloud-ok" }).allowed === false)

console.log("route config:")
{
  const { loadRoutes, loadRoutingPolicy, routeLocation, routeRequiresChatGptOAuth } = await import("../packages/caseforge-cli/dist/src/config.js")
  const { chooseRoute, resolveEvidenceInput, resolveEvtxFallbackPath } = await import("../packages/caseforge-cli/dist/src/commands/investigate.js")
  const { selectedLocalEndpoint } = await import("../packages/caseforge-cli/dist/src/commands/doctor.js")
  const { caseForgeLauncherPath, resolveVerdictRuntime, verdictLauncherPath } = await import("../packages/caseforge-cli/dist/src/chatgpt-auth.js")
  const routes = loadRoutes()
  const policy = loadRoutingPolicy()
  ok("chatgpt-oauth route exists", Boolean(routes["chatgpt-oauth"]))
  ok("chatgpt-oauth is cloud + oauth guarded", routeLocation(routes["chatgpt-oauth"]) === "cloud" && routeRequiresChatGptOAuth(routes["chatgpt-oauth"]))
  ok("non-sensitive default prefers ChatGPT OAuth", policy.non_sensitive_default === "chatgpt-oauth")
  ok("non-sensitive route selection uses policy default", chooseRoute({ privacy: "cloud-ok", evidenceClass: "synthetic" }) === "chatgpt-oauth")
  ok("sensitive route selection uses policy local default", chooseRoute({ privacy: "local-only", evidenceClass: "sensitive" }) === policy.sensitive_default)
  ok("OpenAI API route is explicitly named", Boolean(routes["openai-api"]) && routes["openai-api"].auth === "api-key")
  const launcherPath = fileURLToPath(new URL("../bin/verdict", import.meta.url))
  ok("doctor checks the CaseForge launcher path directly", caseForgeLauncherPath() === launcherPath)
  ok("ChatGPT auth uses repo-local verdict launcher", verdictLauncherPath({}) === launcherPath)
  const runtimeDir = mkdtempSync(join(tmpdir(), "caseforge-runtime-"))
  try {
    const fakeRuntime = join(runtimeDir, "verdict")
    writeFileSync(
      fakeRuntime,
      `#!/usr/bin/env bash
case "$1:$2" in
  --version:) echo "0.0.0-agent-test"; exit 0 ;;
  run:--help) printf '%s\\n' "opencode run [message..]" "--agent" "--model"; exit 0 ;;
  auth:--help) printf '%s\\n' "opencode auth" "opencode auth login" "opencode auth logout"; exit 0 ;;
esac
exit 64
`,
    )
    chmodSync(fakeRuntime, 0o755)
    const explicitRuntime = resolveVerdictRuntime({ ...process.env, VERDICT_BIN: fakeRuntime })
    ok(
      "doctor separates CaseForge launcher from VERDICT runtime",
      explicitRuntime.launcherPath === launcherPath &&
        explicitRuntime.runtimeSource === "VERDICT_BIN" &&
        explicitRuntime.runtimePath === realpathSync(fakeRuntime) &&
        explicitRuntime.runtimeVersion === "0.0.0-agent-test",
    )
    const nonRuntime = resolveVerdictRuntime({ ...process.env, VERDICT_BIN: process.execPath })
    ok("doctor rejects non-verdict executables", !nonRuntime.runtimePath && /not a VERDICT runtime/.test(nonRuntime.reason ?? ""))
    const recursiveRuntime = resolveVerdictRuntime({ ...process.env, VERDICT_BIN: launcherPath })
    ok("doctor flags recursive VERDICT_BIN", recursiveRuntime.recursive === true && !recursiveRuntime.runtimePath)
  } finally {
    rmSync(runtimeDir, { recursive: true, force: true })
  }
  ok("selected local doctor honors endpoint override", selectedLocalEndpoint(routes["spark-ollama"], { VERDICT_LLM_BASEURL: "http://spark.local:11434/v1" }) === "http://spark.local:11434/v1")
  ok(
    "selected local doctor normalizes bare Ollama root to /v1 (m13 404 root cause)",
    selectedLocalEndpoint(routes["spark-ollama"], { VERDICT_LLM_BASEURL: "http://spark.local:11434" }) === "http://spark.local:11434/v1",
  )
  ok("selected local doctor falls back to route endpoint", selectedLocalEndpoint(routes["spark-ollama"], {}) === routes["spark-ollama"].base_url)
  const { normalizeOpenAiCompatBaseUrl } = await import("../packages/caseforge-cli/dist/src/config.js")
  ok("normalize leaves existing /v1 alone", normalizeOpenAiCompatBaseUrl("http://host:11434/v1/") === "http://host:11434/v1")
  ok("normalize leaves non-root paths alone", normalizeOpenAiCompatBaseUrl("https://api.z.ai/api/paas/v4") === "https://api.z.ai/api/paas/v4")
  const modelRoutesText = readFileSync(fileURLToPath(new URL("../configs/model-routes.yaml", import.meta.url)), "utf8")
  const staleEmbeddedRuntimePhrase = ["embedded", "opencode", "engine"].join(" ")
  ok("ChatGPT OAuth route is documented as external runtime", /external VERDICT runtime/.test(modelRoutesText) && !modelRoutesText.includes(staleEmbeddedRuntimePhrase))
  const operatorSmoke = readFileSync(fileURLToPath(new URL("../scripts/operator-chatgpt-smoke.sh", import.meta.url)), "utf8")
  const localRouteSmoke = readFileSync(fileURLToPath(new URL("../scripts/local-route-readiness-smoke.sh", import.meta.url)), "utf8")
  ok("operator smoke checks ChatGPT OAuth auth status", /auth status/.test(operatorSmoke))
  ok("operator smoke doctors the ChatGPT OAuth route", /doctor --route chatgpt-oauth/.test(operatorSmoke))
  ok("operator smoke removes OpenAI API keys for live investigate", /env -u OPENAI_API_KEY VERDICT_DFIR_HOME=/.test(operatorSmoke) && /investigate/.test(operatorSmoke))
  ok("operator smoke uses normal network workflow fixture", /empty\.pcap/.test(operatorSmoke) && /--command network/.test(operatorSmoke))
  ok("operator smoke requires approval for custom cloud evidence", /CASEFORGE_OPERATOR_EVIDENCE_APPROVED=1/.test(operatorSmoke) && /DEFAULT_EVIDENCE_CLASS="approved"/.test(operatorSmoke))
  ok("operator smoke finds produced case by case metadata hash", /EVIDENCE_HASH=/.test(operatorSmoke) && /matching_case_dir/.test(operatorSmoke) && /grep -Fq .*image_hash.*evidence_hash.*case\.json/.test(operatorSmoke))
  ok("operator smoke pins Dev VERDICT case store", /FIND_EVIL_HOME="\$\{DFIR_HOME\}\/\.project-local\/findevil"/.test(operatorSmoke) && /FINDEVIL_HOME="\$\{FIND_EVIL_HOME\}"/.test(operatorSmoke))
  ok("operator smoke verifies the produced Dev VERDICT case", /\.project-local\/findevil/.test(operatorSmoke) && /verify "\$\{after\}"/.test(operatorSmoke))
  ok("local route smoke is separate from ChatGPT OAuth", /CASEFORGE_LOCAL_ROUTE/.test(localRouteSmoke) && /doctor --route "\$\{route\}"/.test(localRouteSmoke) && /selected local endpoint down/.test(localRouteSmoke))
  const sparkSealSmokePath = fileURLToPath(new URL("../scripts/spark-local-seal-smoke.sh", import.meta.url))
  const sparkSealSmoke = readFileSync(sparkSealSmokePath, "utf8")
  const sparkSealMode = statSync(sparkSealSmokePath).mode
  ok("spark-local-seal-smoke exists and is executable", (sparkSealMode & 0o111) !== 0)
  ok(
    "spark-local-seal-smoke SKIPs when Spark endpoint is down (no evidence fabrication)",
    /SKIP: spark down/.test(sparkSealSmoke) &&
      /api\/tags/.test(sparkSealSmoke) &&
      /curl -sS -m 2/.test(sparkSealSmoke) &&
      /PASS: sealed with ed25519/.test(sparkSealSmoke) &&
      /PASS: investigate completed via fallback \(not agent seal\)/.test(sparkSealSmoke) &&
      /exit 0/.test(sparkSealSmoke),
  )
  ok(
    "spark-local-seal-smoke timeout names agent hang after /v1 (not bare-baseURL 404)",
    /agent path likely hung after LLM \/v1/.test(sparkSealSmoke) &&
      /case incomplete \(no run\.manifest\.json\)/.test(sparkSealSmoke) &&
      /not bare-baseURL 404/.test(sparkSealSmoke),
  )
  ok(
    "spark-local-seal-smoke prefers VERDICT_BIN/engine dist over PATH slash-version hang",
    /resolve_verdict_runtime/.test(sparkSealSmoke) &&
      /VERDICT_BIN=/.test(sparkSealSmoke) &&
      /engine\/packages\/opencode\/dist/.test(sparkSealSmoke) &&
      /git ls-remote/.test(sparkSealSmoke),
  )
  ok(
    "spark-local-seal-smoke REQUIRE_AGENT probes Ollama tools capability",
    /REQUIRE_AGENT=1 but Ollama model/.test(sparkSealSmoke) &&
      /tools capability/.test(sparkSealSmoke) &&
      /api\/show/.test(sparkSealSmoke),
  )
  const setup = readFileSync(fileURLToPath(new URL("../scripts/setup.sh", import.meta.url)), "utf8")
  ok(
    "setup installs verdict runtime without following existing symlinks",
    /DEST="\$HOME\/\.local\/bin\/verdict"/.test(setup) &&
      /rm -f "\$DEST"/.test(setup) &&
      /install -m 755 "\$BIN" "\$DEST"/.test(setup) &&
      !/cp "\$BIN" "\$HOME\/\.local\/bin\/verdict"/.test(setup),
  )
  const launcher = readFileSync(fileURLToPath(new URL("../bin/verdict", import.meta.url)), "utf8")
  ok("verdict launcher delegates to external runtime", !/caseforge\/engine|DEFAULT_BIN|VERDICT_WS|build-engine/.test(launcher))
  ok("verdict launcher does not fall back to generic opencode", !/type -P -a opencode|\.opencode\/bin\/opencode|install verdict\/opencode/.test(launcher))
  ok("verdict launcher refuses recursive launch", /VERDICT_BIN points back to this CaseForge launcher/.test(launcher) && /\$resolved" != "\$SELF/.test(launcher))
  const investigateSrc = readFileSync(fileURLToPath(new URL("../packages/caseforge-cli/src/commands/investigate.ts", import.meta.url)), "utf8")
  ok("investigate launches isolated opencode profile", /"run",\s*"--pure",\s*"--agent",\s*"verdict"/.test(investigateSrc))
  ok("investigate prompt scopes authorized defensive DFIR", /authorized, defensive DFIR lab investigation/.test(investigateSrc) && /read-only forensic MCP tools/.test(investigateSrc))
  ok("investigate contains opencode global state", /OPENCODE_TEST_HOME/.test(investigateSrc) && /XDG_CONFIG_HOME/.test(investigateSrc) && /OPENCODE_DISABLE_EXTERNAL_SKILLS/.test(investigateSrc))
  ok("investigate prompt routes case_open to Rust MCP", /findevil-mcp_case_open/.test(investigateSrc) && /never call or invent findevil-agent-mcp_case_open/.test(investigateSrc))
  ok("investigate prompt routes single EVTX to evtx_query", /single EVTX/.test(investigateSrc) && /findevil-mcp_evtx_query/.test(investigateSrc) && /Do not call disk_mount/.test(investigateSrc))
  ok(
    "investigate single EVTX mandates seal sequence without printed JSON substitutes",
    /mandatory tool sequence/.test(investigateSrc) &&
      /findevil-agent-mcp_manifest_finalize/.test(investigateSrc) &&
      /Never print a fenced code block/.test(investigateSrc) &&
      /do not print JSON examples instead of making real tool calls/.test(investigateSrc),
  )
  ok(
    "investigate single EVTX requires structured audit rows and seal-continue",
    /output_summary MUST be a JSON OBJECT/.test(investigateSrc) &&
      /seal-continue attempt/.test(investigateSrc) &&
      /Event ID 1102/.test(investigateSrc) &&
      /never NO_EVIL/.test(investigateSrc),
  )
  ok(
    "investigate seal-continue pins absolute case_dir (not ~/.local/state)",
    /case_dir is exactly/.test(investigateSrc) &&
      /Never use ~\/\.local\/state\/findevil\/cases\//.test(investigateSrc) &&
      /hyphen before mcp/.test(investigateSrc),
  )
  ok("verdict agent has elevated steps budget for seal recovery", /steps:\s*48/.test(readFileSync(fileURLToPath(new URL("../configs/opencode/agent/verdict.md", import.meta.url)), "utf8")))
  ok("investigate prompt avoids helper tool confusion", /Every tool call name must start with findevil-mcp_/.test(investigateSrc) && /do not call a run tool, task tool, skill tool, todowrite tool/.test(investigateSrc))
  ok("investigate pins manifest tools to agent MCP", /Manifest tools are ONLY findevil-agent-mcp_manifest_finalize/.test(investigateSrc) && /never call findevil-mcp_manifest_finalize/.test(investigateSrc))
  ok("investigate requires verified manifest before complete", /manifest_verify reports overall:true/.test(investigateSrc) && /real run\.manifest\.json plus audit\.jsonl/.test(investigateSrc))
  ok("investigate EVTX hint surveys before filtering (no hardcoded eids)", /Do NOT pass an eids filter on the first query/.test(investigateSrc) && !/eids \[1102\], and limit 100/.test(investigateSrc))
  ok("investigate forbids stub signer and prefers ed25519 at seal", /Do NOT pass signer:'stub'/.test(investigateSrc) && /signer:'ed25519'/.test(investigateSrc))
  ok("investigate names manifest_path arg at verify", /argument named manifest_path/.test(investigateSrc))
  ok(
    "investigate local route forces OPENCODE_TOOL_CHOICE required by default",
    /OPENCODE_TOOL_CHOICE/.test(investigateSrc) &&
      /required/.test(investigateSrc) &&
      /VERDICT_FORCE_TOOL_CHOICE/.test(investigateSrc),
  )
  const evidenceDir = mkdtempSync(join(tmpdir(), "caseforge-evidence-"))
  try {
    writeFileSync(join(evidenceDir, "manifest.json"), "{}")
    writeFileSync(join(evidenceDir, "image.E01"), "tiny")
    const resolved = resolveEvidenceInput(evidenceDir)
    ok(
      "directory evidence case_open targets primary regular file (not the directory)",
      resolved.isDirectory === true &&
        resolved.caseOpenPath === join(evidenceDir, "image.E01") &&
        resolved.inventory.includes("image.E01"),
    )
  } finally {
    rmSync(evidenceDir, { recursive: true, force: true })
  }
  const evtxDir = mkdtempSync(join(tmpdir(), "caseforge-evtx-"))
  try {
    const evtxFile = join(evtxDir, "DE_1102_security_log_cleared.evtx")
    writeFileSync(evtxFile, "tiny")
    const resolved = resolveEvidenceInput(evtxFile)
    ok("single EVTX evidence opens exact file", resolved.isDirectory === false && resolved.caseOpenPath === evtxFile)
    ok(
      "single EVTX fallback path is the file itself",
      resolveEvtxFallbackPath(resolved) === evtxFile,
    )
  } finally {
    rmSync(evtxDir, { recursive: true, force: true })
  }
  const multiEvtxDir = mkdtempSync(join(tmpdir(), "caseforge-multi-evtx-"))
  try {
    writeFileSync(join(multiEvtxDir, "LM_Remote_Service02_7045.evtx"), "tiny")
    writeFileSync(join(multiEvtxDir, "LM_WMI_4624_4688_TargetHost.evtx"), "tiny")
    writeFileSync(join(multiEvtxDir, "README.md"), "notes")
    const resolved = resolveEvidenceInput(multiEvtxDir)
    ok(
      "multi-EVTX directory case_open targets a regular EVTX file (MCP requires a file)",
      resolved.isDirectory === true &&
        resolved.caseOpenPath === join(multiEvtxDir, "LM_Remote_Service02_7045.evtx") &&
        resolved.inventory.includes("LM_WMI_4624_4688_TargetHost.evtx"),
    )
    ok(
      "multi-EVTX fallback path is the directory (not first file only)",
      resolveEvtxFallbackPath(resolved) === multiEvtxDir,
    )
  } finally {
    rmSync(multiEvtxDir, { recursive: true, force: true })
  }
  const diskDir = mkdtempSync(join(tmpdir(), "caseforge-disk-only-"))
  try {
    writeFileSync(join(diskDir, "image.E01"), "tiny")
    const resolved = resolveEvidenceInput(diskDir)
    ok("non-EVTX directory has no EVTX fallback path", resolveEvtxFallbackPath(resolved) === undefined)
  } finally {
    rmSync(diskDir, { recursive: true, force: true })
  }
}

console.log("opencode profile guardrails:")
{
  const profile = JSON.parse(readFileSync(fileURLToPath(new URL("../configs/opencode/opencode.json", import.meta.url)), "utf8"))
  ok(
    "opencode profile denies by default but allows VERDICT MCP tools",
    profile.permission?.["*"] === "deny" &&
      profile.permission?.["findevil-mcp_*"] === "allow" &&
      profile.permission?.["findevil-agent-mcp_*"] === "allow",
  )
  ok("opencode profile denies helper prompts", profile.permission?.question === "deny" && profile.permission?.plan_enter === "deny" && profile.permission?.plan_exit === "deny")
  const agentNames = ["verdict", "pool-a", "pool-b", "verifier", "judge", "correlator"]
  for (const name of agentNames) {
    const text = readFileSync(fileURLToPath(new URL(`../configs/opencode/agent/${name}.md`, import.meta.url)), "utf8")
    ok(`${name}: shell/direct FS tools denied`, /bash:\s+deny/.test(text) && /read:\s+deny/.test(text) && /grep:\s+deny/.test(text) && /glob:\s+deny/.test(text) && /list:\s+deny/.test(text))
    ok(`${name}: opencode helper tools denied`, /task:\s+deny/.test(text) && /skill:\s+deny/.test(text) && /todowrite:\s+deny/.test(text))
    ok(
      `${name}: exact MCP tool families allowed`,
      /["']?findevil-mcp_\*["']?:\s+allow/.test(text) && /["']?findevil-agent-mcp_\*["']?:\s+allow/.test(text) && !/^\s*mcp_\*:\s+allow/m.test(text),
    )
  }
  const skill = readFileSync(fileURLToPath(new URL("../configs/opencode/skill/verdict-dfir/SKILL.md", import.meta.url)), "utf8")
  ok("skill names exact opencode MCP tools", /findevil-mcp_case_open/.test(skill) && /findevil-agent-mcp_manifest_verify/.test(skill) && /do not invent underscore variants/i.test(skill))
  const triage = readFileSync(fileURLToPath(new URL("../configs/opencode/command/triage.md", import.meta.url)), "utf8")
  const verdict = readFileSync(fileURLToPath(new URL("../configs/opencode/command/verdict.md", import.meta.url)), "utf8")
  ok("triage command uses exact MCP names", /findevil-mcp_case_open/.test(triage) && /findevil-mcp_disk_mount/.test(triage) && /findevil-agent-mcp_detect_contradictions/.test(triage))
  ok("verdict command uses exact MCP names", /findevil-agent-mcp_audit_verify/.test(verdict) && /findevil-agent-mcp_manifest_finalize/.test(verdict) && /findevil-agent-mcp_manifest_verify/.test(verdict) && /findevil_mcp_manifest_finalize/.test(verdict))
  ok("verdict command forbids Rust manifest variants", /Never call\s+`findevil-mcp_manifest_finalize`/.test(verdict) && /`findevil-mcp_manifest_verify`/.test(verdict))
  ok("verdict command does not require nonexistent report_qa", !/report_qa/.test(verdict))
  ok("triage command has negative-control gate", /Negative-control gate/.test(triage) && /name\/content bait/.test(triage))
  ok("verdict command rejects decoy-only findings", /Do not accept Findings/.test(verdict) && /negative-control leads/.test(verdict))
  ok("verdict skill forbids Rust manifest tools", /Never call\s+`findevil-mcp_manifest_finalize`/.test(skill) && /findevil_mcp_manifest_finalize/.test(skill))
  const verdictAgent = readFileSync(fileURLToPath(new URL("../configs/opencode/agent/verdict.md", import.meta.url)), "utf8")
  ok("verdict agent treats workflows as labels not slash commands", /Evidence-type workflow labels/.test(verdictAgent) && /not slash commands/.test(verdictAgent) && /Do not call a `run`/.test(verdictAgent))
  ok("verdict agent local profile avoids task helper", /local locked profile does not expose subagent helper tools/.test(verdictAgent) && /Do not call `task`/.test(verdictAgent))
}

console.log("finding validator:")
const sha = "a".repeat(64)
ok("rejects finding with no evidence", validateFinding({ id: "1", title: "t", verdict: "SUSPICIOUS", summary: "s", evidence: [] }).valid === false)
ok("rejects bad sha", validateFinding({ id: "1", title: "t", verdict: "SUSPICIOUS", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: "nothex" }] }).valid === false)
ok("rejects bad verdict word", validateFinding({ id: "1", title: "t", verdict: "GUILTY", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: sha }] }).valid === false)
ok("accepts valid finding", validateFinding({ id: "1", title: "t", verdict: "NO_EVIL", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: sha }] }).valid === true)

console.log("artifact + custody validator:")
const dir = mkdtempSync(join(tmpdir(), "caseforge-run-"))
try {
  // 1. empty dir => incomplete (missing the hard custody files)
  let r = await validateRun(dir)
  ok("missing custody => incomplete", r.status === "incomplete" && r.missing.includes("run.manifest.json") && r.missing.includes("audit.jsonl"))

  // 2. all present but manifest verify fails => custody-invalid
  for (const a of REQUIRED_ARTIFACTS) writeFileSync(join(dir, a), a.endsWith(".jsonl") ? "" : "{}")
  writeFileSync(join(dir, "manifest_verify.json"), JSON.stringify({ ok: false }))
  r = await validateRun(dir)
  ok("failed manifest verify => custody-invalid", r.status === "custody-invalid")

  // 3. auto-runner shape: all present and verified => complete (full report)
  writeFileSync(join(dir, "manifest_verify.json"), JSON.stringify({ ok: true }))
  writeFileSync(join(dir, "verdict.json"), JSON.stringify({ attack_coverage: {}, findings: [] }))
  r = await validateRun(dir)
  ok("auto-runner: all present + verified => complete", r.status === "complete" && r.custodyValid === true)

  // 4. interactive agent seal: only run.manifest.json + audit.jsonl (seal on the
  //    audit chain, no manifest_verify.json / verdict.json) => complete (custody-sealed)
  const seal = mkdtempSync(join(tmpdir(), "caseforge-seal-"))
  try {
    writeFileSync(join(seal, "run.manifest.json"), "{}")
    writeFileSync(
      join(seal, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: true } } }) + "\n",
    )
    const rs = await validateRun(seal)
    ok("interactive seal (audit-chain) => complete", rs.status === "complete" && rs.custodyValid === true)
    // negative: same but overall:false => custody-invalid
    writeFileSync(
      join(seal, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: false } } }) + "\n",
    )
    const rf = await validateRun(seal)
    ok("interactive seal overall:false => custody-invalid", rf.status === "custody-invalid")
  } finally {
    rmSync(seal, { recursive: true, force: true })
  }

  // 4. citation custody against audit.jsonl
  writeFileSync(
    join(dir, "audit.jsonl"),
    JSON.stringify({ tool_call_id: "c1", output_sha256: sha }) + "\n",
  )
  const audit = await loadAudit(dir)
  ok("citation matches audit => verified", verifyCitations([{ tool_call_id: "c1", output_sha256: sha }], audit).verified === true)
  ok("unknown tool_call_id => not verified", verifyCitations([{ tool_call_id: "nope", output_sha256: sha }], audit).verified === false)
  ok("hash mismatch => not verified", verifyCitations([{ tool_call_id: "c1", output_sha256: "b".repeat(64) }], audit).verified === false)
} finally {
  rmSync(dir, { recursive: true, force: true })
}

console.log("tui workbench:")
{
  const { loadCase } = await import("../packages/caseforge-tui/dist/src/load.js")
  const { renderHeader, renderFindings, renderScreen } = await import("../packages/caseforge-tui/dist/src/render.js")
  const minimalDir = fileURLToPath(new URL("../fixtures/synthetic/minimal-complete-run", import.meta.url))
  const fixDir = fileURLToPath(new URL("../fixtures/synthetic/sample-run", import.meta.url))
  const minimal = await loadCase(minimalDir)
  ok(
    "tui: minimal fixture renders verdict + recorded/live custody lights",
    minimal.validation.status === "complete" &&
      minimal.validation.custodyValid === true &&
      minimal.recordedManifestOverall === true &&
      /NO_EVIL/.test(renderHeader(minimal)) &&
      /re-verified now/.test(renderHeader(minimal)),
  )
  const v = await loadCase(fixDir)
  ok("tui: fixture run validates complete + custody re-verified", v.validation.status === "complete" && v.validation.custodyValid === true)
  ok("tui: header renders verdict + dual custody lights", /SUSPICIOUS/.test(renderHeader(v)) && /re-verified now/.test(renderHeader(v)))
  ok("tui: findings render cited tool_call_id", /tc-1/.test(renderFindings(v)) && /cited/.test(renderFindings(v)))
  ok("tui: screen composes all panels", renderScreen(v).length > 200)
  const vb = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/broken-chain-run", import.meta.url)))
  ok("tui: broken audit chain caught (chainOk false)", vb.chainOk === false)
  const vn = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/no-report-run", import.meta.url)))
  ok("tui: missing verdict.json degrades but custody holds", vn.verdict === undefined && vn.validation.custodyValid === true)
  const { listRuns } = await import("../packages/caseforge-tui/dist/src/picker.js")
  const { renderPicker } = await import("../packages/caseforge-tui/dist/src/render.js")
  const runs = await listRuns([fileURLToPath(new URL("../fixtures/synthetic", import.meta.url))])
  ok("tui: picker discovers runs with validated status", runs.length >= 3 && /CASES/.test(renderPicker(runs)))
  const { keyOf, reduce, initialState } = await import("../packages/caseforge-tui/dist/src/app.js")
  ok("tui: keyOf maps arrow/enter/quit", keyOf("\x1b[A") === "up" && keyOf("\r") === "enter" && keyOf("\x03") === "quit")
  ok("tui: reduce navigates picker<->case", reduce(reduce(initialState, "enter", 3), "back", 3).view === "picker")
  ok("tui: picker flags a structurally-broken audit chain", runs.some((r) => /broken-chain-run/.test(r.dir) && r.chainOk === false) && /⚠ chain/.test(renderPicker(runs)))
  const { renderHeader: rh } = await import("../packages/caseforge-tui/dist/src/render.js")
  const ci = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/custody-invalid-run", import.meta.url)))
  ok("tui: custody-invalid run re-verifies as invalid", ci.validation.status === "custody-invalid" && ci.validation.custodyValid === false)
  const { renderCustodyBanner } = await import("../packages/caseforge-tui/dist/src/render.js")
  ok("tui: invalid custody warns over findings; valid does not", /CUSTODY NOT VERIFIED/.test(renderCustodyBanner(ci)) && renderCustodyBanner(v) === "")
}

console.log("audit-derived verdict assembly (local-model fallback):")
{
  const run = mkdtempSync(join(tmpdir(), "caseforge-audit-verdict-"))
  try {
    const evtxPath = join(run, "DE_1102_security_log_cleared.evtx")
    const auditLine = JSON.stringify({
      kind: "tool_call_output",
      seq: 7,
      payload: {
        tool_name: "evtx_query",
        arguments: { case_id: "case-evtx-1102", evtx_path: evtxPath, eids: [1102], limit: 100 },
        output_summary: {
          parse_errors: 0,
          records_seen: 112,
          row_count: 1,
          rows: [{ channel: "Security", event_id: 1102, record_id: 1, ts: "2019-03-19T23:35:07.524202Z" }],
        },
      },
      prev_hash: "",
    })
    writeFileSync(join(run, "audit.jsonl"), `${auditLine}\n`)
    const doc = await assembleVerdictFromAudit(run)
    ok(
      "EVTX 1102 audit output assembles to SUSPICIOUS finding with audit-record citation",
      doc?.verdict === "SUSPICIOUS" && (doc?.findings?.length ?? 0) >= 1 && doc.findings[0].citation_kind === "audit_record",
    )
    const custody = checkFindingsCustody(doc)
    ok(
      "audit-record finding passes custody without a tool_call_id",
      custody.ok === true && custody.findings.length >= 1 && custody.findings.every((f) => f.citation === "audit_record" || f.citation === "tool_call"),
    )
    // A non-1102 EVTX row must NOT fabricate a finding.
    const benign = mkdtempSync(join(tmpdir(), "caseforge-audit-benign-"))
    try {
      const benignLine = JSON.stringify({
        kind: "tool_call_output",
        seq: 1,
        payload: {
          tool_name: "evtx_query",
          arguments: { case_id: "c", evtx_path: join(benign, "x.evtx"), eids: [4624], limit: 100 },
          output_summary: { row_count: 1, rows: [{ channel: "Security", event_id: 4624, record_id: 5 }] },
        },
      })
      writeFileSync(join(benign, "audit.jsonl"), `${benignLine}\n`)
      const benignDoc = await assembleVerdictFromAudit(benign)
      ok("non-1102 EVTX row does not fabricate a finding", (benignDoc?.findings?.length ?? 0) === 0)
    } finally {
      rmSync(benign, { recursive: true, force: true })
    }
  } finally {
    rmSync(run, { recursive: true, force: true })
  }
}

console.log("investigate local-model wiring:")
{
  const src = readFileSync(fileURLToPath(new URL("../packages/caseforge-cli/src/commands/investigate.ts", import.meta.url)), "utf8")
  ok("investigate canonicalizes the evidence path (realpathSync)", /realpathSync\(evidencePath\)/.test(src) && /resolveEvidenceInput\(canonicalEvidencePath\)/.test(src))
  ok(
    "investigate falls back to the deterministic EVTX auto-runner when the agent run is incomplete",
    /function runLocalEvtxAutoFallback/.test(src) && /find_evil_auto\.py/.test(src) && /runLocalEvtxAutoFallback\(evidence, env\)/.test(src),
  )
  ok(
    "investigate EVTX fallback scopes multi-file directories (not only first .evtx)",
    /export function resolveEvtxFallbackPath/.test(src) &&
      /find_evil_auto will open every EVTX/.test(src) &&
      !/if \(!evidence\.caseOpenPath\.toLowerCase\(\)\.endsWith\("\.evtx"\)\) return undefined/.test(src),
  )
  const smoke = readFileSync(fileURLToPath(new URL("../scripts/run-local-llm-smoke.sh", import.meta.url)), "utf8")
  ok("local-model smoke targets a local-only Spark Ollama route", /--privacy local-only/.test(smoke) && /CASEFORGE_LOCAL_ROUTE:-spark-ollama/.test(smoke))
  const routes = readFileSync(fileURLToPath(new URL("../configs/model-routes.yaml", import.meta.url)), "utf8")
  ok("sensitive default route is the local Spark Ollama route", /sensitive_default:\s*spark-ollama/.test(routes) && /model:\s*gpt-oss:20b/.test(routes))
}

// --- m27: the declared provider matrix must match the executable route surface --
//
// These assert the *whole* named-route surface, not a hand-built candidate. A
// route that mislabels a cloud provider as privacy_locations:[local] would walk
// straight through the privacy gate, so the location agreement check below is a
// security invariant, not a style check.
console.log("provider matrix vs route surface:")
{
  const { loadRoutes, routeLocation, resolveCandidate } = await import("../packages/caseforge-cli/dist/src/config.js")
  const { parse: parseYaml } = await import("yaml")
  const caps = parseYaml(readFileSync(fileURLToPath(new URL("../configs/provider-capabilities.yaml", import.meta.url)), "utf8"))
  const providers = caps.providers ?? {}
  const routes = loadRoutes()
  const routeIds = Object.keys(routes)

  ok("provider-capabilities declares providers", Object.keys(providers).length > 0)
  ok(
    "every route names a declared provider",
    routeIds.every((id) => Boolean(providers[routes[id].provider])),
  )
  // Security invariant: a route may not claim "local" for a cloud provider.
  ok(
    "route privacy_locations agree with provider location",
    routeIds.every((id) => routeLocation(routes[id]) === providers[routes[id].provider]?.location),
  )

  const cloudRoutes = routeIds.filter((id) => routeLocation(routes[id]) === "cloud")
  const localRoutes = routeIds.filter((id) => routeLocation(routes[id]) === "local")
  ok("there is at least one cloud and one local route", cloudRoutes.length > 0 && localRoutes.length > 0)

  const decide = (id, ctx) => decideModel(resolveCandidate(id).candidate, ctx)
  ok(
    "local-only denies EVERY named cloud route",
    cloudRoutes.every((id) => decide(id, { mode: "local-only" }).allowed === false),
  )
  ok(
    "local-only allows EVERY named local route",
    localRoutes.every((id) => decide(id, { mode: "local-only" }).allowed === true),
  )
  ok(
    "cloud-ok + synthetic allows EVERY named cloud route",
    cloudRoutes.every((id) => decide(id, { mode: "cloud-ok", evidenceClass: "synthetic" }).allowed === true),
  )
  ok(
    "cloud-ok + public allows EVERY named cloud route",
    cloudRoutes.every((id) => decide(id, { mode: "cloud-ok", evidenceClass: "public" }).allowed === true),
  )
  ok(
    "cloud-ok + sensitive denies EVERY named cloud route",
    cloudRoutes.every((id) => decide(id, { mode: "cloud-ok", evidenceClass: "sensitive" }).allowed === false),
  )

  // Honesty gate: a declared provider is either routable today, or explicitly
  // labelled capability-only. Config presence alone is never "live support".
  const routedProviders = new Set(routeIds.map((id) => routes[id].provider))
  ok(
    "every provider declares route_status",
    Object.values(providers).every((p) => p.route_status === "named-route" || p.route_status === "capability-only"),
  )
  ok(
    "route_status: named-route <=> a named route actually exists",
    Object.entries(providers).every(([name, p]) =>
      p.route_status === "named-route" ? routedProviders.has(name) : !routedProviders.has(name),
    ),
  )
  ok(
    "every product-supported local provider has a named route",
    ["local-vllm", "local-ollama", "local-llamacpp", "local-lmstudio", "local-nim"].every(
      (name) => providers[name]?.route_status === "named-route" && routedProviders.has(name),
    ),
  )

  // Docs must not present capability-only entries as live support.
  const support = readFileSync(fileURLToPath(new URL("../docs/LLM_SUPPORT_2026.md", import.meta.url)), "utf8")
  const capabilityOnly = Object.entries(providers)
    .filter(([, p]) => p.route_status === "capability-only")
    .map(([name]) => name)
  ok("there are capability-only providers to label", capabilityOnly.length > 0)
  ok(
    "LLM_SUPPORT_2026 labels capability-only providers experimental/unverified",
    /experimental.*unverified|unverified.*experimental/i.test(support) &&
      /capability-only/i.test(support) &&
      !/planned\/stubbed/i.test(support),
  )
  const tracking = readFileSync(fileURLToPath(new URL("../docs/LOCAL_LLM_FIX_TRACKING.md", import.meta.url)), "utf8")
  ok(
    "LOCAL_LLM_FIX_TRACKING does not still call merged PRs 'open'",
    !/implemented in open PRs/i.test(tracking) && /merged/i.test(tracking),
  )
}

console.log("oauth route env containment:")
{
  const { loadRoutes, oauthRuntimeEnv } = await import("../packages/caseforge-cli/dist/src/config.js")
  const routes = loadRoutes()

  // A subscription-OAuth run must never inherit the ambient platform API key
  // for its own provider, or the engine can silently bill/authenticate the
  // wrong way.
  const chatgpt = oauthRuntimeEnv(routes["chatgpt-oauth"], { OPENAI_API_KEY: "sk-ambient", XAI_API_KEY: "xai-ambient" }, { authContent: '{"openai":{"type":"oauth"}}' })
  ok("chatgpt-oauth clears ambient OPENAI_API_KEY", chatgpt.OPENAI_API_KEY === undefined)
  ok("chatgpt-oauth loads the openai credential", chatgpt.OPENCODE_AUTH_CONTENT === '{"openai":{"type":"oauth"}}')

  const xai = oauthRuntimeEnv(routes["xai-grok-oauth"], { XAI_API_KEY: "xai-ambient", OPENAI_API_KEY: "sk-ambient" }, { authContent: '{"xai":{"type":"oauth"}}' })
  ok("xai-grok-oauth clears ambient XAI_API_KEY", xai.XAI_API_KEY === undefined)
  ok("xai-grok-oauth loads the xai credential", xai.OPENCODE_AUTH_CONTENT === '{"xai":{"type":"oauth"}}')

  // An api-key route is the opposite contract: its key must survive.
  const apiKey = oauthRuntimeEnv(routes["xai-grok"], { XAI_API_KEY: "xai-ambient" }, {})
  ok("api-key route keeps its platform key", apiKey.XAI_API_KEY === "xai-ambient")
  ok("api-key route injects no oauth credential", apiKey.OPENCODE_AUTH_CONTENT === undefined)

  // An operator-supplied credential wins over a file read.
  const ambient = oauthRuntimeEnv(routes["xai-grok-oauth"], { OPENCODE_AUTH_CONTENT: '{"xai":{"type":"oauth"}}' }, { authContent: "FROM_FILE" })
  ok("ambient OPENCODE_AUTH_CONTENT is not overwritten", ambient.OPENCODE_AUTH_CONTENT === '{"xai":{"type":"oauth"}}')

  const input = { XAI_API_KEY: "xai-ambient" }
  oauthRuntimeEnv(routes["xai-grok-oauth"], input, {})
  ok("oauthRuntimeEnv does not mutate its input env", input.XAI_API_KEY === "xai-ambient")
}

console.log("grok cloud smoke evidence selection:")
{
  const { resolveEvidenceInput } = await import("../packages/caseforge-cli/dist/src/commands/investigate.js")
  const artifactFixtures = fileURLToPath(new URL("../fixtures/synthetic", import.meta.url))

  // fixtures/synthetic holds *run artifacts* (verdict.json, audit.jsonl), not a
  // case_open image — it can never be investigated. The smoke defaulted to it.
  let threw = false
  try {
    resolveEvidenceInput(artifactFixtures)
  } catch {
    threw = true
  }
  ok("fixtures/synthetic is not investigable evidence", threw)

  const smoke = readFileSync(fileURLToPath(new URL("../scripts/grok-cloud-smoke.sh", import.meta.url)), "utf8")
  ok("grok smoke does not default evidence to the artifact fixture dir", !/CASEFORGE_GROK_EVIDENCE:-fixtures\/synthetic/.test(smoke))
  ok("grok smoke requires a supported case_open extension", /evtx|pcap|case_open/i.test(smoke) && /SUPPORTED_EVIDENCE_EXTS|case_open extension/.test(smoke))
  ok("grok smoke skips (not fails) when no supported evidence is present", /SKIP: no supported/.test(smoke))
  ok("grok smoke stays cloud-ok + synthetic\\/public only", /--privacy cloud-ok/.test(smoke) && /EVIDENCE_CLASS:-public|EVIDENCE_CLASS:-synthetic/.test(smoke))
}

// --- m28: used_fallback evidenced from the runtime run result (not a constant) --
//
// m27 residual: used_fallback=0 was ASSERTED for the cloud path but recorded in
// no custody artifact and had to be retracted. The value must be READ from the
// runtime run result and recorded so `caseforge verify` can attest it — never
// synthesized.
console.log("used_fallback attestation (runtime run result, not a constant):")
try {
  const { readUsedFallback, assembleRunRecord, writeCaseforgeRun, readCaseforgeRun, attestUsedFallback } = await import(
    "../packages/caseforge-sdk/dist/src/index.js"
  )

  // Only a real boolean is honored; anything else is null (never synthesized).
  ok("readUsedFallback reads a true boolean", readUsedFallback({ used_fallback: true }) === true)
  ok("readUsedFallback reads a false boolean", readUsedFallback({ used_fallback: false }) === false)
  ok("readUsedFallback missing field => null (no synthesis)", readUsedFallback({}) === null)
  ok(
    "readUsedFallback non-boolean/absent => null (no coercion)",
    readUsedFallback({ used_fallback: "0" }) === null && readUsedFallback(undefined) === null && readUsedFallback(1) === null,
  )

  // The recorded value is SOURCED from the runtime result — differing inputs
  // yield differing records, so it cannot be a hardcoded constant.
  const rTrue = assembleRunRecord({ runtimeResult: { used_fallback: true } })
  const rFalse = assembleRunRecord({ runtimeResult: { used_fallback: false } })
  ok("record sources true from runtime run result", rTrue.used_fallback === true && rTrue.used_fallback_source === "runtime_run_result")
  ok("record sources false from runtime run result", rFalse.used_fallback === false && rFalse.used_fallback_source === "runtime_run_result")
  ok("record is not a constant (true != false for differing inputs)", rTrue.used_fallback !== rFalse.used_fallback)
  ok(
    "no runtime result + no orchestration => unknown (never a 0/false constant)",
    assembleRunRecord({}).used_fallback === null && assembleRunRecord({}).used_fallback_source === "unknown",
  )
  const rOrch = assembleRunRecord({ engineUsedFallback: true })
  ok(
    "caseforge deterministic-engine fallback records true from its own control flow",
    rOrch.used_fallback === true && rOrch.used_fallback_source === "caseforge_orchestration",
  )
  ok(
    "runtime run result wins over caseforge orchestration when both present",
    assembleRunRecord({ runtimeResult: { used_fallback: false }, engineUsedFallback: true }).used_fallback === false,
  )

  // Round-trip through the caseforge-owned run artifact + attestation.
  const rd = mkdtempSync(join(tmpdir(), "caseforge-usedfb-"))
  try {
    await writeCaseforgeRun(rd, rTrue)
    const back = await readCaseforgeRun(rd)
    ok("caseforge_run.json round-trips used_fallback", back?.used_fallback === true && back?.used_fallback_source === "runtime_run_result")
    const attested = await attestUsedFallback(rd)
    ok("attestUsedFallback returns the recorded record", attested.used_fallback === true && attested.used_fallback_source === "runtime_run_result")
  } finally {
    rmSync(rd, { recursive: true, force: true })
  }

  // With no caseforge record, attest derives live from the runtime run_result.json.
  const rd2 = mkdtempSync(join(tmpdir(), "caseforge-usedfb2-"))
  try {
    writeFileSync(join(rd2, "run_result.json"), JSON.stringify({ used_fallback: true }))
    const attested = await attestUsedFallback(rd2)
    ok("attest derives used_fallback from runtime run_result.json", attested.used_fallback === true && attested.used_fallback_source === "runtime_run_result")
    const bare = mkdtempSync(join(tmpdir(), "caseforge-usedfb3-"))
    try {
      const a = await attestUsedFallback(bare)
      ok("attest reports unknown when nothing recorded (no synthesis)", a.used_fallback === null && a.used_fallback_source === "unknown")
    } finally {
      rmSync(bare, { recursive: true, force: true })
    }
  } finally {
    rmSync(rd2, { recursive: true, force: true })
  }
} catch (e) {
  ok(`used_fallback attestation section loaded (${(e && e.message) || e})`, false)
}

console.log("verify surfaces used_fallback:")
try {
  const { verify } = await import("../packages/caseforge-cli/dist/src/commands/verify.js")
  const rd = mkdtempSync(join(tmpdir(), "caseforge-verify-fb-"))
  try {
    // A custody-sealed run (audit-chain seal, no verdict.json report).
    writeFileSync(join(rd, "run.manifest.json"), "{}")
    writeFileSync(
      join(rd, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: true } } }) + "\n",
    )
    writeFileSync(join(rd, "run_result.json"), JSON.stringify({ used_fallback: true }))
    const capture = async () => {
      const lines = []
      const orig = console.log
      console.log = (...a) => lines.push(a.join(" "))
      let code
      try {
        code = await verify([rd])
      } finally {
        console.log = orig
      }
      return { out: lines.join("\n"), code }
    }
    const yes = await capture()
    ok("verify surfaces used_fallback: yes sourced from the runtime run result", /used_fallback:\s*yes/i.test(yes.out) && /runtime_run_result/.test(yes.out))
    ok("verify still returns complete (attestation is informational, not a gate)", yes.code === 0)

    rmSync(join(rd, "run_result.json"))
    const unknown = await capture()
    ok("verify reports used_fallback unknown when unrecorded (no synthesized 'no')", /used_fallback:\s*unknown/i.test(unknown.out))
  } finally {
    rmSync(rd, { recursive: true, force: true })
  }
} catch (e) {
  ok(`verify used_fallback section loaded (${(e && e.message) || e})`, false)
}

// --- m28: operator gate on outward cloud investigations --------------------
//
// m27 residual: the lane harness permitted an UNGATED outward cloud call. A
// cloud-privacy investigation must refuse unless the operator explicitly
// acknowledges the egress (CASEFORGE_CLOUD_ACK=1), defaulting off.
console.log("operator cloud-ack gate:")
try {
  const { cloudAckGate, CLOUD_ACK_ENV } = await import("../packages/caseforge-sdk/dist/src/index.js")
  ok("ack env is CASEFORGE_CLOUD_ACK", CLOUD_ACK_ENV === "CASEFORGE_CLOUD_ACK")
  ok("local route needs no operator ack", cloudAckGate({ location: "local" }).allowed === true && cloudAckGate({ location: "local" }).required === false)
  ok("cloud route refuses without ack (default off)", cloudAckGate({ location: "cloud", ack: undefined }).allowed === false)
  ok("cloud route refuses with ack=0", cloudAckGate({ location: "cloud", ack: "0" }).allowed === false)
  ok("cloud route proceeds with ack=1", cloudAckGate({ location: "cloud", ack: "1" }).allowed === true)
  ok("cloud route proceeds with ack=true", cloudAckGate({ location: "cloud", ack: "true" }).allowed === true)
  ok("cloud route proceeds with --cloud-ack flag", cloudAckGate({ location: "cloud", ackFlag: true }).allowed === true)
  ok("refusal reason names the ack env var", /CASEFORGE_CLOUD_ACK/.test(cloudAckGate({ location: "cloud" }).reason))
} catch (e) {
  ok(`cloud-ack gate section loaded (${(e && e.message) || e})`, false)
}

console.log("investigate cloud-ack + used_fallback wiring:")
{
  const src = readFileSync(fileURLToPath(new URL("../packages/caseforge-cli/src/commands/investigate.ts", import.meta.url)), "utf8")
  ok(
    "investigate gates outward cloud calls on operator ack BEFORE any runtime spawn",
    /cloudAckGate/.test(src) && src.indexOf("cloudAckGate") < src.indexOf("spawn(bin") && /CLOUD_ACK_ENV|CASEFORGE_CLOUD_ACK/.test(src),
  )
  ok("investigate refuses ungated cloud without a live call", /ackGate\.allowed/.test(src) && /REFUSED/.test(src))
  ok(
    "investigate records used_fallback from the runtime run result (not a constant)",
    /readRuntimeRunResult/.test(src) && /(assembleRunRecord|writeCaseforgeRun)/.test(src),
  )
  ok(
    "investigate launcher-reserves case_open via FINDEVIL_CASE_OPEN_BINDING",
    /singleEvidenceRegistration/.test(src) && /FINDEVIL_CASE_OPEN_BINDING/.test(src),
  )
  ok(
    "investigate sets parsed-evidence egress ack for cloud routes",
    /FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS/.test(src) && /isCloudRoute/.test(src),
  )
  ok(
    "case_open tool hint includes expected_sha256 when reserved",
    /expected_sha256 exactly/.test(src),
  )
  ok(
    "investigate sets FINDEVIL_CONTROLLER_CAPABILITY for agent-mcp seal tools",
    /FINDEVIL_CONTROLLER_CAPABILITY/.test(src) && /randomBytes\(32\)/.test(src),
  )
  ok(
    "investigate reserves custody boundary like scripts/verdict",
    /FINDEVIL_CUSTODY_BOUNDARY/.test(src) &&
      /reserved_case/.test(src) &&
      /FINDEVIL_ACTIVE_CASE_DIR/.test(src) &&
      /FINDEVIL_ACTIVE_CASE_ID/.test(src) &&
      /FINDEVIL_ACTIVE_RUN_ID/.test(src) &&
      /FINDEVIL_ACTIVE_STARTED_AT/.test(src) &&
      /FINDEVIL_ACTIVE_SIGNER/.test(src) &&
      /\.verdict-case-marker/.test(src) &&
      /reserveCustodyCase/.test(src),
  )
  ok(
    "investigate pins reserved audit/manifest paths and report_qa for seal",
    /report_qa_sha256/.test(src) && /LAB_REPORT_QA_SHA256/.test(src),
  )
  ok(
    "independent manifest re-verify pins ed25519 cert_fingerprint so overall can be true",
    /expected-ed25519-fingerprint/.test(src) && /cert_fingerprint/.test(src),
  )
  {
    const { reserveCustodyCase, LAB_REPORT_QA_SHA256 } = await import(
      "../packages/caseforge-cli/dist/src/commands/investigate.js"
    )
    const findevilHome = mkdtempSync(join(tmpdir(), "cf-custody-"))
    try {
      const env = { FINDEVIL_HOME: findevilHome, XDG_STATE_HOME: join(findevilHome, "state") }
      const c = reserveCustodyCase(env)
      const marker = join(c.caseDir, ".verdict-case-marker")
      ok("reserveCustodyCase creates owner-private case dir + marker", existsSync(marker) && existsSync(c.caseDir))
      ok(
        "reserveCustodyCase sets all FINDEVIL custody env vars",
        env.FINDEVIL_CUSTODY_BOUNDARY === "reserved_case" &&
          env.FINDEVIL_ACTIVE_CASE_DIR === c.caseDir &&
          env.FINDEVIL_ACTIVE_CASE_ID === c.caseId &&
          env.FINDEVIL_ACTIVE_RUN_ID === c.runId &&
          env.FINDEVIL_ACTIVE_STARTED_AT === c.startedAt &&
          env.FINDEVIL_ACTIVE_SIGNER === "ed25519",
      )
      ok("reserveCustodyCase case_id is auto-* uuid style", /^auto-[0-9a-f-]{36}$/i.test(c.caseId))
      ok("LAB_REPORT_QA_SHA256 is 64 hex", /^[0-9a-f]{64}$/.test(LAB_REPORT_QA_SHA256))
      const st = statSync(c.caseDir)
      ok("reserved case dir mode is owner-private (no group/other)", (st.mode & 0o077) === 0)
    } finally {
      rmSync(findevilHome, { recursive: true, force: true })
    }
  }
}

console.log("offline DFIR scorecard grader:")
{
  const gt = loadGroundTruth()
  const runFixture = (name) =>
    JSON.parse(readFileSync(fileURLToPath(new URL(`../fixtures/dfir-scorecard/runs/${name}.verdict.json`, import.meta.url)), "utf8"))

  // All three offline cases were run with the gpt-oss:20b agent forced
  // (CASEFORGE_FORCE_AGENT=1). Every one fell back to the deterministic find_evil_auto
  // engine after the model failed to seal, so the grader must report the detection floor as
  // complete AND flag that the LLM authored none of these seals.
  for (const name of ["win-lateral-movement", "attack-samples", "bench-evtx-2026-07-03"]) {
    const r = scoreRun(runFixture(name), gt.cases[name])
    ok(`scorecard: ${name} elevates every expected target (${r.total_hit}/${r.total_expected})`, r.total_expected > 0 && r.total_hit === r.total_expected)
    ok(`scorecard: ${name} seal is deterministic-fallback (LLM did not author it)`, r.llm_provenance.kind === "deterministic-fallback" && r.llm_provenance.llm === false)
  }

  const winLat = scoreRun(runFixture("win-lateral-movement"), gt.cases["win-lateral-movement"])
  const statusOf = (t) => winLat.techniques.find((x) => x.technique === t)?.status
  ok("scorecard: win-lateral elevates T1047 + T1543.003 (HIT)", statusOf("T1047") === "HIT" && statusOf("T1543.003") === "HIT")
  ok("scorecard: win-lateral cites CVE-2022-21999 (HIT)", winLat.cves.some((c) => c.cve === "CVE-2022-21999" && c.status === "HIT"))
  ok("scorecard: win-lateral verdict in expected band", winLat.verdict === gt.cases["win-lateral-movement"].expected_verdict_band)
  ok("scorecard: grader recognizes an LLM-authored run when present", detectProvenance({ agent: "verdict (gpt-oss:20b)", tool_calls: [1, 2] }).llm === true)
  // Regression guard: if the elevated techniques disappear, the score must drop.
  const regressed = runFixture("win-lateral-movement")
  regressed.attack_coverage = { observed_techniques: [] }
  regressed.findings = []
  ok("scorecard: grader flags a detection regression (fewer HITs)", scoreRun(regressed, gt.cases["win-lateral-movement"]).total_hit < winLat.total_hit)
}

console.log("multi-axis image grader (Proof A):")
{
  const oracle = loadOracle(fileURLToPath(new URL("../fixtures/dfir-image-bench/proofA-winlat/ground-truth.json", import.meta.url)))
  const winLat = JSON.parse(
    readFileSync(fileURLToPath(new URL("../fixtures/dfir-scorecard/runs/win-lateral-movement.verdict.json", import.meta.url)), "utf8"),
  )
  const r = scoreImageRun(winLat, oracle)
  // The captured win-lateral run elevates both techniques + the CVE and emits the planted IOCs,
  // so every axis should score full — proving the grader binds correctly to real verdict fields.
  ok("image: MITRE recall full (techniques + CVE)", r.axes.mitre.hit === r.axes.mitre.total && r.axes.mitre.total === 3)
  ok("image: IOC recovery recall full over emitted categories", r.axes.ioc_recovery.recall === 1 && r.axes.ioc_recovery.hit === 3)
  ok("image: chain coverage + ordering full", r.axes.chain_reconstruction.coverage === 1 && r.axes.chain_reconstruction.ordering === 1)
  ok("image: verdict band matches (INDETERMINATE)", r.axes.verdict_band.match === true)
  ok("image: AI-degree none on a non-AI run (matches oracle)", r.ai_degree.degree === "none" && r.ai_degree.match === true)
  ok("image: provenance is deterministic-fallback (LLM did not author)", r.llm_provenance.kind === "deterministic-fallback")

  // AI-degree detector fires on documented Tier-1 integration artifacts.
  const aiRun = JSON.parse(
    readFileSync(fileURLToPath(new URL("../fixtures/dfir-image-bench/ai-present.verdict.json", import.meta.url)), "utf8"),
  )
  const ai = detectAiDegree(aiRun)
  ok("image: AI-degree = AI-present on seeded integration artifacts", ai.degree === "AI-present" && ai.indicators.includes("provider_key") && ai.indicators.includes("local_llm"))

  // Regression guard: strip the elevated techniques + a planted IOC → MITRE and IOC scores drop.
  const regressed = JSON.parse(JSON.stringify(winLat))
  regressed.attack_coverage = { observed_techniques: [] }
  regressed.findings = []
  regressed.attack_story = { attack_chain: [] }
  regressed.indicators = { ...regressed.indicators, services: [], processes: [], accounts: [] }
  const rr = scoreImageRun(regressed, oracle)
  ok("image: grader flags a detection regression (MITRE + IOC + chain drop)", rr.axes.mitre.hit < r.axes.mitre.hit && rr.axes.ioc_recovery.hit === 0 && rr.axes.chain_reconstruction.coverage === 0)

  // Negative control: an empty verdict must score ~0 on every axis (proves the oracle isn't
  // trivially satisfied), while a wrong-order chain must drop ordering below 1.
  const empty = scoreImageRun({}, oracle)
  ok("image: empty verdict scores zero across axes (negative control)", empty.axes.mitre.hit === 0 && empty.axes.ioc_recovery.hit === 0 && empty.axes.chain_reconstruction.coverage === 0)
  const reordered = JSON.parse(JSON.stringify(winLat))
  reordered.attack_story.attack_chain = [...reordered.attack_story.attack_chain].reverse().map((s, i) => ({ ...s, order: i + 1 }))
  ok("image: reversed chain order drops the ordering score", scoreImageRun(reordered, oracle).axes.chain_reconstruction.ordering < 1)
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
