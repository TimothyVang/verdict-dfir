/** `caseforge doctor` — environment + config prerequisite check. */
import { existsSync } from "node:fs"
import { join } from "node:path"
import { execFileSync } from "node:child_process"
import { DEFAULT_PRIVACY_MODE } from "@verdict/caseforge-sdk"
import { caseForgeLauncherPath, chatGptOAuthStatus, resolveVerdictRuntime } from "../chatgpt-auth.js"
import { xaiOAuthStatus } from "../xai-auth.js"
import {
  configsDir,
  loadRoutes,
  loadRoutingPolicy,
  normalizeOpenAiCompatBaseUrl,
  opencodeProfileDir,
  routeLocation,
  routeRequiresChatGptOAuth,
  routeRequiresXaiOAuth,
  type RouteConfig,
} from "../config.js"

export interface DoctorOpts {
  route?: string
}

function has(cmd: string): boolean {
  try {
    execFileSync("bash", ["-lc", `command -v ${cmd}`], { stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

async function reachable(baseUrl: string): Promise<boolean> {
  const candidates = [baseUrl.replace(/\/v1\/?$/, "/api/tags"), `${baseUrl.replace(/\/$/, "")}/models`]
  for (const url of candidates) {
    try {
      const ctl = new AbortController()
      const t = setTimeout(() => ctl.abort(), 2500)
      const res = await fetch(url, { signal: ctl.signal }).catch(() => undefined)
      clearTimeout(t)
      if (res) return true
    } catch {
      /* try next */
    }
  }
  return false
}

export function selectedLocalEndpoint(route: RouteConfig, env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (routeLocation(route) !== "local") return undefined
  const raw = env.VERDICT_LLM_BASEURL ?? route.base_url ?? "http://localhost:11434/v1"
  return normalizeOpenAiCompatBaseUrl(raw)
}

export async function doctor(opts: DoctorOpts = {}): Promise<number> {
  let fail = 0
  let warn = 0
  const ok = (m: string) => console.log(`  [ok]   ${m}`)
  const miss = (m: string) => {
    console.log(`  [MISS] ${m}`)
    fail++
  }
  const note = (m: string) => {
    console.log(`  [warn] ${m}`)
    warn++
  }

  console.log("caseforge doctor\n")
  console.log(`privacy default: ${DEFAULT_PRIVACY_MODE} (real evidence stays local unless overridden)\n`)

  // agent runtime
  const verdictBin = caseForgeLauncherPath()
  existsSync(verdictBin) ? ok(`CaseForge verdict launcher: ${verdictBin}`) : miss(`CaseForge verdict launcher missing: ${verdictBin}`)
  const runtime = resolveVerdictRuntime()
  runtime.runtimePath
    ? ok(`VERDICT runtime (${runtime.runtimeSource}): ${runtime.runtimePath}${runtime.runtimeVersion ? ` (${runtime.runtimeVersion})` : ""}`)
    : miss(`VERDICT runtime missing: ${runtime.reason}`)

  // locked opencode profile
  existsSync(join(opencodeProfileDir(), "opencode.json"))
    ? ok(`locked opencode profile: ${opencodeProfileDir()}`)
    : miss("configs/opencode/opencode.json missing")

  // VERDICT MCP toolkit
  const dfirHome = process.env.VERDICT_DFIR_HOME
  if (dfirHome && existsSync(join(dfirHome, "scripts/run-mcp-rust.sh"))) {
    ok(`VERDICT toolkit (VERDICT_DFIR_HOME): ${dfirHome}`)
    existsSync(join(dfirHome, "target/release/findevil-mcp"))
      ? ok("findevil-mcp release binary present")
      : miss("findevil-mcp not prebuilt (cargo build --release -p findevil-mcp)")
    has("uv") ? ok("uv present (findevil-agent-mcp)") : miss("uv missing (findevil-agent-mcp)")
  } else {
    miss("VERDICT_DFIR_HOME not set to a toolkit checkout with scripts/run-mcp-rust.sh")
  }

  // routes + local endpoints
  const routes = loadRoutes()
  const policy = loadRoutingPolicy()
  const ids = Object.keys(routes)
  ids.length ? ok(`${ids.length} routes in ${join(configsDir(), "model-routes.yaml")}`) : miss("no routes in configs/model-routes.yaml")
  const selected = opts.route ?? process.env.CASEFORGE_ROUTE ?? policy.sensitive_default
  if (selected) {
    const route = routes[selected]
    if (!route) {
      miss(`selected route '${selected}' not found in configs/model-routes.yaml`)
    } else {
      ok(`selected route: ${selected}`)
      const endpoint = selectedLocalEndpoint(route)
      if (endpoint) {
        ;(await reachable(endpoint)) ? ok(`selected local endpoint reachable (${endpoint})`) : miss(`selected local endpoint down (${endpoint})`)
      }
      if (routeRequiresChatGptOAuth(route)) {
        const status = chatGptOAuthStatus()
        status.ok ? ok("ChatGPT OAuth credential present for provider 'openai'") : miss(`ChatGPT OAuth credential missing: ${status.reason}`)
      }
      if (routeRequiresXaiOAuth(route)) {
        const status = xaiOAuthStatus()
        status.ok
          ? ok("SuperGrok OAuth credential present for provider 'xai'")
          : miss(`SuperGrok OAuth credential missing: ${status.reason}`)
      }
    }
  } else {
    note("no selected/default route configured; set routing_policy.sensitive_default or pass --route")
  }

  for (const [id, r] of Object.entries(routes)) {
    if (id === selected) continue
    if (routeLocation(r) === "local" && r.base_url) {
      ;(await reachable(r.base_url)) ? ok(`optional local route '${id}' endpoint reachable (${r.base_url})`) : note(`optional local route '${id}' endpoint down (${r.base_url})`)
    }
  }

  console.log()
  if (fail === 0) {
    console.log(warn === 0 ? "All prerequisites satisfied." : `Selected-route prerequisites satisfied; ${warn} optional item(s) noted above.`)
    return 0
  }
  console.log(`${fail} required item(s) need attention above; ${warn} optional item(s) noted.`)
  return 1
}
