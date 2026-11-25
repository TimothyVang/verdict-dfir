import { accessSync, constants, existsSync, readFileSync, realpathSync } from "node:fs"
import { delimiter, join } from "node:path"
import { homedir } from "node:os"
import { spawnSync } from "node:child_process"
import { repoRoot } from "./config.js"

const OPENAI_PROVIDER_ID = "openai"
const BROWSER_METHOD = "ChatGPT Pro/Plus (browser)"
const HEADLESS_METHOD = "ChatGPT Pro/Plus (headless)"

export interface ChatGptOAuthStatus {
  ok: boolean
  authPath: string
  source: "env" | "file"
  reason?: string
  credentialType?: string
}

export interface VerdictRuntimeResolution {
  launcherPath: string
  runtimePath?: string
  runtimeSource?: "VERDICT_BIN" | "PATH"
  runtimeVersion?: string
  reason?: string
  recursive?: boolean
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function opencodeAuthPath(): string {
  return join(process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share"), "opencode", "auth.json")
}

export function caseForgeLauncherPath(): string {
  return join(repoRoot(), "bin", "verdict")
}

export function verdictLauncherPath(env: NodeJS.ProcessEnv = process.env): string {
  const local = caseForgeLauncherPath()
  if (existsSync(local)) return local
  return env.VERDICT_BIN ?? "verdict"
}

function realPath(path: string): string {
  try {
    return realpathSync(path)
  } catch {
    return path
  }
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}

function executableNames(): string[] {
  return process.platform === "win32" ? ["verdict.exe", "verdict.cmd", "verdict.bat", "verdict"] : ["verdict"]
}

function runProbe(bin: string, args: string[], env: NodeJS.ProcessEnv): { ok: true; output: string } | { ok: false; reason: string } {
  const result = spawnSync(bin, args, {
    encoding: "utf8",
    env,
    timeout: 5000,
    maxBuffer: 128 * 1024,
  })
  if (result.error) return { ok: false, reason: result.error.message }
  if (result.status !== 0) return { ok: false, reason: `${args.join(" ")} exited ${result.status ?? "unknown"}` }
  return { ok: true, output: `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim() }
}

function probeVerdictRuntime(bin: string, env: NodeJS.ProcessEnv): { ok: true; version: string } | { ok: false; reason: string } {
  const version = runProbe(bin, ["--version"], env)
  if (!version.ok) return { ok: false, reason: `--version failed: ${version.reason}` }
  const versionLine = version.output.split(/\r?\n/).find(Boolean)?.trim() ?? ""
  if (!/\d+\.\d+\.\d+/.test(versionLine)) return { ok: false, reason: `--version did not look like an opencode/verdict version: ${versionLine || "<empty>"}` }

  const runHelp = runProbe(bin, ["run", "--help"], env)
  if (!runHelp.ok) return { ok: false, reason: `run --help failed: ${runHelp.reason}` }
  if (!/\b(?:opencode|verdict) run\b/i.test(runHelp.output) || !/--agent\b/.test(runHelp.output) || !/--model\b/.test(runHelp.output)) {
    return { ok: false, reason: "run --help did not expose the expected opencode/verdict run interface" }
  }

  const authHelp = runProbe(bin, ["auth", "--help"], env)
  if (!authHelp.ok) return { ok: false, reason: `auth --help failed: ${authHelp.reason}` }
  if (!/\b(?:opencode|verdict) auth\b/i.test(authHelp.output) || !/\bauth login\b/.test(authHelp.output) || !/\bauth logout\b/.test(authHelp.output)) {
    return { ok: false, reason: "auth --help did not expose the expected opencode/verdict auth interface" }
  }

  return { ok: true, version: versionLine }
}

function runtimeCandidate(
  bin: string,
  source: "VERDICT_BIN" | "PATH",
  launcherPath: string,
  env: NodeJS.ProcessEnv,
): VerdictRuntimeResolution | undefined {
  if (!isExecutable(bin)) return source === "VERDICT_BIN" ? { launcherPath, reason: `VERDICT_BIN is not executable: ${bin}` } : undefined
  const probe = probeVerdictRuntime(bin, env)
  if (!probe.ok) return source === "VERDICT_BIN" ? { launcherPath, reason: `VERDICT_BIN is not a VERDICT runtime: ${probe.reason}` } : undefined
  return { launcherPath, runtimePath: realPath(bin), runtimeSource: source, runtimeVersion: probe.version }
}

export function resolveVerdictRuntime(env: NodeJS.ProcessEnv = process.env): VerdictRuntimeResolution {
  const launcherPath = caseForgeLauncherPath()
  const launcherReal = existsSync(launcherPath) ? realPath(launcherPath) : undefined
  const fromEnv = env.VERDICT_BIN

  if (fromEnv) {
    const runtimeReal = realPath(fromEnv)
    if (launcherReal && runtimeReal === launcherReal) {
      return {
        launcherPath,
        reason: "VERDICT_BIN points back to the CaseForge launcher",
        recursive: true,
      }
    }
    return runtimeCandidate(fromEnv, "VERDICT_BIN", launcherPath, env) ?? { launcherPath, reason: `VERDICT_BIN is not executable: ${fromEnv}` }
  }

  for (const dir of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
    for (const name of executableNames()) {
      const candidate = join(dir, name)
      const candidateReal = realPath(candidate)
      if (candidateReal === launcherReal || !isExecutable(candidate)) continue
      const runtime = runtimeCandidate(candidate, "PATH", launcherPath, env)
      if (runtime) return runtime
    }
  }

  return {
    launcherPath,
    reason: "external verdict runtime not found on PATH; set VERDICT_BIN=/path/to/verdict",
  }
}

function readAuthRecord(): { source: "env" | "file"; authPath: string; record?: Record<string, unknown>; reason?: string } {
  const authPath = opencodeAuthPath()
  const content = process.env.OPENCODE_AUTH_CONTENT
  if (content) {
    try {
      const parsed: unknown = JSON.parse(content)
      return isRecord(parsed) ? { source: "env", authPath, record: parsed } : { source: "env", authPath, reason: "OPENCODE_AUTH_CONTENT is not an object" }
    } catch {
      return { source: "env", authPath, reason: "OPENCODE_AUTH_CONTENT is not valid JSON" }
    }
  }

  if (!existsSync(authPath)) return { source: "file", authPath, reason: "no opencode auth.json found" }
  try {
    const parsed: unknown = JSON.parse(readFileSync(authPath, "utf8"))
    return isRecord(parsed) ? { source: "file", authPath, record: parsed } : { source: "file", authPath, reason: "opencode auth.json is not an object" }
  } catch {
    return { source: "file", authPath, reason: "opencode auth.json is not valid JSON" }
  }
}

export function chatGptOAuthStatus(): ChatGptOAuthStatus {
  const loaded = readAuthRecord()
  if (!loaded.record) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      reason: loaded.reason ?? "OpenAI OAuth credential is missing",
    }
  }

  const credential = loaded.record[OPENAI_PROVIDER_ID]
  if (!isRecord(credential)) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      reason: "OpenAI credential is missing",
    }
  }

  const type = typeof credential.type === "string" ? credential.type : undefined
  if (type !== "oauth") {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      credentialType: type,
      reason: type ? `OpenAI credential is '${type}', not ChatGPT OAuth` : "OpenAI credential has no type",
    }
  }

  if (typeof credential.refresh !== "string" || credential.refresh.length === 0) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      credentialType: type,
      reason: "OpenAI OAuth credential has no refresh token",
    }
  }

  return {
    ok: true,
    authPath: loaded.authPath,
    source: loaded.source,
    credentialType: type,
  }
}

export function chatGptOAuthLogin(method: string | boolean | undefined): number {
  const label = method === "browser" ? BROWSER_METHOD : HEADLESS_METHOD
  const bin = verdictLauncherPath()
  const result = spawnSync(bin, ["auth", "login", "--provider", OPENAI_PROVIDER_ID, "--method", label], {
    stdio: "inherit",
    env: process.env,
  })
  if (result.error) {
    console.error(`failed to launch ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

export function chatGptOAuthLogout(): number {
  const bin = verdictLauncherPath()
  const result = spawnSync(bin, ["auth", "logout", OPENAI_PROVIDER_ID], {
    stdio: "inherit",
    env: process.env,
  })
  if (result.error) {
    console.error(`failed to launch ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

export function printChatGptOAuthSetup(): void {
  console.error("Run: caseforge auth login --method headless")
  console.error("or:  caseforge auth login --method browser")
}
