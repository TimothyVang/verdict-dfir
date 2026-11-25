/**
 * xAI Grok subscription OAuth (SuperGrok) — not XAI_API_KEY platform billing.
 *
 * Uses the VERDICT/opencode runtime: `verdict auth login --provider xai --method …`
 * Credentials land in ~/.local/share/opencode/auth.json under key "xai" (type oauth).
 */
import { existsSync, readFileSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { opencodeAuthPath, verdictLauncherPath } from "./chatgpt-auth.js"

const XAI_PROVIDER_ID = "xai"
const BROWSER_METHOD = "xAI Grok OAuth (SuperGrok Subscription)"
const HEADLESS_METHOD = "xAI Grok OAuth (Headless / Remote / VPS)"

export interface XaiOAuthStatus {
  ok: boolean
  authPath: string
  source: "env" | "file"
  reason?: string
  credentialType?: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function readAuthRecord(): {
  source: "env" | "file"
  authPath: string
  record?: Record<string, unknown>
  reason?: string
} {
  const authPath = opencodeAuthPath()
  const content = process.env.OPENCODE_AUTH_CONTENT
  if (content) {
    try {
      const parsed: unknown = JSON.parse(content)
      return isRecord(parsed)
        ? { source: "env", authPath, record: parsed }
        : { source: "env", authPath, reason: "OPENCODE_AUTH_CONTENT is not an object" }
    } catch {
      return { source: "env", authPath, reason: "OPENCODE_AUTH_CONTENT is not valid JSON" }
    }
  }

  if (!existsSync(authPath)) return { source: "file", authPath, reason: "no opencode auth.json found" }
  try {
    const parsed: unknown = JSON.parse(readFileSync(authPath, "utf8"))
    return isRecord(parsed)
      ? { source: "file", authPath, record: parsed }
      : { source: "file", authPath, reason: "opencode auth.json is not an object" }
  } catch {
    return { source: "file", authPath, reason: "opencode auth.json is not valid JSON" }
  }
}

export function xaiOAuthStatus(): XaiOAuthStatus {
  const loaded = readAuthRecord()
  if (!loaded.record) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      reason: loaded.reason ?? "xAI OAuth credential is missing",
    }
  }

  const credential = loaded.record[XAI_PROVIDER_ID]
  if (!isRecord(credential)) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      reason: "xAI credential is missing",
    }
  }

  const type = typeof credential.type === "string" ? credential.type : undefined
  if (type !== "oauth") {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      credentialType: type,
      reason: type ? `xAI credential is '${type}', not SuperGrok OAuth` : "xAI credential has no type",
    }
  }

  // Access may be short-lived; refresh is required for long agent runs.
  if (typeof credential.refresh !== "string" || credential.refresh.length === 0) {
    return {
      ok: false,
      authPath: loaded.authPath,
      source: loaded.source,
      credentialType: type,
      reason: "xAI OAuth credential has no refresh token",
    }
  }

  return {
    ok: true,
    authPath: loaded.authPath,
    source: loaded.source,
    credentialType: type,
  }
}

export function xaiOAuthLogin(method: string | boolean | undefined): number {
  // default headless (device code) — works on remote/VPS without loopback
  const label = method === "browser" ? BROWSER_METHOD : HEADLESS_METHOD
  const bin = verdictLauncherPath()
  const result = spawnSync(bin, ["auth", "login", "--provider", XAI_PROVIDER_ID, "--method", label], {
    stdio: "inherit",
    env: process.env,
  })
  if (result.error) {
    console.error(`failed to launch ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

export function xaiOAuthLogout(): number {
  const bin = verdictLauncherPath()
  const result = spawnSync(bin, ["auth", "logout", XAI_PROVIDER_ID], {
    stdio: "inherit",
    env: process.env,
  })
  if (result.error) {
    console.error(`failed to launch ${bin}: ${result.error.message}`)
    return 1
  }
  return result.status ?? 1
}

export function printXaiOAuthSetup(): void {
  console.error("Run SuperGrok subscription OAuth (not XAI_API_KEY):")
  console.error("  caseforge auth login --provider xai --method headless")
  console.error("  caseforge auth login --provider xai --method browser")
  console.error("Then: caseforge investigate … --privacy cloud-ok --evidence synthetic --route xai-grok-oauth")
}
