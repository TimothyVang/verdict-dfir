/**
 * Unit tests for SuperGrok OAuth status + route auth flags.
 * Drives the shipped modules (no reimplementation).
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { routeRequiresXaiOAuth, routeRequiresChatGptOAuth, type RouteConfig } from "./config.js"
import { xaiOAuthStatus } from "./xai-auth.js"

const oauthRoute: RouteConfig = {
  provider: "xai",
  model: "grok-3",
  auth: "xai-oauth",
  privacy_locations: ["cloud"],
}
const apiRoute: RouteConfig = {
  provider: "xai",
  model: "grok-3",
  auth: "api-key",
  privacy_locations: ["cloud"],
}
const chatgptRoute: RouteConfig = {
  provider: "openai",
  model: "gpt-5.5",
  auth: "chatgpt-oauth",
  privacy_locations: ["cloud"],
}

describe("routeRequiresXaiOAuth (shipped config)", () => {
  test("xai-oauth routes require SuperGrok OAuth", () => {
    expect(routeRequiresXaiOAuth(oauthRoute)).toBe(true)
    expect(routeRequiresXaiOAuth(apiRoute)).toBe(false)
    expect(routeRequiresChatGptOAuth(oauthRoute)).toBe(false)
    expect(routeRequiresChatGptOAuth(chatgptRoute)).toBe(true)
  })
})

describe("xaiOAuthStatus (shipped xai-auth)", () => {
  const prevContent = process.env.OPENCODE_AUTH_CONTENT
  const prevXdg = process.env.XDG_DATA_HOME
  let dataHome: string

  beforeEach(() => {
    dataHome = join(tmpdir(), `caseforge-xai-auth-test-${process.pid}-${Date.now()}`)
    mkdirSync(join(dataHome, "opencode"), { recursive: true })
    process.env.XDG_DATA_HOME = dataHome
    delete process.env.OPENCODE_AUTH_CONTENT
  })

  afterEach(() => {
    if (prevContent === undefined) delete process.env.OPENCODE_AUTH_CONTENT
    else process.env.OPENCODE_AUTH_CONTENT = prevContent
    if (prevXdg === undefined) delete process.env.XDG_DATA_HOME
    else process.env.XDG_DATA_HOME = prevXdg
    try {
      rmSync(dataHome, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  })

  test("missing auth.json → not ok", () => {
    const st = xaiOAuthStatus()
    expect(st.ok).toBe(false)
    expect(st.reason).toMatch(/no opencode auth\.json|missing/i)
  })

  test("api-key credential for xai is not SuperGrok OAuth", () => {
    writeFileSync(
      join(dataHome, "opencode", "auth.json"),
      JSON.stringify({ xai: { type: "api", key: "xai-fake" } }),
    )
    const st = xaiOAuthStatus()
    expect(st.ok).toBe(false)
    expect(st.credentialType).toBe("api")
    expect(st.reason).toMatch(/not SuperGrok OAuth|api/i)
  })

  test("oauth without refresh token is not ok", () => {
    writeFileSync(
      join(dataHome, "opencode", "auth.json"),
      JSON.stringify({ xai: { type: "oauth", access: "tok", refresh: "" } }),
    )
    const st = xaiOAuthStatus()
    expect(st.ok).toBe(false)
    expect(st.reason).toMatch(/refresh/i)
  })

  test("valid oauth refresh token is ok", () => {
    writeFileSync(
      join(dataHome, "opencode", "auth.json"),
      JSON.stringify({
        xai: { type: "oauth", access: "access-tok", refresh: "refresh-tok", expires: Date.now() + 3600_000 },
      }),
    )
    const st = xaiOAuthStatus()
    expect(st.ok).toBe(true)
    expect(st.credentialType).toBe("oauth")
    expect(st.source).toBe("file")
  })

  test("OPENCODE_AUTH_CONTENT env overrides file", () => {
    writeFileSync(join(dataHome, "opencode", "auth.json"), JSON.stringify({ xai: { type: "oauth", refresh: "file" } }))
    process.env.OPENCODE_AUTH_CONTENT = JSON.stringify({})
    const st = xaiOAuthStatus()
    expect(st.ok).toBe(false)
    expect(st.source).toBe("env")
    expect(existsSync(join(dataHome, "opencode", "auth.json"))).toBe(true)
  })
})
