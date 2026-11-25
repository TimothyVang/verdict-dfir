/**
 * Load caseforge configs (model routes + provider capabilities) and resolve a
 * route into a privacy-aware ModelCandidate the SDK router can evaluate.
 */
import { readFileSync, existsSync } from "node:fs"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { parse as parseYaml } from "yaml"
import type { ModelCandidate, ProviderLocation } from "@verdict/caseforge-sdk"

export type RouteAuth = "chatgpt-oauth" | "xai-oauth" | "api-key"

export interface RouteConfig {
  provider: string
  model: string
  base_url?: string
  auth?: RouteAuth
  tool_calling?: boolean | "unknown"
  /** Router contract: cloud-tainted if any listed location is "cloud". */
  privacy_locations: ProviderLocation[]
  network?: boolean
}

export interface RoutingPolicy {
  sensitive_default?: string
  non_sensitive_default?: string
  notes?: string
}

/** Collapse privacy_locations to a single location (fail-closed to cloud). */
export function routeLocation(route: RouteConfig): ProviderLocation {
  return route.privacy_locations?.includes("cloud") ? "cloud" : "local"
}

/**
 * Normalize a local OpenAI-compatible base URL for @ai-sdk/openai-compatible.
 *
 * That client POSTs `${baseURL}/chat/completions`. Ollama/vLLM expose the
 * OpenAI surface under `/v1/chat/completions`. A bare host root
 * (`http://host:11434`) therefore becomes `.../chat/completions` and Ollama
 * answers `404 page not found` — the m13 agent-path failure before EVTX fallback.
 *
 * Only rewrites URLs whose path is empty or `/`. Existing paths (`/v1`,
 * `/api/paas/v4`, etc.) are left alone aside from trailing-slash trim.
 */
export function normalizeOpenAiCompatBaseUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, "")
  if (!trimmed) return trimmed
  try {
    const u = new URL(trimmed)
    if (u.pathname === "" || u.pathname === "/") {
      u.pathname = "/v1"
      return u.toString().replace(/\/$/, "")
    }
    return trimmed
  } catch {
    if (/^https?:\/\/[^/]+$/i.test(trimmed)) return `${trimmed}/v1`
    return trimmed
  }
}

export function routeRequiresChatGptOAuth(route: RouteConfig): boolean {
  return route.auth === "chatgpt-oauth"
}

/** SuperGrok subscription OAuth via verdict/opencode xAI plugin (not XAI_API_KEY). */
export function routeRequiresXaiOAuth(route: RouteConfig): boolean {
  return route.auth === "xai-oauth"
}

/**
 * Platform API-key env var per provider. A subscription-OAuth route must never
 * inherit its own provider's ambient key: the engine would otherwise silently
 * authenticate (and bill) as a platform API user instead of the subscription.
 */
const PROVIDER_PLATFORM_KEY_ENV: Readonly<Record<string, string>> = {
  openai: "OPENAI_API_KEY",
  xai: "XAI_API_KEY",
}

/**
 * Build the child-process env for `route`, returning a NEW object.
 *
 * For an OAuth route: drop the provider's ambient platform key and load the
 * provider's opencode credential (unless the caller already supplied one via
 * the ambient `OPENCODE_AUTH_CONTENT`). For an api-key route: leave the env
 * alone — its platform key is exactly what it needs.
 */
export function oauthRuntimeEnv(
  route: RouteConfig,
  baseEnv: NodeJS.ProcessEnv,
  opts: { authContent?: string } = {},
): NodeJS.ProcessEnv {
  const isOAuth = routeRequiresChatGptOAuth(route) || routeRequiresXaiOAuth(route)
  if (!isOAuth) return { ...baseEnv }

  const env: NodeJS.ProcessEnv = { ...baseEnv }
  const platformKey = PROVIDER_PLATFORM_KEY_ENV[route.provider]
  if (platformKey) delete env[platformKey]
  if (!env.OPENCODE_AUTH_CONTENT && opts.authContent) env.OPENCODE_AUTH_CONTENT = opts.authContent
  return env
}

/**
 * Repo root: walk up from this module until a directory containing
 * `configs/model-routes.yaml` is found. Robust to running from `src` or `dist`.
 */
export function repoRoot(): string {
  let dir = resolve(fileURLToPath(import.meta.url), "..")
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "configs", "model-routes.yaml"))) return dir
    const parent = resolve(dir, "..")
    if (parent === dir) break
    dir = parent
  }
  // Fallback to CWD (supports CASEFORGE_CONFIG_DIR override in configsDir()).
  return process.cwd()
}

export function configsDir(): string {
  return process.env.CASEFORGE_CONFIG_DIR ?? join(repoRoot(), "configs")
}

function loadYaml<T>(name: string): T | undefined {
  const path = join(configsDir(), name)
  if (!existsSync(path)) return undefined
  return parseYaml(readFileSync(path, "utf8")) as T
}

/** All named routes from model-routes.yaml (routes: { id: {...} }). */
export function loadRoutes(): Record<string, RouteConfig> {
  const doc = loadYaml<{ routes?: Record<string, RouteConfig> }>("model-routes.yaml")
  return doc?.routes ?? {}
}

export function loadRoutingPolicy(): RoutingPolicy {
  const doc = loadYaml<{ routing_policy?: RoutingPolicy }>("model-routes.yaml")
  return doc?.routing_policy ?? {}
}

/** Resolve a route id into a ModelCandidate for the privacy router. */
export function resolveCandidate(routeId: string): { candidate: ModelCandidate; route: RouteConfig } | undefined {
  const routes = loadRoutes()
  const route = routes[routeId]
  if (!route) return undefined
  return {
    route,
    candidate: {
      id: `${routeId}`,
      location: routeLocation(route),
      network: route.network,
    },
  }
}

/** The locked opencode profile directory (agents/commands/skill + config). */
export function opencodeProfileDir(): string {
  return join(configsDir(), "opencode")
}
