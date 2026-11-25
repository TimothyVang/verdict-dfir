import {
  createOpencodeClient,
  createOpencodeServer,
  createOpencodeTui,
  type OpencodeClient,
} from "@opencode-ai/sdk"

import type {
  AskOptions,
  ModelRef,
  SessionHandle,
  TuiLaunchOptions,
  VerdictHarnessOptions,
  VerdictMcpConfig,
} from "./types.js"
import { printMasthead } from "./masthead.js"

const DEFAULT_HOSTNAME = "127.0.0.1"
const DEFAULT_MCP_NAME = "verdict"

/** VERDICT brand theme shipped in `.opencode/themes/verdict.json`. */
export const DEFAULT_THEME = "verdict"

/** VERDICT-branded opencode fork binary. */
export const DEFAULT_BINARY = "verdict"

/**
 * Drives an opencode agent that has the VERDICT forensic MCP server attached.
 *
 * Two modes:
 *  - Spawned: no `baseUrl` given -> the harness starts its own opencode server
 *    (via the vendored SDK) with the VERDICT MCP server wired into its config.
 *  - Attached: `baseUrl` given -> the harness connects to an existing server and
 *    leaves lifecycle/config to whoever launched it.
 */
export class VerdictHarness {
  private readonly options: VerdictHarnessOptions
  private client: OpencodeClient | null = null
  private server: { url: string; close(): void } | null = null

  constructor(options: VerdictHarnessOptions = {}) {
    this.options = options
  }

  /** Start (or connect to) the server and return the ready harness. */
  async start(): Promise<this> {
    if (this.client) return this

    if (this.options.baseUrl) {
      this.client = createOpencodeClient({
        baseUrl: this.options.baseUrl,
        directory: this.options.directory,
      })
      return this
    }

    this.applyBinaryEnv()
    this.server = await createOpencodeServer({
      hostname: this.options.hostname ?? DEFAULT_HOSTNAME,
      port: this.options.port,
      config: this.buildServerConfig(),
    })
    this.client = createOpencodeClient({
      baseUrl: this.server.url,
      directory: this.options.directory,
    })
    return this
  }

  /** Stop a harness-spawned server. No-op in attached mode. */
  async stop(): Promise<void> {
    this.server?.close()
    this.server = null
    this.client = null
  }

  /** The underlying SDK client, for calls the harness does not wrap. */
  get raw(): OpencodeClient {
    return this.requireClient()
  }

  /** Base URL of the server the harness is talking to. */
  get url(): string | undefined {
    return this.server?.url ?? this.options.baseUrl
  }

  // --- session lifecycle -------------------------------------------------

  async createSession(title?: string): Promise<SessionHandle> {
    const res = await this.requireClient().session.create({
      body: title ? { title } : {},
      query: this.directoryQuery(),
    })
    const info = unwrap(res, "session.create")
    return { id: info.id, title: info.title }
  }

  async deleteSession(id: string): Promise<void> {
    const res = await this.requireClient().session.delete({ path: { id } })
    unwrap(res, "session.delete")
  }

  /**
   * Send one prompt turn and return the assistant's concatenated text.
   * Model/agent fall back to the harness defaults when not overridden.
   */
  async ask(sessionID: string, text: string, opts: AskOptions = {}): Promise<string> {
    const model = opts.model ?? this.options.model
    const agent = opts.agent ?? this.options.agent

    const res = await this.requireClient().session.prompt({
      path: { id: sessionID },
      body: {
        ...(model ? { model } : {}),
        ...(agent ? { agent } : {}),
        ...(opts.system ? { system: opts.system } : {}),
        ...(opts.tools ? { tools: opts.tools } : {}),
        parts: [{ type: "text", text }],
      },
    })
    const message = unwrap(res, "session.prompt")
    return extractText(message)
  }

  // --- introspection -----------------------------------------------------

  /** All tool IDs the server currently exposes (including VERDICT's). */
  async listTools(): Promise<string[]> {
    const res = await this.requireClient().tool.ids()
    return unwrap(res, "tool.ids") as string[]
  }

  /** Connection status of every configured MCP server. */
  async mcpStatus(): Promise<unknown> {
    const res = await this.requireClient().mcp.status()
    return unwrap(res, "mcp.status")
  }

  /** Available provider/model catalog. */
  async providers(): Promise<unknown> {
    const res = await this.requireClient().config.providers()
    return unwrap(res, "config.providers")
  }

  /** Named agent presets configured on the server. */
  async agents(): Promise<unknown> {
    const res = await this.requireClient().app.agents()
    return unwrap(res, "app.agents")
  }

  // --- event stream ------------------------------------------------------

  /**
   * Subscribe to the server event stream and invoke `handler` per event.
   * Resolves when the stream ends or `signal` aborts. Errors from `handler`
   * are surfaced to the caller (the stream stops).
   */
  async onEvents(
    handler: (event: unknown) => void | Promise<void>,
    signal?: AbortSignal,
  ): Promise<void> {
    const { stream } = await this.requireClient().event.subscribe()
    for await (const event of stream) {
      if (signal?.aborted) break
      await handler(event)
    }
  }

  // --- TUI ---------------------------------------------------------------

  /**
   * Launch the opencode terminal UI, branded with the VERDICT theme, pointed at
   * the harness working directory. Returns a handle whose `close()` stops the
   * TUI process. Does not require `start()` — it spawns its own opencode TUI.
   */
  launchTui(opts: TuiLaunchOptions = {}): { close(): void } {
    const model = opts.model ?? this.options.model
    const theme = this.resolveTheme()
    const banner = opts.banner ?? "exit"

    this.applyBinaryEnv()
    if (banner === "launch" || banner === "both") printMasthead()

    const tui = createOpencodeTui({
      project: this.options.directory,
      agent: opts.agent ?? this.options.agent,
      session: opts.session,
      signal: opts.signal,
      ...(model ? { model: `${model.providerID}/${model.modelID}` } : {}),
      ...(theme ? { config: { theme } } : {}),
    })

    if (banner === "exit" || banner === "both") {
      return {
        close: () => {
          tui.close()
          printMasthead()
        },
      }
    }
    return tui
  }

  // --- internals ---------------------------------------------------------

  private buildServerConfig() {
    const config: Record<string, unknown> = {}

    const theme = this.resolveTheme()
    if (theme) config.theme = theme

    const mcp = this.options.verdictMcp
    if (mcp) {
      const name = this.options.mcpName ?? DEFAULT_MCP_NAME
      config.mcp = { [name]: toSdkMcp(mcp) }
    }

    return Object.keys(config).length > 0 ? config : undefined
  }

  /** Resolve the theme name, honouring an explicit `null` opt-out. */
  private resolveTheme(): string | undefined {
    if (this.options.theme === null) return undefined
    return this.options.theme ?? DEFAULT_THEME
  }

  /**
   * Point the vendored SDK at the configured binary (default: the branded
   * `verdict` fork) via its `OPENCODE_BIN` env hook, read at spawn time.
   */
  private applyBinaryEnv(): void {
    process.env.OPENCODE_BIN = this.options.binary ?? DEFAULT_BINARY
  }

  private directoryQuery() {
    return this.options.directory ? { directory: this.options.directory } : undefined
  }

  private requireClient(): OpencodeClient {
    if (!this.client) {
      throw new Error("VerdictHarness not started — call start() first")
    }
    return this.client
  }
}

/** Translate the harness MCP config into the opencode SDK config shape. */
function toSdkMcp(mcp: VerdictMcpConfig) {
  if (mcp.type === "local") {
    return {
      type: "local" as const,
      command: mcp.command,
      environment: mcp.environment,
      enabled: mcp.enabled ?? true,
    }
  }
  return {
    type: "remote" as const,
    url: mcp.url,
    headers: mcp.headers,
    enabled: mcp.enabled ?? true,
  }
}

/**
 * hey-api calls return `{ data, error }` unless `throwOnError` is set. Centralise
 * that unwrap so every wrapper fails loudly with a named context on error.
 */
function unwrap<T>(res: { data?: T; error?: unknown }, context: string): T {
  if (res.error !== undefined && res.error !== null) {
    throw new Error(`${context} failed: ${JSON.stringify(res.error)}`)
  }
  if (res.data === undefined) {
    throw new Error(`${context} returned no data`)
  }
  return res.data
}

/** Concatenate text parts from an assistant message response. */
function extractText(message: unknown): string {
  const parts = (message as { parts?: Array<{ type: string; text?: string }> })?.parts
  if (!Array.isArray(parts)) return ""
  return parts
    .filter((p) => p.type === "text" && typeof p.text === "string")
    .map((p) => p.text as string)
    .join("")
}

export type { ModelRef }
