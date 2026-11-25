/**
 * Public types for the VERDICT agent harness.
 *
 * These are intentionally small and decoupled from the vendored opencode SDK
 * so callers depend on this surface, not on generated SDK internals.
 */

/** A concrete provider/model selection understood by the opencode server. */
export interface ModelRef {
  providerID: string
  modelID: string
}

/**
 * How the VERDICT forensic MCP server should be attached to the opencode
 * session. VERDICT ships as a read-only MCP server exposing typed DFIR tools;
 * the harness wires it in so an agent can drive investigations.
 */
export type VerdictMcpConfig = VerdictMcpLocal | VerdictMcpRemote

export interface VerdictMcpLocal {
  type: "local"
  /** Command + args that launch the VERDICT MCP server, e.g. ["verdict", "mcp"]. */
  command: string[]
  environment?: Record<string, string>
  /** Defaults to true. */
  enabled?: boolean
}

export interface VerdictMcpRemote {
  type: "remote"
  /** URL of a running VERDICT MCP server. */
  url: string
  headers?: Record<string, string>
  /** Defaults to true. */
  enabled?: boolean
}

export interface VerdictHarnessOptions {
  /**
   * Connect to an already-running opencode server at this base URL. When set,
   * the harness will NOT spawn its own server and `mcp`/`config` that require a
   * fresh server launch are ignored.
   */
  baseUrl?: string

  /** Hostname for a harness-spawned server. Defaults to 127.0.0.1. */
  hostname?: string
  /** Port for a harness-spawned server. Defaults to an ephemeral port. */
  port?: number

  /**
   * Working directory the agent operates in (the evidence/case workspace).
   * Defaults to the current process directory.
   */
  directory?: string

  /** Default model for prompts when a call does not specify one. */
  model?: ModelRef

  /** Default named agent (opencode agent preset) for prompts. */
  agent?: string

  /** VERDICT MCP server wiring. Injected into the spawned server config. */
  verdictMcp?: VerdictMcpConfig

  /** Key under which the VERDICT MCP server is registered. Defaults to "verdict". */
  mcpName?: string

  /**
   * opencode theme name applied to the spawned server and any launched TUI.
   * Defaults to "verdict" (the VERDICT brand theme shipped in
   * `.opencode/themes/verdict.json`). Set to `null` to leave the theme unset
   * and inherit opencode's default.
   */
  theme?: string | null

  /**
   * Binary that runs the opencode server/TUI. Defaults to "verdict" — the
   * VERDICT-branded fork (https://github.com/TimothyVang/verdict-opencode).
   * Set to "opencode" to use stock upstream, or an absolute path to a specific
   * build. Ignored in attached (`baseUrl`) mode. Applied via the vendored SDK's
   * `OPENCODE_BIN` env hook.
   */
  binary?: string
}

/** Options for launching the branded opencode TUI. */
export interface TuiLaunchOptions {
  /** Attach the TUI to an existing session instead of a fresh one. */
  session?: string
  /** Override the harness default model for the TUI. */
  model?: ModelRef
  /** Override the harness default agent for the TUI. */
  agent?: string
  /** Abort signal to close the TUI process. */
  signal?: AbortSignal

  /**
   * When to print the VERDICT brand masthead around the TUI. The TUI uses the
   * alternate screen buffer, so a "launch" banner is usually cleared once it
   * paints — "exit" is the one that reliably persists. Default: "exit".
   */
  banner?: "launch" | "exit" | "both" | "none"
}

/** Options for a single prompt turn. */
export interface AskOptions {
  /** Override the harness default model for this turn. */
  model?: ModelRef
  /** Override the harness default agent for this turn. */
  agent?: string
  /** Per-tool enable/disable map, e.g. { "verdict_*": true }. */
  tools?: Record<string, boolean>
  /** System prompt override for this turn. */
  system?: string
}

/** Minimal shape of an opencode session the harness returns to callers. */
export interface SessionHandle {
  id: string
  title?: string
}
