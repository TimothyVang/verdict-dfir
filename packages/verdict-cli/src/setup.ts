import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"

export type SetupClient = "claude" | "cursor" | "codex" | "all"

export interface SetupAction {
  client: string
  config_path: string
  backup_path: string | null
  skill_dest: string
  applied: boolean
}

function utcStamp(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")
}

function mergeJsonMcpServer(
  configPath: string,
  entryScript: string,
  apply: boolean,
): { backupPath: string | null; applied: boolean } {
  let backupPath: string | null = null
  if (!apply) {
    return { backupPath: existsSync(configPath) ? `${configPath}.<timestamp>.bak` : null, applied: false }
  }

  mkdirSync(dirname(configPath), { recursive: true })
  let doc: Record<string, unknown> = {}
  if (existsSync(configPath)) {
    backupPath = `${configPath}.${utcStamp()}.bak`
    copyFileSync(configPath, backupPath)
    try {
      doc = JSON.parse(readFileSync(configPath, "utf8")) as Record<string, unknown>
    } catch {
      doc = {}
    }
  }

  const mcpServers = (doc.mcpServers && typeof doc.mcpServers === "object" ? doc.mcpServers : {}) as Record<
    string,
    unknown
  >
  mcpServers.verdict = {
    command: "node",
    args: [entryScript, "serve"],
  }
  doc.mcpServers = mcpServers
  writeFileSync(configPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8")
  return { backupPath, applied: true }
}

/**
 * REA-style setup: read-only plan by default; with `apply: true`, backs up existing
 * configs with UTC timestamps, registers the `verdict` MCP server, and copies the
 * portable `.agents/skills/verdict-dfir` skill.
 */
export function runSetup(opts: {
  repoRoot: string
  client: SetupClient
  apply: boolean
  homeDir?: string
}): {
  mode: "read-only-plan" | "applied"
  mcp_command: { command: string; args: string[] }
  actions: SetupAction[]
} {
  const home = resolve(opts.homeDir ?? homedir())
  const entryScript = resolve(opts.repoRoot, "packages/verdict-cli/dist/src/cli.js")
  const skillSrc = resolve(opts.repoRoot, ".agents/skills/verdict-dfir")
  const targets = opts.client === "all" ? (["claude", "cursor", "codex"] as const) : ([opts.client] as const)

  const actions: SetupAction[] = []
  for (const c of targets) {
    if (c === "claude") {
      const cfg = join(home, ".claude.json")
      const skillDest = join(home, ".claude", "skills", "verdict-dfir")
      const res = mergeJsonMcpServer(cfg, entryScript, opts.apply)
      if (opts.apply && existsSync(skillSrc)) {
        mkdirSync(dirname(skillDest), { recursive: true })
        cpSync(skillSrc, skillDest, { recursive: true })
      }
      actions.push({ client: "claude", config_path: cfg, backup_path: res.backupPath, skill_dest: skillDest, applied: res.applied })
    } else if (c === "cursor") {
      const cfg = join(home, ".cursor", "mcp.json")
      const skillDest = join(home, ".cursor", "skills", "verdict-dfir")
      const res = mergeJsonMcpServer(cfg, entryScript, opts.apply)
      if (opts.apply && existsSync(skillSrc)) {
        mkdirSync(dirname(skillDest), { recursive: true })
        cpSync(skillSrc, skillDest, { recursive: true })
      }
      actions.push({ client: "cursor", config_path: cfg, backup_path: res.backupPath, skill_dest: skillDest, applied: res.applied })
    } else if (c === "codex") {
      const cfg = join(home, ".codex", "mcp.verdict.json")
      const skillDest = join(home, ".codex", "skills", "verdict-dfir")
      const res = mergeJsonMcpServer(cfg, entryScript, opts.apply)
      if (opts.apply && existsSync(skillSrc)) {
        mkdirSync(dirname(skillDest), { recursive: true })
        cpSync(skillSrc, skillDest, { recursive: true })
      }
      actions.push({ client: "codex", config_path: cfg, backup_path: res.backupPath, skill_dest: skillDest, applied: res.applied })
    }
  }

  return {
    mode: opts.apply ? "applied" : "read-only-plan",
    mcp_command: { command: "node", args: [entryScript, "serve"] },
    actions,
  }
}
