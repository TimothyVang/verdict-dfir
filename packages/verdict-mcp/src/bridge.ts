import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { join } from "node:path"
import { ArtifactClass, EvidenceRecord, VerdictMcpError } from "./evidence.js"
import { EvidenceLedger } from "./ledger.js"

export type BridgeTarget = "findevil" | "custody"

interface BridgeSpec {
  command: string
  args: string[]
  cwd: string
  engineName: string
}

const DESTRUCTIVE_TOOL_RE = /(dumpfiles|procdump|memdump|write_file|delete_file|rm_|exec_shell|execute_shell|bash|run_command|upload|exfil|format)/i

function inferArtifactClass(toolName: string, target: BridgeTarget): ArtifactClass {
  if (target === "custody") return "custody"
  const n = toolName.toLowerCase()
  if (n.startsWith("vol_")) return "memory"
  if (n.includes("evtx") || n.includes("hayabusa") || n.includes("sysmon")) return "evtx"
  if (n.includes("pcap") || n.includes("zeek") || n.includes("suricata") || n.includes("nfdump")) return "network"
  if (n.includes("registry") || n.includes("regf")) return "registry"
  if (n.includes("yara")) return "malware"
  if (n.includes("journal") || n.includes("ausearch") || n.includes("login_accounting")) return "linux"
  return "disk"
}

export function resolveBridgeSpec(repoRoot: string, target: BridgeTarget): BridgeSpec {
  if (target === "findevil") {
    const bin = join(repoRoot, "target", "release", "findevil-mcp")
    if (!existsSync(bin)) {
      throw new VerdictMcpError(
        "provider_unavailable",
        `Rust findevil-mcp binary not built at ${bin}.`,
        {
          details: { target, expected_path: bin },
          remediation: { action: "Run `cargo build --release -p findevil-mcp` in the VERDICT repo root." },
        },
      )
    }
    return { command: bin, args: [], cwd: repoRoot, engineName: "findevil-mcp-rust" }
  }

  const agentMcpDir = join(repoRoot, "services", "agent_mcp")
  if (!existsSync(agentMcpDir)) {
    throw new VerdictMcpError("provider_unavailable", `Python custody MCP directory not found at ${agentMcpDir}.`)
  }
  return {
    command: "uv",
    args: ["run", "--directory", agentMcpDir, "findevil-agent-mcp"],
    cwd: repoRoot,
    engineName: "findevil-agent-mcp-python",
  }
}

function sendJsonRpcBatch(spec: BridgeSpec, requests: Array<Record<string, unknown>>, timeoutMs = 45_000): Array<Record<string, unknown>> {
  const stdinPayload = requests.map((r) => JSON.stringify(r)).join("\n") + "\n"
  const proc = spawnSync(spec.command, spec.args, {
    cwd: spec.cwd,
    input: stdinPayload,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 16 * 1024 * 1024,
  })

  if (proc.error) {
    throw new VerdictMcpError("provider_unavailable", `Failed to launch ${spec.engineName}: ${proc.error.message}`, {
      details: { command: spec.command, args: spec.args },
    })
  }

  const responses: Array<Record<string, unknown>> = []
  for (const line of (proc.stdout ?? "").split(/\r?\n/)) {
    const t = line.trim()
    if (!t.startsWith("{")) continue
    try {
      responses.push(JSON.parse(t) as Record<string, unknown>)
    } catch {
      /* ignore non-JSON diagnostic lines */
    }
  }
  return responses
}

export function listBridgedTools(repoRoot: string, target: BridgeTarget): {
  target: BridgeTarget
  engine: string
  tool_count: number
  tools: Array<{ name: string; description: string }>
} {
  const spec = resolveBridgeSpec(repoRoot, target)
  const replies = sendJsonRpcBatch(spec, [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "verdict-bridge", version: "1.0.0" } },
    },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ])
  const listReply = replies.find((r) => r.id === 2)
  const resObj = listReply?.result
  const rawTools =
    resObj && typeof resObj === "object" && "tools" in resObj && Array.isArray(resObj.tools)
      ? (resObj.tools as Array<{ name: string; description?: string }>)
      : []
  const safeTools = rawTools
    .filter((t) => !DESTRUCTIVE_TOOL_RE.test(t.name))
    .map((t) => ({ name: t.name, description: (t.description ?? "").slice(0, 180) }))

  return {
    target,
    engine: spec.engineName,
    tool_count: safeTools.length,
    tools: safeTools,
  }
}

export function callBridgedTool(
  ledger: EvidenceLedger,
  repoRoot: string,
  target: BridgeTarget,
  toolName: string,
  toolArgs: Record<string, unknown> = {},
): EvidenceRecord<Record<string, unknown>> {
  if (DESTRUCTIVE_TOOL_RE.test(toolName)) {
    throw new VerdictMcpError(
      "forensic_rule_violation",
      `Refused bridged tool '${toolName}': destructive/exfiltration verbs are blocked by VERDICT read-only policy.`,
      { details: { target, tool: toolName } },
    )
  }

  const spec = resolveBridgeSpec(repoRoot, target)
  const replies = sendJsonRpcBatch(spec, [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "verdict-bridge", version: "1.0.0" } },
    },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: toolName, arguments: toolArgs } },
  ])

  const callReply = replies.find((r) => r.id === 2)
  if (!callReply) {
    throw new VerdictMcpError("provider_unavailable", `No JSON-RPC reply from ${spec.engineName} for tool '${toolName}'.`)
  }
  if (callReply.error) {
    throw new VerdictMcpError("invalid_request", `Bridged tool '${toolName}' returned RPC error: ${JSON.stringify(callReply.error)}`)
  }

  const rpcResult = (callReply.result ?? {}) as {
    isError?: boolean
    structuredContent?: Record<string, unknown>
    content?: Array<{ type: string; text?: string }>
  }

  let normalized: Record<string, unknown>
  if (rpcResult.structuredContent) {
    normalized = rpcResult.structuredContent
  } else {
    const textBlob = (rpcResult.content ?? []).map((c) => c.text ?? "").join("\n").trim()
    try {
      const parsed = JSON.parse(textBlob)
      normalized = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : { data: parsed }
    } catch {
      normalized = { output_text: textBlob }
    }
  }

  const limitations: string[] = []
  if (rpcResult.isError) {
    limitations.push(`Upstream ${spec.engineName} reported isError=true for '${toolName}'.`)
  }

  return ledger.retain({
    tool: `${target}:${toolName}`,
    artifact_class: inferArtifactClass(toolName, target),
    parameters: toolArgs,
    analysis_profile: {
      engine: spec.engineName,
      version: "1.0.0",
      mode: "deterministic",
    },
    normalized_result: normalized,
    raw_result: null,
    coverage: {
      scope: `bridged:${target}:${toolName}`,
      status: rpcResult.isError ? "unknown" : "complete",
    },
    limitations,
  })
}
