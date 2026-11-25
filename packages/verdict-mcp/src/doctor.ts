import { execFileSync } from "node:child_process"
import { existsSync } from "node:fs"
import { join } from "node:path"

export interface ToolProbe {
  name: string
  category: "core" | "forensics" | "malware_re" | "llm"
  available: boolean
  location: string | null
  note: string
}

function whichBinary(cmd: string): string | null {
  try {
    const out = execFileSync("which", [cmd], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim()
    return out || null
  } catch {
    return null
  }
}

export function runDoctor(repoRoot: string): {
  ready_zero_install: boolean
  repo_root: string
  probes: ToolProbe[]
} {
  const findevilBin = join(repoRoot, "target", "release", "findevil-mcp")
  const agentMcpDir = join(repoRoot, "services", "agent_mcp")

  const probes: ToolProbe[] = [
    {
      name: "findevil-mcp (Rust 34 tools)",
      category: "core",
      available: existsSync(findevilBin),
      location: existsSync(findevilBin) ? findevilBin : null,
      note: existsSync(findevilBin) ? "built" : "run `cargo build --release -p findevil-mcp`",
    },
    {
      name: "findevil-agent-mcp (Python custody)",
      category: "core",
      available: existsSync(agentMcpDir),
      location: existsSync(agentMcpDir) ? agentMcpDir : null,
      note: "Ed25519 custody & Merkle verification",
    },
    ...(["vol", "tshark", "fls", "hayabusa", "chainsaw", "yara"] as const).map((bin) => {
      const loc = whichBinary(bin)
      return {
        name: bin,
        category: "forensics" as const,
        available: Boolean(loc),
        location: loc,
        note: loc ? "available" : "optional Tier-1 SIFT/DFIR provider",
      }
    }),
    ...(["rea", "capa", "floss", "radare2"] as const).map((bin) => {
      const loc = whichBinary(bin)
      return {
        name: bin,
        category: "malware_re" as const,
        available: Boolean(loc),
        location: loc,
        note: loc ? "available" : "optional Tier-2 RE bridge",
      }
    }),
    ...(["ollama", "vllm", "claude", "codex"] as const).map((bin) => {
      const loc = whichBinary(bin)
      return {
        name: bin,
        category: "llm" as const,
        available: Boolean(loc),
        location: loc,
        note: loc ? "available" : "optional runtime/model provider",
      }
    }),
  ]

  return {
    ready_zero_install: true,
    repo_root: repoRoot,
    probes,
  }
}
