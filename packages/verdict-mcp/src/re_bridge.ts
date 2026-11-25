import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { existsSync, lstatSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import { EvidenceRecord, VerdictMcpError } from "./evidence.js"
import { EvidenceLedger } from "./ledger.js"

export interface BinaryTriageResult {
  path: string
  size_bytes: number
  sha256: string
  format: "PE" | "ELF" | "Mach-O" | "Mach-O-Fat" | "Script" | "Unknown"
  shannon_entropy: number
  likely_packed_or_encrypted: boolean
  suspicious_strings: string[]
  external_bridges: Record<string, { invoked: boolean; summary?: string; note?: string }>
  [key: string]: unknown
}

function shannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0
  const freq = new Uint32Array(256)
  for (let i = 0; i < buf.length; i++) {
    freq[buf[i]!] = (freq[buf[i]!] ?? 0) + 1
  }
  let entropy = 0
  const len = buf.length
  for (let i = 0; i < 256; i++) {
    const count = freq[i]!
    if (count > 0) {
      const p = count / len
      entropy -= p * Math.log2(p)
    }
  }
  return Number(entropy.toFixed(4))
}

function detectFormat(buf: Buffer): BinaryTriageResult["format"] {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return "PE"
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return "ELF"
  if (buf.length >= 4) {
    const magic = buf.readUInt32BE(0)
    if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) return "Mach-O"
    if (magic === 0xcafebabe || magic === 0xbebafeca) return "Mach-O-Fat"
  }
  if (buf.length >= 2 && buf[0] === 0x23 && buf[1] === 0x21) return "Script"
  return "Unknown"
}

function extractSuspiciousStrings(buf: Buffer): string[] {
  const text = buf.subarray(0, Math.min(buf.length, 4 * 1024 * 1024)).toString("latin1")
  const matches = text.match(/[\x20-\x7e]{6,120}/g) ?? []
  const interesting = matches.filter((s) =>
    /(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|powershell|cmd\.exe|\/bin\/sh|http:\/\/|https:\/\/|mimikatz|lsass|UPX0|UPX1|IsDebuggerPresent|LoadLibrary)/i.test(
      s,
    ),
  )
  return [...new Set(interesting)].slice(0, 64)
}

function whichBinary(cmd: string): string | null {
  try {
    return execFileSync("which", [cmd], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null
  } catch {
    return null
  }
}

/**
 * Execution-free binary & malware triage (Malvex / REA-Argonaut Tier-0 + optional Tier-2 bridges).
 * Never executes the target sample. Optionally queries installed `capa` or `rea` read-only CLI if requested.
 */
export function triageBinary(
  ledger: EvidenceLedger,
  filePath: string,
  opts?: { invokeExternal?: boolean },
): EvidenceRecord<BinaryTriageResult> {
  const absPath = resolve(filePath)
  if (!existsSync(absPath)) {
    throw new VerdictMcpError("invalid_request", `Binary target does not exist: ${absPath}`)
  }
  const st = lstatSync(absPath)
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new VerdictMcpError("invalid_request", `Binary target must be a regular file (symlinks refused): ${absPath}`)
  }

  const maxRead = 32 * 1024 * 1024
  const limitations: string[] = []
  const raw = readFileSync(absPath)
  const sha256 = createHash("sha256").update(raw).digest("hex")
  const sample = raw.length > maxRead ? raw.subarray(0, maxRead) : raw
  if (raw.length > maxRead) {
    limitations.push(`Entropy and string scan capped at first ${maxRead} bytes; SHA-256 covers full file.`)
  }

  const format = detectFormat(sample)
  const entropy = shannonEntropy(sample)
  const likelyPacked = entropy >= 7.2
  const suspiciousStrings = extractSuspiciousStrings(sample)

  const externalBridges: BinaryTriageResult["external_bridges"] = {
    rea: { invoked: false, note: whichBinary("rea") ? "installed (pass invoke_external=true)" : "not installed" },
    capa: { invoked: false, note: whichBinary("capa") ? "installed (pass invoke_external=true)" : "not installed" },
    floss: { invoked: false, note: whichBinary("floss") ? "installed (use --no-emulation for static-only)" : "not installed" },
  }

  if (opts?.invokeExternal) {
    const capaBin = whichBinary("capa")
    if (capaBin && (format === "PE" || format === "ELF")) {
      try {
        const out = execFileSync(capaBin, ["--json", absPath], {
          encoding: "utf8",
          timeout: 30_000,
          maxBuffer: 8 * 1024 * 1024,
          stdio: ["ignore", "pipe", "pipe"],
        })
        const parsed = JSON.parse(out) as { rules?: Record<string, unknown> }
        const ruleNames = Object.keys(parsed.rules ?? {})
        externalBridges.capa = {
          invoked: true,
          summary: `${ruleNames.length} capability rules matched: ${ruleNames.slice(0, 10).join(", ")}`,
        }
      } catch (err) {
        externalBridges.capa = {
          invoked: true,
          note: `capa exited non-zero: ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`,
        }
        limitations.push("External capa bridge failed or timed out; static header/entropy triage still valid.")
      }
    }
  }

  return ledger.retain({
    tool: "triage_binary",
    artifact_class: "malware",
    parameters: { path: absPath, invoke_external: Boolean(opts?.invokeExternal) },
    analysis_profile: {
      engine: "verdict-binary-triage",
      version: "1.0.0",
      mode: "deterministic",
    },
    normalized_result: {
      path: absPath,
      size_bytes: st.size,
      sha256,
      format,
      shannon_entropy: entropy,
      likely_packed_or_encrypted: likelyPacked,
      suspicious_strings: suspiciousStrings,
      external_bridges: externalBridges,
    },
    coverage: {
      scope: "static-binary-triage",
      status: limitations.length > 0 ? "partial" : "complete",
      total_count: suspiciousStrings.length,
      returned_count: suspiciousStrings.length,
      next_offset: null,
    },
    limitations,
  })
}
