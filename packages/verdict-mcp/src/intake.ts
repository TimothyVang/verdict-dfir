import { createHash } from "node:crypto"
import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs"
import { extname, join, relative, resolve } from "node:path"
import { ArtifactClass, EvidenceRecord, VerdictMcpError } from "./evidence.js"
import { EvidenceLedger } from "./ledger.js"

export interface IntakeItem {
  logical_path: string
  size_bytes: number
  sha256: string | null
  artifact_class: ArtifactClass
  detected_type: string
  hash_skipped_reason?: string
}

const MAX_HASH_BYTES = 50 * 1024 * 1024 // 50 MiB cap for fast target-free intake hashing

export function classifyArtifact(filePath: string): { artifact_class: ArtifactClass; detected_type: string } {
  const lower = filePath.toLowerCase()
  const ext = extname(lower)
  if (ext === ".evtx" || ext === ".evt") return { artifact_class: "evtx", detected_type: "windows_evtx" }
  if (ext === ".pcap" || ext === ".pcapng" || ext === ".har" || ext === ".saz")
    return { artifact_class: "network", detected_type: `network_${ext.slice(1)}` }
  if (ext === ".raw" || ext === ".mem" || ext === ".dmp" || ext === ".vmem" || ext === ".lime")
    return { artifact_class: "memory", detected_type: "memory_image" }
  if (ext === ".e01" || ext === ".dd" || ext === ".img" || ext === ".vhd" || ext === ".vhdx" || ext === ".pf")
    return { artifact_class: "disk", detected_type: ext === ".pf" ? "windows_prefetch" : "disk_image" }
  if (/(^|[\\/])(system|software|sam|security|ntuser\.dat|usrclass\.dat|amcache\.hve)$/.test(lower))
    return { artifact_class: "registry", detected_type: "windows_registry_hive" }
  if (/(^|[\\/])(\$mft|\$usnjrnl)$/.test(lower))
    return { artifact_class: "disk", detected_type: "ntfs_metadata" }
  if (ext === ".exe" || ext === ".dll" || ext === ".sys" || ext === ".elf" || ext === ".apk" || ext === ".ps1")
    return { artifact_class: "malware", detected_type: `executable_${ext.slice(1)}` }
  if (/(auth\.log|syslog|journal|authorized_keys|sudoers|crontab|systemd)/.test(lower))
    return { artifact_class: "linux", detected_type: "linux_forensic_artifact" }
  return { artifact_class: "disk", detected_type: "generic_file" }
}

export function runIntake(
  ledger: EvidenceLedger,
  targetPath: string,
  opts?: { maxFiles?: number },
): EvidenceRecord<{ target: string; items: IntakeItem[]; class_counts: Record<string, number> }> {
  const absTarget = resolve(targetPath)
  let rootStat
  try {
    rootStat = lstatSync(absTarget)
  } catch {
    throw new VerdictMcpError("invalid_request", `Intake target does not exist: ${absTarget}`)
  }

  const maxFiles = Math.max(1, Math.min(5000, opts?.maxFiles ?? 1000))
  const items: IntakeItem[] = []
  const limitations: string[] = []
  let truncated = false

  const visit = (currentPath: string) => {
    if (items.length >= maxFiles) {
      truncated = true
      return
    }
    const st = lstatSync(currentPath)
    if (st.isSymbolicLink()) {
      limitations.push(`Skipped symlink: ${relative(absTarget, currentPath) || currentPath}`)
      return
    }
    if (st.isDirectory()) {
      const entries = readdirSync(currentPath).sort()
      for (const name of entries) {
        if (items.length >= maxFiles) {
          truncated = true
          return
        }
        visit(join(currentPath, name))
      }
      return
    }
    if (!st.isFile()) {
      limitations.push(`Skipped non-regular file: ${relative(absTarget, currentPath) || currentPath}`)
      return
    }

    const logical = rootStat.isDirectory() ? relative(absTarget, currentPath) : currentPath.split("/").pop() ?? currentPath
    const { artifact_class, detected_type } = classifyArtifact(logical)
    let sha256: string | null = null
    let hash_skipped_reason: string | undefined

    if (st.size <= MAX_HASH_BYTES) {
      const buf = readFileSync(currentPath)
      sha256 = createHash("sha256").update(buf).digest("hex")
    } else {
      hash_skipped_reason = `Exceeds ${MAX_HASH_BYTES} byte inline intake cap; hash with streaming ingest.`
      limitations.push(`Large file hash deferred (${st.size} bytes): ${logical}`)
    }

    items.push({
      logical_path: logical,
      size_bytes: st.size,
      sha256,
      artifact_class,
      detected_type,
      ...(hash_skipped_reason ? { hash_skipped_reason } : {}),
    })
  }

  if (rootStat.isFile()) {
    const st = statSync(absTarget)
    const { artifact_class, detected_type } = classifyArtifact(absTarget)
    let sha256: string | null = null
    let hash_skipped_reason: string | undefined
    if (st.size <= MAX_HASH_BYTES) {
      sha256 = createHash("sha256").update(readFileSync(absTarget)).digest("hex")
    } else {
      hash_skipped_reason = `Exceeds ${MAX_HASH_BYTES} byte inline intake cap.`
      limitations.push(`Large file hash deferred (${st.size} bytes): ${absTarget}`)
    }
    items.push({
      logical_path: absTarget.split("/").pop() ?? absTarget,
      size_bytes: st.size,
      sha256,
      artifact_class,
      detected_type,
      ...(hash_skipped_reason ? { hash_skipped_reason } : {}),
    })
  } else {
    visit(absTarget)
  }

  if (truncated) {
    limitations.push(`Traversal stopped at maxFiles=${maxFiles}; unexamined files remain.`)
  }

  const class_counts: Record<string, number> = {}
  for (const item of items) {
    class_counts[item.artifact_class] = (class_counts[item.artifact_class] ?? 0) + 1
  }

  return ledger.retain({
    tool: "verdict_intake",
    artifact_class: "custody",
    parameters: { target: absTarget, max_files: maxFiles },
    analysis_profile: {
      engine: "verdict-intake-zero-install",
      version: "1.0.0",
      mode: "deterministic",
    },
    normalized_result: {
      target: absTarget,
      items,
      class_counts,
    },
    coverage: {
      scope: rootStat.isDirectory() ? "directory-tree" : "single-file",
      status: truncated || limitations.length > 0 ? "partial" : "complete",
      total_count: items.length,
      returned_count: items.length,
      next_offset: null,
    },
    limitations,
  })
}
