import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs"
import { join, relative, resolve } from "node:path"
import { EvidenceRecord, VerdictMcpError } from "./evidence.js"
import { EvidenceLedger } from "./ledger.js"

export interface LinuxArtifactHit {
  category: "auth" | "persistence_cron" | "persistence_systemd" | "ssh_keys" | "sudoers" | "ld_preload" | "webshell"
  logical_path: string
  indicator: string
  severity: "high" | "medium" | "low" | "info"
  excerpt: string
}

const MAX_READ_BYTES = 2 * 1024 * 1024 // 2 MiB per text file cap

function safeReadText(filePath: string, limitations: string[], rootDir: string): string | null {
  try {
    const st = lstatSync(filePath)
    if (st.isSymbolicLink() || !st.isFile()) {
      limitations.push(`Skipped non-regular/symlink: ${relative(rootDir, filePath)}`)
      return null
    }
    if (st.size > MAX_READ_BYTES) {
      limitations.push(`Truncated read at ${MAX_READ_BYTES} bytes: ${relative(rootDir, filePath)}`)
      return readFileSync(filePath).subarray(0, MAX_READ_BYTES).toString("utf8")
    }
    return readFileSync(filePath, "utf8")
  } catch {
    return null
  }
}

function walkFiles(dir: string, maxFiles: number, out: string[], rootDir: string, limitations: string[]): void {
  if (!existsSync(dir) || out.length >= maxFiles) return
  let entries: string[]
  try {
    entries = readdirSync(dir).sort()
  } catch {
    return
  }
  for (const name of entries) {
    if (out.length >= maxFiles) return
    const full = join(dir, name)
    try {
      const st = lstatSync(full)
      if (st.isSymbolicLink()) {
        limitations.push(`Skipped symlink: ${relative(rootDir, full)}`)
        continue
      }
      if (st.isDirectory()) {
        walkFiles(full, maxFiles, out, rootDir, limitations)
      } else if (st.isFile()) {
        out.push(full)
      }
    } catch {
      /* ignore unreadable entries */
    }
  }
}

/**
 * Read-only Linux dead-disk typed parser pack (inspired by marlyocat/findevil).
 * Inspects a mounted/extracted Linux rootfs without executing any host or target binary.
 */
export function triageLinuxDisk(
  ledger: EvidenceLedger,
  rootfsPath: string,
): EvidenceRecord<{ rootfs: string; hits: LinuxArtifactHit[]; checked_surfaces: string[] }> {
  const absRoot = resolve(rootfsPath)
  if (!existsSync(absRoot) || !lstatSync(absRoot).isDirectory()) {
    throw new VerdictMcpError("invalid_request", `Linux rootfs directory not found: ${absRoot}`)
  }

  const hits: LinuxArtifactHit[] = []
  const limitations: string[] = []
  const checked: string[] = []

  // 1. /etc/ld.so.preload (LD_PRELOAD rootkit/hijack persistence)
  const ldPreload = join(absRoot, "etc", "ld.so.preload")
  if (existsSync(ldPreload)) {
    checked.push("etc/ld.so.preload")
    const text = safeReadText(ldPreload, limitations, absRoot)
    if (text) {
      for (const line of text.split(/\r?\n/)) {
        const t = line.trim()
        if (t && !t.startsWith("#")) {
          hits.push({
            category: "ld_preload",
            logical_path: "etc/ld.so.preload",
            indicator: "LD_PRELOAD library entry",
            severity: "high",
            excerpt: t.slice(0, 200),
          })
        }
      }
    }
  }

  // 2. /etc/sudoers and /etc/sudoers.d/*
  const sudoFiles = [join(absRoot, "etc", "sudoers")]
  walkFiles(join(absRoot, "etc", "sudoers.d"), 100, sudoFiles, absRoot, limitations)
  for (const f of sudoFiles) {
    if (!existsSync(f)) continue
    checked.push(relative(absRoot, f))
    const text = safeReadText(f, limitations, absRoot)
    if (!text) continue
    for (const line of text.split(/\r?\n/)) {
      const t = line.trim()
      if (!t || t.startsWith("#")) continue
      if (/NOPASSWD\s*:\s*ALL/i.test(t)) {
        hits.push({
          category: "sudoers",
          logical_path: relative(absRoot, f),
          indicator: "NOPASSWD:ALL sudoers privilege",
          severity: "high",
          excerpt: t.slice(0, 200),
        })
      }
    }
  }

  // 3. SSH authorized_keys (/root/.ssh/authorized_keys & /home/*/.ssh/authorized_keys)
  const sshCandidates = [join(absRoot, "root", ".ssh", "authorized_keys")]
  const homeDir = join(absRoot, "home")
  if (existsSync(homeDir)) {
    for (const user of readdirSync(homeDir).sort()) {
      sshCandidates.push(join(homeDir, user, ".ssh", "authorized_keys"))
    }
  }
  for (const f of sshCandidates) {
    if (!existsSync(f)) continue
    checked.push(relative(absRoot, f))
    const text = safeReadText(f, limitations, absRoot)
    if (!text) continue
    for (const line of text.split(/\r?\n/)) {
      const t = line.trim()
      if (!t || t.startsWith("#")) continue
      hits.push({
        category: "ssh_keys",
        logical_path: relative(absRoot, f),
        indicator: "SSH authorized_keys entry",
        severity: /command=|from=/i.test(t) ? "medium" : "info",
        excerpt: t.slice(0, 200),
      })
    }
  }

  // 4. Cron persistence (/etc/crontab, /etc/cron.d/*, /var/spool/cron/*)
  const cronFiles = [join(absRoot, "etc", "crontab")]
  walkFiles(join(absRoot, "etc", "cron.d"), 100, cronFiles, absRoot, limitations)
  walkFiles(join(absRoot, "var", "spool", "cron"), 100, cronFiles, absRoot, limitations)
  for (const f of cronFiles) {
    if (!existsSync(f)) continue
    checked.push(relative(absRoot, f))
    const text = safeReadText(f, limitations, absRoot)
    if (!text) continue
    for (const line of text.split(/\r?\n/)) {
      const t = line.trim()
      if (!t || t.startsWith("#")) continue
      if (/(curl|wget|bash\s+-i|\/dev\/tcp|nc\s|ncat|python[23]?\s+-c|base64\s+-d|chmod\s+\+x)/i.test(t)) {
        hits.push({
          category: "persistence_cron",
          logical_path: relative(absRoot, f),
          indicator: "Suspicious cron command",
          severity: "high",
          excerpt: t.slice(0, 200),
        })
      }
    }
  }

  // 5. Systemd unit persistence (/etc/systemd/system/*.service)
  const unitFiles: string[] = []
  walkFiles(join(absRoot, "etc", "systemd", "system"), 200, unitFiles, absRoot, limitations)
  for (const f of unitFiles) {
    if (!f.endsWith(".service")) continue
    checked.push(relative(absRoot, f))
    const text = safeReadText(f, limitations, absRoot)
    if (!text) continue
    const execLine = text.split(/\r?\n/).find((l) => /^\s*ExecStart=/i.test(l))
    if (execLine && /(\/tmp\/|\/dev\/shm\/|curl|wget|bash\s+-c|python|nc\s|base64)/i.test(execLine)) {
      hits.push({
        category: "persistence_systemd",
        logical_path: relative(absRoot, f),
        indicator: "Suspicious systemd ExecStart",
        severity: "high",
        excerpt: execLine.trim().slice(0, 200),
      })
    }
  }

  // 6. Auth logs (/var/log/auth.log, /var/log/secure)
  for (const logName of ["auth.log", "secure"]) {
    const f = join(absRoot, "var", "log", logName)
    if (!existsSync(f)) continue
    checked.push(relative(absRoot, f))
    const text = safeReadText(f, limitations, absRoot)
    if (!text) continue
    for (const line of text.split(/\r?\n/)) {
      if (/(Accepted (password|publickey) for root|Failed password for|useradd|usermod.*sudo)/i.test(line)) {
        hits.push({
          category: "auth",
          logical_path: relative(absRoot, f),
          indicator: /Failed password/i.test(line) ? "SSH failed password" : "Privileged auth/account event",
          severity: /Accepted .* root|usermod.*sudo/i.test(line) ? "high" : "low",
          excerpt: line.trim().slice(0, 200),
        })
      }
    }
  }

  // 7. Webshell scan (/var/www)
  const webFiles: string[] = []
  walkFiles(join(absRoot, "var", "www"), 500, webFiles, absRoot, limitations)
  for (const f of webFiles) {
    if (!/\.(php|jsp|asp|aspx|py|sh)$/i.test(f)) continue
    checked.push(relative(absRoot, f))
    const text = safeReadText(f, limitations, absRoot)
    if (!text) continue
    const match = text.match(/(eval\s*\(\s*\$_(POST|GET|REQUEST)|system\s*\(\s*\$_(POST|GET|REQUEST)|shell_exec\s*\(|passthru\s*\(|base64_decode\s*\(\s*\$_)/i)
    if (match) {
      hits.push({
        category: "webshell",
        logical_path: relative(absRoot, f),
        indicator: `Webshell execution sink (${match[0].slice(0, 40)})`,
        severity: "high",
        excerpt: match[0].slice(0, 200),
      })
    }
  }

  return ledger.retain({
    tool: "triage_linux_disk",
    artifact_class: "linux",
    parameters: { rootfs: absRoot },
    analysis_profile: {
      engine: "verdict-linux-dead-disk",
      version: "1.0.0",
      mode: "deterministic",
    },
    normalized_result: {
      rootfs: absRoot,
      hits,
      checked_surfaces: checked,
    },
    coverage: {
      scope: "linux-rootfs-known-surfaces",
      status: limitations.length > 0 ? "partial" : "complete",
      total_count: hits.length,
      returned_count: hits.length,
      next_offset: null,
    },
    limitations,
  })
}
