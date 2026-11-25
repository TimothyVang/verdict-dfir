import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

/** Resolve the caseforge-fleet binary: $FLEET_BIN, then repo-relative target/, then PATH. */
function resolveFleetBin(): string {
  if (process.env.FLEET_BIN && existsSync(process.env.FLEET_BIN)) return process.env.FLEET_BIN
  const here = dirname(fileURLToPath(import.meta.url)) // packages/caseforge-cli/dist/src/commands
  const root = join(here, "..", "..", "..", "..", "..") // -> repo root
  for (const profile of ["release", "debug"]) {
    const p = join(root, "crates", "caseforge-fleet", "target", profile, "caseforge-fleet")
    if (existsSync(p)) return p
  }
  return "caseforge-fleet" // fall back to PATH
}

/** Launch the DFIR investigation multiplexer, forwarding all args to the binary. */
export function fleet(args: string[]): number {
  const bin = resolveFleetBin()
  const r = spawnSync(bin, args, { stdio: "inherit" })
  if (r.error) {
    console.error(`caseforge fleet: could not launch '${bin}': ${r.error.message}`)
    console.error("build it: cargo build --release --manifest-path crates/caseforge-fleet/Cargo.toml")
    return 127
  }
  return r.status ?? 0
}
