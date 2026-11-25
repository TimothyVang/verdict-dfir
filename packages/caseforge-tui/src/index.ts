export * from "./load.js"
export * from "./render.js"
export * from "./picker.js"
export * from "./app.js"
export * from "./components.js"
import { join } from "node:path"
import { loadCase } from "./load.js"
import { renderScreen, renderPicker } from "./render.js"
import { listRuns } from "./picker.js"

const DEFAULT_ROOTS = ["tmp/auto-runs", "tmp/fleet-runs", "docs/sample-run", "fixtures/synthetic"]

/** Launch the read-only workbench.
 *  - `runDir` given: render that case (static).
 *  - no arg + interactive TTY: keyboard-driven picker -> viewer.
 *  - no arg + non-TTY (pipe/CI): static picker dump (kept for the gate). */
export async function launchTui(runDir?: string): Promise<number> {
  if (runDir) {
    process.stdout.write(renderScreen(await loadCase(runDir)) + "\n")
    return 0
  }
  const roots = [...DEFAULT_ROOTS]
  if (process.env.FINDEVIL_HOME) roots.push(join(process.env.FINDEVIL_HOME, "cases"))
  if (process.stdin.isTTY) {
    const { runInteractive } = await import("./runtime.js")
    return runInteractive(roots)
  }
  const entries = await listRuns(roots)
  process.stdout.write(renderPicker(entries) + "\n")
  if (entries.length === 0) process.stderr.write("\nno runs found — pass a run dir: caseforge tui <run-dir>\n")
  return 0
}
