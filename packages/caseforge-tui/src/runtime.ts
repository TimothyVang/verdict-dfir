import { loadCase } from "./load.js"
import {
  renderScreen,
  renderPicker,
  renderFooter,
  renderFindingDetail,
  renderTimelineDetail,
  renderCoverageDetail,
} from "./render.js"
import { listRuns } from "./picker.js"
import type { RunEntry } from "./picker.js"
import { keyOf, reduce, initialState } from "./app.js"
import type { AppState } from "./app.js"

const CLEAR = "\x1b[2J\x1b[H"

interface DrawCounts {
  findingCount: number
  timelineCount: number
  coverageCount: number
}

/** Draw the current state. Returns list counts for reduce() cursor clamps. */
async function draw(state: AppState, runs: RunEntry[]): Promise<DrawCounts> {
  if (state.view === "picker") {
    const body = `${renderPicker(runs, state.cursor)}\n\n${renderFooter("picker")}`
    process.stdout.write(CLEAR + body + "\n")
    return { findingCount: 0, timelineCount: 0, coverageCount: 0 }
  }
  const entry = runs[state.cursor]
  const view = entry ? await loadCase(entry.dir) : undefined
  const findingCount = view?.verdict?.findings?.length ?? 0
  const timelineCount = view?.timeline?.length ?? 0
  const coverageCount = view?.coverage?.length ?? 0
  let panel: string
  if (!view) panel = "no case selected"
  else if (state.view === "detail") panel = renderFindingDetail(view, state.finding)
  else if (state.view === "timeline-detail") panel = renderTimelineDetail(view, state.timeline)
  else if (state.view === "coverage-detail") panel = renderCoverageDetail(view, state.coverage)
  else
    panel = renderScreen(
      view,
      state.finding,
      state.timeline,
      state.panel,
      state.coverage,
    )
  const body = `${panel}\n\n${renderFooter(state.view)}`
  process.stdout.write(CLEAR + body + "\n")
  return { findingCount, timelineCount, coverageCount }
}

/** Interactive picker->viewer loop. Thin I/O shell over the pure app.ts core;
 * all navigation logic lives in reduce()/keyOf() and is unit-tested. */
export async function runInteractive(roots: string[]): Promise<number> {
  const runs = await listRuns(roots)
  if (runs.length === 0) {
    process.stdout.write(`${renderPicker(runs)}\nno runs found — pass a run dir: caseforge tui <run-dir>\n`)
    return 0
  }
  const stdin = process.stdin
  if (stdin.isTTY) stdin.setRawMode(true)
  process.stdout.write("\x1b[?25l") // hide cursor
  stdin.resume()
  stdin.setEncoding("utf8")

  let state: AppState = initialState
  let counts = await draw(state, runs)

  return await new Promise<number>((resolve) => {
    const cleanup = (): void => {
      if (stdin.isTTY) stdin.setRawMode(false)
      stdin.pause()
      stdin.off("data", onData)
      process.stdout.write("\x1b[?25h" + CLEAR) // restore cursor
    }
    const onData = (seq: string): void => {
      state = reduce(
        state,
        keyOf(seq),
        runs.length,
        counts.findingCount,
        counts.timelineCount,
        counts.coverageCount,
      )
      if (state.quit) {
        cleanup()
        resolve(0)
        return
      }
      void draw(state, runs).then((n) => {
        counts = n
      })
    }
    stdin.on("data", onData)
  })
}
