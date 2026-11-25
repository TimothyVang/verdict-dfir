/** Pure interactivity core: raw key bytes -> intent, and (state, intent) -> state.
 * Kept free of any I/O so it is fully unit-testable; the TTY loop in runtime.ts
 * is the only untestable shell and stays as thin as possible. */

export type Key = "up" | "down" | "enter" | "back" | "quit" | "tab" | "other"

/** Focus target inside the case view (findings / timeline / coverage). */
export type CasePanel = "findings" | "timeline" | "coverage"

const PANEL_ORDER: CasePanel[] = ["findings", "timeline", "coverage"]

export interface AppState {
  view: "picker" | "case" | "detail" | "timeline-detail" | "coverage-detail"
  cursor: number
  finding: number
  /** Cursor into the timeline event list when panel is "timeline". */
  timeline: number
  /** Cursor into the coverage rows when panel is "coverage". */
  coverage: number
  /** Which list up/down and enter act on in the case view. */
  panel: CasePanel
  quit: boolean
}

export const initialState: AppState = {
  view: "picker",
  cursor: 0,
  finding: 0,
  timeline: 0,
  coverage: 0,
  panel: "findings",
  quit: false,
}

/** Map a raw stdin sequence to a navigation intent. */
export function keyOf(seq: string): Key {
  if (seq === "\x1b[A" || seq === "k") return "up"
  if (seq === "\x1b[B" || seq === "j") return "down"
  if (seq === "\r" || seq === "\n" || seq === " ") return "enter"
  if (seq === "\t") return "tab"
  if (seq === "q" || seq === "\x1b") return "back"
  if (seq === "\x03") return "quit" // ctrl-c
  return "other"
}

function nextPanel(panel: CasePanel): CasePanel {
  const i = PANEL_ORDER.indexOf(panel)
  return PANEL_ORDER[(i + 1) % PANEL_ORDER.length] ?? "findings"
}

/** Advance the app state. Pure: no I/O, immutable (returns a new state).
 * Count args bound cursors in the case view (default 0 when unused). */
export function reduce(
  state: AppState,
  key: Key,
  runCount: number,
  findingCount = 0,
  timelineCount = 0,
  coverageCount = 0,
): AppState {
  if (state.quit) return state
  if (key === "quit") return { ...state, quit: true }
  const lastRun = Math.max(0, runCount - 1)
  const lastFinding = Math.max(0, findingCount - 1)
  const lastTimeline = Math.max(0, timelineCount - 1)
  const lastCoverage = Math.max(0, coverageCount - 1)

  if (state.view === "picker") {
    if (key === "up") return { ...state, cursor: Math.max(0, state.cursor - 1) }
    if (key === "down") return { ...state, cursor: Math.min(lastRun, state.cursor + 1) }
    if (key === "enter")
      return runCount > 0
        ? {
            ...state,
            view: "case",
            finding: 0,
            timeline: 0,
            coverage: 0,
            panel: "findings",
          }
        : state
    if (key === "back") return { ...state, quit: true }
    return state
  }

  if (state.view === "case") {
    if (key === "tab") return { ...state, panel: nextPanel(state.panel) }
    if (state.panel === "findings") {
      if (key === "up") return { ...state, finding: Math.max(0, state.finding - 1) }
      if (key === "down") return { ...state, finding: Math.min(lastFinding, state.finding + 1) }
      if (key === "enter") return findingCount > 0 ? { ...state, view: "detail" } : state
    } else if (state.panel === "timeline") {
      if (key === "up") return { ...state, timeline: Math.max(0, state.timeline - 1) }
      if (key === "down") return { ...state, timeline: Math.min(lastTimeline, state.timeline + 1) }
      if (key === "enter")
        return timelineCount > 0 ? { ...state, view: "timeline-detail" } : state
    } else {
      if (key === "up") return { ...state, coverage: Math.max(0, state.coverage - 1) }
      if (key === "down") return { ...state, coverage: Math.min(lastCoverage, state.coverage + 1) }
      if (key === "enter")
        return coverageCount > 0 ? { ...state, view: "coverage-detail" } : state
    }
    if (key === "back") return { ...state, view: "picker" }
    return state
  }

  if (
    state.view === "detail" ||
    state.view === "timeline-detail" ||
    state.view === "coverage-detail"
  ) {
    if (key === "back") return { ...state, view: "case" }
    return state
  }

  return state
}
