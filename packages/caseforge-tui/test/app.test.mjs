import { test } from "node:test"
import assert from "node:assert/strict"
import { keyOf, reduce, initialState } from "../dist/src/app.js"

test("keyOf maps arrows, vim keys, enter, back, quit, tab", () => {
  assert.equal(keyOf("\x1b[A"), "up")
  assert.equal(keyOf("k"), "up")
  assert.equal(keyOf("\x1b[B"), "down")
  assert.equal(keyOf("j"), "down")
  assert.equal(keyOf("\r"), "enter")
  assert.equal(keyOf("\t"), "tab")
  assert.equal(keyOf("q"), "back")
  assert.equal(keyOf("\x03"), "quit")
  assert.equal(keyOf("z"), "other")
})
test("picker cursor moves within bounds", () => {
  let s = initialState
  assert.equal(s.cursor, 0)
  s = reduce(s, "up", 3) // clamp at 0
  assert.equal(s.cursor, 0)
  s = reduce(s, "down", 3)
  assert.equal(s.cursor, 1)
  s = reduce(s, "down", 3)
  s = reduce(s, "down", 3) // clamp at last
  assert.equal(s.cursor, 2)
})
test("enter opens the case; back returns to picker", () => {
  let s = reduce(initialState, "enter", 3)
  assert.equal(s.view, "case")
  s = reduce(s, "back", 3)
  assert.equal(s.view, "picker")
})
test("enter with no runs is a no-op; q on picker quits", () => {
  assert.equal(reduce(initialState, "enter", 0).view, "picker")
  assert.equal(reduce(initialState, "back", 3).quit, true)
})
test("reduce is immutable (returns a new object)", () => {
  const s = initialState
  const s2 = reduce(s, "down", 3)
  assert.notEqual(s, s2)
  assert.equal(s.cursor, 0) // original unchanged
})
test("finding cursor moves within bounds in the case view", () => {
  let s = reduce(initialState, "enter", 3) // -> case view
  assert.equal(s.view, "case")
  assert.equal(s.finding, 0)
  s = reduce(s, "up", 3, 2) // clamp at 0
  assert.equal(s.finding, 0)
  s = reduce(s, "down", 3, 2)
  assert.equal(s.finding, 1)
  s = reduce(s, "down", 3, 2) // clamp at findings.length-1
  assert.equal(s.finding, 1)
})
test("finding cursor clamps at 0 when the case has no findings", () => {
  let s = reduce(initialState, "enter", 3) // -> case view
  s = reduce(s, "down", 3, 0) // findingCount 0 -> last is 0
  assert.equal(s.finding, 0)
})
test("entering the case resets the finding cursor to 0", () => {
  let s = reduce(initialState, "enter", 3)
  s = reduce(s, "down", 3, 3) // finding -> 1
  assert.equal(s.finding, 1)
  s = reduce(s, "back", 3, 3) // -> picker
  assert.equal(s.view, "picker")
  s = reduce(s, "enter", 3) // -> case again
  assert.equal(s.finding, 0)
})
test("enter opens detail for the selected finding; back returns detail -> case", () => {
  let s = reduce(initialState, "enter", 3) // -> case
  s = reduce(s, "enter", 3, 2) // -> detail
  assert.equal(s.view, "detail")
  s = reduce(s, "back", 3, 2) // -> case
  assert.equal(s.view, "case")
})
test("enter in the case view with no findings is a no-op (stays in case)", () => {
  let s = reduce(initialState, "enter", 3) // -> case
  s = reduce(s, "enter", 3, 0) // no findings -> no detail
  assert.equal(s.view, "case")
})
test("ctrl-c quits from the detail view", () => {
  let s = reduce(initialState, "enter", 3)
  s = reduce(s, "enter", 3, 2) // -> detail
  s = reduce(s, "quit", 3, 2)
  assert.equal(s.quit, true)
})
test("tab cycles case panel findings -> timeline -> coverage", () => {
  let s = reduce(initialState, "enter", 3) // case
  assert.equal(s.panel, "findings")
  s = reduce(s, "tab", 3, 2, 4, 3)
  assert.equal(s.panel, "timeline")
  s = reduce(s, "tab", 3, 2, 4, 3)
  assert.equal(s.panel, "coverage")
  s = reduce(s, "tab", 3, 2, 4, 3)
  assert.equal(s.panel, "findings")
})
test("timeline panel cursor moves and enter opens timeline-detail", () => {
  let s = reduce(initialState, "enter", 3) // case
  s = reduce(s, "tab", 3, 2, 3, 2) // timeline panel
  assert.equal(s.panel, "timeline")
  s = reduce(s, "down", 3, 2, 3, 2)
  assert.equal(s.timeline, 1)
  s = reduce(s, "enter", 3, 2, 3, 2)
  assert.equal(s.view, "timeline-detail")
  s = reduce(s, "back", 3, 2, 3, 2)
  assert.equal(s.view, "case")
  assert.equal(s.panel, "timeline")
})
test("enter on empty timeline panel is a no-op", () => {
  let s = reduce(initialState, "enter", 3)
  s = reduce(s, "tab", 3, 2, 0, 0)
  s = reduce(s, "enter", 3, 2, 0, 0)
  assert.equal(s.view, "case")
})
test("coverage panel enter opens coverage-detail", () => {
  let s = reduce(initialState, "enter", 3)
  s = reduce(s, "tab", 3, 2, 2, 3)
  s = reduce(s, "tab", 3, 2, 2, 3) // coverage
  assert.equal(s.panel, "coverage")
  s = reduce(s, "down", 3, 2, 2, 3)
  assert.equal(s.coverage, 1)
  s = reduce(s, "enter", 3, 2, 2, 3)
  assert.equal(s.view, "coverage-detail")
  s = reduce(s, "back", 3, 2, 2, 3)
  assert.equal(s.view, "case")
})
