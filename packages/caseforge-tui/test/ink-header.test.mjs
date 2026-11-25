import { test } from "node:test"
import assert from "node:assert/strict"
import React from "react"
import { render } from "ink-testing-library"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { custodyColor, loadCase, VerdictHeader } from "../dist/src/index.js"

const here = dirname(fileURLToPath(import.meta.url))
const FIX = join(here, "..", "..", "..", "fixtures", "synthetic", "minimal-complete-run")

test("Ink VerdictHeader renders verdict word and dual custody state", async () => {
  const view = await loadCase(FIX)
  assert.equal(view.recordedManifestOverall, true)
  assert.equal(view.validation.status, "complete")
  assert.equal(view.validation.custodyValid, true)

  const app = render(React.createElement(VerdictHeader, { view }))
  const frame = app.lastFrame() ?? ""

  assert.match(frame, /VERDICT/)
  assert.match(frame, /NO_EVIL/)
  assert.match(frame, /recorded verified manifest_verify/)
  assert.match(frame, /re-verified now verified/)
})

test("Ink custody color keeps missing distinct from failed", () => {
  assert.equal(custodyColor(true), "green")
  assert.equal(custodyColor(false), "red")
  assert.equal(custodyColor(undefined), "yellow")
})
