import { test } from "node:test"
import assert from "node:assert/strict"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { loadCase } from "../dist/src/load.js"
import { renderHeader, renderFindings, renderCoverage, renderAudit, renderScreen } from "../dist/src/render.js"

const here = dirname(fileURLToPath(import.meta.url))
const FIX = join(here, "..", "..", "..", "fixtures", "synthetic", "sample-run")
const MINIMAL = join(here, "..", "..", "..", "fixtures", "synthetic", "minimal-complete-run")

test("fixture run validates complete + custody valid (live re-verify)", async () => {
  const v = await loadCase(FIX)
  assert.equal(v.validation.status, "complete")
  assert.equal(v.validation.custodyValid, true)
})
test("minimal complete fixture supports the read-only header slice", async () => {
  const v = await loadCase(MINIMAL)
  assert.equal(v.validation.status, "complete")
  assert.equal(v.validation.custodyValid, true)
  assert.equal(v.recordedManifestOverall, true)
  assert.equal(v.verdict?.verdict, "NO_EVIL")

  const h = renderHeader(v)
  assert.match(h, /NO_EVIL/)
  assert.match(h, /recorded/)
  assert.match(h, /re-verified now/)
})
test("header renders verdict word + dual custody lights", async () => {
  const h = renderHeader(await loadCase(FIX))
  assert.match(h, /SUSPICIOUS/)
  assert.match(h, /recorded/)
  assert.match(h, /re-verified now/)
})
test("findings render with technique + custody (cited + tool_call_id)", async () => {
  const f = renderFindings(await loadCase(FIX))
  assert.match(f, /T1070\.001/)
  assert.match(f, /cited/)
  assert.match(f, /tc-1/)
})
test("coverage + audit render; chain linkage OK on the fixture", async () => {
  const v = await loadCase(FIX)
  assert.match(renderCoverage(v), /evtx/)
  assert.match(renderAudit(v), /chain linkage OK/)
})
test("full screen composes all panels", async () => {
  const s = renderScreen(await loadCase(FIX))
  assert.ok(s.length > 200)
})

import { renderTimeline } from "../dist/src/render.js"
const BROKEN = join(here, "..", "..", "..", "fixtures", "synthetic", "broken-chain-run")
const NOREPORT = join(here, "..", "..", "..", "fixtures", "synthetic", "no-report-run")

test("timeline panel renders events from normalized_timeline", async () => {
  const t = renderTimeline(await loadCase(FIX))
  assert.match(t, /TIMELINE/)
  assert.match(t, /T1070\.001/)
  assert.match(t, /events/)
})
test("timeline degrades honestly when absent", async () => {
  assert.match(renderTimeline(await loadCase(NOREPORT)), /not produced by this run/)
})
test("broken audit chain is caught by the structural check", async () => {
  const v = await loadCase(BROKEN)
  assert.equal(v.chainOk, false)
  assert.match(renderAudit(v), /chain linkage BROKEN/)
})
test("missing verdict.json degrades honestly (not fabricated)", async () => {
  const v = await loadCase(NOREPORT)
  assert.equal(v.verdict, undefined)
  assert.match(renderFindings(v), /not produced by this run/)
  // custody still holds (sealed run)
  assert.equal(v.validation.custodyValid, true)
})

import { listRuns as listRunsP } from "../dist/src/picker.js"
import { renderPicker } from "../dist/src/render.js"
const SYNTH_ROOT = join(here, "..", "..", "..", "fixtures", "synthetic")

test("picker discovers the synthetic run dirs with statuses", async () => {
  const runs = await listRunsP([SYNTH_ROOT])
  assert.ok(runs.length >= 3, `expected >=3 runs, got ${runs.length}`)
  assert.ok(runs.some((r) => r.status === "complete"))
  const p = renderPicker(runs)
  assert.match(p, /CASES/)
  assert.match(p, /sample-run/)
})

test("picker highlights the cursor row", async () => {
  const runs = await listRunsP([SYNTH_ROOT])
  const p = renderPicker(runs, 1)
  const lines = p.split("\n")
  // the 2nd run row (index 1) carries the cursor arrow; row 0 does not
  const rowLines = lines.filter((l) => /fixtures\/synthetic/.test(l))
  assert.match(rowLines[1], /▶/)
  assert.doesNotMatch(rowLines[0], /▶/)
})

test("picker flags a run whose audit chain is structurally broken", async () => {
  const runs = await listRunsP([SYNTH_ROOT])
  const broken = runs.find((r) => /broken-chain-run/.test(r.dir))
  assert.ok(broken, "broken-chain-run present")
  assert.equal(broken.chainOk, false)
  const good = runs.find((r) => /sample-run/.test(r.dir))
  assert.equal(good.chainOk, true)
  const p = renderPicker(runs, 0)
  assert.match(p, /⚠ chain/) // the broken run is flagged even though status=complete
})

import { renderCustodyBanner } from "../dist/src/render.js"
const CINVALID = join(here, "..", "..", "..", "fixtures", "synthetic", "custody-invalid-run")

test("custody-invalid case shows a NOT VERIFIED banner over findings", async () => {
  const v = await loadCase(CINVALID)
  assert.match(renderCustodyBanner(v), /CUSTODY NOT VERIFIED/)
  assert.match(renderScreen(v), /CUSTODY NOT VERIFIED/)
})
test("valid custody shows no warning banner", async () => {
  assert.equal(renderCustodyBanner(await loadCase(FIX)), "")
})

import { renderFindingDetail } from "../dist/src/render.js"

test("finding detail renders the full finding with custody, tool_call_id, output_sha256", async () => {
  const v = await loadCase(FIX)
  const d = renderFindingDetail(v, 0)
  assert.match(d, /FINDING DETAIL/)
  assert.match(d, /f-1/) // finding_id
  assert.match(d, /T1070\.001/) // technique
  assert.match(d, /Security event log cleared/) // full description
  assert.match(d, /cited/) // custody citation status
  assert.match(d, /tc-1/) // tool_call_id
  assert.match(d, /aa11/) // output_sha256
})
test("finding detail matches the selected index (second finding)", async () => {
  const d = renderFindingDetail(await loadCase(FIX), 1)
  assert.match(d, /f-2/)
  assert.match(d, /tc-2/)
  assert.match(d, /bb22/)
})
test("finding detail surfaces the matching audit.jsonl record when available", async () => {
  const d = renderFindingDetail(await loadCase(FIX), 0)
  // audit record for tc-1 is a tool_call_result at seq 3
  assert.match(d, /tool_call_result/)
})
test("finding detail degrades honestly when findings are absent (no fabrication)", async () => {
  const v = await loadCase(NOREPORT) // no verdict.json -> no findings
  const d = renderFindingDetail(v, 0)
  assert.match(d, /not produced by this run/)
  assert.doesNotMatch(d, /tc-/) // no fabricated tool_call_id
})
test("finding detail degrades honestly for an out-of-range index", async () => {
  const d = renderFindingDetail(await loadCase(FIX), 99)
  assert.match(d, /not produced by this run/)
})
test("finding detail degrades honestly for an uncited finding (no fabricated custody)", () => {
  // Hand-built CaseView slice: a hypothesis finding with no tool_call_id and a
  // custody report that marks it uncited. Exercises the honest-degradation
  // branch that no on-disk synthetic fixture covers. No evidence involved.
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: {
      verdict: "INDETERMINATE",
      findings: [{ finding_id: "h-1", verdict: "HYPOTHESIS", description: "Possible staging, unconfirmed" }],
    },
    custody: {
      total: 1, cited: 0, uncited: 1, replayVerified: 0, replayFailed: 0, ok: true,
      findings: [{ finding_id: "h-1", cited: false, replayVerified: null, reason: "unanchored (hypothesis) — no tool_call_id required" }],
    },
    coverage: [],
    audit: [],
    timeline: [],
    chainOk: false,
  }
  const d = renderFindingDetail(v, 0)
  assert.match(d, /h-1/)
  assert.match(d, /Possible staging, unconfirmed/) // full description still shown
  assert.match(d, /not cited/) // honest custody state
  assert.doesNotMatch(d, /tc-/) // no fabricated tool_call_id
  assert.doesNotMatch(d, /sha256 [0-9a-f]/) // no fabricated output hash
})

import { renderTimelineDetail } from "../dist/src/render.js"

test("timeline detail renders full event fields", () => {
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: { verdict: "SUSPICIOUS", findings: [] },
    custody: undefined,
    coverage: [],
    audit: [],
    timeline: [
      {
        ts: "2026-01-01T00:00:00Z",
        confidence: "CONFIRMED",
        technique: "T1543.003",
        significance: "high",
        summary: "Service install observed",
      },
    ],
    chainOk: true,
  }
  const d = renderTimelineDetail(v, 0)
  assert.match(d, /TIMELINE DETAIL/)
  assert.match(d, /T1543\.003/)
  assert.match(d, /Service install observed/)
  assert.match(d, /2026-01-01/)
  assert.match(d, /high/)
})
test("timeline detail degrades honestly for empty timeline", () => {
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: { verdict: "NO_EVIL", findings: [] },
    custody: undefined,
    coverage: [],
    audit: [],
    timeline: [],
    chainOk: true,
  }
  assert.match(renderTimelineDetail(v, 0), /not produced by this run/)
})
test("timeline detail degrades honestly for out-of-range index", () => {
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: { verdict: "SUSPICIOUS", findings: [] },
    custody: undefined,
    coverage: [],
    audit: [],
    timeline: [{ ts: "t", summary: "one" }],
    chainOk: true,
  }
  assert.match(renderTimelineDetail(v, 9), /not produced by this run/)
})
test("timeline list highlights selection when focused", () => {
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: { verdict: "SUSPICIOUS", findings: [] },
    custody: undefined,
    coverage: [],
    audit: [],
    timeline: [
      { ts: "t0", technique: "T1", summary: "first" },
      { ts: "t1", technique: "T2", summary: "second" },
    ],
    chainOk: true,
  }
  const t = renderTimeline(v, 1, true)
  assert.match(t, /TIMELINE/)
  assert.match(t, /second/)
})

import { renderCoverageDetail } from "../dist/src/render.js"

test("coverage detail renders class flags", () => {
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: { verdict: "SUSPICIOUS", findings: [] },
    custody: undefined,
    coverage: [{ artifact_class: "evtx", available: true, attempted: true, parsed: false, supported: true }],
    audit: [],
    timeline: [],
    chainOk: true,
  }
  const d = renderCoverageDetail(v, 0)
  assert.match(d, /COVERAGE DETAIL/)
  assert.match(d, /evtx/)
  assert.match(d, /available/)
  assert.match(d, /parsed/)
})
test("coverage detail degrades when empty", () => {
  const v = {
    runDir: "(synthetic)",
    validation: { status: "complete", custodyValid: true, detail: "" },
    recordedManifestOverall: true,
    verdict: { verdict: "NO_EVIL", findings: [] },
    custody: undefined,
    coverage: [],
    audit: [],
    timeline: [],
    chainOk: true,
  }
  assert.match(renderCoverageDetail(v, 0), /not produced by this run/)
})
