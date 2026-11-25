import React from "react"
import { Box, Text } from "ink"
import type { CaseView } from "./load.js"

function custodyLabel(ok: boolean | undefined): string {
  if (ok === true) return "verified"
  if (ok === false) return "failed"
  return "not produced"
}

export function custodyColor(ok: boolean | undefined): "green" | "red" | "yellow" {
  if (ok === true) return "green"
  if (ok === false) return "red"
  return "yellow"
}

function verdictColor(verdict: string | undefined): "red" | "green" | "yellow" {
  const word = (verdict ?? "").toUpperCase()
  if (word === "SUSPICIOUS") return "red"
  if (word === "NO_EVIL") return "green"
  return "yellow"
}

export interface VerdictHeaderProps {
  readonly view: CaseView
}

/** Read-only Ink header: verdict word plus recorded and live custody lights. */
export function VerdictHeader({ view }: VerdictHeaderProps): React.ReactElement {
  const verdict = view.verdict?.verdict ?? "(no verdict.json)"
  const caseId = view.verdict?.case_id ?? view.runDir

  return React.createElement(
    Box,
    { flexDirection: "column" },
    React.createElement(
      Text,
      null,
      React.createElement(Text, { bold: true, color: "magenta" }, "VERDICT · caseforge workbench"),
      React.createElement(Text, { dimColor: true }, "   read-only · presentation only"),
    ),
    React.createElement(
      Text,
      null,
      React.createElement(Text, { bold: true, color: verdictColor(view.verdict?.verdict) }, verdict),
      React.createElement(Text, { dimColor: true }, `   case ${caseId}`),
    ),
    React.createElement(
      Text,
      null,
      "custody: recorded ",
      React.createElement(Text, { color: custodyColor(view.recordedManifestOverall) }, custodyLabel(view.recordedManifestOverall)),
      " manifest_verify | re-verified now ",
      React.createElement(Text, { color: custodyColor(view.validation.custodyValid) }, custodyLabel(view.validation.custodyValid)),
      React.createElement(Text, { dimColor: true }, ` (${view.validation.status})`),
    ),
  )
}
