/**
 * `caseforge models` — list configured routes and whether each is permitted
 * under the current privacy mode + evidence class.
 */
import { decideModel, DEFAULT_PRIVACY_MODE } from "@verdict/caseforge-sdk"
import type { PrivacyMode, EvidenceClass } from "@verdict/caseforge-sdk"
import { loadRoutes, resolveCandidate, routeLocation } from "../config.js"

export function models(opts: { privacy?: PrivacyMode; evidence?: EvidenceClass }): number {
  const mode = opts.privacy ?? (process.env.CASEFORGE_PRIVACY as PrivacyMode) ?? DEFAULT_PRIVACY_MODE
  const evidenceClass = opts.evidence ?? "sensitive"
  const routes = loadRoutes()
  const ids = Object.keys(routes)

  console.log(`privacy mode: ${mode}   evidence class: ${evidenceClass}`)
  if (!ids.length) {
    console.log("no routes found in configs/model-routes.yaml")
    return 0
  }
  console.log("routes:")
  for (const id of ids) {
    const resolved = resolveCandidate(id)
    if (!resolved) continue
    const d = decideModel(resolved.candidate, { mode, evidenceClass })
    const loc = routeLocation(resolved.route)
    const tc = resolved.route.tool_calling === false ? " (no tool-calling)" : ""
    const auth = resolved.route.auth ? ` auth=${resolved.route.auth}` : ""
    console.log(`  ${d.allowed ? "[allow]" : "[deny] "} ${id.padEnd(16)} ${loc.padEnd(6)} ${resolved.route.model}${tc}${auth}`)
    if (!d.allowed) console.log(`             ${d.reason}`)
  }
  return 0
}
