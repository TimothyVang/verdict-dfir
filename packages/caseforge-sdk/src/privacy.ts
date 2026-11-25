/**
 * Privacy-mode router.
 *
 * Default rule: real/private evidence uses local-only by default. Cloud models
 * are allowed only for synthetic/public/operator-approved evidence, or over
 * redacted summaries. This module is the single gate every model selection
 * passes through — it never sends evidence anywhere itself, it only decides
 * whether a candidate model+route is permitted for the current context.
 */

export type PrivacyMode = "local-only" | "redacted-cloud" | "cloud-ok"

/** Where a provider physically runs. Cloud = evidence would leave the host. */
export type ProviderLocation = "local" | "cloud"

/**
 * Classification of the evidence under investigation. Anything unknown is
 * treated as `sensitive` (fail-closed) so real evidence never leaks by default.
 */
export type EvidenceClass = "synthetic" | "public" | "approved" | "sensitive"

export interface ModelCandidate {
  /** Route/model id, e.g. "local-vllm/qwen2.5-coder" or "openai/gpt-5.5". */
  id: string
  location: ProviderLocation
  /** True if the provider also enables web/tool access to the network. */
  network?: boolean
}

export interface PrivacyContext {
  mode: PrivacyMode
  /** Defaults to "sensitive" when omitted (fail-closed). */
  evidenceClass?: EvidenceClass
  /** True only when this request carries operator-redacted content. */
  redacted?: boolean
}

export interface PrivacyDecision {
  allowed: boolean
  reason: string
}

/** The default mode for real/unknown evidence. */
export const DEFAULT_PRIVACY_MODE: PrivacyMode = "local-only"

/**
 * Decide whether `model` may be used under `ctx`. Pure and fail-closed: any
 * ambiguity resolves to denied.
 */
export function decideModel(model: ModelCandidate, ctx: PrivacyContext): PrivacyDecision {
  const evidenceClass = ctx.evidenceClass ?? "sensitive"

  // Local providers are always permitted — evidence never leaves the host.
  if (model.location === "local") {
    return { allowed: true, reason: "local provider — evidence stays on host" }
  }

  // From here down the provider is cloud: evidence could leave the host.
  switch (ctx.mode) {
    case "local-only":
      return {
        allowed: false,
        reason: "local-only mode blocks all cloud/API models and web access",
      }

    case "redacted-cloud":
      if (ctx.redacted === true) {
        return { allowed: true, reason: "redacted-cloud mode: content is redacted" }
      }
      return {
        allowed: false,
        reason: "redacted-cloud mode requires redacted content before a cloud model is used",
      }

    case "cloud-ok":
      if (evidenceClass === "synthetic" || evidenceClass === "public" || evidenceClass === "approved") {
        return { allowed: true, reason: `cloud-ok mode: evidence is ${evidenceClass}` }
      }
      return {
        allowed: false,
        reason: "cloud-ok mode still blocks sensitive evidence — reclassify, approve, or redact it",
      }

    default:
      return { allowed: false, reason: `unknown privacy mode '${String(ctx.mode)}' — denied` }
  }
}

/** Throw a clear error if a model is not permitted. Use before any prompt. */
export function assertModelAllowed(model: ModelCandidate, ctx: PrivacyContext): void {
  const d = decideModel(model, ctx)
  if (!d.allowed) {
    throw new PrivacyViolationError(
      `Model '${model.id}' denied under ${ctx.mode} (evidence=${ctx.evidenceClass ?? "sensitive"}): ${d.reason}`,
    )
  }
}

export class PrivacyViolationError extends Error {
  readonly name = "PrivacyViolationError"
}

// --- redaction ------------------------------------------------------------

export interface RedactionOptions {
  domains?: boolean // redact bare domains (off by default; often needed as IOCs)
  ips?: boolean // redact IPv4/IPv6 (on by default)
}

const REDACTIONS: Array<{ label: string; re: RegExp }> = [
  { label: "EMAIL", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { label: "AWS_KEY", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "TOKEN", re: /\b(?:gh[posru]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b/g },
  { label: "SECRET", re: /\b(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*\S+/gi },
]

/**
 * Redact secrets/PII from text for redacted-cloud mode. Conservative: emails,
 * keys, tokens, secret-assignments always; IPs by default; usernames/hostnames
 * and domains are context-specific and passed in by the caller.
 */
export function redact(
  text: string,
  opts: RedactionOptions & { usernames?: string[]; hostnames?: string[] } = {},
): string {
  let out = text
  for (const { label, re } of REDACTIONS) out = out.replace(re, `[REDACTED:${label}]`)
  if (opts.ips !== false) {
    out = out
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED:IP]")
      .replace(/\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/g, "[REDACTED:IP6]")
  }
  for (const u of opts.usernames ?? []) if (u) out = out.split(u).join("[REDACTED:USER]")
  for (const h of opts.hostnames ?? []) if (h) out = out.split(h).join("[REDACTED:HOST]")
  if (opts.domains) {
    out = out.replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi, "[REDACTED:DOMAIN]")
  }
  return out
}

// --- operator cloud-ack gate -----------------------------------------------

/**
 * Env var an operator sets to acknowledge that an outward cloud investigation
 * may leave the host. Defaults OFF — absence means refuse.
 */
export const CLOUD_ACK_ENV = "CASEFORGE_CLOUD_ACK"

export interface CloudAckOptions {
  /** Physical location of the chosen route. Only "cloud" requires acknowledgement. */
  location: ProviderLocation
  /** Value of CASEFORGE_CLOUD_ACK (or any operator-supplied env value). */
  ack?: string | boolean
  /** Explicit --cloud-ack CLI flag. */
  ackFlag?: boolean
}

export interface CloudAckResult {
  required: boolean
  acknowledged: boolean
  allowed: boolean
  reason: string
}

/** Truthy acknowledgement values (env strings or a boolean). */
function isAcknowledged(ack: string | boolean | undefined, ackFlag: boolean | undefined): boolean {
  if (ackFlag === true || ack === true) return true
  if (typeof ack !== "string") return false
  return ["1", "true", "yes", "on"].includes(ack.trim().toLowerCase())
}

/**
 * Gate an outward cloud call on an explicit operator acknowledgement. This is a
 * harness guard distinct from the privacy router: even when the privacy router
 * permits a cloud route (cloud-ok/approved), caseforge still refuses to make the
 * outward call unless the operator has explicitly acknowledged the egress. Local
 * routes never require acknowledgement. Fail-closed: default off.
 */
export function cloudAckGate(opts: CloudAckOptions): CloudAckResult {
  if (opts.location !== "cloud") {
    return { required: false, acknowledged: true, allowed: true, reason: "local route — no operator acknowledgement required" }
  }
  const acknowledged = isAcknowledged(opts.ack, opts.ackFlag)
  return acknowledged
    ? { required: true, acknowledged: true, allowed: true, reason: "operator acknowledged an outward cloud investigation" }
    : {
        required: true,
        acknowledged: false,
        allowed: false,
        reason: `outward cloud investigation refused: set ${CLOUD_ACK_ENV}=1 (or pass --cloud-ack) to acknowledge that evidence/prompts leave the host`,
      }
}
