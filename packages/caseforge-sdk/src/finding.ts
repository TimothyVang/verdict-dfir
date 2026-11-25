/**
 * Structured finding schema.
 *
 * Enforces the default security rule: the LLM is not the forensic source of
 * truth. Every reportable finding must be backed by VERDICT tool evidence —
 * at least one citation carrying a `tool_call_id` and an `output_sha256`.
 * A finding with no verifiable evidence is invalid and must be rejected.
 */
import { z } from "zod"

/** VERDICT's three scoped verdict words — nothing else is a valid verdict. */
export const VerdictWord = z.enum(["SUSPICIOUS", "INDETERMINATE", "NO_EVIL"])
export type VerdictWord = z.infer<typeof VerdictWord>

const Sha256 = z
  .string()
  .regex(/^[a-f0-9]{64}$/i, "output_sha256 must be a 64-char hex SHA-256")

/** One citation: the exact tool call that produced an asserted value. */
export const EvidenceCitation = z.object({
  tool: z.string().min(1),
  tool_call_id: z.string().min(1),
  output_sha256: Sha256,
  artifact: z.string().optional(),
  cited_value: z.string().optional(),
})
export type EvidenceCitation = z.infer<typeof EvidenceCitation>

export const Finding = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    verdict: VerdictWord,
    severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
    summary: z.string().min(1),
    /** Every finding cites at least one tool call — the anti-hallucination gate. */
    evidence: z.array(EvidenceCitation).min(1, "a finding must cite at least one tool call"),
    hypotheses: z
      .array(z.object({ statement: z.string(), confidence: z.number().min(0).max(1).optional() }))
      .optional(),
    created_at: z.string().optional(),
  })
  .strict()
export type Finding = z.infer<typeof Finding>

export interface ValidationResult {
  valid: boolean
  errors: string[]
}

/** Validate a single finding object. */
export function validateFinding(input: unknown): ValidationResult {
  const r = Finding.safeParse(input)
  if (r.success) return { valid: true, errors: [] }
  return { valid: false, errors: r.error.issues.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`) }
}

/**
 * Validate a batch, partitioning accepted vs rejected. Rejected findings must
 * never appear in a report — the caller is expected to drop them and surface
 * the reasons.
 */
export function validateFindings(inputs: unknown[]): {
  accepted: Finding[]
  rejected: Array<{ index: number; errors: string[] }>
} {
  const accepted: Finding[] = []
  const rejected: Array<{ index: number; errors: string[] }> = []
  inputs.forEach((f, index) => {
    const r = Finding.safeParse(f)
    if (r.success) accepted.push(r.data)
    else rejected.push({ index, errors: r.error.issues.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`) })
  })
  return { accepted, rejected }
}
