// Evidence-meta derivation — surfaces *what is being investigated* in the
// dashboard. The data is already in the audit stream: the engine's `case_open`
// step (scripts/find_evil_auto.py:case_open) emits a `tool_call_start` carrying
// `arguments.image_path` and a matching `tool_call_output` carrying
// `output_hash` (the evidence SHA-256), `size_bytes`, and `case_id`. This pure
// reducer pulls those into a single EvidenceMeta for <EvidenceBanner>.
//
// Mirrors the shape/discipline of lib/sprite-state.ts: pure, immutable, called
// via useMemo over the full event log every render. Returns null until the
// case_open start lands (nothing evidence-worthy to show yet); returns partial
// meta (name/type, no hash/size) between the start and its output.

import type { AuditLine } from "@/lib/audit-tail";

export interface EvidenceMeta {
  /** Full case_id (e.g. "auto-<uuid>"); null until any event carries one. */
  caseId: string | null;
  /** case_open arguments.image_path — the evidence under investigation. */
  path: string | null;
  /** Basename of `path`. */
  name: string | null;
  /**
   * memory | evtx | disk | network | velociraptor | directory | evidence.
   * Prefers an authoritative `evidence_type` from the case_open output when the
   * engine emits one; otherwise a display-only guess from the file extension.
   * Source of truth is the orchestrator's detect_evidence_type — this mapping
   * exists only so the banner reads sensibly when the field is absent.
   */
  evidenceType: string;
  /** case_open tool_call_output.output_hash (evidence SHA-256). */
  sha256: string | null;
  /** case_open tool_call_output.size_bytes. */
  sizeBytes: number | null;
  /** Human-readable `sizeBytes` (e.g. "5.4 GB"); null when size is unknown. */
  sizeHuman: string | null;
}

// File-extension → evidence type. Aligned with evidence/README.md accepted
// formats. Display-only; the orchestrator classifies authoritatively.
const EXT_TYPE: Readonly<Record<string, string>> = {
  img: "memory",
  mem: "memory",
  raw: "memory",
  vmem: "memory",
  dmp: "memory",
  lime: "memory",
  evtx: "evtx",
  e01: "disk",
  dd: "disk",
  aff: "disk",
  aff4: "disk",
  vhd: "disk",
  vhdx: "disk",
  pcap: "network",
  pcapng: "network",
  zip: "velociraptor",
};

const SIZE_UNITS = ["KB", "MB", "GB", "TB"] as const;

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : path;
}

function evidenceTypeFromPath(path: string): string {
  const name = basename(path);
  const dot = name.lastIndexOf(".");
  if (dot < 0 || dot === name.length - 1) return "evidence";
  const ext = name.slice(dot + 1).toLowerCase();
  return EXT_TYPE[ext] ?? "evidence";
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < SIZE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  // Whole numbers >= 100 read better without a decimal; below that keep one.
  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${rounded} ${SIZE_UNITS[unit]}`;
}

function isCaseOpenTool(tool: unknown): boolean {
  // "case_open" for single images; tolerate a "case_open_directory" variant.
  return typeof tool === "string" && tool.startsWith("case_open");
}

/**
 * Derive evidence metadata from a chronologically-ordered audit event log.
 * Pure; safe to call every render. Returns null when no case_open has streamed.
 */
export function deriveEvidenceMeta(
  events: ReadonlyArray<AuditLine>,
): EvidenceMeta | null {
  // 1. Locate the case_open tool_call_start.
  let path: string | null = null;
  let toolCallId: string | null = null;
  for (const ev of events) {
    if (ev.kind !== "tool_call_start") continue;
    const payload = (ev.payload ?? {}) as Record<string, unknown>;
    if (!isCaseOpenTool(payload.tool)) continue;
    const args = (payload.arguments ?? {}) as Record<string, unknown>;
    path =
      asString(args.image_path) ??
      asString(args.path) ??
      asString(args.dir_path);
    toolCallId = asString(payload.tool_call_id);
    break;
  }

  if (path === null) return null;

  // 2. Match the case_open tool_call_output for hash / size / authoritative type.
  let sha256: string | null = null;
  let sizeBytes: number | null = null;
  let authoritativeType: string | null = null;
  if (toolCallId !== null) {
    for (const ev of events) {
      if (ev.kind !== "tool_call_output") continue;
      const payload = (ev.payload ?? {}) as Record<string, unknown>;
      if (asString(payload.tool_call_id) !== toolCallId) continue;
      sha256 = asString(payload.output_hash);
      sizeBytes = asNumber(payload.size_bytes);
      authoritativeType = asString(payload.evidence_type);
      break;
    }
  }

  // 3. case_id from the earliest event that carries one.
  let caseId: string | null = null;
  for (const ev of events) {
    const raw = asString(((ev.payload ?? {}) as Record<string, unknown>).case_id);
    if (raw) {
      caseId = raw;
      break;
    }
  }

  return {
    caseId,
    path,
    name: basename(path),
    evidenceType: authoritativeType ?? evidenceTypeFromPath(path),
    sha256,
    sizeBytes,
    sizeHuman: sizeBytes !== null ? humanSize(sizeBytes) : null,
  };
}
