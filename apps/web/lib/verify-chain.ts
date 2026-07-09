// Independent, browser-side custody re-verifier — a SECOND implementation of
// the offline manifest_verify path, recomputed in the client with the Web
// Crypto API (SubtleCrypto). It re-derives the custody chain from the audit
// tail + run.manifest.json instead of trusting the values the dashboard
// merely displays, so a zero-trust reader can confirm in-browser that:
//
//   1. the hash chain folds (each line's prev_hash == SHA-256 of the prior
//      line, seq monotonic from 0),
//   2. the audit log is consistent with what the manifest declares (record
//      count, final hash, and the re-derived Merkle leaves),
//   3. the Merkle root rebuilds from those leaves to the manifest's
//      merkle_root_hex, and
//   4. an Ed25519 manifest signature verifies cryptographically offline.
//
// This MIRRORS the canonical algorithm in services/agent/findevil_agent/crypto
// (audit_log.py + manifest.py), which the Rust/Python `manifest_verify` tool
// uses, so a valid chain verifies here and a tampered one fails — identically.
//
// PURE READ-SIDE. This module never writes, never calls a mutating endpoint,
// and never touches the audit chain or the manifest. It only recomputes.
// It depends solely on Web Crypto + pure TS, so it is safe to import into both
// a client component and the Node server tail.

/** Recursive JSON value shape produced by JSON.parse. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * The audit-record fields that are hashed into the chain — the on-disk line is
 * exactly the JCS canonicalization of these five keys (see
 * audit_log.py:AuditRecord.to_canonical_dict). Selecting them explicitly
 * mirrors the Python "content fields" selection and strips any non-content key
 * (for example a display-only `line_hash`) before canonicalizing.
 */
export const CONTENT_FIELDS = [
  "kind",
  "payload",
  "prev_hash",
  "seq",
  "ts",
] as const;

/** One parsed audit line, kept in original order with its exact on-disk bytes. */
export interface ParsedAuditRecord {
  seq: number;
  kind: string;
  ts: string;
  prevHash: string;
  payload: Record<string, JsonValue>;
  /** Exact on-disk line (no trailing newline) — what the chain commits to. */
  raw: string;
}

/** One Merkle leaf re-derived from the audit log, in the manifest's shape. */
export interface DerivedLeaf {
  seq: number;
  kind: string;
  digest_hex: string;
  record_id: string;
}

/** Result of re-verifying the whole custody chain in the browser. */
export interface CustodyVerification {
  /** True once both an audit tail and a manifest were supplied to verify. */
  available: boolean;
  /** Chain fold + log/manifest consistency (count, final hash, leaves). */
  auditChainOk: boolean | string;
  /** Merkle root rebuilt from the manifest's declared leaves. */
  merkleRootOk: boolean | string;
  /** Declared leaf_count matches the actual leaves array length. */
  leafCountOk: boolean | string;
  /** A signature bundle is present in the manifest. */
  signaturePresent: boolean;
  /** Which signer sealed the run: "ed25519" | "sigstore" | "stub". */
  signatureKind: string;
  /**
   * Honest cryptographic-verification status. True only for an Ed25519 bundle
   * that verifies offline; stub/sigstore return an explicit reason string.
   * Advisory — does not gate `overall` (mirrors verify_manifest).
   */
  signatureVerified: boolean | string;
  /**
   * Presence-based overall, mirroring verify_manifest: chain + Merkle + leaf
   * count verify and a signature is present, and no NON-advisory signature
   * (a present ed25519/unknown bundle) failed verification.
   */
  overall: boolean;
}

const SHA256_HEX = /^[0-9a-fA-F]{64}$/;
const ZERO_ROOT = "00".repeat(32);
const ADVISORY_SIGNER_KINDS = new Set(["stub", "sigstore"]);

// ---------------------------------------------------------------------------
// Canonicalization — RFC-8785-compatible JCS, byte-for-byte matching the
// Python writer (json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=True)). Validated against every committed sample-run audit
// tail + manifest in __tests__.
// ---------------------------------------------------------------------------

/** Return the canonical JSON string for `value`, matching canonicalize_json. */
export function canonicalizeJson(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return canonicalizeNumber(value);
    case "string":
      return encodeString(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map(canonicalizeJson).join(",") + "]";
      }
      // Sort keys ascending. Keys in this domain are ASCII identifiers, for
      // which UTF-16 lexicographic order equals Python's code-point order.
      const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const parts = keys.map(
        (k) => encodeString(k) + ":" + canonicalizeJson(value[k]),
      );
      return "{" + parts.join(",") + "}";
    }
    default:
      throw new Error(`cannot canonicalize value of type ${typeof value}`);
  }
}

function canonicalizeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    // Python's json would emit Infinity/NaN (non-standard); our records never
    // contain them. Refuse rather than emit something the verifier can't match.
    throw new Error("cannot canonicalize a non-finite number");
  }
  return String(value);
}

/** Escape a string exactly as CPython's ensure_ascii encoder does. */
function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x09) out += "\\t";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0d) out += "\\r";
    else if (code < 0x20 || code > 0x7e) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

/**
 * Project a parsed record onto CONTENT_FIELDS only. The on-disk audit line is
 * the canonicalization of exactly these keys; selecting them drops any
 * presentation-only field a producer might attach.
 */
export function extractContentRecord(obj: Record<string, JsonValue>): JsonValue {
  const record: Record<string, JsonValue> = {};
  for (const field of CONTENT_FIELDS) {
    if (field in obj) record[field] = obj[field];
  }
  return record;
}

// ---------------------------------------------------------------------------
// Byte / hash helpers (Web Crypto).
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** SHA-256 hex of raw bytes, via SubtleCrypto. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

/** SHA-256 hex of the UTF-8 bytes of an audit line — the per-line chain hash. */
async function hashLine(rawLine: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(rawLine));
}

// ---------------------------------------------------------------------------
// Audit-tail parsing + chain fold.
// ---------------------------------------------------------------------------

/** Split an audit.jsonl blob into non-empty lines (matching the writer). */
export function splitAuditLines(text: string): string[] {
  return text.split(/\r?\n/).filter((line) => line.length > 0);
}

/** Parse one raw line into a ParsedAuditRecord, or null when malformed. */
export function parseAuditRecord(rawLine: string): ParsedAuditRecord | null {
  let obj: unknown;
  try {
    obj = JSON.parse(rawLine);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return null;
  const record = obj as Record<string, JsonValue>;
  const seq = record.seq;
  const prevHash = record.prev_hash;
  if (typeof seq !== "number" || typeof prevHash !== "string") return null;
  const payload =
    typeof record.payload === "object" &&
    record.payload !== null &&
    !Array.isArray(record.payload)
      ? (record.payload as Record<string, JsonValue>)
      : {};
  return {
    seq,
    kind: typeof record.kind === "string" ? record.kind : "unknown",
    ts: typeof record.ts === "string" ? record.ts : "",
    prevHash,
    payload,
    raw: rawLine,
  };
}

interface ChainFold {
  ok: boolean | string;
  records: ParsedAuditRecord[];
  recordCount: number;
  finalHash: string;
}

/**
 * Re-fold the hash chain from raw lines. Independently re-derives each
 * per-line hash (SHA-256 of the on-disk bytes) and checks seq monotonicity +
 * prev_hash linkage — exactly the invariant AuditLog.verify() enforces.
 * Hashing the on-disk bytes (rather than re-serializing the parsed value)
 * reproduces the Python value for every canonical line, including whole-number
 * floats that a JS number cannot round-trip back to text.
 */
export async function foldAuditChain(rawLines: string[]): Promise<ChainFold> {
  const records: ParsedAuditRecord[] = [];
  let prevHash = "";
  let finalHash = "";
  for (let i = 0; i < rawLines.length; i += 1) {
    const parsed = parseAuditRecord(rawLines[i]);
    if (!parsed) {
      return {
        ok: `seq ${i}: line is not a valid audit record`,
        records,
        recordCount: records.length,
        finalHash,
      };
    }
    if (parsed.seq !== i) {
      return {
        ok: `seq ${i}: expected seq=${i}, got seq=${parsed.seq}`,
        records,
        recordCount: records.length,
        finalHash,
      };
    }
    if (parsed.prevHash !== prevHash) {
      return {
        ok: `seq ${i}: prev_hash break (declared=${parsed.prevHash}, expected=${prevHash})`,
        records,
        recordCount: records.length,
        finalHash,
      };
    }
    const lineHash = await hashLine(parsed.raw);
    prevHash = lineHash;
    finalHash = lineHash;
    records.push(parsed);
  }
  return { ok: true, records, recordCount: records.length, finalHash };
}

// ---------------------------------------------------------------------------
// Merkle root + leaf derivation.
// ---------------------------------------------------------------------------

/**
 * Rebuild the Merkle root from leaf digests (hex). Mirrors merkle.py: leaves
 * in insertion order, duplicate-last on an odd tier, internal node =
 * SHA-256(left || right), empty tree => 32 zero bytes.
 */
export async function merkleRootHex(leafHexes: string[]): Promise<string> {
  if (leafHexes.length === 0) return ZERO_ROOT;
  let tier = leafHexes.map(hexToBytes);
  while (tier.length > 1) {
    if (tier.length % 2 === 1) tier.push(tier[tier.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < tier.length; i += 2) {
      const left = tier[i];
      const right = tier[i + 1];
      const concat = new Uint8Array(left.length + right.length);
      concat.set(left, 0);
      concat.set(right, left.length);
      const digest = await crypto.subtle.digest("SHA-256", concat as BufferSource);
      next.push(new Uint8Array(digest));
    }
    tier = next;
  }
  return bytesToHex(tier[0]);
}

/**
 * Re-derive the Merkle-eligible leaves from the audit records, matching
 * manifest.py:_walk_audit_log. A tool_call_output contributes its payload
 * output_hash (when it is a valid 64-hex digest) else the SHA-256 of its line;
 * a finding_approved contributes the SHA-256 of its line.
 */
export async function deriveLeaves(
  records: ParsedAuditRecord[],
): Promise<DerivedLeaf[]> {
  const leaves: DerivedLeaf[] = [];
  for (const record of records) {
    if (record.kind === "tool_call_output") {
      const outputHash = record.payload.output_hash;
      const digest =
        typeof outputHash === "string" && SHA256_HEX.test(outputHash)
          ? outputHash
          : await hashLine(record.raw);
      leaves.push({
        seq: record.seq,
        kind: "tool_call_output",
        digest_hex: digest,
        record_id: stringField(record.payload.tool_call_id),
      });
    } else if (record.kind === "finding_approved") {
      leaves.push({
        seq: record.seq,
        kind: "finding",
        digest_hex: await hashLine(record.raw),
        record_id: stringField(record.payload.finding_id),
      });
    }
  }
  return leaves;
}

function stringField(value: JsonValue | undefined): string {
  return value === undefined || value === null ? "" : String(value);
}

// ---------------------------------------------------------------------------
// Ed25519 manifest-signature verification.
// ---------------------------------------------------------------------------

/**
 * Honest signature status, mirroring manifest.py:_signature_verified. Never
 * returns true for a stub (a deterministic placeholder, not proof) and never
 * claims to have cryptographically checked a sigstore bundle it cannot verify
 * offline without an expected identity.
 */
export async function verifyManifestSignature(
  manifest: Record<string, JsonValue>,
): Promise<{ present: boolean; kind: string; verified: boolean | string }> {
  const sig =
    typeof manifest.signature === "object" &&
    manifest.signature !== null &&
    !Array.isArray(manifest.signature)
      ? (manifest.signature as Record<string, JsonValue>)
      : {};
  const present = Boolean(sig.bundle_b64 && sig.payload_sha256);
  const kind = typeof sig.kind === "string" ? sig.kind : "stub";
  if (!present) {
    return { present, kind, verified: "no signature bundle present" };
  }
  if (kind === "stub") {
    return {
      present,
      kind,
      verified:
        "stub signature: deterministic dev/offline placeholder, not cryptographic proof",
    };
  }
  if (kind === "sigstore") {
    return {
      present,
      kind,
      verified:
        "sigstore bundle present and recorded; offline cryptographic verification " +
        "requires the verifier to supply the expected signer identity (deployment policy)",
    };
  }
  if (kind === "ed25519") {
    return { present, kind, verified: await verifyEd25519(sig, manifest) };
  }
  return { present, kind, verified: `unknown signer kind '${kind}'` };
}

async function verifyEd25519(
  sig: Record<string, JsonValue>,
  manifest: Record<string, JsonValue>,
): Promise<boolean | string> {
  let publicKeyB64: string;
  let signatureB64: string;
  try {
    const bundleJson = new TextDecoder().decode(
      base64ToBytes(String(sig.bundle_b64 ?? "")),
    );
    const bundle = JSON.parse(bundleJson) as Record<string, JsonValue>;
    publicKeyB64 = String(bundle.public_key_b64);
    signatureB64 = String(bundle.signature_b64);
    if (!bundle.public_key_b64 || !bundle.signature_b64) {
      throw new Error("missing public_key_b64 / signature_b64");
    }
  } catch (err) {
    return `ed25519 bundle malformed: ${errorMessage(err)}`;
  }

  // Reconstruct the exact bytes that were signed: the canonical manifest body
  // with the `signature` field removed (mirror of build_manifest, which signs
  // canonicalize_json(body without signature)).
  const body: Record<string, JsonValue> = {};
  for (const [key, val] of Object.entries(manifest)) {
    if (key !== "signature") body[key] = val;
  }
  const bodyBytes = new TextEncoder().encode(canonicalizeJson(body));

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      base64ToBytes(publicKeyB64) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      base64ToBytes(signatureB64) as BufferSource,
      bodyBytes as BufferSource,
    );
    return ok
      ? true
      : "ed25519 signature verification FAILED: manifest body does not match the signature";
  } catch (err) {
    return `ed25519 signature verification failed: ${errorMessage(err)}`;
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Top-level: re-verify the whole custody chain.
// ---------------------------------------------------------------------------

export interface CustodyInputs {
  /** Verbatim audit.jsonl contents. */
  auditText: string;
  /** Parsed run.manifest.json object. */
  manifest: Record<string, JsonValue>;
}

/**
 * Re-derive and verify the custody chain entirely in the browser. Returns a
 * structured pass/fail mirroring verify_manifest's fields. Reads only — never
 * mutates the chain, the manifest, or any server state.
 */
export async function verifyCustodyChain(
  inputs: CustodyInputs,
): Promise<CustodyVerification> {
  const { auditText, manifest } = inputs;
  const fold = await foldAuditChain(splitAuditLines(auditText));

  let auditChainOk = fold.ok;

  // Log-vs-manifest consistency: a tail-truncated log still folds cleanly and a
  // self-consistent forged leaf set still rebuilds its own root, so compare the
  // re-derived count / final hash / leaves to the manifest's declarations
  // (mirror of verify_manifest step 1b).
  let derivedLeaves: DerivedLeaf[] = [];
  if (auditChainOk === true) {
    derivedLeaves = await deriveLeaves(fold.records);
    const declaredCount = manifest.audit_log_record_count;
    const declaredFinal = stringField(manifest.audit_log_final_hash);
    const declaredLeaves = Array.isArray(manifest.leaves) ? manifest.leaves : [];
    if (declaredCount !== fold.recordCount) {
      auditChainOk =
        `audit log has ${fold.recordCount} record(s) but the manifest ` +
        `declares ${String(declaredCount)} (tail truncation or post-seal append)`;
    } else if (declaredFinal !== fold.finalHash) {
      auditChainOk =
        "audit log final hash does not match the manifest's audit_log_final_hash";
    } else if (!leavesEqual(derivedLeaves, declaredLeaves)) {
      auditChainOk =
        "leaves re-derived from the audit log do not match the manifest's declared leaves";
    }
  }

  // Merkle root rebuilt from the manifest's DECLARED leaves (matches
  // verify_manifest, which rebuilds from obj["leaves"]).
  const declaredLeaves = Array.isArray(manifest.leaves) ? manifest.leaves : [];
  let merkleRootOk: boolean | string = true;
  try {
    const declaredRoot = stringField(manifest.merkle_root_hex);
    const rebuilt = await merkleRootHex(
      declaredLeaves.map((leaf) => leafDigestHex(leaf)),
    );
    if (rebuilt !== declaredRoot) {
      merkleRootOk = `declared root ${declaredRoot} != rebuilt ${rebuilt}`;
    }
  } catch (err) {
    merkleRootOk = `merkle rebuild failed: ${errorMessage(err)}`;
  }

  // Leaf count.
  const declaredLeafCount = manifest.leaf_count;
  const actualLeafCount = declaredLeaves.length;
  const leafCountOk: boolean | string =
    declaredLeafCount === actualLeafCount
      ? true
      : `leaf_count ${String(declaredLeafCount)} != actual ${actualLeafCount}`;

  const { present, kind, verified } = await verifyManifestSignature(manifest);

  const sigFailed =
    present && !ADVISORY_SIGNER_KINDS.has(kind) && verified !== true;
  const overall =
    auditChainOk === true &&
    merkleRootOk === true &&
    leafCountOk === true &&
    present &&
    !sigFailed;

  return {
    available: true,
    auditChainOk,
    merkleRootOk,
    leafCountOk,
    signaturePresent: present,
    signatureKind: kind,
    signatureVerified: verified,
    overall,
  };
}

function leafDigestHex(leaf: JsonValue): string {
  if (typeof leaf === "object" && leaf !== null && !Array.isArray(leaf)) {
    return stringField((leaf as Record<string, JsonValue>).digest_hex);
  }
  return "";
}

function leavesEqual(derived: DerivedLeaf[], declared: JsonValue[]): boolean {
  if (derived.length !== declared.length) return false;
  for (let i = 0; i < derived.length; i += 1) {
    const d = derived[i];
    const raw = declared[i];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
    const obj = raw as Record<string, JsonValue>;
    if (
      d.seq !== obj.seq ||
      d.kind !== obj.kind ||
      d.digest_hex !== obj.digest_hex ||
      d.record_id !== stringField(obj.record_id)
    ) {
      return false;
    }
  }
  return true;
}
