// Unit tests for the independent, browser-side custody re-verifier
// (lib/verify-chain). The committed fixture under fixtures/custody/ was sealed
// by the REAL production Python stack (findevil_agent.crypto: AuditLog +
// LocalEd25519Signer + build_manifest) and verifies under verify_manifest, so
// these tests prove the TypeScript second implementation agrees with the
// canonical Rust/Python verifier: a valid chain verifies, a tampered one fails.

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  canonicalizeJson,
  extractContentRecord,
  merkleRootHex,
  parseAuditRecord,
  splitAuditLines,
  verifyCustodyChain,
  verifyManifestSignature,
  type JsonValue,
} from "@/lib/verify-chain";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.resolve(here, "fixtures", "custody");
const AUDIT_PATH = path.join(FIXTURE_DIR, "audit.jsonl");
const MANIFEST_PATH = path.join(FIXTURE_DIR, "run.manifest.json");

function loadFixture(): {
  auditText: string;
  manifest: Record<string, JsonValue>;
} {
  const auditText = readFileSync(AUDIT_PATH, "utf-8");
  const manifest = JSON.parse(
    readFileSync(MANIFEST_PATH, "utf-8"),
  ) as Record<string, JsonValue>;
  return { auditText, manifest };
}

describe("canonicalizeJson", () => {
  it("byte-matches each on-disk line via the CONTENT_FIELDS projection", () => {
    // The on-disk line IS the JCS canonicalization of the content fields, so
    // re-canonicalizing the parsed record must reproduce the exact bytes —
    // including the float (50.396626) and the escaped non-ASCII string.
    const { auditText } = loadFixture();
    const lines = splitAuditLines(auditText);
    expect(lines.length).toBeGreaterThan(0);
    for (const raw of lines) {
      const parsed = JSON.parse(raw) as Record<string, JsonValue>;
      expect(canonicalizeJson(extractContentRecord(parsed))).toBe(raw);
    }
  });

  it("sorts object keys and escapes non-ASCII to lowercase \\uXXXX", () => {
    expect(canonicalizeJson({ b: 1, a: 2 } as JsonValue)).toBe('{"a":2,"b":1}');
    expect(canonicalizeJson("unicóde ✓")).toBe('"unic\\u00f3de \\u2713"');
    expect(canonicalizeJson([true, null, 3])).toBe("[true,null,3]");
  });

  it("drops non-content fields when projecting onto CONTENT_FIELDS", () => {
    const projected = extractContentRecord({
      seq: 1,
      kind: "x",
      ts: "t",
      prev_hash: "",
      payload: { a: 1 },
      line_hash: "should-be-dropped",
    } as Record<string, JsonValue>);
    expect(JSON.parse(canonicalizeJson(projected))).not.toHaveProperty(
      "line_hash",
    );
  });
});

describe("merkleRootHex", () => {
  it("returns 32 zero bytes for an empty leaf set", async () => {
    expect(await merkleRootHex([])).toBe("00".repeat(32));
  });
});

describe("verifyCustodyChain (valid fixture)", () => {
  it("re-derives a fully verifying custody chain", async () => {
    const result = await verifyCustodyChain(loadFixture());
    expect(result.auditChainOk).toBe(true);
    expect(result.merkleRootOk).toBe(true);
    expect(result.leafCountOk).toBe(true);
    expect(result.signaturePresent).toBe(true);
    expect(result.signatureKind).toBe("ed25519");
    expect(result.signatureVerified).toBe(true);
    expect(result.overall).toBe(true);
  });
});

describe("verifyCustodyChain (tamper detection)", () => {
  it("fails when an audit line's bytes are altered (chain break)", async () => {
    const { auditText, manifest } = loadFixture();
    // Alter the finding_approved line — the NEXT line's prev_hash no longer
    // links, so the fold breaks.
    const tampered = auditText.replace("demo finding", "demo findinX");
    expect(tampered).not.toBe(auditText);
    const result = await verifyCustodyChain({ auditText: tampered, manifest });
    expect(result.auditChainOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails when a manifest Merkle leaf digest is swapped", async () => {
    const { auditText, manifest } = loadFixture();
    const leaves = (manifest.leaves as JsonValue[]).map((leaf) => ({
      ...(leaf as Record<string, JsonValue>),
    }));
    (leaves[0] as Record<string, JsonValue>).digest_hex = "b".repeat(64);
    const result = await verifyCustodyChain({
      auditText,
      manifest: { ...manifest, leaves },
    });
    expect(result.merkleRootOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails when the signed manifest body is changed", async () => {
    const { auditText, manifest } = loadFixture();
    const result = await verifyCustodyChain({
      auditText,
      manifest: { ...manifest, case_id: "tampered-case" },
    });
    expect(result.signatureVerified).not.toBe(true);
    expect(result.overall).toBe(false);
  });

  it("fails when the audit tail is truncated", async () => {
    const { auditText, manifest } = loadFixture();
    const lines = splitAuditLines(auditText);
    const truncated = lines.slice(0, -1).join("\n") + "\n";
    const result = await verifyCustodyChain({ auditText: truncated, manifest });
    expect(result.auditChainOk).not.toBe(true);
    expect(result.overall).toBe(false);
  });
});

describe("verifyManifestSignature (honest tiers)", () => {
  it("never reports a stub bundle as cryptographically verified", async () => {
    const res = await verifyManifestSignature({
      signature: { kind: "stub", bundle_b64: "x", payload_sha256: "y" },
    } as Record<string, JsonValue>);
    expect(res.present).toBe(true);
    expect(res.kind).toBe("stub");
    expect(res.verified).not.toBe(true);
  });

  it("reports an absent signature as not present", async () => {
    const res = await verifyManifestSignature(
      {} as Record<string, JsonValue>,
    );
    expect(res.present).toBe(false);
    expect(res.verified).not.toBe(true);
  });

  it("flags a sigstore bundle as advisory, not offline-verified", async () => {
    const res = await verifyManifestSignature({
      signature: { kind: "sigstore", bundle_b64: "x", payload_sha256: "y" },
    } as Record<string, JsonValue>);
    expect(res.kind).toBe("sigstore");
    expect(res.verified).not.toBe(true);
  });
});

describe("parseAuditRecord", () => {
  it("returns null for malformed JSON", () => {
    expect(parseAuditRecord("{not json")).toBeNull();
  });

  it("parses a well-formed record", () => {
    const rec = parseAuditRecord(
      '{"kind":"agent_message","payload":{"a":1},"prev_hash":"","seq":0,"ts":"t"}',
    );
    expect(rec?.seq).toBe(0);
    expect(rec?.kind).toBe("agent_message");
    expect(rec?.prevHash).toBe("");
  });
});

// Anchor canonicalization parity against committed PRODUCTION sample runs when
// present (skipped in a stripped release checkout that drops docs/sample-run).
describe("canonicalization parity vs committed sample runs", () => {
  const repoRoot = path.resolve(here, "..", "..", "..");
  const sampleAudit = path.join(
    repoRoot,
    "docs",
    "sample-run",
    "synthetic-benign",
    "audit.jsonl",
  );
  it.skipIf(!existsSync(sampleAudit))(
    "re-canonicalizes every sample-run line byte-for-byte",
    () => {
      const lines = splitAuditLines(readFileSync(sampleAudit, "utf-8"));
      expect(lines.length).toBeGreaterThan(0);
      for (const raw of lines) {
        const parsed = JSON.parse(raw) as Record<string, JsonValue>;
        expect(canonicalizeJson(extractContentRecord(parsed))).toBe(raw);
      }
    },
  );
});
