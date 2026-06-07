// Unit tests for deriveEvidenceMeta — the audit-stream → evidence-banner
// reducer. Mirrors __tests__/sprite-state.test.ts: tests the pure logic, not
// React rendering (the banner is validated visually in the live e2e run).

import { describe, expect, it } from "vitest";

import type { AuditLine } from "@/lib/audit-tail";
import { deriveEvidenceMeta } from "@/lib/evidence-meta";

function line(
  seq: number,
  kind: string,
  payload: Record<string, unknown>,
): AuditLine {
  return {
    seq,
    kind,
    ts: "2026-06-07T01:00:00Z",
    payload,
    line_hash: "deadbeef".padEnd(64, "0").slice(0, 64),
    raw_line: JSON.stringify({ seq, kind, payload }),
  };
}

function caseOpenStart(
  path: string,
  toolCallId = "tc-001",
): AuditLine {
  return line(0, "tool_call_start", {
    tool: "case_open",
    tool_call_id: toolCallId,
    arguments: { image_path: path, label: "evidence" },
  });
}

function caseOpenOutput(
  extra: Record<string, unknown>,
  toolCallId = "tc-001",
): AuditLine {
  return line(1, "tool_call_output", { tool_call_id: toolCallId, ...extra });
}

describe("deriveEvidenceMeta", () => {
  it("returns null for an empty event log", () => {
    expect(deriveEvidenceMeta([])).toBeNull();
  });

  it("returns null when no case_open start has streamed", () => {
    const meta = deriveEvidenceMeta([
      line(0, "tool_call_start", { tool: "vol_pslist", tool_call_id: "tc-2" }),
      line(1, "tool_call_output", { tool_call_id: "tc-2", output_hash: "x" }),
    ]);
    expect(meta).toBeNull();
  });

  it("derives full meta from a case_open start + output pair", () => {
    const meta = deriveEvidenceMeta([
      caseOpenStart("/cases/base-dc-memory.img"),
      caseOpenOutput({
        output_hash: "a".repeat(64),
        case_id: "auto-1234abcd-5678",
        size_bytes: 5_368_709_120, // exactly 5 GiB
      }),
    ]);
    expect(meta).not.toBeNull();
    expect(meta!.path).toBe("/cases/base-dc-memory.img");
    expect(meta!.name).toBe("base-dc-memory.img");
    expect(meta!.evidenceType).toBe("memory");
    expect(meta!.sha256).toBe("a".repeat(64));
    expect(meta!.sizeBytes).toBe(5_368_709_120);
    expect(meta!.sizeHuman).toBe("5 GB");
    expect(meta!.caseId).toBe("auto-1234abcd-5678");
  });

  it("maps file extensions to evidence types", () => {
    const cases: ReadonlyArray<readonly [string, string]> = [
      ["/x/a.img", "memory"],
      ["/x/a.mem", "memory"],
      ["/x/a.raw", "memory"],
      ["/x/a.evtx", "evtx"],
      ["/x/a.E01", "disk"], // case-insensitive
      ["/x/a.dd", "disk"],
      ["/x/a.pcap", "network"],
      ["/x/a.pcapng", "network"],
      ["/x/a.zip", "velociraptor"],
      ["/x/a.bin", "evidence"], // unknown extension
      ["/x/noext", "evidence"], // no extension at all
    ];
    for (const [path, expected] of cases) {
      const meta = deriveEvidenceMeta([caseOpenStart(path)]);
      expect(meta?.evidenceType, path).toBe(expected);
    }
  });

  it("prefers an authoritative evidence_type from the output over the extension guess", () => {
    const meta = deriveEvidenceMeta([
      caseOpenStart("/x/ambiguous.img"), // extension would guess "memory"
      caseOpenOutput({
        output_hash: "b".repeat(64),
        size_bytes: 1024,
        evidence_type: "disk",
      }),
    ]);
    expect(meta?.evidenceType).toBe("disk");
  });

  it("returns partial meta when the output has not arrived yet", () => {
    const meta = deriveEvidenceMeta([caseOpenStart("/x/host.mem")]);
    expect(meta).not.toBeNull();
    expect(meta!.name).toBe("host.mem");
    expect(meta!.evidenceType).toBe("memory");
    expect(meta!.sha256).toBeNull();
    expect(meta!.sizeBytes).toBeNull();
    expect(meta!.sizeHuman).toBeNull();
  });

  it("reads case_id from a later event when the case_open output lacks it", () => {
    const meta = deriveEvidenceMeta([
      caseOpenStart("/x/host.mem"),
      caseOpenOutput({ output_hash: "c".repeat(64), size_bytes: 2048 }),
      line(2, "finding_approved", {
        case_id: "auto-deadbeef-9999",
        pool_origin: "A",
      }),
    ]);
    expect(meta?.caseId).toBe("auto-deadbeef-9999");
  });

  it("does not match an unrelated tool_call_output to case_open", () => {
    const meta = deriveEvidenceMeta([
      caseOpenStart("/x/host.mem", "tc-001"),
      line(1, "tool_call_output", {
        tool_call_id: "tc-002", // different tool
        output_hash: "f".repeat(64),
        size_bytes: 999,
      }),
    ]);
    expect(meta?.sha256).toBeNull();
    expect(meta?.sizeBytes).toBeNull();
  });

  it("formats sizes in human-readable units", () => {
    const sizeFor = (bytes: number) =>
      deriveEvidenceMeta([
        caseOpenStart("/x/host.mem"),
        caseOpenOutput({ output_hash: "d".repeat(64), size_bytes: bytes }),
      ])?.sizeHuman;
    expect(sizeFor(512)).toBe("512 B");
    expect(sizeFor(2048)).toBe("2 KB");
    expect(sizeFor(1_572_864)).toBe("1.5 MB");
    expect(sizeFor(1_610_612_736)).toBe("1.5 GB");
  });
});
