// Integration test: audit-tail.ts against a real on-disk audit.jsonl
// that gets appended to mid-test. Per A3 plan Task 4.2.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  isAllowedCasePath,
  listCases,
  tailAuditLog,
  type AuditLine,
} from "@/lib/audit-tail";

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "audit-tail-"));
});

afterEach(async () => {
  await fs.rm(tmpDir, { recursive: true, force: true });
});

function lineFor(seq: number, kind: string, payload: object): string {
  return JSON.stringify({
    seq,
    kind,
    ts: "2026-04-27T01:00:00Z",
    payload,
    line_hash:
      "deadbeef".padEnd(64, "0").slice(0, 64),
    prev_hash:
      "00000000".padEnd(64, "0").slice(0, 64),
  });
}

async function createRepoMarkers(root: string): Promise<void> {
  await fs.mkdir(path.join(root, "scripts"), { recursive: true });
  await fs.mkdir(path.join(root, "apps", "web"), { recursive: true });
  await fs.writeFile(path.join(root, "scripts", "doctor.sh"), "#!/usr/bin/env bash\n", "utf-8");
  await fs.writeFile(path.join(root, "apps", "web", "package.json"), "{}\n", "utf-8");
  await fs.writeFile(path.join(root, "pnpm-workspace.yaml"), "packages: []\n", "utf-8");
}

describe("tailAuditLog", () => {
  it("yields existing lines on initial drain", async () => {
    const auditPath = path.join(tmpDir, "audit.jsonl");
    await fs.writeFile(
      auditPath,
      [
        lineFor(0, "agent_message", { role: "supervisor", content: "go" }),
        lineFor(1, "tool_call_start", { tool_call_id: "tc-1" }),
      ].join("\n") + "\n",
      "utf-8",
    );

    const ac = new AbortController();
    const collected: AuditLine[] = [];
    const iter = tailAuditLog(auditPath, ac.signal);

    for (let i = 0; i < 2; i++) {
      const next = await iter.next();
      if (next.done) break;
      collected.push(next.value);
    }
    ac.abort();
    // Drain the generator so the watcher cleanly closes.
    await iter.next();

    expect(collected).toHaveLength(2);
    expect(collected[0].seq).toBe(0);
    expect(collected[0].kind).toBe("agent_message");
    expect(collected[1].seq).toBe(1);
    expect(collected[1].kind).toBe("tool_call_start");
  });

  it("yields a line appended after the consumer is already listening", async () => {
    const auditPath = path.join(tmpDir, "audit.jsonl");
    // Pre-create empty so chokidar starts watching immediately.
    await fs.writeFile(auditPath, "", "utf-8");

    const ac = new AbortController();
    const iter = tailAuditLog(auditPath, ac.signal);

    // Kick the consumer first; it'll await the next line.
    const nextPromise = iter.next();

    // Give chokidar a tick to attach to the file before we append.
    await new Promise((r) => setTimeout(r, 100));

    await fs.appendFile(
      auditPath,
      lineFor(0, "finding_approved", { finding_id: "f-A-1" }) + "\n",
      "utf-8",
    );

    // Race the result against a 1500ms timeout — chokidar fires fast
    // but Windows fs.watch can lag on the first event.
    type RaceResult = { value: AuditLine | undefined; timed_out: boolean };
    const winner: RaceResult = await Promise.race<RaceResult>([
      nextPromise.then(
        (r): RaceResult => ({
          // r.value is AuditLine | void (void when r.done === true);
          // narrow to AuditLine | undefined for the assertion below.
          value: r.done ? undefined : r.value,
          timed_out: false,
        }),
      ),
      new Promise<RaceResult>((r) =>
        setTimeout(() => r({ value: undefined, timed_out: true }), 1500),
      ),
    ]);

    ac.abort();
    await iter.next();

    expect(winner.timed_out).toBe(false);
    expect(winner.value).toBeDefined();
    expect(winner.value?.seq).toBe(0);
    expect(winner.value?.kind).toBe("finding_approved");
  });

  it("skips malformed JSON lines without aborting the stream", async () => {
    const auditPath = path.join(tmpDir, "audit.jsonl");
    await fs.writeFile(
      auditPath,
      [
        lineFor(0, "agent_message", { content: "first" }),
        "this is not json",
        lineFor(1, "agent_message", { content: "second" }),
      ].join("\n") + "\n",
      "utf-8",
    );

    const ac = new AbortController();
    const iter = tailAuditLog(auditPath, ac.signal);
    const collected: AuditLine[] = [];
    for (let i = 0; i < 2; i++) {
      const next = await iter.next();
      if (next.done) break;
      collected.push(next.value);
    }
    ac.abort();
    await iter.next().catch(() => undefined);

    expect(collected).toHaveLength(2);
    expect(collected[0].payload).toEqual({ content: "first" });
    expect(collected[1].payload).toEqual({ content: "second" });
  });
});

describe("isAllowedCasePath", () => {
  let fakeRepoRoot: string;

  beforeEach(async () => {
    fakeRepoRoot = path.join(tmpDir, "repo");
    await createRepoMarkers(fakeRepoRoot);
    vi.spyOn(process, "cwd").mockReturnValue(fakeRepoRoot);
    delete process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS;
  });

  it("allows a case dir directly under goldens/synthetic-benign/", () => {
    const caseDir = path.join(
      fakeRepoRoot,
      "goldens",
      "synthetic-benign",
      "case-001",
    );
    expect(isAllowedCasePath(caseDir)).toBe(true);
  });

  it("allows a custom root supplied via FINDEVIL_DASHBOARD_EXTRA_ROOTS", () => {
    const customRoot =
      process.platform === "win32" ? "D:\\evidence" : "/srv/evidence";
    const caseDir = path.join(customRoot, "case-2026-04-26");
    // Path-delimiter-separated: ":" on POSIX, ";" on Windows.
    process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS = customRoot;
    expect(isAllowedCasePath(caseDir)).toBe(true);
  });

  it("blocks a path obviously outside the allow-list", () => {
    const outside =
      process.platform === "win32" ? "C:\\Windows\\System32" : "/etc";
    expect(isAllowedCasePath(outside)).toBe(false);
  });

  it("blocks a traversal that resolves outside the allow-list", () => {
    // `goldens/../../etc` resolves (against fakeRepoRoot) above the
    // repo root and outside every allow-listed root.
    const traversal = path.join(fakeRepoRoot, "goldens", "..", "..", "etc");
    expect(isAllowedCasePath(traversal)).toBe(false);
  });

  it("does not prefix-match (custom root /foo/bar allowed != /foo/baroot allowed)", () => {
    // Allow-list a narrow custom root, then check that a sibling
    // directory whose name shares the prefix does NOT match it. The
    // trailing path-separator check is what prevents this foot-gun.
    // Use a custom root well outside the default allow-list so the
    // assertion is unambiguous.
    const allowed =
      process.platform === "win32" ? "D:\\foo\\bar" : "/foo/bar";
    const siblingPrefix =
      process.platform === "win32" ? "D:\\foo\\baroot" : "/foo/baroot";
    process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS = allowed;
    expect(isAllowedCasePath(path.join(siblingPrefix, "case-1"))).toBe(
      false,
    );
    // Sanity: the actually-allowed root and a child of it both pass.
    expect(isAllowedCasePath(allowed)).toBe(true);
    expect(isAllowedCasePath(path.join(allowed, "case-1"))).toBe(true);
  });

  it("fails closed when no trusted repo root is available", async () => {
    const markerlessRoot = path.join(tmpDir, "not-a-repo");
    await fs.mkdir(markerlessRoot, { recursive: true });
    vi.restoreAllMocks();
    vi.spyOn(process, "cwd").mockReturnValue(markerlessRoot);

    expect(isAllowedCasePath(path.join(markerlessRoot, "goldens", "case-1"))).toBe(false);
    await expect(listCases()).resolves.toEqual([]);
  });
});
