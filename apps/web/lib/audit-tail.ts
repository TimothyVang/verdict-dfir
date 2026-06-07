// Server-side audit-log tail: watch a case's audit.jsonl, yield each
// event as it's appended. The route handler in
// app/api/audit/route.ts wraps this in an SSE stream; tests in
// __tests__/audit-tail.test.ts drive it directly without HTTP.
//
// Per A3 plan Task 4.2.

import { promises as fs } from "node:fs";
import path from "node:path";

import chokidar, { type FSWatcher } from "chokidar";

import type { AgentEvent } from "@/lib/events";

/**
 * Default allow-listed case roots, resolved against the repo root
 * (assumed to be `process.cwd()` — Next.js dev server runs from the
 * repo root, and the dashboard is started via `pnpm --filter
 * @findevil/web dev` from there). The route handler uses
 * isAllowedCasePath() to reject `?case=` paths that don't sit inside
 * one of these roots, closing the path-traversal hole flagged in PR
 * #7's `route.ts` comment + this README's "Path allow-list" section.
 *
 *  - `goldens/`        committed test fixtures
 *  - `tmp/auto-runs/`  find-evil-auto headless output
 *  - `tmp/smoke/`      synthetic smoke output
 *  - `test-forensics/` operator's local DFIR corpus (gitignored)
 *
 * Operators can extend this set without code changes via the
 * `FINDEVIL_DASHBOARD_EXTRA_ROOTS` env var (path-delimiter-separated:
 * `:` on POSIX, `;` on Windows — i.e. `path.delimiter`).
 */
const DEFAULT_ALLOWED_ROOTS = [
  "goldens",
  "tmp/auto-runs",
  "tmp/smoke",
  "test-forensics",
];

/**
 * Return true iff `absPath` resolves to a location strictly INSIDE
 * one of the allow-listed roots (default roots + any
 * `FINDEVIL_DASHBOARD_EXTRA_ROOTS` entries). The trailing-separator
 * check guards against the prefix-match foot-gun where, given an
 * allowed root `/foo/bar`, a path like `/foo/baroot/case` would
 * otherwise pass a naive `startsWith`.
 *
 * The path itself is allowed when it is exactly equal to a root
 * (operators sometimes point the dashboard at the root directory
 * itself for a smoke check).
 *
 * Relative default roots resolve against the repo root. `pnpm --filter
 * @findevil/web dev` can run with cwd=apps/web, so the launcher exports
 * `FINDEVIL_REPO_ROOT`; absent that we fall back to process.cwd() (which the
 * unit tests pin).
 */
function repoRoot(): string {
  return process.env.FINDEVIL_REPO_ROOT ?? process.cwd();
}

export function isAllowedCasePath(absPath: string): boolean {
  const resolved = path.resolve(absPath);
  const base = repoRoot();
  const extraRaw = process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS ?? "";
  const extras = extraRaw
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const allRoots = [...DEFAULT_ALLOWED_ROOTS, ...extras];
  for (const root of allRoots) {
    const rootAbs = path.isAbsolute(root) ? root : path.resolve(base, root);
    if (resolved === rootAbs) return true;
    if (resolved.startsWith(rootAbs + path.sep)) return true;
  }
  return false;
}

/** One selectable case in the dashboard picker. */
export interface CaseEntry {
  /** Absolute case directory. */
  path: string;
  /** Directory basename, shown in the picker. */
  name: string;
  /** audit.jsonl mtime (ms) — used to sort newest-first. */
  mtime: number;
}

/**
 * List case directories (immediate children of the allow-listed roots that
 * contain an audit.jsonl), newest-first. Powers the dashboard case picker so
 * an investigator selects a case instead of pasting an absolute path.
 */
export async function listCases(): Promise<CaseEntry[]> {
  const base = repoRoot();
  const extraRaw = process.env.FINDEVIL_DASHBOARD_EXTRA_ROOTS ?? "";
  const extras = extraRaw
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const roots = [...DEFAULT_ALLOWED_ROOTS, ...extras].map((r) =>
    path.isAbsolute(r) ? r : path.resolve(base, r),
  );

  const out: CaseEntry[] = [];
  const seen = new Set<string>();
  for (const root of roots) {
    let entries;
    try {
      entries = await fs.readdir(root, { withFileTypes: true });
    } catch {
      continue; // root doesn't exist on this host — skip
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const dir = path.join(root, e.name);
      if (seen.has(dir)) continue;
      try {
        const s = await fs.stat(path.join(dir, "audit.jsonl"));
        out.push({ path: dir, name: e.name, mtime: s.mtimeMs });
        seen.add(dir);
      } catch {
        // no audit.jsonl → not a case dir
      }
    }
  }
  out.sort((a, b) => b.mtime - a.mtime);
  return out;
}

/**
 * One yielded record. We surface the raw parsed JSON object plus a
 * `kind` tag because audit.jsonl carries lines OUTSIDE the
 * AgentEvent union too — `audit_append`, `acp_handoff`, etc. The
 * `event` field is the typed AgentEvent subset; everything else
 * falls into `raw`.
 */
export interface AuditLine {
  /** Sequence number from the audit chain (added by the agent's
   *  AuditLog.append; present on every well-formed line). */
  seq: number;
  /** Audit-log "kind" field — distinguishes AgentEvent variants from
   *  the bookkeeping records (acp_handoff, …). */
  kind: string;
  /** ISO-8601Z timestamp from the line. */
  ts: string;
  /** Parsed payload (the typed AgentEvent for kind∈AgentEvent.event_type;
   *  arbitrary object otherwise). */
  payload: AgentEvent | Record<string, unknown>;
  /** SHA-256 of the canonicalized line — for the hash-chain badge. */
  line_hash?: string;
  /** Raw JSON line, byte-identical to what's in audit.jsonl. Useful
   *  for re-verifying the chain client-side. */
  raw_line: string;
}

/**
 * Open a tail over a case's audit.jsonl. Yields every existing line
 * first (so a late-connecting consumer doesn't miss earlier events),
 * then continues yielding appended lines until the abort signal
 * fires.
 */
export async function* tailAuditLog(
  auditPath: string,
  signal: AbortSignal,
): AsyncGenerator<AuditLine, void, void> {
  const absPath = path.resolve(auditPath);

  // Set up abort tracking up-front so a mid-drain abort doesn't get
  // lost. Without this, `signal.addEventListener("abort", …)` would
  // be registered AFTER the initial drain — and abort events fire
  // exactly once, so a missed event = a hung iterator.
  let done = false;
  let watcher: FSWatcher | null = null;
  let resolve: (() => void) | null = null;

  const wakeup = (): void => {
    if (resolve) {
      const r = resolve;
      resolve = null;
      r();
    }
  };

  const onAbort = (): void => {
    done = true;
    if (watcher) {
      watcher.close().catch(() => {
        // best-effort
      });
    }
    wakeup();
  };

  if (signal.aborted) {
    return;
  }
  signal.addEventListener("abort", onAbort);

  try {
    // 1. Initial drain — read whatever's already on disk so a late
    //    connection sees full history.
    let position = 0;
    try {
      const stat = await fs.stat(absPath);
      if (stat.size > 0) {
        const initial = await fs.readFile(absPath, { encoding: "utf-8" });
        position = Buffer.byteLength(initial, "utf-8");
        for (const line of splitLines(initial)) {
          if (done) return;
          const parsed = parseLine(line);
          if (parsed) yield parsed;
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      // File doesn't exist yet — that's fine; chokidar will catch
      // the first append.
    }

    if (done) return;

    // 2. Watch for appends. Buffer partial lines across reads since
    //    the writer (Python) may flush mid-line.
    watcher = chokidar.watch(absPath, {
      persistent: true,
      awaitWriteFinish: false,
      ignoreInitial: true,
    });

    // The pending queue lets us yield from inside an async iterator
    // without losing events that arrive while we're awaiting.
    const pending: AuditLine[] = [];
    let lineBuffer = "";

    const readNew = async (p: string): Promise<void> => {
      if (path.resolve(p) !== absPath) return;
      try {
        const stat = await fs.stat(absPath);
        if (stat.size === position) return;
        // Re-open per change to keep the implementation simple; for
        // multi-MB audit logs we'd hold an fd open and seek instead.
        const fd = await fs.open(absPath, "r");
        try {
          const length = stat.size - position;
          if (length <= 0) return;
          const buf = Buffer.alloc(length);
          await fd.read(buf, 0, length, position);
          position = stat.size;
          lineBuffer += buf.toString("utf-8");
          const newlineIdx = lineBuffer.lastIndexOf("\n");
          if (newlineIdx === -1) return;
          const ready = lineBuffer.slice(0, newlineIdx);
          lineBuffer = lineBuffer.slice(newlineIdx + 1);
          for (const line of splitLines(ready)) {
            const parsed = parseLine(line);
            if (parsed) {
              pending.push(parsed);
            }
          }
          wakeup();
        } finally {
          await fd.close();
        }
      } catch (err) {
        console.error("audit-tail read error:", err);
      }
    };

    watcher.on("add", (changedPath: string) => void readNew(changedPath));
    watcher.on("change", (changedPath: string) => void readNew(changedPath));
    watcher.on("error", (err: unknown) => {
      console.error("audit-tail watcher error:", err);
    });

    while (!done) {
      while (pending.length > 0) {
        const line = pending.shift();
        if (line) yield line;
      }
      if (done) break;
      await new Promise<void>((r) => {
        resolve = r;
      });
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
    if (watcher) {
      await watcher.close().catch(() => undefined);
    }
  }
}

function splitLines(text: string): string[] {
  return text.split(/\r?\n/).filter((line) => line.length > 0);
}

function parseLine(line: string): AuditLine | null {
  try {
    const obj = JSON.parse(line) as Record<string, unknown>;
    const seq = typeof obj.seq === "number" ? obj.seq : -1;
    const kind = typeof obj.kind === "string" ? obj.kind : "unknown";
    const ts = typeof obj.ts === "string" ? obj.ts : "";
    return {
      seq,
      kind,
      ts,
      payload: (obj.payload ?? obj) as AgentEvent | Record<string, unknown>,
      line_hash:
        typeof obj.line_hash === "string" ? obj.line_hash : undefined,
      raw_line: line,
    };
  } catch {
    // Malformed line — skip silently rather than abort the stream.
    // Future: surface as a `kind=tail_parse_error` synthetic event.
    return null;
  }
}
