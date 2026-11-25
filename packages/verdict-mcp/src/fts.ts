import { DatabaseSync } from "node:sqlite"
import { EvidenceRecord } from "./evidence.js"

export interface FtsHit {
  evidence_id: string
  tool: string
  artifact_class: string
  event_time: string | null
  snippet: string
  rank: number
}

/**
 * Per-case SQLite FTS5 index (Mulder pattern) built on Node 24's built-in `node:sqlite`.
 * Indexes every retained EvidenceRecord's normalized_result so agents can run fast
 * cross-artifact full-text queries without loading megabytes into context.
 */
export class CaseFtsIndex {
  private readonly db: DatabaseSync

  constructor(dbPath = ":memory:") {
    this.db = new DatabaseSync(dbPath)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS evidence_docs (
        doc_id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT NOT NULL UNIQUE,
        tool TEXT NOT NULL,
        artifact_class TEXT NOT NULL,
        event_time TEXT,
        raw_text TEXT NOT NULL
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(
        raw_text,
        content='evidence_docs',
        content_rowid='doc_id'
      );
      CREATE TRIGGER IF NOT EXISTS evidence_docs_ai AFTER INSERT ON evidence_docs BEGIN
        INSERT INTO evidence_fts(rowid, raw_text) VALUES (new.doc_id, new.raw_text);
      END;
    `)
  }

  indexRecord(record: EvidenceRecord): void {
    const rawText = JSON.stringify(record.normalized_result)
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO evidence_docs (evidence_id, tool, artifact_class, event_time, raw_text)
      VALUES (?, ?, ?, ?, ?)
    `)
    stmt.run(record.evidence_id, record.tool, record.artifact_class, record.recorded_at, rawText)
  }

  search(query: string, opts?: { artifact_class?: string; limit?: number }): FtsHit[] {
    const trimmed = query.trim()
    if (!trimmed) return []
    const limit = Math.max(1, Math.min(200, opts?.limit ?? 25))

    // Escape bare hyphens/special chars by quoting simple tokens if user passes raw IOCs like IP/path
    const safeQuery = /["*()^:]|\b(AND|OR|NOT)\b/.test(trimmed)
      ? trimmed
      : trimmed
          .split(/\s+/)
          .filter(Boolean)
          .map((tok) => `"${tok.replace(/"/g, '""')}"`)
          .join(" ")

    const sql = opts?.artifact_class
      ? `
        SELECT d.evidence_id, d.tool, d.artifact_class, d.event_time,
               snippet(evidence_fts, 0, '[', ']', '...', 18) AS snippet,
               bm25(evidence_fts) AS rank
        FROM evidence_fts
        JOIN evidence_docs d ON d.doc_id = evidence_fts.rowid
        WHERE evidence_fts MATCH ? AND d.artifact_class = ?
        ORDER BY rank
        LIMIT ?
      `
      : `
        SELECT d.evidence_id, d.tool, d.artifact_class, d.event_time,
               snippet(evidence_fts, 0, '[', ']', '...', 18) AS snippet,
               bm25(evidence_fts) AS rank
        FROM evidence_fts
        JOIN evidence_docs d ON d.doc_id = evidence_fts.rowid
        WHERE evidence_fts MATCH ?
        ORDER BY rank
        LIMIT ?
      `

    const stmt = this.db.prepare(sql)
    const rows = (opts?.artifact_class ? stmt.all(safeQuery, opts.artifact_class, limit) : stmt.all(safeQuery, limit)) as Array<
      Record<string, unknown>
    >
    return rows.map((r) => ({
      evidence_id: String(r.evidence_id),
      tool: String(r.tool),
      artifact_class: String(r.artifact_class),
      event_time: r.event_time ? String(r.event_time) : null,
      snippet: String(r.snippet),
      rank: Number(r.rank),
    }))
  }

  count(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM evidence_docs").get() as { n: number }
    return Number(row.n)
  }

  close(): void {
    this.db.close()
  }
}
