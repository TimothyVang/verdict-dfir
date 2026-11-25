import { createInterface } from "node:readline"
import { DairDirector } from "./dair.js"
import { runDoctor } from "./doctor.js"
import { EvidenceSource, VerdictMcpError } from "./evidence.js"
import { FindingsStore, RecordFindingInput } from "./findings.js"
import { CaseFtsIndex } from "./fts.js"
import { runIntake } from "./intake.js"
import { AnalysisViewQuery, EvidenceLedger } from "./ledger.js"
import { triageLinuxDisk } from "./linux.js"
import { triageBinary } from "./re_bridge.js"
import { UnknownsRegistry } from "./unknowns.js"

interface JsonRpcRequest {
  jsonrpc: "2.0"
  id?: string | number | null
  method: string
  params?: Record<string, unknown>
}

export class VerdictMcpSession {
  readonly ledger: EvidenceLedger
  readonly fts: CaseFtsIndex
  readonly unknowns: UnknownsRegistry
  readonly findings: FindingsStore
  readonly dair: DairDirector
  readonly repoRoot: string

  constructor(opts?: { repoRoot?: string; auditPath?: string; ftsDbPath?: string }) {
    this.repoRoot = opts?.repoRoot ?? process.cwd()
    this.fts = new CaseFtsIndex(opts?.ftsDbPath ?? ":memory:")
    this.ledger = new EvidenceLedger({
      auditPath: opts?.auditPath,
      onRetain: (record) => this.fts.indexRecord(record),
    })
    this.unknowns = new UnknownsRegistry()
    this.findings = new FindingsStore()
    this.dair = new DairDirector()
  }

  listTools() {
    return [
      {
        name: "verdict_doctor",
        description: "Check available VERDICT core binaries, Tier-1 SIFT/DFIR providers, Tier-2 REA/RE bridges, and local LLM endpoints.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
      },
      {
        name: "verdict_intake",
        description: "Read-only target-free intake: classify and SHA-256 hash evidence files. Defaults to detail='summary' and retains the full inventory in the session ledger.",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
            detail: { type: "string", enum: ["summary", "complete"] },
            max_files: { type: "number" },
          },
          required: ["path"],
          additionalProperties: false,
        },
      },
      {
        name: "inspect_analysis_view",
        description: "Page or filter a retained Evidence record without re-running the producing tool. Pass source={kind:'retained-evidence', evidence_id} and view.",
        inputSchema: {
          type: "object",
          properties: {
            source: { type: "object" },
            view: { type: "object" },
          },
          required: ["source", "view"],
          additionalProperties: false,
        },
      },
      {
        name: "record_unknown",
        description: "Record an unresolved forensic question and the authority/artifact required to resolve it.",
        inputSchema: {
          type: "object",
          properties: {
            question: { type: "string" },
            required_authority: { type: "string" },
            supporting_evidence_ids: { type: "array", items: { type: "string" } },
            contradicting_evidence_ids: { type: "array", items: { type: "string" } },
          },
          required: ["question", "required_authority"],
          additionalProperties: false,
        },
      },
      {
        name: "update_unknown",
        description: "Update an unknown with optimistic revision checking. Resolving requires verified supporting evidence_ids.",
        inputSchema: {
          type: "object",
          properties: {
            unknown_id: { type: "string" },
            expected_revision: { type: "number" },
            status: { type: "string", enum: ["open", "resolved", "unresolvable"] },
            supporting_evidence_ids: { type: "array", items: { type: "string" } },
            contradicting_evidence_ids: { type: "array", items: { type: "string" } },
            resolution_note: { type: "string" },
          },
          required: ["unknown_id", "expected_revision"],
          additionalProperties: false,
        },
      },
      {
        name: "record_finding",
        description: "Record a forensic finding with API-boundary citation validation, ISO-8601 timestamp checks, Amcache caveat enforcement, and >=2 artifact-class corroboration for confirmed status.",
        inputSchema: {
          type: "object",
          properties: {
            title: { type: "string" },
            claim: { type: "string" },
            severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
            status: { type: "string", enum: ["proposed", "confirmed", "inferred", "refuted", "uncertain"] },
            mitre_techniques: { type: "array", items: { type: "string" } },
            evidence_refs: { type: "array", items: { type: "string" } },
            event_timestamp: { type: ["string", "null"] },
            caveats_acknowledged: { type: "array", items: { type: "string" } },
          },
          required: ["title", "claim", "severity", "evidence_refs"],
          additionalProperties: false,
        },
      },
      {
        name: "challenge_finding",
        description: "Adversarial Skeptic pass: attach a counter-hypothesis and optional counter-evidence to confirm, infer, or refute an existing finding.",
        inputSchema: {
          type: "object",
          properties: {
            finding_id: { type: "string" },
            challenger: { type: "string" },
            counter_hypothesis: { type: "string" },
            counter_evidence_refs: { type: "array", items: { type: "string" } },
            outcome: { type: "string", enum: ["confirmed", "inferred", "refuted", "uncertain"] },
            notes: { type: "string" },
          },
          required: ["finding_id", "challenger", "counter_hypothesis", "outcome", "notes"],
          additionalProperties: false,
        },
      },
      {
        name: "verdict_summary",
        description: "Derive the honest case verdict (SUSPICIOUS | INDETERMINATE | NO_EVIL) from verified findings, open unknowns, coverage, and audit chain integrity.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
      },
      {
        name: "export_evidence_bundle",
        description: "Export the authenticated session evidence bundle to JSON (and optionally write to output_path).",
        inputSchema: {
          type: "object",
          properties: {
            output_path: { type: "string" },
          },
          additionalProperties: false,
        },
      },
      {
        name: "search_evidence",
        description: "Full-text SQLite FTS5 search across all retained case Evidence records with BM25 ranking and evidence_id provenance.",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            artifact_class: { type: "string" },
            limit: { type: "number" },
          },
          required: ["query"],
          additionalProperties: false,
        },
      },
      {
        name: "triage_linux_disk",
        description: "Read-only Linux dead-disk parser pack: inspects ld.so.preload, sudoers, SSH authorized_keys, cron, systemd, auth logs, and /var/www webshells.",
        inputSchema: {
          type: "object",
          properties: {
            rootfs: { type: "string" },
            detail: { type: "string", enum: ["summary", "complete"] },
          },
          required: ["rootfs"],
          additionalProperties: false,
        },
      },
      {
        name: "triage_binary",
        description: "Execution-free binary & malware triage (PE/ELF/Mach-O format, Shannon entropy, suspicious strings, optional CAPA/REA bridge).",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
            invoke_external: { type: "boolean" },
            detail: { type: "string", enum: ["summary", "complete"] },
          },
          required: ["path"],
          additionalProperties: false,
        },
      },
      {
        name: "conduct_assess",
        description: "TRUDI-style DAIR phase director: evaluates sealed session state and emits next phase, priority_tools, coverage audit, and curiosity_budget.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
      },
      {
        name: "record_curiosity_probe",
        description: "Spend 1 unit of active DAIR curiosity_budget to log an off-plan read-only exploratory probe with explicit rationale.",
        inputSchema: {
          type: "object",
          properties: {
            rationale: { type: "string" },
            target: { type: "string" },
          },
          required: ["rationale", "target"],
          additionalProperties: false,
        },
      },
    ]
  }

  callTool(name: string, args: Record<string, unknown> = {}): {
    isError?: boolean
    structuredContent?: Record<string, unknown>
    content: Array<{ type: "text"; text: string }>
  } {
    try {
      let result: Record<string, unknown>
      switch (name) {
        case "verdict_doctor":
          result = runDoctor(this.repoRoot)
          break
        case "verdict_intake": {
          const targetPath = String(args.path ?? "")
          if (!targetPath) {
            throw new VerdictMcpError("invalid_request", "Missing required parameter 'path'.", {
              recovery: { kind: "inspect_input_contract", operation: "verdict_intake" },
            })
          }
          const rec = runIntake(this.ledger, targetPath, {
            maxFiles: typeof args.max_files === "number" ? args.max_files : undefined,
          })
          const detail = args.detail === "complete" ? "complete" : "summary"
          result =
            detail === "complete"
              ? (rec as unknown as Record<string, unknown>)
              : ({
                  detail: "summary",
                  normalized_result: this.ledger.summarize(rec),
                } as Record<string, unknown>)
          break
        }
        case "inspect_analysis_view":
          result = this.ledger.inspectView(args.source as EvidenceSource, args.view as AnalysisViewQuery)
          break
        case "record_unknown":
          result = this.unknowns.record(this.ledger, {
            question: String(args.question ?? ""),
            required_authority: String(args.required_authority ?? ""),
            supporting_evidence_ids: Array.isArray(args.supporting_evidence_ids)
              ? (args.supporting_evidence_ids as string[])
              : undefined,
            contradicting_evidence_ids: Array.isArray(args.contradicting_evidence_ids)
              ? (args.contradicting_evidence_ids as string[])
              : undefined,
          }) as unknown as Record<string, unknown>
          break
        case "update_unknown":
          result = this.unknowns.update(this.ledger, {
            unknown_id: String(args.unknown_id ?? ""),
            expected_revision: Number(args.expected_revision),
            status: args.status as "open" | "resolved" | "unresolvable" | undefined,
            supporting_evidence_ids: Array.isArray(args.supporting_evidence_ids)
              ? (args.supporting_evidence_ids as string[])
              : undefined,
            contradicting_evidence_ids: Array.isArray(args.contradicting_evidence_ids)
              ? (args.contradicting_evidence_ids as string[])
              : undefined,
            resolution_note: typeof args.resolution_note === "string" ? args.resolution_note : undefined,
          }) as unknown as Record<string, unknown>
          break
        case "record_finding":
          result = this.findings.record(
            this.ledger,
            args as unknown as RecordFindingInput,
          ) as unknown as Record<string, unknown>
          break
        case "challenge_finding":
          result = this.findings.challenge(this.ledger, {
            finding_id: String(args.finding_id ?? ""),
            challenger: String(args.challenger ?? "skeptic"),
            counter_hypothesis: String(args.counter_hypothesis ?? ""),
            counter_evidence_refs: Array.isArray(args.counter_evidence_refs)
              ? (args.counter_evidence_refs as string[])
              : undefined,
            outcome: args.outcome as "confirmed" | "inferred" | "refuted" | "uncertain",
            notes: String(args.notes ?? ""),
          }) as unknown as Record<string, unknown>
          break
        case "verdict_summary":
          result = {
            ...this.findings.computeCaseVerdict(this.ledger, this.unknowns),
            findings: this.findings.list(),
            unknowns: this.unknowns.list(),
          }
          break
        case "export_evidence_bundle":
          result = this.ledger.exportBundle(
            typeof args.output_path === "string" ? args.output_path : undefined,
          ) as unknown as Record<string, unknown>
          break
        case "search_evidence": {
          const hits = this.fts.search(String(args.query ?? ""), {
            artifact_class: typeof args.artifact_class === "string" ? args.artifact_class : undefined,
            limit: typeof args.limit === "number" ? args.limit : undefined,
          })
          result = { query: String(args.query ?? ""), indexed_docs: this.fts.count(), hits }
          break
        }
        case "triage_linux_disk": {
          const rec = triageLinuxDisk(this.ledger, String(args.rootfs ?? ""))
          const detail = args.detail === "complete" ? "complete" : "summary"
          result =
            detail === "complete"
              ? (rec as unknown as Record<string, unknown>)
              : { detail: "summary", normalized_result: this.ledger.summarize(rec) }
          break
        }
        case "triage_binary": {
          const rec = triageBinary(this.ledger, String(args.path ?? ""), {
            invokeExternal: Boolean(args.invoke_external),
          })
          const detail = args.detail === "complete" ? "complete" : "summary"
          result =
            detail === "complete"
              ? (rec as unknown as Record<string, unknown>)
              : { detail: "summary", normalized_result: this.ledger.summarize(rec) }
          break
        }
        case "conduct_assess":
          result = this.dair.assess(this.ledger, this.findings, this.unknowns) as unknown as Record<string, unknown>
          break
        case "record_curiosity_probe":
          result = this.dair.recordCuriosityProbe(
            String(args.rationale ?? ""),
            String(args.target ?? ""),
          ) as unknown as Record<string, unknown>
          break
        default:
          throw new VerdictMcpError("invalid_request", `Unknown tool '${name}'. Call tools/list to inspect available operations.`)
      }

      return {
        structuredContent: result,
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      }
    } catch (err) {
      const diag =
        err instanceof VerdictMcpError
          ? err.toDiagnostic()
          : { error: { code: "invalid_request", message: err instanceof Error ? err.message : String(err) } }
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify(diag, null, 2) }],
      }
    }
  }

  handleJsonRpc(req: JsonRpcRequest): Record<string, unknown> | null {
    if (req.method === "notifications/initialized") {
      return null
    }
    if (req.method === "initialize") {
      return {
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "verdict-mcp", version: "1.0.0" },
        },
      }
    }
    if (req.method === "ping") {
      return { jsonrpc: "2.0", id: req.id ?? null, result: {} }
    }
    if (req.method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: { tools: this.listTools() },
      }
    }
    if (req.method === "tools/call") {
      const params = req.params ?? {}
      const toolName = String(params.name ?? "")
      const toolArgs = (params.arguments ?? {}) as Record<string, unknown>
      return {
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: this.callTool(toolName, toolArgs),
      }
    }
    return {
      jsonrpc: "2.0",
      id: req.id ?? null,
      error: { code: -32601, message: `Method not found: ${req.method}` },
    }
  }
}

export function startStdioServer(opts?: { repoRoot?: string; auditPath?: string }): void {
  const session = new VerdictMcpSession(opts)
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })
  rl.on("line", (line) => {
    const trimmed = line.trim()
    if (!trimmed) return
    try {
      const req = JSON.parse(trimmed) as JsonRpcRequest
      const resp = session.handleJsonRpc(req)
      if (resp) {
        process.stdout.write(`${JSON.stringify(resp)}\n`)
      }
    } catch (err) {
      const resp = {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: err instanceof Error ? err.message : "Parse error" },
      }
      process.stdout.write(`${JSON.stringify(resp)}\n`)
    }
  })
}
