# Resolved spec/code divergences

Settled facts. Each entry was once an active divergence between a spec and the shipped code; the resolution is now CI-enforced, documented in a pin file, or otherwise stable. Preserved here for archaeology — when you find an old spec sentence that contradicts these bullets, the bullet wins.

**New divergences do NOT go here.** Active uncertainty stays in `CLAUDE.md §11`. Move a bullet down here only after the resolution stops being a moving target.

---

- **Rust toolchain: spec pins 1.83, repo ships 1.88.** `Cargo.toml` (`rust-version = "1.88"`) and `rust-toolchain.toml` (`channel = "1.88.0"`) note the bump was needed because transitive deps (e.g. `clap_builder` 4.6) require edition-2024 stabilization (Rust ≥1.85). Spec #2 §16 is superseded; don't downgrade.

- **`Cargo.lock` is committed.** `.gitignore` has an explicit comment: "Cargo.lock IS committed — this is an application workspace with a shipped binary (findevil-mcp), not a library." Don't add it back to the ignore list.

- **Python CLI package is `findevil_agent`, not `services.agent`.** Tests + entry points use `findevil_agent.*`. The `cli.py` submodule was dropped under A2 (Claude Code IS the orchestrator). Dockerfile wrapper + `scripts/build-deb.sh` cut 2026-04-27 (PR #4) per `docs/runbooks/dockerfile-a2-decision.md`. L0 `amendment-a2-guard` + L1 `scripts/divergence-smoke.py` §3 fail CI if `findevil_agent.cli` reappears.

- **Rust MCP tool count is 19, not 11.** Spec #2 §6 enumerates 11; we ship `vol_psscan` (12th, DKOM cross-val), `vol_psxview` (13th, cross-references views after divergence), `disk_mount` / `disk_extract_artifacts` / `disk_unmount` (Track 1 disk-resource slice), plus 3 network/log triage tools. Memory tools are deliberately redundant — divergence between them IS the T1014/Rootkit finding. Don't fold them.

- **`rmcp` is intentionally NOT a runtime dependency.** Spec #2 §4.1 lists `rmcp 0.16.x`; we ship a hand-rolled stdio JSON-RPC 2.0 (MCP 2024-11-05) in `services/mcp/src/server.rs` for wire-format stability and Python-server dispatch parity. `Cargo.toml:27` keeps the `rmcp` line commented as a deliberate marker. See `services/mcp/README.md`.

- **A3 MemoryStore: FTS5 phrase-quoting + Python-side sort.** Plan Task 1.1/spec §2.4 specified raw `params=[query]` MATCH + `ORDER BY score`. Shipped `services/agent/findevil_agent/memory/store.py` phrase-quotes (`fts_query = '"' + query.replace('"','""') + '"'`) — required so queries like `evil.com` or `T1059.001` don't trip `fts5: syntax error near "."` — and re-sorts by combined `confidence` so decay breaks BM25 ties. Plan + spec updated; multi-word recall is conservative phrase-match.

- **A3 audit-log push: SSE, not WebSocket.** Plan Task 4.2 specified WebSocket; PR #7 (`281d26f`) shipped SSE. Flow is strictly server→client, App Router doesn't natively support WS upgrade. Live handler: `apps/web/app/api/audit/route.ts` (Node runtime, SSE MIME, 15s keepalive comment frame). Iterator: `apps/web/lib/audit-tail.ts`. Consumers: `new EventSource("/api/audit?case=…")` + `addEventListener("audit_line", …)`. Don't "upgrade" back to WS without a spec amendment naming a concrete client→server message.

- **`findevil-agent-mcp` tool count is 12, not 11.** Spec #2 §6 and some A5-era prose enumerate 11; Track 4 adds `expert_miss_capture` so expert edits become a hash-chained improvement ledger. `services/agent_mcp/tests/test_stdio_smoke.py` and `scripts/agent-mcp-smoke.py` are the canaries.
