# Third-Party Notices

caseforge-core is Apache-2.0. It builds on:

- **VERDICT DFIR toolkit** — https://github.com/TimothyVang/verdict-dfir-community (Apache-2.0).
  Forensic MCP servers (findevil-mcp, findevil-agent-mcp) and the DFIR doctrine
  ported into `configs/opencode/`. Not vendored here; referenced via VERDICT_DFIR_HOME.
- **verdict-opencode** — https://github.com/TimothyVang/verdict-opencode, a fork of
  **opencode** (https://github.com/sst/opencode, MIT). The vendored SDK under
  `packages/caseforge-sdk/vendor/opencode-sdk` is `@opencode-ai/sdk` (MIT).
- **zod** (MIT), **yaml** (ISC) — see their package licenses.
