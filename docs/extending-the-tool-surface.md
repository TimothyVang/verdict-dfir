# Extending the tool surface — add a typed DFIR tool

The point of this hackathon is that **winning code goes back into the open-source
Protocol SIFT toolset**. So the bar for a new tool is not "does it work" — it's
"does it preserve the property that makes VERDICT trustworthy": a **narrow, typed,
read-only surface with no `execute_shell`**. A new tool that opens a shell, takes
untyped input, or writes to evidence breaks the security pitch for everyone.

This is the worked example. Reference implementation to copy:
[`services/mcp/src/tools/prefetch_parse.rs`](../services/mcp/src/tools/prefetch_parse.rs).

## The five steps

### 1. Write the tool module — typed in, typed out, read-only

Create a new `my_tool.rs` in `services/mcp/src/tools/`. Every tool is a **pure function** over a
typed input that returns a typed output or a typed error — never a panic, never a
shell string.

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]            // <- INVARIANT: unknown fields are rejected
pub struct MyToolInput {
    pub case_id: String,
    pub artifact_path: PathBuf,          // typed path, never a shell fragment
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MyToolOutput {
    pub rows: Vec<String>,
    pub rows_seen: usize,
}

#[derive(Debug, Error)]
pub enum MyToolError {
    #[error("artifact not found: {0}")]
    NotFound(PathBuf),
    #[error("parse failed: {0}")]
    ParseFailed(String),
}

/// Read-only. Opens evidence read-only, never mutates it. If it shells out to a
/// SIFT binary, it uses FIXED argv — `Command::new(bin).args([...])`, never
/// `sh -c` — so a path can never be re-parsed as a flag or a command.
pub fn my_tool(input: &MyToolInput) -> Result<MyToolOutput, MyToolError> {
    if !input.artifact_path.exists() {
        return Err(MyToolError::NotFound(input.artifact_path.clone()));
    }
    // ... parse read-only, build the typed output ...
    Ok(MyToolOutput { rows: vec![], rows_seen: 0 })
}
```

### 2. Export it

In [`services/mcp/src/tools/mod.rs`](../services/mcp/src/tools/mod.rs):

```rust
pub mod my_tool;
```

In [`services/mcp/src/lib.rs`](../services/mcp/src/lib.rs), re-export the public types
so integration tests and the server can use them:

```rust
pub use crate::tools::my_tool::{my_tool, MyToolError, MyToolInput, MyToolOutput};
```

### 3. Register it in the JSON-RPC registry

In [`services/mcp/src/server.rs`](../services/mcp/src/server.rs) `build_registry()`,
add a `ToolEntry`. The `annotations` are how the agent and any MCP scanner learn the
tool is read-only — set them honestly.

```rust
ToolEntry {
    name: "my_tool",
    description: "What it extracts and the DFIR caveat that bounds it \
                  (e.g. 'Amcache LastModified != execution' per agent-config/MEMORY.md). \
                  ERRORS: NotFound (check the path), ParseFailed (corrupt/unsupported).",
    annotations: ToolAnnotations {
        title: "My Tool",
        read_only: true,        // <- INVARIANT for any evidence-touching tool
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    schema: || schema_for::<MyToolInput>(),
    handler: |args| dispatch_my_tool(args),
},
```

Add the small `dispatch_my_tool` shim next to the others (it deserializes the typed
input, calls `my_tool`, serializes the output or maps the typed error to a JSON-RPC
error).

### 4. Add a smoke test

Create a `my_tool_smoke.rs` in `services/mcp/tests/` following
[`prefetch_parse_smoke.rs`](../services/mcp/tests/prefetch_parse_smoke.rs): assert the
error paths (missing file → typed `NotFound`), the schema roundtrip, and an **opt-in**
real-fixture parse that is skipped when no fixture is present (so CI stays green
without shipping evidence).

### 5. Keep the architectural invariants (this is what's actually being graded)

A reviewer will check these with a grep, not your word:

- **No `execute_shell`, no `sh -c`.** Subprocesses use fixed argv. The adversarial
  proof lives in [`services/mcp/tests/bypass_paths.rs`](../services/mcp/tests/bypass_paths.rs)
  — a shell-payload *filename* must stay an inert path. If your tool shells out, add a
  case there.
- **`deny_unknown_fields`** on every input struct.
- **Read-only on evidence.** No write/delete/rename of the original. Work on copies.
- **Typed errors, not panics.** A bad path is a `NotFound`, not an `unwrap()`.
- **The agent cites it, you don't.** Your tool just returns typed output; the agent
  layer records the `tool_call_id` and SHA-256s the result into the audit chain.

## Adding a Python tool (`findevil-agent-mcp`)

The 13 Python tools are protocol shims, not DFIR primitives — crypto, ACH, memory,
expert-feedback. Domain logic lives in `services/agent/` (`findevil_agent`); the tool is
a typed Pydantic wrapper that calls it. Reference implementation:
[`services/agent_mcp/findevil_agent_mcp/tools/audit_append.py`](../services/agent_mcp/findevil_agent_mcp/tools/audit_append.py).

The same five-step pattern, in Python:

1. **Typed I/O, deny-unknown-fields.** A module under
   `services/agent_mcp/findevil_agent_mcp/tools/` with a Pydantic `*Input` and `*Output`,
   each `model_config = ConfigDict(extra="forbid", frozen=True)` (the Python analogue of
   `deny_unknown_fields`), and a `Field(..., description=...)` on every field so the agent
   understands each parameter.
2. **An async `_handle(inp)`** that calls `findevil_agent` domain code (never a shell, never
   raw I/O on the original evidence) and returns the typed `*Output`.
3. **Export `SPEC = ToolSpec(name, description, input_model, output_model, handler)`**
   (the shared `ToolSpec` in `_base.py`) plus `__all__`.
4. **Register it** by adding the module to the `all_specs()` aggregator in
   [`services/agent_mcp/findevil_agent_mcp/tools/__init__.py`](../services/agent_mcp/findevil_agent_mcp/tools/__init__.py)
   — it raises if a module does not export a `SPEC`.
5. **Add a test** under `services/agent_mcp/tests/` (`test_audit_tools.py` is the pattern):
   the input schema rejects an unknown field, the handler returns the typed output, and any
   error path raises a typed exception (not a bare `Exception`).

Invariants are identical to the Rust side: typed in / typed out, read-only on evidence,
typed errors not panics, and the agent — not the tool — records the `tool_call_id` into the
audit chain. Verify with `uv run --directory services/agent_mcp pytest` and `ruff check .`.

## Why the narrowness is the feature

32 typed Rust tools with no shell verb is not a limitation we apologize for — it is the
reason a judge can run `manifest_verify` and trust the result. Adding a tool that keeps
this contract grows the surface **without** growing the attack surface, which is exactly
the kind of contribution Protocol SIFT wants back.
