# caseforge-fleet

DFIR investigation multiplexer for caseforge — a terminal UI to launch and monitor
many `caseforge investigate` runs at once, with a status grid, live-attach, a socket
API, and detach/reattach. Clean-room, Apache-2.0 (built from herdr's behavior, not
its code).

## Run

```bash
cargo build --release
caseforge fleet <run-dir> [<run-dir> ...]     # via the caseforge CLI
# or directly:
./target/release/caseforge-fleet <run-dir> ... [--socket <path>] [--attach <path>]
```

## What it does

- **Status grid** — per-investigation state (idle / working / blocked / done) derived
  deterministically from the run dir's custody artifacts, plus custody state
  (complete / custody-invalid, prominently flagged).
- **Tabs** — filter by all / active / done / issues.
- **Detail / attach** — Enter zooms to an investigation; a running one shows a live
  PTY output pane, a finished one its audit tail. `o` opens the full `caseforge tui`
  case viewer.
- **Launch** — `n` prompts for evidence and spawns `caseforge investigate`, then
  discovers the case dir it creates and tracks it.
- **Socket API** — `--socket <path>` serves line-delimited JSON (`ping`/`list`/`launch`)
  so an agent can orchestrate the fleet.
- **Detach/reattach** — `--attach <path>` connects to a running fleet from any
  terminal; the server keeps running when you detach.

Keys: `↑↓/jk` move · `Tab` filter · `Enter` attach · `n` launch · `o` viewer · `q`
back/quit · mouse (click a row or tab).

## Boundaries

Read-only on evidence; the fleet only launches and observes. It talks to caseforge via
its CLI + run-dir JSON — no linking, no AGPL.
