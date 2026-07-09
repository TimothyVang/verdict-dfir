# Optional OS-level hardening — deny-hook + rootless sandbox

This page documents an **optional, opt-in, defense-in-depth** layer that sits
*below* VERDICT's primary, code-enforced boundary. It is **not** a replacement
for that boundary and it is **off by default** — turning it on changes nothing
about how a normal `scripts/verdict` run behaves until an operator deliberately
wires it.

## What it is NOT

VERDICT's real no-arbitrary-execution guarantee is **architectural and already
shipped**, not this hook:

- The two product MCP servers (`findevil-mcp`, `findevil-agent-mcp`) have **no
  `execute_shell` verb** and a fixed, compile-time tool registry. Adding a shell
  passthrough is a code change + PR + review, not a runtime toggle.
- Every typed wrapper invokes its forensic binary with **fixed argv**
  (`Command::new(bin).args([...])`, never `sh -c`), adversarially pinned by
  `services/mcp/tests/bypass_paths.rs`.

The hook and sandbox below are a **second, OS-level layer** for operators who
want belt-and-suspenders containment of the *host process* that Claude Code and
the forensic tools run in. They can only **deny**; they never widen the surface
and never add an `execute_shell`-style capability.

---

## Part 1 — PreToolUse binary deny-hook (opt-in)

`scripts/pretooluse-deny-hook.sh` is a Claude Code **`Bash` PreToolUse** hook.
When wired, it inspects each `Bash` tool call *before* it runs and **hard-exits
nonzero** unless the first invoked binary's basename is on
`scripts/forensic-allowlist.txt` — the single source of truth listing exactly
the forensic binaries the typed wrappers shell out to (`vol`, `log2timeline.py`,
the EZ tools, `hayabusa`, Sleuth Kit `fls`/`icat`/`mmls`, `tshark`/`zeek`/…).

It **fails closed**: a malformed payload, an empty command, a shell-chaining
metacharacter (`;` `|` `&` `` ` `` `$(`), or an off-list binary all deny with a
clear `[deny-hook] BLOCKED:` message on stderr (exit code 2, the Claude Code
hard-block convention). Non-`Bash` tool calls (Read/Edit/…) are out of scope and
pass through untouched.

### Enable it (defaults OFF)

Add a `PreToolUse` matcher for the `Bash` tool to your **project-local**
`.claude/settings.json` (or `~/.claude/settings.json`). Until you add this, the
hook never runs:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/scripts/pretooluse-deny-hook.sh\""
          }
        ]
      }
    ]
  }
}
```

To point at a custom allow-list, export
`VERDICT_DENY_HOOK_ALLOWLIST=/path/to/list.txt` before launching Claude Code.

### Widening the allow-list

The allow-list is intentionally minimal: it is exactly the binaries the typed
wrappers already invoke. Adding a line is a **reviewed, deliberate** widening of
the permitted OS surface — treat it like any other security change (PR + review),
and keep it in sync with `services/mcp/src/tools/*` when a new typed wrapper
shells out to a new binary.

### Verify it

```bash
python3 scripts/pretooluse-deny-hook-smoke.py   # 14 deterministic allow/deny cases
bash -n scripts/pretooluse-deny-hook.sh         # syntax check
```

The smoke is also wired into `scripts/run-all-smokes.sh`.

---

## Part 2 — Rootless-podman sandbox (opt-in)

For operators who want the whole analysis process contained at the OS level, run
VERDICT inside a **rootless** container with a **read-only evidence mount** and a
**seccomp** profile. This is guidance, not a mandatory dependency — the default
`scripts/verdict` path runs natively.

The repo already ships container assets under `docker/` (the L1 dev-base and
L2 SIFT-lite images). The snippet below is a *launcher* posture, not a new image:
it mounts the read-only evidence and runs as a non-root user with dropped caps.

```bash
# Rootless podman: read-only evidence mount + dropped caps + seccomp + no-new-privs.
# Evidence is mounted :ro,z so the container physically cannot write the originals.
podman run --rm -it \
  --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  --security-opt no-new-privileges \
  --security-opt seccomp=docker/seccomp-forensic.json \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev \
  -v /evidence:/evidence:ro,z \
  -v "$PWD":/workspace:rw,z \
  -w /workspace \
  findevil/l2-siftlite:local \
  bash scripts/verdict /evidence/<image>
```

Notes:

- **Rootless** (`--userns=keep-id`, non-root `--user`) means a container escape
  lands as your unprivileged host user, not root.
- **`--read-only` + `:ro` evidence mount** enforces the read-only-evidence
  invariant at the kernel mount layer, complementing the code-level read-only
  open. Writable scratch is confined to a `tmpfs /tmp`.
- **`--cap-drop=ALL` + `no-new-privileges`** removes ambient capabilities and
  blocks setuid escalation.
- **seccomp** restricts the syscall surface. Start from Docker/podman's default
  profile and tighten; provide your own at `docker/seccomp-forensic.json`. A
  seccomp profile that is too tight will break a forensic tool, so validate on a
  known-good image before relying on it.
- **Disk-image mounting caveat:** `disk_mount` / `disk_extract_artifacts` use
  `sudo -n mount`/`ewfmount`, which need mount capabilities a fully cap-dropped
  rootless container does not have. For disk-image cases prefer the SIFT VM
  (`scripts/verdict --sift`) — the recommended full-parity path — and reserve
  this rootless posture for memory / EVTX / PCAP / extracted-artifact cases.

This sandbox and the deny-hook are independent: you can enable either, both, or
neither. Neither is required for a valid, custody-complete run.
