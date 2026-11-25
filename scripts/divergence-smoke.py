#!/usr/bin/env python3
"""divergence-smoke - assert CLAUDE.md "Spec/code divergences" stay
downstream-clean.

CLAUDE.md documents 8 spec/code divergence sections; 6 currently
have executable wrong-pattern checks. The previous 11 iterations of
doc-vs-code audits caught 25 stale references where the "wrong" half
of a divergence had survived in active files.
Three iterations of the divergence-sweep procedure (commits
782f364, e6ddc2d, fb319dd) cleaned the active surface area; this
smoke locks the cleanup so a future contributor can't silently
re-introduce one of the bad shapes.

For each divergence with an executable wrong-pattern, this smoke
scans active files for that pattern and FAILs if it appears
outside an allow-list. The allow-list is intentionally narrow:
historical specs/plans + CHANGELOG entries describing the
historical bug + the deliberately-commented marker line.

Wall-clock: ~30ms. Wired into docker/l1-compose.yml after
launcher-smoke as the 7th L1 smoke.

The divergences (matching CLAUDE.md "Spec/code divergences"):

  §1  Rust 1.83 -> 1.88                bad: rust:1.83-bookworm
  §2  Cargo.lock committed             declarative; nothing to scan
  §3  findevil_agent.cli dropped (A2)  bad: python -m findevil_agent.cli
  §4  Rust MCP tool count is 31        bad: stale 11/12/20 Rust or 32-tool count
  §5  rmcp not a runtime dep           bad: live `rmcp = "=...` (uncommented)
  §7  A3 MemoryStore phrase-quote      doc-only; no shipped wrong-pattern
  §8  A3 audit push: SSE not WebSocket bad: "ws": "..." dep in apps/web pkg
"""

from __future__ import annotations

import re
import sys
from os import walk
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Files/dirs intentionally excluded from active-drift scans.
# Order matters - more-specific exclusions first.
EXCLUDED_PATH_PARTS = (
    # Vendored research clones - .gitignore'd, never ship.
    "openclaw",
    "hermes-agent",
    "Linear-Coding-Agent-Harness",
    ".playwright-mcp",
    # Expanded research-library directory added 2026-04-26 holding
    # 7+ upstream clones (claude-agent-sdk-{python,typescript},
    # openclaw, hermes-agent, hermes-agent-self-evolution,
    # pixel-agents, awesome-openclaw-skills, plus DFIR awesome-lists
    # like LOLBAS / ThreatHunter-Playbook / awesome-forensics).
    # All .gitignore'd at /git-hub-references/ per Amendment A3 §1.3
    # but git rglob still walks the dir; scanning these picks up
    # legitimate-but-unrelated patterns from upstream code (e.g.
    # Archon ships the `ws` npm dep, which trips divergence #8).
    "git-hub-references",
    # n8n automation reference clones - .gitignore'd, never ship.
    "n8n-references",
    # Build / venv / cache.
    "target",
    "node_modules",
    ".venv",
    "__pycache__",
    ".git",
    # Claude Code subagent worktrees created under the project-local
    # .claude directory. These are ignored runtime checkouts, not part
    # of the active publication tree, and can legitimately contain
    # stale text from the branch they were created from.
    "worktrees",
    # Sibling worktrees from `git worktree add .worktrees/<name>` —
    # checked-out copies of feature branches living under the repo
    # root. .gitignore'd at /.worktrees/ but git rglob still finds
    # them; scanning them causes false drift hits when a feature
    # branch's CHANGELOG / docs naturally quote the historical bad
    # pattern (the master tree's CHANGELOG already has these allow-
    # listed via ALLOWED_FILES below).
    ".worktrees",
    # Generated artifacts (PDFs, HTML have embedded assets that
    # can grep-match the wrong-pattern coincidentally).
    "graphify-out",
    "site",
    "tmp",
    "site",
    # Pre-Phase-2 (2026-05-02), the historical specs + plans lived
    # at docs/superpowers/{specs,plans}/ and were excluded via the
    # generic "superpowers" path-component match. Phase 2 moved them
    # to docs/{specs,plans}/, where the path-component name "specs"
    # or "plans" is too generic to exclude wholesale (would risk
    # masking unrelated future dirs of the same name). The historical
    # spec + plan files are now listed individually in ALLOWED_FILES.
)

# Files specifically allow-listed even though they live in an
# otherwise-active path. Keys are repo-relative POSIX paths.
ALLOWED_FILES = {
    # CHANGELOG.md describes historical bugs; matches there are
    # archival, not active drift.
    "CHANGELOG.md",
    # CLAUDE.md is the source-of-truth that DOCUMENTS each
    # divergence and necessarily quotes the bad form. Scanning
    # it for those exact strings would be circular.
    "CLAUDE.md",
    # The smoke itself necessarily contains the bad patterns in
    # its docstring + DIVERGENCES table to know what to check for.
    "scripts/divergence-smoke.py",
    # The launcher-smoke also contains the `claude-code` bad
    # pattern in its own check logic.
    "scripts/launcher-smoke.py",
    # smoke-regex-tests carries synthetic positive + negative
    # test fixtures for every smoke's regex; those fixtures
    # legitimately contain the bad-half patterns to verify the
    # regexes catch them.
    "scripts/smoke-regex-tests.py",
    "Find_Evil_Research_and_Build_Plan.docx",
    # The autonomous-queue file describes the audit history.
    "memory/project_autonomous_queue.md",
    # Decision-helper runbooks deliberately quote both halves
    # of a divergence to lay out tradeoffs side by side.
    "docs/runbooks/dockerfile-a2-decision.md",
}


# Divergence patterns. Each entry:
#   id, label - human-readable
#   regex     - compiled, applied to file text
#   allowed_in_path - repo-relative paths or path-prefixes where the
#                     pattern is deliberately legal (e.g. the
#                     commented-marker line in services/mcp/Cargo.toml
#                     for divergence #5).
#   remediation - what to do if the pattern resurfaces.
DIVERGENCES = [
    {
        "id": "#1",
        "label": "Rust 1.83 -> 1.88 (Dockerfile + plan files use 1.88)",
        "regex": re.compile(r"\brust:1\.83-(?:bookworm|bullseye|slim)\b"),
        "allowed_in_path": (),
        "remediation": (
            "rust-toolchain.toml channel=1.88.0 is authoritative; "
            "Cargo.toml requires rust-version=1.88. Do not pin a "
            "Docker base older than that. See CLAUDE.md "
            "'Spec/code divergences' §1."
        ),
    },
    {
        "id": "#3",
        "label": "findevil_agent.cli was dropped per Amendment A2",
        # `find-evil run/verify/serve` and `python -m
        # findevil_agent.cli` are the bad shapes. Negative lookbehind
        # on backtick excludes prose that QUOTES the bad form (e.g.
        # comments documenting why we replaced it). Active code
        # rarely backticks the executable line; documentation
        # comments often do.
        "regex": re.compile(
            r"(?<!`)(?:python3?\s+-m\s+findevil_agent\.cli|"
            r"\bfind-evil\s+(?:run|verify|serve)\b)"
        ),
        # 2026-04-27: the Dockerfile wrapper + scripts/build-deb.sh
        # were both cut per docs/runbooks/dockerfile-a2-decision.md
        # "Option B" (PR #4). The allow-list is empty now — any future
        # re-introduction of the bad pattern in active code is a
        # genuine regression and should fail this smoke loudly.
        "allowed_in_path": (),
        "remediation": (
            "A2 dropped findevil_agent/cli.py and the L0 "
            "amendment-a2-guard fails CI on its return. Use "
            "scripts/find-evil (interactive) or "
            "bash scripts/find-evil-auto <evidence> (headless). "
            "See CLAUDE.md 'Spec/code divergences' §3."
        ),
    },
    {
        "id": "#4",
        "label": "Rust MCP tool count is 32 (long-tail typed wrappers included)",
        "regex": re.compile(
            r"(?:1[12]\s+typed\s+Rust|"
            r"1[12]\s+DFIR\s+tools|"
            r"1[23]\s+typed\s+Rust\s+MCP\s+tools|"
            r"1[239]-tool\s+(?:dispatch|catalog|surface)|"
            r"20\s+(?:typed\s+)?(?:Rust|DFIR)(?:\s+(?:DFIR\s+)?tools|\s+primitives)?|"
            r"20-tool\s+(?:dispatch|catalog|surface)|"
            r"20/20\s+shipped|"
            r"twenty\s+real\s+forensic\s+tools\s+in\s+Rust|"
            r"\b31\s+(?:narrow,\s+schema-validated\s+|typed,\s+read-only\s+|typed\s+read-only\s+)?Rust(?:\s+DFIR)?\s+tools\b|"
            r"\b31-tool\s+surface\b|"
            r"\b31-tool\s+(?:typed\s+)?product\b|"
            r"\b31-tool\s+count\b|"
            r"all\s+1[12]\s+Rust|"
            r"findevil-mcp.*?\(1[12]\s+(?:typed|DFIR|tools))"
        ),
        "allowed_in_path": (),
        "remediation": (
            "The current product surface is 45 tools: 32 Rust DFIR "
            "tools plus 13 Python crypto/ACH/memory/ACP/expert tools. "
            "See CLAUDE.md 'Spec/code divergences' §4."
        ),
    },
    {
        "id": "#5",
        "label": "rmcp is intentionally NOT a runtime dep",
        # Match an UNCOMMENTED `rmcp = "=...` line at start of line.
        # The deliberate marker in services/mcp/Cargo.toml has a
        # leading `#` so this regex won't fire on it.
        "regex": re.compile(r"^\s*rmcp\s*=\s*[\"{]", re.MULTILINE),
        "allowed_in_path": (),
        "remediation": (
            "services/mcp ships a hand-rolled stdio JSON-RPC 2.0 "
            "server in src/server.rs. Do NOT activate rmcp without "
            "a spec amendment - the architectural choice is "
            "wire-format stability across rmcp's API churn. The "
            "commented marker line in services/mcp/Cargo.toml is "
            "deliberate. See CLAUDE.md 'Spec/code divergences' §5."
        ),
    },
    {
        "id": "#8",
        "label": "A3 audit-log push uses SSE, not WebSocket",
        # Match a `"ws"` dep in any active package.json — the most
        # likely re-introduction shape if a future executor follows
        # A3 plan §4.2's stale "WebSocket upgrade" instruction. The
        # `ws` npm package is the de-facto WebSocket-server lib for
        # Node; adding it back to apps/web/package.json is the canary.
        # `\b"ws"\s*:\s*"` matches the JSON dep line; the leading \b
        # ensures we don't match `"aws"` / `"news"` / `"awscli"` etc.
        "regex": re.compile(r'(?<![A-Za-z0-9_-])"ws"\s*:\s*"'),
        "allowed_in_path": (),
        "remediation": (
            "PR #7 (sha 281d26f) shipped Server-Sent Events instead "
            "of WebSocket: data flow is strictly server->client, SSE "
            "is App-Router-native (no custom server.ts), all target "
            "browsers support SSE. Live handler is "
            "apps/web/app/api/audit/route.ts (text/event-stream + "
            "15s :keepalive); iterator is apps/web/lib/audit-tail.ts. "
            "Do not add the 'ws' npm dep without a spec amendment "
            "naming a concrete client->server message. See CLAUDE.md "
            "'Spec/code divergences' SSE-not-WebSocket entry."
        ),
    },
    {
        "id": "#9",
        "label": "Product forks Pool A/B via native Task, not CLAUDE_CODE_FORK_SUBAGENT",
        "regex": re.compile(r"CLAUDE_CODE_FORK_SUBAGENT"),
        "allowed_in_path": (
            # The divergence check itself must name the pattern.
            "scripts/divergence-smoke.py",
            # Docs that EXPLAIN the divergence necessarily quote the env var.
            "agent-config/PLAYBOOK.md",
            "agent-config/AGENTS.md",
            "docs/architecture.md",
            "CLAUDE.md",
        ),
        "remediation": (
            "CLAUDE_CODE_FORK_SUBAGENT=1 is a build-time internal and "
            "is not used in the product. In the product (what judges "
            "run), Claude Code forks Pool A/B via its native Task "
            "mechanism — no env var is set. Docs that claim the product "
            "uses this env var mislead judges. Use 'native Task "
            "mechanism' instead."
        ),
    },
]


def _ascii_safe(s: str) -> str:
    """Return s with non-ASCII chars escaped so cp1252 consoles + CI
    log capture don't UnicodeEncodeError. Section signs / em-dashes
    /arrows in CLAUDE.md prose used to crash the smoke."""
    return s.encode("ascii", "backslashreplace").decode("ascii")


def _is_excluded(path: Path) -> bool:
    """True if path should not be scanned (vendored / generated / cache)."""
    rel_parts = path.relative_to(REPO).parts
    if any(part in EXCLUDED_PATH_PARTS for part in rel_parts):
        return True
    rel_posix = path.relative_to(REPO).as_posix()
    if rel_posix in ALLOWED_FILES:
        return True
    return False


def _list_active_files() -> list[Path]:
    """All text files we should scan (markdown + Python + Rust + sh + toml + yml)."""
    suffixes = {".bash", ".json", ".md", ".py", ".rs", ".sh", ".toml", ".yaml", ".yml"}
    out: list[Path] = []
    for root, dirs, files in walk(REPO):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in EXCLUDED_PATH_PARTS]
        for filename in files:
            p = root_path / filename
            if p.suffix not in suffixes or _is_excluded(p):
                continue
            out.append(p)
    # Also include the extension-less launchers.
    for name in ("find-evil", "find-evil-auto", "find-evil-sift"):
        p = REPO / "scripts" / name
        if p.exists():
            out.append(p)
    return sorted(set(out))


def _path_is_allowed(rel_posix: str, allowed: tuple[str, ...]) -> bool:
    """True if rel_posix matches any entry in allowed (exact or prefix)."""
    return any(rel_posix == a or rel_posix.startswith(a + "/") for a in allowed)


_MCP_JSON_FORBIDDEN_TOKENS = (
    "protocol-sift",
    "sift-gateway",
    "execute_shell",
    "bash -c",
    "fetch",
    "browser",
)
_MCP_JSON_REQUIRED_SERVERS = frozenset({"findevil-mcp", "findevil-agent-mcp"})
# Non-product servers .mcp.json may also register (CLAUDE.md §3/§4): they never
# touch evidence, never emit Findings, and are not in the audit chain. Six
# servers total = 2 product + these 4. The forbidden-token (gateway/shell)
# check below applies only to the product servers, since the narrow audit-chain
# surface is the invariant — these are explicitly browser/automation/memory tools.
_MCP_JSON_ALLOWED_NONPRODUCT_SERVERS = frozenset(
    {"n8n-mcp", "playwright", "puppeteer", "qmd"}
)
_MCP_DOC_FORBIDDEN_PHRASES = (
    (Path("CLAUDE.md"), "Two MCP servers registered in `.mcp.json`"),
    (
        Path("AGENTS.md"),
        ".mcp.json` is the canonical local MCP config: `findevil-mcp` via `cargo run",
    ),
)
_MCP_DOC_FORBIDDEN_REGEXES = (
    re.compile(r"Find Evil ships two MCP servers in `\.mcp\.json`", re.IGNORECASE),
    re.compile(
        r"`?\.mcp\.json`?[^.\n]{0,90}\b(?:registers|ships|contains|has)\b"
        r"[^.\n]{0,90}\btwo\s+(?:typed\s+)?MCP servers\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"This mirrors `\.mcp\.json` and does not require tokens\.",
        re.IGNORECASE,
    ),
)
_MCP_DOC_SCAN_EXCLUDED_PREFIXES: tuple[str, ...] = ()


def _check_mcp_json_surface() -> list[str]:
    """Assert .mcp.json keeps the two typed product servers (plus only the
    documented non-product servers) and no gateway/shell drift on the product
    surface."""
    import json

    mcp_path = REPO / ".mcp.json"
    if not mcp_path.exists():
        return [".mcp.json not found — required for Find Evil! agent session"]

    try:
        data = json.loads(mcp_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f".mcp.json is not valid JSON: {exc}"]

    servers = data.get("mcpServers", {})
    server_names = frozenset(servers.keys())
    issues = []

    extra = (
        server_names - _MCP_JSON_REQUIRED_SERVERS - _MCP_JSON_ALLOWED_NONPRODUCT_SERVERS
    )
    if extra:
        issues.append(
            f".mcp.json has unexpected server(s): {sorted(extra)} — only the two "
            "product servers (findevil-mcp, findevil-agent-mcp) and the documented "
            f"non-product servers {sorted(_MCP_JSON_ALLOWED_NONPRODUCT_SERVERS)} "
            "are permitted"
        )
    missing = _MCP_JSON_REQUIRED_SERVERS - server_names
    if missing:
        issues.append(f".mcp.json is missing required server(s): {sorted(missing)}")

    # Gateway/shell pass-through is forbidden on the product (audit-chain)
    # surface. The non-product servers are by-design browser/automation tools
    # and are not in the audit chain, so they are exempt from this scan.
    for name, server in servers.items():
        if name not in _MCP_JSON_REQUIRED_SERVERS:
            continue
        args = server.get("args", [])
        cmd = server.get("command", "")
        combined = " ".join([cmd] + args).lower()
        for token in _MCP_JSON_FORBIDDEN_TOKENS:
            if token in combined:
                issues.append(
                    f".mcp.json server '{name}' contains forbidden token '{token}' "
                    f"in command/args — gateway/shell pass-through is not permitted"
                )
    return issues


def _check_mcp_json_doc_wording(files: list[Path]) -> list[str]:
    issues = []
    for rel_path, phrase in _MCP_DOC_FORBIDDEN_PHRASES:
        path = REPO / rel_path
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        if phrase in text:
            issues.append(
                f"{rel_path.as_posix()} still uses stale .mcp.json wording: {phrase!r}"
            )
    for path in files:
        rel = path.relative_to(REPO).as_posix()
        if rel in ALLOWED_FILES:
            continue
        if _path_is_allowed(rel, ()):
            continue
        if any(rel.startswith(prefix) for prefix in _MCP_DOC_SCAN_EXCLUDED_PREFIXES):
            continue
        if path.suffix.lower() not in {".md", ".txt", ".py", ".yml", ".yaml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for regex in _MCP_DOC_FORBIDDEN_REGEXES:
            for match in regex.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                line = text.splitlines()[line_no - 1].strip()
                issues.append(
                    f"{rel}:{line_no} implies .mcp.json has only two servers: {line!r}"
                )
    return issues


def main() -> int:
    print("=" * 60)
    print("Find Evil! - divergence-smoke")
    print("=" * 60)

    files = _list_active_files()
    print(
        f"scanning {len(files)} active text files for stale "
        f"references to {len(DIVERGENCES)} documented divergences..."
    )
    print()

    failed = 0
    total_checks = 0
    for div in DIVERGENCES:
        total_checks += 1
        hits = []
        for p in files:
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for m in div["regex"].finditer(text):
                rel = p.relative_to(REPO).as_posix()
                if _path_is_allowed(rel, div["allowed_in_path"]):
                    continue
                line_no = text[: m.start()].count("\n") + 1
                line = text.splitlines()[line_no - 1].strip()
                hits.append((rel, line_no, line))

        if hits:
            # Output must survive cp1252 consoles (Windows cmd.exe
            # without VT processing) and CI log capture. Repr
            # already escapes most chars; the line preview can
            # carry ASCII-incompatible chars from the source file
            # so we further force ASCII via backslashreplace.
            print(_ascii_safe(f"[FAIL] {div['id']}  {div['label']}"))
            for rel, line_no, line in hits:
                preview = _ascii_safe(line)
                print(f"         {rel}:{line_no}: {preview}")
            print(_ascii_safe(f"         remediation: {div['remediation']}"))
            print()
            failed += 1
        else:
            print(_ascii_safe(f"[OK  ] {div['id']}  {div['label']}"))

    # Structural check: .mcp.json surface lock
    total_checks += 1
    mcp_issues = _check_mcp_json_surface()
    if mcp_issues:
        print(
            "[FAIL] #10  .mcp.json locks product servers plus documented non-product servers"
        )
        for issue in mcp_issues:
            print(f"         {issue}")
        print(
            "         remediation: .mcp.json must contain findevil-mcp, "
            "findevil-agent-mcp, and only the documented non-product servers; product "
            "server command/args must not contain protocol-sift, sift-gateway, "
            "execute_shell, bash -c, fetch, or browser tokens."
        )
        failed += 1
    else:
        print(
            "[OK  ] #10  .mcp.json locks product servers plus documented non-product servers"
        )

    # Documentation check: active guidance must not imply .mcp.json has only
    # the two product servers. That stale wording obscures the product vs.
    # non-product boundary and causes avoidable judge-review confusion.
    total_checks += 1
    mcp_doc_issues = _check_mcp_json_doc_wording(files)
    if mcp_doc_issues:
        print(
            "[FAIL] #11  active docs distinguish registered servers from product tools"
        )
        for issue in mcp_doc_issues:
            print(f"         {issue}")
        print(
            "         remediation: active guidance must say .mcp.json has 6 registered "
            "servers total, with only findevil-mcp and findevil-agent-mcp in the "
            "audit-chained product surface."
        )
        failed += 1
    else:
        print(
            "[OK  ] #11  active docs distinguish registered servers from product tools"
        )

    print()
    print("=" * 60)
    if failed:
        print(f"FAIL - {failed} of {total_checks} divergences have active drift.")
        return 1
    print(f"OK - all {total_checks} active divergences are downstream-clean.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
