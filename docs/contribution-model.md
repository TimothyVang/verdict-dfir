# Contribution Model

How VERDICT is developed in the open: the branch model, how changes are gated **without depending on
GitHub Actions runners**, and how releases are cut. It is deliberately portable — nothing here assumes
a particular machine, account, or clone path. Use your own fork and the standard `origin` remote.

For the build/test commands themselves, see [CONTRIBUTING.md](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/CONTRIBUTING.md).
For where to plug in, see [Help Wanted](help-wanted.md).

## Branches

| Branch | Role |
|--------|------|
| `main` | The published, release-quality line — what users install. Treat it as read-only; you do not PR into it directly. |
| `develop` | The contribution line. All pull requests target `develop`. It is never overwritten by a publish. |

A maintainer may keep additional private staging outside this repo; that is invisible to contributors
and never required to contribute. Everything you need is `main` (to read) and `develop` (to change).

## How to contribute

1. **Fork** this repo and clone your fork.
2. **Branch off `develop`:** `git switch develop && git switch -c fix/<short-topic>`.
3. Make a **surgical** change (see the invariants in CONTRIBUTING). Keep files in their
   place — the repo root is config + public docs only; everything else lives in a named
   directory (see [repo-layout.md](repo-layout.md), enforced by `scripts/repo-layout-smoke.py`).
4. **Run the gates locally** (next section). Open the PR only when they are green.
5. **Open a pull request against `develop`** with a clear summary and a test plan.

## The gate — local checks, not cloud CI

VERDICT does **not** rely on hosted CI runners to decide whether a change is acceptable. The gate is
the same set of commands a maintainer runs on your branch before approving:

```bash
bash scripts/run-all-smokes.sh          # the project smokes (counts are printed, never hard-coded)

cargo test --workspace --locked         # Rust MCP server
uv run --directory services/agent_mcp pytest
uv run --directory services/agent pytest
ruff check . && ruff format --check .
pnpm --filter @findevil/web test        # dashboard (when touched)
```

Why local instead of Actions:

- **Free and portable.** It runs on any contributor's machine and on an air-gapped maintainer box
  with no runner minutes and no third-party dependency.
- **Honest signal.** "Green locally" is the bar; there is no separate cloud configuration that can
  drift from what you actually ran.

A repository may still keep optional GitHub Actions workflows for convenience signal, but they are not
the authority — review backed by a locally-run gate is.

## Approval and auto-merge

Branch protection on `develop` requires:

- **Two approving reviews, including a maintainer / code owner** (see [`.github/CODEOWNERS`](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/.github/CODEOWNERS)).
  Requiring a code owner means at least one reviewer who has actually run the gate on your branch —
  this is what stands in for an automated status check.
- A branch up to date with `develop`.

When those are satisfied, enable **GitHub's native auto-merge** on the PR and it merges itself — no
bot, no custom automation. That is the "two approvals and it merges" flow.

## Releases

Releases are a maintainer decision, never triggered by an approval count (vote counts measure "this
looks correct," not "cut a release now," and are gameable in open source). The maintainer:

1. Integrates `develop` and re-validates the gate.
2. Publishes with **`git ship`** — a platform-agnostic push + release helper that uses plain `git`
   plus the host CLI (`gh` / `glab`) or the REST API as a fallback. It pushes the branch and tag and
   creates the release object. No paid CI runner is involved.

```bash
git ship --tag vX.Y.Z            # push current branch + cut the vX.Y.Z release
git ship --dry-run --tag vX.Y.Z  # print every command, change nothing
```

`git ship` ships releases; it does **not** run your tests. The test gate is the local checks above;
`git ship` is only the push-and-publish leg.
