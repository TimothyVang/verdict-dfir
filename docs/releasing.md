# Releasing

Releases are cut with **`git-ship`** (vendored at `scripts/git-ship`) — a free,
platform-agnostic push + release tool. The same command works on GitHub and GitLab;
it auto-detects the host from the `origin` (or chosen) remote.

## Easy release — free, runs locally, no CI minutes

When you are ready to release:

```bash
git tag v1.2.0
bash scripts/git-ship --tag v1.2.0
```

That pushes the tag and creates the release on whatever host the remote points at
(GitHub Release via `gh`/REST API, GitLab Release via `glab`/REST API). It uses **no
CI runner, so it costs nothing — even on a private repo.** This is the recommended
path while GitHub Actions is disabled on the private dev repo.

Release to a **separate release repo** by pointing a remote at it:

```bash
git remote add release <url-of-release-repo>      # one time
bash scripts/git-ship --remote release --tag v1.2.0
```

Preview without changing anything:

```bash
bash scripts/git-ship --dry-run --tag v1.2.0
```

## Automatic release on tag — CI/CD

Two ready pipelines cut the release automatically when a `v*` tag is pushed. Both run
the identical `bash scripts/git-ship --tag <tag>` call:

| File | Platform | How to activate |
|------|----------|-----------------|
| `.github/workflows/release-on-tag.yml` | GitHub Actions | runs on tag push once Actions is enabled |
| `ci/gitlab-release-on-tag.yml` | GitLab CI/CD | copy to `.gitlab-ci.yml` (or `include:` it) |

### Cost note (important)

GitHub Actions is currently **disabled on the private dev repo** to avoid billed
minutes, so `.github/workflows/release-on-tag.yml` **will not run here** until Actions
is re-enabled — and on a *private* repo, re-enabling reintroduces per-minute cost.

- **Private dev repo:** keep Actions off; release with the free local `git ship --tag`
  path above.
- **Public release repo:** standard-runner minutes are free, so the tag-triggered
  pipeline is free there. That is its intended home.

Re-enable Actions only if you want tag-triggered CI on the dev repo and accept the
private-repo minute cost:

```bash
gh api -X PUT repos/<owner>/<repo>/actions/permissions -F enabled=true
```
