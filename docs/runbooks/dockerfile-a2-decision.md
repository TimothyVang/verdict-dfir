# Dockerfile A2 wrapper — decision helper

**Status: DECISION TAKEN — Option B, 2026-04-27 (PR #4).** The
`find-evil` in-container wrapper was cut from `Dockerfile`,
`scripts/build-deb.sh` was deleted entirely, and the `build-deb`
job was removed from `.github/workflows/release.yml`. The L0
`amendment-a2-guard` GHA job + L1 `divergence-smoke.py` §3 remain
in place to fail CI if `findevil_agent.cli` resurfaces. CLAUDE.md
"Spec/code divergences" §3 is updated to reflect the resolved
state. The body below is preserved as the decision record — useful
for future re-evaluations if A2 is ever revisited.

---

**Original status (open hard blocker as of 2026-04-26):** Documented in
`CHANGELOG.md`
"Hard blockers discovered" (commit `47f67b0`).  This file lays
out the two paths so the decision-maker has both options side
by side without having to reverse-engineer them from the
divergence flag.

---

## Background

`Dockerfile` lines 80–84 produce an in-container `find-evil`
shell wrapper that invokes the Python CLI:

```bash
RUN cat <<'SH' > /usr/local/bin/find-evil && chmod +x /usr/local/bin/find-evil
#!/usr/bin/env bash
set -euo pipefail
exec python3 -m findevil_agent.cli "$@"
SH
```

`scripts/build-deb.sh:50–58 + 96` inlines the same wrapper into
the `.deb` package's `/usr/bin/find-evil` and tells the user (in
the postinst) to run `find-evil run --case <path.e01>`.

But Amendment A2 dropped `services/agent/findevil_agent/cli.py`.
The L0 `amendment-a2-guard` GHA job fails CI if that module
reappears.  So:

* `docker build` succeeds (the wrapper is just a shell file).
* `docker run ... find-evil <args>` errors at first invocation
  with `No module named findevil_agent.cli`.
* The `.deb` installs cleanly but `find-evil` from the user's
  PATH likewise errors out the first time it's called.

The contract the user sees and the contract the code provides
have been silently disagreeing since A2 landed.  Two options
to reconcile.

---

## Option A — rewrite the wrapper to invoke `find-evil-auto`

`find-evil-auto` is the surviving A2 entry point: a Python
orchestrator (`scripts/find_evil_auto.py`) wrapped by a Bash
shim (`scripts/find-evil-auto`) that runs case_open → tool
sequence → ACH stack → manifest_finalize → render_report
end-to-end against a SIFT VM accessed over SSH.

**Diff sketch (Dockerfile):**

```diff
 RUN cat <<'SH' > /usr/local/bin/find-evil && chmod +x /usr/local/bin/find-evil
 #!/usr/bin/env bash
 set -euo pipefail
-exec python3 -m findevil_agent.cli "$@"
+# A2: there is no findevil_agent.cli; route to the headless
+# orchestrator instead.  Requires SIFT VM accessible over SSH;
+# preflight check inside find_evil_auto.py validates that.
+exec python3 /usr/share/find-evil/find_evil_auto.py "$@"
 SH
```

(The `.py` orchestrator + its dependencies would need to be
COPY'd into `/usr/share/find-evil/` in stage 3 and pip-installed
into `python3 -m`.)

**Pros:**
* `.deb` continues to be a meaningful artifact: install it, get
  a working `find-evil <evidence>` command on PATH.
* `find-evil run --case X.e01` from the postinst maps onto a
  real workflow.

**Cons:**
* Two entry points compete for "the way to run Find Evil!" —
  `claude` (interactive, repo-cloned) and the `.deb`'s
  `find-evil` (headless, dpkg-installed).  Devpost README has
  to either explain both or pick one.
* `find_evil_auto.py` assumes a SIFT VM accessible over SSH at
  a specific IP.  Inside a `docker run` invocation that doesn't
  hold; the wrapper would fail unless the container has SSH
  access to the host's VM.  Lots of scaffolding for an unusual
  deployment shape.
* The `.deb` is then a different experience from
  `scripts/find-evil` (interactive Claude Code).  Two product
  surfaces increases support load.

---

## Option B — cut the `find-evil` wrapper + `.deb` entirely

A2's "Claude Code IS the orchestrator" framing means the
canonical user contract is `claude` + this repo, not
`find-evil` from a system path.  The `.deb` was a pre-A2
artifact built when the orchestrator was a Python CLI we
distributed.  Under A2, the .deb has no runtime — the
orchestrator binary doesn't exist.

**Diff sketch (Dockerfile):**

```diff
-# CLI wrapper mirrors what the .deb postinst sets up.
-RUN cat <<'SH' > /usr/local/bin/find-evil && chmod +x /usr/local/bin/find-evil
-#!/usr/bin/env bash
-set -euo pipefail
-exec python3 -m findevil_agent.cli "$@"
-SH
-
-CMD ["find-evil", "--help"]
+# A2: no in-container CLI.  This image ships the Rust MCP
+# binary + Python wheel as build artifacts; the canonical
+# user contract is `claude` invoked from a repo clone with
+# .mcp.json present.  The image is useful for reproducing
+# CI build state, not as a turnkey runtime.
+CMD ["bash"]
```

**Diff sketch (release.yml):** drop the `build-deb` job
entirely; the workflow stops producing a `.deb` artifact.
`scripts/build-deb.sh` either gets deleted or kept as
deprecated-with-comment.

**Pros:**
* One product surface, exactly as A2 intended.
* No "find-evil run" instruction in the `.deb` postinst that
  could mislead a judge.
* Matches the autonomous-queue's repeated finding that the
  in-container CLI has no runtime under A2.

**Cons:**
* The Devpost submission loses a tangible "downloadable artifact"
  bullet.  The repo + `claude` install is the only delivery
  mechanism.  (Mitigation: the v-submit Devpost zip continues
  to ship via `scripts/package-devpost.sh`; that's the actual
  judging artifact, not the .deb.)
* Existing CI infra (`build-deb` GHA job, `dist/*.deb`
  signing) becomes dead code; needs removal.

---

## Recommendation framing

Option B is more A2-idiomatic — A2's central claim is "Claude
Code IS the orchestrator," and a `find-evil` system binary
contradicts that.  Option A keeps the `.deb` working but at
the cost of two competing product surfaces.

The decision is the user's.  Concrete next step either way:

* **If A:** the wrapper + scripts/build-deb.sh +
  release.yml.build-deb job all need updating.  Estimated
  ~30 lines of change across 3 files.
* **If B:** the wrapper (3 places) + scripts/build-deb.sh
  (whole file) + release.yml.build-deb job all need
  removal.  Estimated ~150 lines of deletion across 3 files.
  Then update `CHANGELOG.md` to drop the hard-blocker note.

After the decision lands, the `divergence-smoke` allow-list
for §3 (`Dockerfile`, `scripts/build-deb.sh`) can be removed
in the same commit — those exemptions exist solely because
the broken state is currently flagged as a hard blocker.
