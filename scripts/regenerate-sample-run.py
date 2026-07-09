#!/usr/bin/env python3
"""scripts/regenerate-sample-run.py - refresh a committed sample run, /home-free.

Refresh a committed ``docs/sample-run/<case>`` from a fresh run directory
(``tmp/auto-runs/<case-id>``) so regenerating a stale sample run is one
hygiene-clean command:

    scripts/regenerate-sample-run.py --from tmp/auto-runs/<case-id> \
        --into docs/sample-run/<name> [--dry-run]

It copies the canonical artifacts and relativizes machine-specific provenance
paths (``/home/<user>/...``, ``/Users/<user>/...`` and the run's own absolute
run-dir prefix) per the CLAUDE.md release-hygiene rule, WITHOUT mangling hashes,
enums, or timestamps - the scrub only matches the ``/home/<user>`` /
``/Users/<user>`` path class and the literal ``--from`` directory prefix, none of
which appear inside a SHA hex digest, an ISO-8601 ``...Z`` timestamp, or a short
enum token.

CUSTODY BOUNDARY (the load-bearing rule)
----------------------------------------
The audit chain and the signed manifest hash their *content*, so a path string
inside them is a HASHED field. Editing it would break ``manifest_verify`` replay:

* ``audit.jsonl`` - every line is JCS-canonicalized and hash-chained via
  ``prev_hash``; ``verify_manifest`` re-derives ``audit_log_final_hash`` and the
  Merkle leaves from the log. A single byte changes the chain and fails
  ``audit_chain_ok``/``overall``.
* ``run.manifest.json`` - the entire body (every field except ``signature``) is
  Ed25519-signed. ``ed25519`` is a non-advisory signer kind, so a body edit makes
  ``signature_verified`` fail and flips ``overall`` to false.
* ``verdict.json`` - its SHA-256 is bound into the signed manifest
  (``extra.packet_attestation.verdict_artifact_sha256``); editing it desyncs the
  file from the value the manifest attests.
* ``manifest_verify.json`` - the offline verification record itself; copied as-is.

Therefore this tool NEVER scrubs those four. It copies them byte-for-byte and, if
a machine path is still present, it WARNS (it does not silently corrupt custody).
A residual ``/home/<user>`` leak inside a custody-bound artifact means the SOURCE
run is stale and must be regenerated with the relativizing engine
(``scripts/find_evil_auto.py`` already relativizes ``verdict.json`` /
``run.manifest`` provenance at serialization time) - it is an engine fix, never a
packaging patch. Only the display artifacts (the rendered report and the
coverage/recall sidecars, which are not bound into the signed chain) are scrubbed.

Deterministic and stdlib-only so it runs under the same bare ``python3`` as the
host engine.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Artifact classification.
# ---------------------------------------------------------------------------

# The canonical sample-run artifacts, copied when present in the source run dir.
CANONICAL_ARTIFACTS: tuple[str, ...] = (
    "audit.jsonl",
    "verdict.json",
    "coverage_manifest.json",
    "run.manifest.json",
    "manifest_verify.json",
    "recall-score.json",
    "REPORT.md",
    "REPORT.html",
)

# Custody-bound artifacts: their bytes (or a SHA of them) are hashed into the
# audit chain or the signed manifest. NEVER scrub these - copy verbatim and warn
# on any residual machine path. See the module docstring for the why.
CUSTODY_BOUND: frozenset[str] = frozenset(
    {
        "audit.jsonl",
        "verdict.json",
        "run.manifest.json",
        "manifest_verify.json",
    }
)

# Everything else in CANONICAL_ARTIFACTS is a display artifact: scrubbable.

DEFAULT_HOME_PLACEHOLDER = "<HOME>"

# Matches the machine-specific prefix of a POSIX home path: ``/home/<user>`` or
# ``/Users/<user>``. The user segment stops at the next slash, whitespace, or
# quote, so only the identity-bearing prefix is replaced and the rest of the path
# is preserved. A SHA hex digest, an ISO-8601 timestamp, and a short enum token
# contain no ``/home/<user>`` substring, so none of them can match.
HOME_PREFIX_RE = re.compile(r"/(?:home|Users)/[^/\s\"'\\]+")


@dataclass(frozen=True)
class FilePlan:
    """The planned action for one canonical artifact."""

    name: str
    present: bool
    custody_bound: bool
    src: Path
    dst: Path
    payload: bytes
    """Exact bytes to write to ``dst``. For custody-bound files this is the
    verbatim source bytes; for display files it is the scrubbed bytes."""
    scrub_count: int
    """Replacements applied (always 0 for custody-bound)."""
    leak_count: int
    """Machine-path hits remaining in ``payload`` (a warning when > 0)."""
    binary_fallback: bool = False
    """A display artifact that did not decode as UTF-8 was copied verbatim."""

    @property
    def verbatim(self) -> bool:
        return self.custody_bound or self.binary_fallback


# ---------------------------------------------------------------------------
# Scrub primitives.
# ---------------------------------------------------------------------------


def count_machine_paths(data: bytes | str, *, run_dir_abs: str = "") -> int:
    """Count machine-path hits in DATA.

    Counts both supported leak classes: ``/home/<user>`` / ``/Users/<user>``
    prefixes and the exact absolute ``--from`` run-dir prefix.
    """
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    run_dir_hits = text.count(run_dir_abs) if run_dir_abs else 0
    return run_dir_hits + len(HOME_PREFIX_RE.findall(text))


def scrub_text(
    text: str,
    *,
    run_dir_abs: str = "",
    dest_rel: str = "",
    home_placeholder: str = DEFAULT_HOME_PLACEHOLDER,
) -> tuple[str, int]:
    """Relativize machine-specific paths in TEXT. Returns ``(scrubbed, count)``.

    Two passes, in order:

    1. Replace the literal absolute ``--from`` run-dir prefix (``run_dir_abs``)
       with the repo-relative destination (``dest_rel``), so the run's own
       case-id temp path becomes a stable repo-relative reference.
    2. Replace each ``/home/<user>`` / ``/Users/<user>`` prefix (evidence paths,
       case-home mounts, etc.) with ``home_placeholder``.

    Only those two path classes are touched. SHA digests, ISO-8601 timestamps,
    and enum tokens carry no such substring, so they pass through unchanged. Pure
    and deterministic: the same input always yields the same output.
    """
    count = 0
    if run_dir_abs and dest_rel:
        hits = text.count(run_dir_abs)
        if hits:
            text = text.replace(run_dir_abs, dest_rel)
            count += hits

    def _replace(_match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return home_placeholder

    text = HOME_PREFIX_RE.sub(_replace, text)
    return text, count


# ---------------------------------------------------------------------------
# Planning.
# ---------------------------------------------------------------------------


def _dest_rel(into_abs: Path, repo_root: Path, into_arg: str) -> str:
    """Repo-relative POSIX form of the destination dir (falls back to the arg)."""
    try:
        return into_abs.relative_to(repo_root).as_posix()
    except ValueError:
        return Path(into_arg).as_posix()


def plan_regeneration(
    from_dir: Path,
    into_arg: str,
    *,
    repo_root: Path,
    home_placeholder: str = DEFAULT_HOME_PLACEHOLDER,
) -> list[FilePlan]:
    """Build the per-artifact plan without writing anything.

    Custody-bound artifacts are scanned (leak count) and queued for a verbatim
    copy. Display artifacts are scrubbed; a display artifact that is not valid
    UTF-8 falls back to a verbatim copy (never corrupt unknown bytes).
    """
    from_dir = Path(from_dir)
    run_dir_abs = str(from_dir.resolve())
    into_abs = Path(into_arg).resolve()
    dest_rel = _dest_rel(into_abs, repo_root, into_arg)

    plans: list[FilePlan] = []
    for name in CANONICAL_ARTIFACTS:
        src = from_dir / name
        dst = into_abs / name
        if not src.is_file():
            plans.append(
                FilePlan(
                    name=name,
                    present=False,
                    custody_bound=name in CUSTODY_BOUND,
                    src=src,
                    dst=dst,
                    payload=b"",
                    scrub_count=0,
                    leak_count=0,
                )
            )
            continue

        raw = src.read_bytes()
        custody = name in CUSTODY_BOUND
        if custody:
            plans.append(
                FilePlan(
                    name=name,
                    present=True,
                    custody_bound=True,
                    src=src,
                    dst=dst,
                    payload=raw,
                    scrub_count=0,
                    leak_count=count_machine_paths(raw, run_dir_abs=run_dir_abs),
                )
            )
            continue

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            plans.append(
                FilePlan(
                    name=name,
                    present=True,
                    custody_bound=False,
                    src=src,
                    dst=dst,
                    payload=raw,
                    scrub_count=0,
                    leak_count=count_machine_paths(raw, run_dir_abs=run_dir_abs),
                    binary_fallback=True,
                )
            )
            continue

        scrubbed, n = scrub_text(
            text,
            run_dir_abs=run_dir_abs,
            dest_rel=dest_rel,
            home_placeholder=home_placeholder,
        )
        payload = scrubbed.encode("utf-8")
        plans.append(
            FilePlan(
                name=name,
                present=True,
                custody_bound=False,
                src=src,
                dst=dst,
                payload=payload,
                scrub_count=n,
                leak_count=count_machine_paths(scrubbed, run_dir_abs=run_dir_abs),
            )
        )
    return plans


def apply_plans(plans: list[FilePlan], into_abs: Path) -> None:
    """Write every present plan's payload to its destination."""
    into_abs.mkdir(parents=True, exist_ok=True)
    for plan in plans:
        if plan.present:
            plan.dst.write_bytes(plan.payload)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _print_plan(plans: list[FilePlan], *, dry_run: bool) -> bool:
    """Print the plan. Returns True when the output is hygiene-clean."""
    clean = True
    for plan in plans:
        if not plan.present:
            print(f"  [SKIP]  {plan.name} (not present in run dir)")
            continue
        if plan.verbatim:
            tag = (
                "custody-bound, verbatim" if plan.custody_bound else "binary, verbatim"
            )
            print(f"  [KEEP]  {plan.name} ({tag})")
            if plan.leak_count:
                clean = False
                if plan.custody_bound:
                    print(
                        f"          WARNING: {plan.leak_count} machine-path leak(s) remain in "
                        f"this signed/chained artifact. It CANNOT be scrubbed in place without "
                        f"breaking manifest_verify; regenerate the source run with the "
                        f"relativizing engine, then re-run this tool."
                    )
                else:
                    print(
                        f"          WARNING: {plan.leak_count} machine-path leak(s) remain "
                        f"(non-UTF-8 artifact copied verbatim)."
                    )
        else:
            print(f"  [SCRUB] {plan.name}: {plan.scrub_count} replacement(s)")
            if plan.leak_count:
                clean = False
                print(
                    f"          WARNING: {plan.leak_count} machine-path leak(s) remain after scrub."
                )
    verb = "would be written" if dry_run else "written"
    print(f"\n  Hygiene: {'CLEAN' if clean else 'LEAKS REMAIN'} ({verb})")
    return clean


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="regenerate-sample-run.py",
        description="Refresh a committed docs/sample-run/<case> from a fresh run dir, /home-free.",
    )
    parser.add_argument(
        "--from",
        dest="from_dir",
        required=True,
        help="Source run directory (e.g. tmp/auto-runs/<case-id>).",
    )
    parser.add_argument(
        "--into",
        dest="into",
        required=True,
        help="Destination sample-run directory (e.g. docs/sample-run/<name>).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned scrubs/copies without writing anything.",
    )
    parser.add_argument(
        "--home-placeholder",
        default=DEFAULT_HOME_PLACEHOLDER,
        help=f"Replacement for /home/<user> and /Users/<user> (default: {DEFAULT_HOME_PLACEHOLDER}).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    from_dir = Path(args.from_dir)
    if not from_dir.is_dir():
        print(f"error: --from is not a directory: {from_dir}", file=sys.stderr)
        return 1

    into_abs = Path(args.into).resolve()
    plans = plan_regeneration(
        from_dir,
        args.into,
        repo_root=repo_root,
        home_placeholder=args.home_placeholder,
    )
    present = [p for p in plans if p.present]
    if not present:
        print(f"error: no canonical artifacts found under {from_dir}", file=sys.stderr)
        return 1

    print(f"Regenerate sample run:\n  from: {from_dir}\n  into: {into_abs}\n")
    if args.dry_run:
        clean = _print_plan(plans, dry_run=True)
        print("\n  DRY RUN - no files written.")
        return 0 if clean else 2

    apply_plans(plans, into_abs)
    clean = _print_plan(plans, dry_run=False)
    return 0 if clean else 2


if __name__ == "__main__":
    sys.exit(main())
