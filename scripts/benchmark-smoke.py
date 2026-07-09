#!/usr/bin/env python3
"""benchmark-smoke — validate goldens/CORPUS.json + scripts/benchmark wiring.

Fast and evidence-free, so it belongs in the run-all-smokes gate (unlike
scripts/benchmark itself, which needs staged evidence and real runs). It checks
the corpus manifest is well-formed, every scoreable case points at a real
golden, and the runner is present and syntactically valid — so a broken corpus
entry is caught before an operator kicks off a long benchmark run.

Path-agnostic: derives the repo root from this file's location.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "goldens" / "CORPUS.json"
RUNNER = REPO_ROOT / "scripts" / "benchmark"

# Per plan-Phase-1: each entry carries at least {name, url, sha256, type,
# license}; the runner also needs {evidence, golden, runnable_local}.
REQUIRED = ("name", "type", "evidence", "golden", "license")
KNOWN_TYPES = {"disk", "memory", "network", "evtx", "mixed", "synthetic"}


def main() -> int:
    errors: list[str] = []
    notes: list[str] = []

    if not CORPUS.is_file():
        print(f"FAIL: {CORPUS} missing", file=sys.stderr)
        return 1
    try:
        data = json.loads(CORPUS.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL: {CORPUS} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    if "schema_version" not in data:
        errors.append("CORPUS.json missing schema_version")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        print("FAIL: CORPUS.json has no cases[]", file=sys.stderr)
        return 1

    seen: set[str] = set()
    scoreable = 0
    for i, c in enumerate(cases):
        where = c.get("name", f"case[{i}]")
        for field in REQUIRED:
            if not isinstance(c.get(field), str) or not c[field]:
                errors.append(f"{where}: missing/empty required field '{field}'")
        # url and sha256 must be present as keys (may be null for local/synthetic).
        for field in ("url", "sha256"):
            if field not in c:
                errors.append(f"{where}: missing key '{field}' (may be null)")
        if "runnable_local" not in c:
            errors.append(f"{where}: missing 'runnable_local' bool")
        name = c.get("name", "")
        if name in seen:
            errors.append(f"{where}: duplicate case name")
        seen.add(name)
        if c.get("type") not in KNOWN_TYPES:
            errors.append(
                f"{where}: unknown type {c.get('type')!r} (known: {sorted(KNOWN_TYPES)})"
            )

        golden = c.get("golden", "")
        golden_key = REPO_ROOT / golden / "expected-findings.json"
        if c.get("needs_golden"):
            notes.append(f"{name}: golden pending authoring ({golden})")
            if golden_key.is_file():
                errors.append(
                    f"{where}: flagged needs_golden but {golden}/expected-findings.json already exists — drop the flag"
                )
        else:
            scoreable += 1
            if not golden_key.is_file():
                errors.append(
                    f"{where}: golden {golden}/expected-findings.json does not exist"
                )
        # env_url / env_sha256, when present, must be plausible env-var names.
        for envf in ("env_url", "env_sha256"):
            v = c.get(envf)
            if v is not None and (
                not isinstance(v, str)
                or not v.replace("_", "").isalnum()
                or not v.isupper()
            ):
                errors.append(
                    f"{where}: {envf}={v!r} is not an UPPER_SNAKE env-var name"
                )

    # Runner present + syntactically valid.
    if not RUNNER.is_file():
        errors.append("scripts/benchmark missing")
    else:
        try:
            r = subprocess.run(
                ["bash", "-n", str(RUNNER)], capture_output=True, text=True, timeout=30
            )
            if r.returncode != 0:
                errors.append(
                    f"scripts/benchmark has a bash syntax error: {r.stderr.strip()[:200]}"
                )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"could not bash -n scripts/benchmark: {exc}")

    for n in notes:
        print(f"  note: {n}")
    if errors:
        print("FAIL: benchmark corpus/runner issues:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        f"  PASS: CORPUS.json well-formed ({len(cases)} cases, {scoreable} scoreable), runner valid."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
