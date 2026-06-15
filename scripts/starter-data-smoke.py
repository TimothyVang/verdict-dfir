#!/usr/bin/env python3
"""Smoke test: SANS starter data staging hook.

Verifies:
- goldens/sans-starter/expected-findings.json exists with the required schema
- fetch-fixtures.sh contains the SANS_STARTER_URL contract
- when SANS_STARTER_URL and SANS_STARTER_SHA256 are set, the hook logic stages
  and safely extracts the archive
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDENS_STUB = REPO_ROOT / "goldens" / "sans-starter" / "expected-findings.json"
FETCH_SCRIPT = REPO_ROOT / "scripts" / "fetch-fixtures.sh"


def test_stub_exists_and_valid() -> None:
    assert GOLDENS_STUB.exists(), f"Missing stub: {GOLDENS_STUB}"
    data = json.loads(GOLDENS_STUB.read_text(encoding="utf-8"))
    assert (
        data.get("status") == "pending_manual_walkthrough"
    ), f"Expected status=pending_manual_walkthrough, got {data.get('status')!r}"
    assert "case_id" in data, "stub missing case_id"
    assert "findings" in data, "stub missing findings list"


def test_fetch_script_has_starter_url_contract() -> None:
    text = FETCH_SCRIPT.read_text(encoding="utf-8")
    assert (
        "SANS_STARTER_URL" in text
    ), "fetch-fixtures.sh missing SANS_STARTER_URL reference"
    assert (
        "SKIP sans-starter" in text
    ), "fetch-fixtures.sh missing SKIP sans-starter message"
    assert (
        "SANS_STARTER_SHA256 is missing" in text
    ), "fetch-fixtures.sh must require SANS_STARTER_SHA256 before extraction"
    assert (
        "extract_zip_fixture" in text
    ), "fetch-fixtures.sh must use guarded zip extraction"
    assert re.search(
        r"if\s+\[\[.*SANS_STARTER_URL", text
    ), "fetch-fixtures.sh missing SANS_STARTER_URL conditional"


def test_fetch_stages_when_url_set() -> None:
    # Exercise only the starter-data snippet, not the full network-heavy script.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        zip_path = tmp / "sans-starter.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("stub.txt", "SANS hackathon starter placeholder\n")
        zip_sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        fixtures_dir = tmp / "fixtures"
        fixtures_dir.mkdir()
        snippet = f"""
set -euo pipefail
FIXTURES='{fixtures_dir}'
fetch_fixture() {{
  local url="$1" dest_sub="$2" expected_sha="$3"
  mkdir -p "${{FIXTURES}}/$(dirname "${{dest_sub}}")"
  local abs="${{FIXTURES}}/${{dest_sub}}"
  curl -fsSL "$url" -o "$abs" 2>/dev/null || cp "${{url#file://}}" "$abs" 2>/dev/null || true
  local got_sha
  got_sha="$(sha256sum "$abs" | awk '{{print $1}}')"
  if [[ "$got_sha" != "$expected_sha" ]]; then
    exit 1
  fi
}}
extract_zip_fixture() {{
  local zip_path="$1" target_dir="$2"
  python3 - "$zip_path" "$target_dir" <<'PY'
from pathlib import PurePosixPath
import stat
import sys
import zipfile

zip_path = sys.argv[1]
target_dir = sys.argv[2]
with zipfile.ZipFile(zip_path) as archive:
    for info in archive.infolist():
        raw = info.filename
        normalized = raw.replace('\\\\', '/')
        path = PurePosixPath(normalized)
        if not normalized or normalized.startswith('/') or path.is_absolute() or '..' in path.parts:
            raise SystemExit('unsafe zip member path: ' + raw)
        mode = (info.external_attr >> 16) & 0o170000
        if mode in {{stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK}}:
            raise SystemExit('unsafe zip member type: ' + raw)
    archive.extractall(target_dir)
PY
}}
log() {{ printf '[fetch-fixtures] %s\n' "$*" >&2; }}
SANS_STARTER_URL='{zip_path.as_uri()}'
SANS_STARTER_SHA256='{zip_sha256}'
if [[ -n "${{SANS_STARTER_URL:-}}" ]]; then
  if [[ -z "${{SANS_STARTER_SHA256:-}}" ]]; then
    log "ERROR: SANS_STARTER_URL is set but SANS_STARTER_SHA256 is missing. Pin the archive SHA-256 before extraction."
    exit 1
  fi
  log "SANS_STARTER_URL set - fetching SANS starter dataset"
  fetch_fixture "${{SANS_STARTER_URL}}" "sans-starter/sans-starter.zip" "${{SANS_STARTER_SHA256}}"
  if [[ -f "${{FIXTURES}}/sans-starter/sans-starter.zip" ]]; then
    extract_zip_fixture "${{FIXTURES}}/sans-starter/sans-starter.zip" "${{FIXTURES}}/sans-starter"
  fi
else
  log "SKIP sans-starter: set SANS_STARTER_URL to stage the dataset"
fi
"""
        result = subprocess.run(
            ["bash", "-c", snippet],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"snippet failed: {result.stderr[:300]}"
        unpacked = fixtures_dir / "sans-starter" / "stub.txt"
        assert (
            unpacked.exists()
        ), f"Expected unpacked stub.txt at {unpacked}; stderr: {result.stderr[:200]}"


def main() -> int:
    tests = [
        ("stub_exists_and_valid", test_stub_exists_and_valid),
        (
            "fetch_script_has_starter_url_contract",
            test_fetch_script_has_starter_url_contract,
        ),
        ("fetch_stages_when_url_set", test_fetch_stages_when_url_set),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1
    print(f"\nstarter-data-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
