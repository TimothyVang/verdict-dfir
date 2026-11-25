#!/usr/bin/env python3
"""install-bootstrap-smoke — contract guard for scripts/install.sh --bootstrap.

The canonical installer's DEFAULT behavior is fail-closed: if a required
toolchain prerequisite (cargo, uv) is missing it errors out with instructions
and `exit 1`. The opt-in `--bootstrap` / `FINDEVIL_BOOTSTRAP=1` mode installs
those prerequisites first instead. Judges and CI rely on the default contract,
so this smoke asserts:

  1. install.sh is syntactically valid (`bash -n`).
  2. The `--bootstrap` flag and `FINDEVIL_BOOTSTRAP` env are both honored.
  3. The bootstrap installers (rustup / astral uv / fnm) are GATED behind the
     bootstrap toggle — never invoked on the default path.
  4. The default fail-closed behavior is preserved: the cargo-missing and
     uv-missing branches still `exit 1`.
  5. The prebuilt-binary fetch is the DEFAULT (auto-detects the latest published
     release) and checksum-verified, with a source-build opt-out
     (FINDEVIL_MCP_FROM_SOURCE / CI) and `cargo build` preserved as the fallback.
  6. The C-toolchain bootstrap (build-essential) is gated by the toggle —
     rustup installs Rust but not the cc/linker that crates need to build.
  7. install.sh honors the canonical doctor.sh readiness result instead of
     ignoring it and printing READY after a failed preflight.

Static assertions (not execution) because install.sh builds the Rust binary;
running it is the job of the live test, not a unit smoke.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO / "scripts" / "install.sh"


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def main() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    # 1. Syntax.
    proc = subprocess.run(
        ["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True
    )
    if proc.returncode != 0:
        fail(f"bash -n failed:\n{proc.stderr}")

    # 2. Flag + env both honored.
    if "--bootstrap" not in text:
        fail("install.sh does not parse the --bootstrap flag")
    if "FINDEVIL_BOOTSTRAP" not in text:
        fail("install.sh does not honor FINDEVIL_BOOTSTRAP")

    # 3. The remote-script installers MUST be gated behind the bootstrap toggle
    #    so the default path never pipes a remote script to a shell. Check the
    #    exact installer URLs (the security-relevant lines), each within a
    #    bootstrap_enabled-guarded block.
    if "bootstrap_enabled" not in text:
        fail("expected a bootstrap_enabled guard helper")
    lines = text.splitlines()

    def is_execution(line: str) -> bool:
        # A printed instruction (echo/printf) or comment is documentation, not a
        # remote-script execution — only executions need the bootstrap gate.
        stripped = line.lstrip()
        return not stripped.startswith(("echo", "printf", "#"))

    for marker in ("sh.rustup.rs", "astral.sh/uv/install.sh", "fnm.vercel.app/install"):
        exec_hits = [
            i for i, ln in enumerate(lines) if marker in ln and is_execution(ln)
        ]
        if not exec_hits:
            fail(f"expected the bootstrap to wire (and execute) installer '{marker}'")
        for i in exec_hits:
            window = "\n".join(lines[max(0, i - 6) : i + 1])
            if "bootstrap_enabled" not in window:
                fail(
                    f"installer '{marker}' at line {i + 1} is not gated by "
                    f"bootstrap_enabled (default path must not pipe it to a shell)"
                )

    # 4. Fail-closed default preserved for the two required tools.
    for tool, hint in (("cargo", "rustup"), ("uv", "uv")):
        # The missing-<tool> branch must still exit 1.
        pat = re.compile(
            r"command -v " + tool + r".*?\n(?:.*?\n){0,12}?\s*exit 1", re.DOTALL
        )
        if not pat.search(text):
            fail(f"the missing-{tool} branch no longer fails closed (exit 1)")

    # 5. Prebuilt-binary fetch is the DEFAULT (auto-detects the latest release),
    #    checksum-verified, with a source-build opt-out (FINDEVIL_MCP_FROM_SOURCE
    #    / CI) and cargo build preserved as the fallback on any failure.
    if "try_fetch_prebuilt" not in text:
        fail("expected a try_fetch_prebuilt helper")
    if "releases/latest" not in text:
        fail(
            "prebuilt fetch does not auto-detect the latest release (the default fast path)"
        )
    if "FINDEVIL_MCP_FROM_SOURCE" not in text:
        fail("no source-build opt-out (FINDEVIL_MCP_FROM_SOURCE) for CI/judges")
    if "FINDEVIL_MCP_PREBUILT" not in text:
        fail("FINDEVIL_MCP_PREBUILT override is no longer honored")
    if "sha256sum -c" not in text:
        fail("prebuilt fetch does not checksum-verify the download")
    if "cargo build --release --locked -p findevil-mcp" not in text:
        fail("the cargo build fallback was removed")

    # 6. The C-toolchain bootstrap (build-essential) is gated by the toggle too —
    #    rustup installs Rust but not the cc/linker that crates need to build.
    be_hits = [
        i
        for i, ln in enumerate(lines)
        if "build-essential" in ln and "apt-get install" in ln
    ]
    if not be_hits:
        fail("expected --bootstrap to apt-install build-essential (C toolchain)")
    for i in be_hits:
        window = "\n".join(lines[max(0, i - 10) : i + 1])
        if "bootstrap_enabled" not in window:
            fail(
                f"build-essential install at line {i + 1} is not gated by "
                f"bootstrap_enabled"
            )

    # 7. The installer may complete builds while the environment remains NOT
    #    READY. It must not ignore doctor.sh failures and then print a green
    #    ready banner.
    if 'bash "${REPO}/scripts/doctor.sh" || true' in text:
        fail("install.sh still ignores doctor.sh failure with '|| true'")
    if "DOCTOR_STATUS" not in text:
        fail("install.sh does not capture doctor.sh status")
    if "build complete, but environment is NOT READY" not in text:
        fail("install.sh does not print a clear build-complete-but-not-ready banner")
    if 'exit "${DOCTOR_STATUS}"' not in text:
        fail("install.sh does not exit with the doctor.sh readiness status")

    print(
        "OK - install.sh contract holds (bootstrap gated, prebuilt verified, fail-closed)."
    )


if __name__ == "__main__":
    main()
