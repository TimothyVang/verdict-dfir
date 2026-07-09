"""ATT&CK technique mappings must match the evidence the artifact attests.

Regression for the report-review finding that on-host EXECUTION artifacts were
tagged as off-host acquisition (T1588.002 Obtain Capabilities) or web C2
(T1071.001 Web Protocols). A Prefetch record proves a binary RAN -> User Execution
(T1204.002); a hacking-tool file on disk is Ingress Tool Transfer (T1105), not the
adversary acquiring tooling off-host.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_prefetch_tool_hints_are_execution_not_acquisition_or_web_c2() -> None:
    hints = {tok: tech for tok, _desc, tech in fea.SUSPICIOUS_PREFETCH_TOOL_HINTS}
    # On-host execution evidence — never off-host acquisition or web C2.
    assert hints["CAIN"] != "T1588.002"
    assert hints["MIRC"] != "T1071.001"
    assert hints["CAIN"].startswith("T1204")
    assert hints["MIRC"].startswith("T1204")
    # Function-based mappings that were already correct stay put.
    assert hints["ETHEREAL"] == "T1040"  # Network Sniffing
    assert hints["NETSTUMBLER"] == "T1046"  # Network Service Discovery


def test_no_execution_artifact_tagged_obtain_capabilities() -> None:
    # T1588.002 (Obtain Capabilities) is an off-host, pre-attack adversary technique;
    # nothing the engine detects on a host image should be ASSIGNED it. Comments that
    # name the wrong code to document the fix are fine, so match the quoted value only.
    src = (Path(_SCRIPTS) / "find_evil_auto.py").read_text()
    assert (
        '"T1588.002"' not in src
    ), "T1588.002 (off-host acquisition) must not tag on-host artifacts"
