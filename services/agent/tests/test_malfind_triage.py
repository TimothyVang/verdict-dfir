"""Tests for the deterministic vol_malfind benign-region classifier.

The classifier annotates an *uncorroborated* malfind lead with a benign-candidate
HINT (JIT runtime / AV emulation) so the analyst can deprioritize the common
false positives. The load-bearing property is the SAFETY direction: a region that
shows ANY injection signal — an MZ header where none belongs, a shellcode GetPC
prologue, or an owner that is a known LOLBin — must NEVER be classified benign.
The hint never changes a finding's tier; corroboration (the >=2-artifact-class
gate) is what promotes a malfind hit to a real claim.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as _fea  # noqa: E402

# The classifier is inlined in the 3.10 host engine (find_evil_auto.py), not the
# 3.11 findevil_agent package — the orchestrator cannot import the package.
classify_malfind_region = _fea._classify_malfind_region

# A benign-looking 64-byte sample: a normal function prologue, no GetPC stub.
_BENIGN_HEX = "4889" + "5c2408" + "57" + "4883ec20" + "00" * 24
# A classic x64 shellcode prologue: cld; and a call $+5 GetPC.
_SHELLCODE_HEX = "fc" + "e800000000" + "5b" + "00" * 24


def _row(
    image: str, *, mz: bool = False, sample: str = _BENIGN_HEX, prot: str = "PAGE_EXECUTE_READWRITE"
):
    return {"image_name": image, "mz_match": mz, "sample_hex": sample, "protection": prot}


def test_av_scanner_region_is_benign_candidate() -> None:
    assert classify_malfind_region(_row("MsMpEng.exe")) == "possible_av_emulation"


def test_managed_runtime_host_is_benign_candidate() -> None:
    assert classify_malfind_region(_row("w3wp.exe")) == "possible_benign_jit_runtime"
    assert classify_malfind_region(_row("dotnet.exe")) == "possible_benign_jit_runtime"


def test_mz_header_is_never_benign() -> None:
    # A reflective-PE tell overrides any benign owner guess.
    assert classify_malfind_region(_row("w3wp.exe", mz=True)) is None
    assert classify_malfind_region(_row("MsMpEng.exe", mz=True)) is None


def test_shellcode_signature_is_never_benign() -> None:
    assert classify_malfind_region(_row("w3wp.exe", sample=_SHELLCODE_HEX)) is None


def test_lolbin_hosts_are_not_auto_benign() -> None:
    # powershell/mshta/rundll32/regsvr32 JIT too, but are prime injection vectors —
    # never auto-classify their malfind hits as benign.
    for lolbin in ("powershell.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe"):
        assert classify_malfind_region(_row(lolbin)) is None, lolbin


def test_unknown_process_is_not_guessed_benign() -> None:
    assert classify_malfind_region(_row("totally-unknown.exe")) is None
    assert classify_malfind_region(_row("")) is None


def test_case_insensitive_owner_match() -> None:
    assert classify_malfind_region(_row("MSMPENG.EXE")) == "possible_av_emulation"
    assert classify_malfind_region(_row("W3WP.EXE")) == "possible_benign_jit_runtime"
