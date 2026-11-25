"""Tests for the OE newsgroup-affiliation emitter in the orchestrator.

The finding must be ONE Pool B HYPOTHESIS lead that cites the store with the most
hacking newsgroups, lists the groups, and stays an *artifact* statement — never
an intrusion claim and never actor identity/intent (host-artifact guardrail).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestNewsgroupAffiliationEmitter:
    def _inv(self):
        inv = fea.Investigation("disk.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-ng"}
        return inv

    def _stores(self):
        return [
            (
                "/m/alt.2600.hackerz.dbx",
                "tc-a",
                {
                    "hacking_newsgroups": ["alt.2600.hackerz"],
                    "subjects": ["How to hack hotmail"],
                },
            ),
            (
                "/m/alt.binaries.hacking.beginner.dbx",
                "tc-b",
                {
                    "hacking_newsgroups": ["alt.binaries.hacking.beginner", "alt.hacking"],
                    "subjects": ["Bios Password Hacking"],
                },
            ),
        ]

    def test_emits_one_hypothesis_finding_citing_primary(self) -> None:
        inv = self._inv()
        inv._emit_newsgroup_affiliation_finding(self._stores())
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["pool_origin"] == "B"
        assert f.get("mitre_technique") is None  # affiliation maps to no ATT&CK technique
        # primary = the store with the most hacking newsgroups (tc-b)
        assert f["tool_call_id"] == "tc-b"
        assert set(f["derived_from"]) == {"tc-a", "tc-b"}
        desc = f["description"].lower()
        assert "alt.2600.hackerz" in desc and "alt.binaries.hacking.beginner" in desc
        # honesty boundary: artifact-only, no intrusion/intent/identity claim
        assert "not, on its own, evidence of any specific intrusion" in desc
        assert "out of scope" in desc

    def test_no_stores_emits_nothing(self) -> None:
        inv = self._inv()
        inv._emit_newsgroup_affiliation_finding([])
        assert inv.findings_pool_b == []
