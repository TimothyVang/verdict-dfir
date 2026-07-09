"""fleet_correlate / render_fleet_report — cross-host hygiene wiring.

The OS-signed-binary / too-common-pivot suppression and the
discriminating-pivot campaign-lead gate are built and unit-tested in
``findevil_agent.correlator`` (see ``test_correlator.py``). These tests lock in
that the LIVE fleet pipeline actually *applies* them: fleet_correlate mines
shared artifacts from per-host finding ``asserted_values``, runs the shipped
``correlate_cross_host`` gate, and surfaces the result in
``fleet_correlation.json`` + both fleet reports.

Pure read-side: nothing here touches verify_finding, the audit chain, the
signed manifest, or any scoring math — the fleet report is a derivative summary.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


fc = _load("fleet_correlate")


def _host(name: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"_host": name, "verdict": "SUSPICIOUS", "findings": findings}


def _av(path: str, expected: str) -> dict[str, str]:
    return {"path": path, "expected": expected}


def _by_value(hygiene: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {o["value"]: o for o in hygiene["outcomes"]}


# --------------------------------------------------------------------------- #
# Availability: the supported runtime (3.11+ / agent venv) must resolve the
# shipped functions. If this flips False, the wiring is silently dead.
# --------------------------------------------------------------------------- #
def test_hygiene_functions_are_wired_in() -> None:
    assert fc._CROSS_HOST_HYGIENE_AVAILABLE is True


# --------------------------------------------------------------------------- #
# Mining: hash+signer pairing and snake_case network-path tokenization.
# --------------------------------------------------------------------------- #
def test_mine_pairs_hash_with_signer_and_extracts_pivots() -> None:
    verdicts = [
        _host(
            "H1",
            [
                {
                    "asserted_values": [
                        _av("row.sha256", "A" * 64),
                        _av("row.publisher", "Microsoft Windows Publisher"),
                    ]
                },
                {"asserted_values": [_av("conn.dest_domain", "rare-c2.example")]},
            ],
        ),
        _host(
            "H2",
            [
                {
                    "asserted_values": [
                        _av("row.sha256", "a" * 64),  # same hash, mixed case
                        _av("row.publisher", "Microsoft Windows Publisher"),
                    ]
                },
                {"asserted_values": [_av("conn.dest_domain", "rare-c2.example")]},
            ],
        ),
    ]
    arts = {a.value: a for a in fc.mine_shared_artifacts(verdicts)}
    # Hash normalized to lowercase and grouped across the two hosts with signer.
    assert "a" * 64 in arts
    binary = arts["a" * 64]
    assert binary.kind == "binary"
    assert binary.signer == "Microsoft Windows Publisher"
    assert set(binary.hosts) == {"H1", "H2"}
    # snake_case "dest_domain" tokenizes to the "domain" network token.
    assert "rare-c2.example" in arts
    assert arts["rare-c2.example"].kind == "network_pivot"


def test_descriptions_are_not_mined_only_asserted_values() -> None:
    # A SHA-256 sitting in free-text description must NOT become an artifact —
    # only the structured, audited asserted_values channel is mined.
    verdicts = [
        _host("H1", [{"description": "implant " + "e" * 64, "asserted_values": []}]),
        _host("H2", [{"description": "implant " + "e" * 64, "asserted_values": []}]),
    ]
    assert fc.mine_shared_artifacts(verdicts) == []


# --------------------------------------------------------------------------- #
# Suppression + lead gating end-to-end through cross_host_hygiene().
# --------------------------------------------------------------------------- #
def test_os_signed_shared_binary_is_suppressed() -> None:
    verdicts = [
        _host(
            h,
            [
                {
                    "asserted_values": [
                        _av("sha256", "a" * 64),
                        _av("signer", "Microsoft Corporation"),
                    ]
                }
            ],
        )
        for h in ("H1", "H2")
    ]
    hygiene = fc.cross_host_hygiene(verdicts)
    assert hygiene["available"] is True
    assert hygiene["actor_link"] is False
    assert _by_value(hygiene)["a" * 64]["decision"] == "suppressed"


def test_unsigned_shared_binary_grouped_for_review() -> None:
    verdicts = [_host(h, [{"asserted_values": [_av("sha256", "b" * 64)]}]) for h in ("H1", "H2")]
    hygiene = fc.cross_host_hygiene(verdicts)
    out = _by_value(hygiene)["b" * 64]
    assert out["decision"] == "shared_binaries_review"
    assert out["epistemic_label"] == "HYPOTHESIS"


def test_too_common_pivot_suppressed_co_occurrence_only() -> None:
    verdicts = [
        _host(h, [{"asserted_values": [_av("tls.registrar", "GoDaddy.com, LLC")]}])
        for h in ("H1", "H2")
    ]
    hygiene = fc.cross_host_hygiene(verdicts)
    assert hygiene["actor_link"] is False
    assert hygiene["co_occurrence"] is True
    assert _by_value(hygiene)["GoDaddy.com, LLC"]["decision"] == "suppressed"


def test_discriminating_pivot_emits_campaign_lead() -> None:
    verdicts = [
        _host(h, [{"asserted_values": [_av("conn.c2_domain", "update-7f3a.rare-c2.example")]}])
        for h in ("H1", "H2")
    ]
    hygiene = fc.cross_host_hygiene(verdicts)
    assert hygiene["actor_link"] is True
    assert hygiene["co_occurrence"] is False
    out = _by_value(hygiene)["update-7f3a.rare-c2.example"]
    assert out["decision"] == "campaign_lead"
    assert out["epistemic_label"] == "HYPOTHESIS"


def test_single_host_artifact_is_ignored() -> None:
    verdicts = [_host("H1", [{"asserted_values": [_av("sha256", "c" * 64)]}])]
    hygiene = fc.cross_host_hygiene(verdicts)
    assert hygiene["artifact_count"] == 0
    assert hygiene["outcomes"] == []


def test_attribution_invariant_is_always_false() -> None:
    verdicts = [
        _host(
            h,
            [
                {"asserted_values": [_av("sha256", "d" * 64)]},
                {"asserted_values": [_av("conn.domain", "rare-c2.example")]},
                {"asserted_values": [_av("tls.registrar", "Namecheap")]},
            ],
        )
        for h in ("H1", "H2")
    ]
    hygiene = fc.cross_host_hygiene(verdicts)
    assert hygiene["attribution"] is False
    assert all(o["attribution"] is False for o in hygiene["outcomes"])


def test_too_common_pivot_does_not_gate_a_co_present_discriminator() -> None:
    verdicts = [
        _host(
            h,
            [
                {"asserted_values": [_av("conn.domain", "cdn.cloudflare.net")]},
                {"asserted_values": [_av("conn.c2_domain", "discriminating-c2.example")]},
            ],
        )
        for h in ("H1", "H2")
    ]
    hygiene = fc.cross_host_hygiene(verdicts)
    assert hygiene["actor_link"] is True
    by_value = _by_value(hygiene)
    assert by_value["cdn.cloudflare.net"]["decision"] == "suppressed"
    assert by_value["discriminating-c2.example"]["decision"] == "campaign_lead"


# --------------------------------------------------------------------------- #
# Both fleet reports surface the hygiene section.
# --------------------------------------------------------------------------- #
def test_fleet_correlation_md_contains_hygiene_section(tmp_path: Path) -> None:
    hygiene = {
        "available": True,
        "artifact_count": 1,
        "actor_link": True,
        "co_occurrence": False,
        "attribution": False,
        "outcomes": [
            {
                "kind": "network_pivot",
                "value": "rare-c2.example",
                "hosts": ["H1", "H2"],
                "decision": "campaign_lead",
                "reason": "discriminating network pivot",
                "epistemic_label": "HYPOTHESIS",
                "attribution": False,
            }
        ],
    }
    from collections import Counter

    fc.write_outputs(
        tmp_path,
        verdicts=[],
        cross_procs={},
        clusters=[],
        mitre=Counter(),
        distrib=Counter({"SUSPICIOUS": 2}),
        unique_roots=(2, 2),
        hygiene=hygiene,
    )
    md = (tmp_path / "fleet_correlation.md").read_text(encoding="utf-8")
    assert "Cross-host hygiene" in md
    assert "campaign_lead" in md
    assert "rare-c2.example" in md


def test_render_fleet_report_md_contains_hygiene_section(tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")
    render = _load("render_fleet_report")
    corr = {
        "host_count": 2,
        "verdict_distribution": {"SUSPICIOUS": 2},
        "cross_host_processes": {},
        "temporal_clusters": [],
        "cryptographic_attestation": {},
        "mitre_technique_density": {},
        "cross_host_hygiene": {
            "available": True,
            "actor_link": True,
            "co_occurrence": False,
            "attribution": False,
            "outcomes": [
                {
                    "kind": "network_pivot",
                    "value": "rare-c2.example",
                    "hosts": ["H1", "H2"],
                    "decision": "campaign_lead",
                    "reason": "discriminating network pivot",
                    "epistemic_label": "HYPOTHESIS",
                    "attribution": False,
                },
                {
                    "kind": "binary",
                    "value": "a" * 64,
                    "hosts": ["H1", "H2"],
                    "decision": "suppressed",
                    "reason": "OS / Microsoft-signed baseline binary",
                    "epistemic_label": "",
                    "attribution": False,
                },
            ],
        },
    }
    md = render.write_markdown(tmp_path, corr, has_temporal=False)
    text = md.read_text(encoding="utf-8")
    assert "Cross-host hygiene" in text
    assert "discriminating cross-host pivot" in text
    assert "rare-c2.example" in text
    assert "suppressed as expected baseline noise" in text
