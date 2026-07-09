"""One disk image = one host.

Regression for the "findings span 13 hosts" defect: when a finding's linked events
carry no host entity (true for prefetch / registry / MFT findings on a single disk
image), ``tag_finding_hosts`` fell back to the artifact-file basename, so each
``.pf`` file and registry hive became a separate "host" and ``build_host_groups``
produced one group per artifact filename. A single image is one host; extracted
artifacts are evidence, not hosts.

These tests pin:
- H1: prefetch / hive / $MFT findings with no host entity collapse into ONE host group.
- H2: a directory case with genuinely host-named evidence files (not artifact-class
      basenames) still groups by host, so separate hosts stay separate.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _timeline_without_host(findings: list[dict]) -> dict:
    # One event per finding, linked to it, carrying NO host/workstation entity.
    return {
        "events": [
            {
                "timestamp_utc": "2004-08-27T15:00:00Z",
                "linked_finding_ids": [f["finding_id"]],
                "entities": {},
            }
            for f in findings
        ]
    }


def test_extracted_artifacts_collapse_to_one_host() -> None:
    # H1: prefetch files, a registry hive, and $MFT on one disk image must not each
    # become a "host".
    findings = [
        {
            "finding_id": "f-B-prefetch-cain-exe",
            "confidence": "CONFIRMED",
            "tool_call_id": "tc-010",
            "artifact_path": "cases/x/extracted/disk/dx/prefetch/CAIN.EXE-23D61279.pf",
            "description": "Prefetch shows CAIN.EXE executed.",
        },
        {
            "finding_id": "f-B-prefetch-ethereal-exe",
            "confidence": "CONFIRMED",
            "tool_call_id": "tc-011",
            "artifact_path": "cases/x/extracted/disk/dx/prefetch/ETHEREAL.EXE-1C148EEF.pf",
            "description": "Prefetch shows ETHEREAL.EXE executed.",
        },
        {
            "finding_id": "f-A-sam-account",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-050",
            "artifact_path": "cases/x/extracted/disk/dx/registry/SAM",
            "description": "SAM records a local account.",
        },
        {
            "finding_id": "f-A-mft-tools",
            "confidence": "INFERRED",
            "tool_call_id": "tc-004",
            "artifact_path": "cases/x/extracted/disk/dx/mft/$MFT",
            "description": "MFT lists hacking-tool files.",
        },
    ]
    timeline = _timeline_without_host(findings)

    fea.tag_finding_hosts(findings, timeline)
    # No finding's host is an extracted-artifact basename.
    for f in findings:
        assert not f["host"].lower().endswith(".pf")
        assert f["host"] not in {"SAM", "$MFT"}

    groups = fea.build_host_groups(findings, timeline)
    assert len(groups) == 1, f"expected one host group, got {[g['host'] for g in groups]}"
    assert groups[0]["finding_count"] == 4


def test_extracted_lnk_recyclebin_indexdat_collapse_to_one_host() -> None:
    # H3: LNK, Recycle Bin INFO2, and index.dat extracted from one disk image are
    # artifacts, not hosts — keyed off the /extracted/ path, not a basename list.
    base = "cases/x/extracted/disk/dx"
    findings = [
        {
            "finding_id": "f-lnk",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-1",
            "artifact_path": f"{base}/lnk/Documents and Settings/u/Recent/GhostWare.lnk",
            "description": "LNK target lead.",
        },
        {
            "finding_id": "f-info2",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-2",
            "artifact_path": f"{base}/recyclebin/RECYCLER/S-1-5/INFO2",
            "description": "Recycle Bin.",
        },
        {
            "finding_id": "f-iehist",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-3",
            "artifact_path": f"{base}/iehistory/index.dat",
            "description": "IE history.",
        },
        {
            "finding_id": "f-evt",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-4",
            "artifact_path": f"{base}/evt/SysEvent.Evt",
            "description": "Event log.",
        },
    ]
    timeline = _timeline_without_host(findings)
    fea.tag_finding_hosts(findings, timeline)
    for f in findings:
        assert f["host"] == "", f"{f['finding_id']} got host {f['host']!r}"
    groups = fea.build_host_groups(findings, timeline)
    assert len(groups) == 1


def test_host_named_evidence_still_groups_by_host() -> None:
    # H2: a directory case whose evidence files are genuinely host-named (not an
    # extracted-artifact class) still falls back to the basename, keeping separate
    # hosts separate.
    findings = [
        {
            "finding_id": "f1",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-1",
            "artifact_path": "/evidence/HOST-A.evtx",
            "description": "x",
        },
        {
            "finding_id": "f2",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-2",
            "artifact_path": "/evidence/HOST-B.evtx",
            "description": "y",
        },
    ]
    timeline = _timeline_without_host(findings)

    fea.tag_finding_hosts(findings, timeline)
    groups = fea.build_host_groups(findings, timeline)
    assert len(groups) == 2
