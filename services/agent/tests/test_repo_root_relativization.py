"""Record-side contract: the EVIDENCE path + opener agent_message go /home-free.

A fresh disk run's ``audit.jsonl`` leaked the absolute machine path
(``/home/<user>/.../evidence/<image>.dd``) in two record classes the existing
case-store relativizer never covered, because the evidence source lives UNDER the
repo but OUTSIDE the case store:

- ``tool_call_start.arguments.image_path`` / ``evidence_path`` — the replay-bearing
  ``*_path`` arguments (the 30 ``image_path`` leaks).
- ``agent_message.content`` — the opening "begin investigation of <path>" record.

``_relativize_repo_root_path`` mirrors ``_relativize_extracted_path`` but anchors on
the REPO ROOT (reconstructable identically at record + replay), so a path under the
repo is recorded repo-relative (``evidence/<image>.dd``). ``_release_arguments``
applies the case store anchor FIRST (a ``cases/...`` value replay resolves via
case_home) and only falls back to the repo root for paths outside the case store.
Evidence OUTSIDE the repo has no repo anchor and stays absolute — a documented
residual; the committed corpus always lives under ``evidence/``.

These tests pin the record-side transform. Replay-side re-absolutization of a
repo-relative value against the repo root is the verifier's job
(``findevil_agent.case_paths``) and is validated there / live on SCHARDT.dd.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class TestRelativizeRepoRootPath:
    def test_path_under_repo_becomes_repo_relative(self) -> None:
        absolute = str(fea.REPO_ROOT / "evidence" / "SAMPLE.dd")
        rel = fea._relativize_repo_root_path(absolute)
        assert rel == "evidence/SAMPLE.dd"
        assert "/home/" not in rel
        assert not rel.startswith("/")

    def test_nested_path_under_repo_keeps_posix_subpath(self) -> None:
        absolute = str(fea.REPO_ROOT / "evidence" / "case-a" / "disk.raw")
        assert fea._relativize_repo_root_path(absolute) == "evidence/case-a/disk.raw"

    def test_path_outside_repo_is_unchanged(self) -> None:
        # Evidence elsewhere on the host has no repo anchor to resolve against at
        # replay, so it passes through verbatim (documented residual).
        outside = "/mnt/storage/evidence/SAMPLE.dd"
        assert fea._relativize_repo_root_path(outside) == outside

    def test_relative_input_is_unchanged(self) -> None:
        assert fea._relativize_repo_root_path("evidence/SAMPLE.dd") == "evidence/SAMPLE.dd"

    def test_empty_input_is_unchanged(self) -> None:
        assert fea._relativize_repo_root_path("") == ""


class TestReleaseArgumentsRepoRoot:
    def test_evidence_image_path_under_repo_is_repo_relative(self) -> None:
        # Part A: the 30 image_path leaks. An evidence *_path under the repo but
        # outside the case store is recorded repo-relative, not absolute.
        image_path = str(fea.REPO_ROOT / "evidence" / "SAMPLE.dd")
        out = fea._release_arguments({"case_id": "c1", "image_path": image_path})
        assert out["image_path"] == "evidence/SAMPLE.dd"
        assert "/home/" not in out["image_path"]
        # Non-path keys untouched.
        assert out["case_id"] == "c1"

    def test_case_store_path_wins_over_repo_root(self, monkeypatch) -> None:
        # Ordering contract: case store base FIRST, then repo root. Under
        # containment the case store lives UNDER the repo, so a case-store *_path
        # is under BOTH anchors — it must record case-relative (``cases/...``),
        # which the verifier resolves via case_home, not repo-relative.
        case_home = fea.REPO_ROOT / ".project-local" / "findevil"
        monkeypatch.setenv("FINDEVIL_HOME", str(case_home))
        mft_path = str(case_home / "cases" / "abcd1234" / "extracted" / "disk" / "mft" / "$MFT")
        out = fea._release_arguments({"mft_path": mft_path})
        assert out["mft_path"] == "cases/abcd1234/extracted/disk/mft/$MFT"
        assert not out["mft_path"].startswith(".project-local/")
        assert "/home/" not in out["mft_path"]

    def test_path_outside_both_anchors_is_unchanged(self, monkeypatch) -> None:
        monkeypatch.setenv("FINDEVIL_HOME", str(fea.REPO_ROOT / ".project-local" / "findevil"))
        outside = "/mnt/storage/evidence/SAMPLE.dd"
        out = fea._release_arguments({"evidence_path": outside})
        assert out["evidence_path"] == outside

    def test_non_path_keys_are_copied_verbatim(self) -> None:
        args = {"case_id": "c1", "limit": 500, "recursive": True}
        assert fea._release_arguments(args) == args


class TestOpenerAgentMessageRelativized:
    """Part C: the ``begin investigation of <path>`` opener is /home-free.

    The opener content is built as
    ``f"begin investigation of {_release_path(self.evidence, REPO_ROOT)}"`` (mirror
    of the directory-investigation opener). These pin the relativization the emit
    applies without spinning up the ssh/MCP tool path.
    """

    def test_under_repo_evidence_opener_is_repo_relative(self) -> None:
        evidence = str(fea.REPO_ROOT / "evidence" / "SAMPLE.dd")
        content = f"begin investigation of {fea._release_path(evidence, fea.REPO_ROOT)}"
        assert content == "begin investigation of evidence/SAMPLE.dd"
        assert "/home/" not in content

    def test_outside_repo_evidence_opener_falls_back_to_basename(self) -> None:
        # A descriptive (non-replay) record: out-of-repo evidence records the
        # basename so the opener never leaks /home even when the source lives
        # outside the repo.
        evidence = "/mnt/storage/nested/SAMPLE.dd"
        content = f"begin investigation of {fea._release_path(evidence, fea.REPO_ROOT)}"
        assert content == "begin investigation of SAMPLE.dd"
        assert "/home/" not in content
