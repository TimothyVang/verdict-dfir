"""Tests for /home-free extracted-artifact paths in the signed audit chain.

On disk/memory cases VERDICT extracts artifacts to
``<case_home>/cases/<id>/extracted/disk/disk-extract-<id>/...`` and records that
ABSOLUTE path in each tool call's ``arguments`` (the replay-bearing dict). The
signed audit chain therefore leaks ``/home/<user>/...`` on a disk case, so a disk
case dir is not publicly committable. PR #77 relativized the provenance records
but not the per-tool-call ``*_path`` arguments.

``artifact_path`` (and its sibling ``*_path`` args) is operationally load-bearing:
the verifier replays a cited call by re-running the tool with its recorded
``arguments``. The fix records the path RELATIVE to ``case_home`` (portable,
reconstructable at both record and replay time) and resolves it back to the
absolute file at replay time, so the chain stays /home-free AND replay keeps
finding the file (``output_sha256`` matches).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from findevil_agent.case_paths import (
    relativize_extracted_path,
    resolve_extracted_path,
    rewrite_arguments_for_replay,
)
from findevil_agent.mcp_client import MockMcpClient
from findevil_agent.replay import replay_tool_call


def _sha(obj: object) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestRelativize:
    def test_extracted_path_becomes_home_free(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        absolute = (
            f"{tmp_path}/.findevil/cases/db256d79/extracted/disk/" "disk-extract-3bb2/mft/$MFT"
        )
        released = relativize_extracted_path(absolute, env=env)
        assert "/home/" not in released
        assert str(tmp_path) not in released
        assert released == "cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT"

    def test_evidence_path_is_unchanged(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        # /evidence/ is read-only source evidence — documented as not-a-/home-leak.
        # It is NOT under case_home, so it must pass through untouched (relativizing
        # to a basename would break replay).
        assert relativize_extracted_path("/evidence/SCHARDT.dd", env=env) == "/evidence/SCHARDT.dd"

    def test_unrelated_absolute_path_is_unchanged(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        assert (
            relativize_extracted_path("/home/sansforensics/find-evil/x.evtx", env=env)
            == "/home/sansforensics/find-evil/x.evtx"
        )

    def test_already_relative_path_is_unchanged(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        rel = "cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT"
        assert relativize_extracted_path(rel, env=env) == rel


class TestResolveRoundTrip:
    def test_resolve_reverses_relativize(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        absolute = (
            f"{tmp_path}/.findevil/cases/db256d79/extracted/disk/" "disk-extract-3bb2/mft/$MFT"
        )
        released = relativize_extracted_path(absolute, env=env)
        assert resolve_extracted_path(released, env=env) == absolute

    def test_resolve_leaves_absolute_and_evidence_paths_alone(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        assert resolve_extracted_path("/evidence/SCHARDT.dd", env=env) == "/evidence/SCHARDT.dd"
        abs_path = f"{tmp_path}/.findevil/cases/x/extracted/disk/y/$MFT"
        assert resolve_extracted_path(abs_path, env=env) == abs_path

    def test_rewrite_arguments_resolves_only_path_keys(self, tmp_path: Path) -> None:
        env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
        rel = "cases/x/extracted/disk/y/$MFT"
        args = {"case_id": "c-1", "mft_path": rel, "limit": 5000}
        rewritten = rewrite_arguments_for_replay(args, env=env)
        assert rewritten["mft_path"] == f"{tmp_path}/.findevil/cases/x/extracted/disk/y/$MFT"
        # Non-path keys untouched.
        assert rewritten["case_id"] == "c-1"
        assert rewritten["limit"] == 5000
        # Original dict not mutated (immutability).
        assert args["mft_path"] == rel


class TestReplayResolvesRelativePath:
    def test_replay_finds_file_via_resolved_relative_path(self, tmp_path: Path) -> None:
        """End-to-end: a record carrying a /home-free RELATIVE *_path replays
        successfully — replay resolves it back to the real file, so output_sha256
        matches. This is the load-bearing guarantee: the chain is /home-free AND
        replay still finds the artifact.
        """
        case_home = tmp_path / ".findevil"
        env = {"FINDEVIL_HOME": str(case_home)}
        extracted = case_home / "cases" / "db256d79" / "extracted" / "disk" / "dx" / "mft"
        extracted.mkdir(parents=True)
        mft_file = extracted / "$MFT"
        mft_file.write_bytes(b"FILE0-real-mft-bytes")

        absolute = str(mft_file)
        relative = relativize_extracted_path(absolute, env=env)
        assert "/home/" not in relative
        assert str(tmp_path) not in relative

        # The mock parser hashes the FILE CONTENTS at the path it is handed, so a
        # path that fails to resolve would read nothing and drift the SHA.
        def handler(args: dict[str, object]) -> dict[str, object]:
            path = Path(str(args["mft_path"]))
            data = path.read_bytes() if path.is_file() else b""
            return {"sha": hashlib.sha256(data).hexdigest(), "row_count": len(data)}

        # Expected SHA: what the parser produces when handed the REAL absolute path.
        expected_output = handler({"mft_path": absolute})
        expected_sha = _sha(expected_output)

        client = MockMcpClient()
        client.register("mft_timeline", handler)

        # The audit record stores the /home-free RELATIVE path.
        record = {
            "tool_name": "mft_timeline",
            "arguments": {"case_id": "c-1", "mft_path": relative, "limit": 5000},
            "output_sha256": expected_sha,
        }
        artifact = replay_tool_call(tool_call_id="tc-1", record=record, mcp=client, env=env)
        assert artifact.drift_class == "exact_match", artifact.drift_reason
        assert artifact.matched is True
        # And the tool was actually handed the resolved ABSOLUTE path.
        _called_tool, called_args, _ = client.calls[-1]
        assert called_args["mft_path"] == absolute
