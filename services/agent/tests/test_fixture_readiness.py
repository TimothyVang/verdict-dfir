"""Regression tests for the L3 golden-fixture readiness boundary.

An answer key and a directory are not sufficient to make a benchmark scorable.
The staged fixture must contain engine-supported evidence, and explicitly
NOT_READY answer keys must remain excluded even if placeholder files exist.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
_SPEC = importlib.util.spec_from_file_location(
    "fixture_readiness", _SCRIPTS / "fixture-readiness.py"
)
assert _SPEC and _SPEC.loader
fixture_readiness = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fixture_readiness)


def _golden(tmp_path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {
        "case_id": "case",
        "source_url": "https://example.invalid/case",
        "license": "test",
        "verdict": "INDETERMINATE",
        "min_recall_percent": 0,
        "findings": [],
        **overrides,
    }
    path = tmp_path / "expected-findings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_explicit_not_ready_fixture_is_not_scorable(tmp_path: Path) -> None:
    golden = _golden(
        tmp_path,
        scoring_status="not_ready",
        not_ready_reason="placeholder is not forensic evidence",
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "sample.evtx").write_bytes(b"ElfFile\x00payload")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is False
    assert result.reason == "placeholder is not forensic evidence"


def test_cli_distinguishes_not_ready_from_checker_error(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    golden = _golden(
        tmp_path,
        scoring_status="not_ready",
        not_ready_reason="fixture acquisition is incomplete",
    )

    not_ready = subprocess.run(
        [
            sys.executable,
            str(_SCRIPTS / "fixture-readiness.py"),
            "--json",
            str(golden),
            str(fixture),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert not_ready.returncode == 3
    assert json.loads(not_ready.stdout)["status"] == "NOT_READY"

    golden.write_text(
        json.dumps(
            {
                "case_id": "case",
                "scoring_status": "invalid",
                "min_recall_percent": 0,
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    checker_error = subprocess.run(
        [
            sys.executable,
            str(_SCRIPTS / "fixture-readiness.py"),
            "--json",
            str(golden),
            str(fixture),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert checker_error.returncode == 2
    assert json.loads(checker_error.stdout)["status"] == "ERROR"


def test_documentation_and_archives_alone_are_not_scorable(tmp_path: Path) -> None:
    golden = _golden(tmp_path)
    fixture = tmp_path / "fixture"
    (fixture / ".git").mkdir(parents=True)
    (fixture / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (fixture / "README.md").write_text("scenario source", encoding="utf-8")
    (fixture / "telemetry.tar.gz").write_bytes(b"not extracted telemetry")
    (fixture / "telemetry.zip").write_bytes(b"not extracted telemetry")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is False
    assert "no supported evidence artifacts" in result.reason


def test_nonempty_supported_evidence_is_scorable(tmp_path: Path) -> None:
    golden = _golden(tmp_path)
    fixture = tmp_path / "fixture"
    evidence = fixture / "nested" / "Security.evtx"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"ElfFile\x00payload")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is True
    assert result.artifacts == ("nested/Security.evtx",)


def test_empty_supported_evidence_is_not_scorable(tmp_path: Path) -> None:
    golden = _golden(tmp_path)
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "events.json").touch()

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is False
    assert "no supported evidence artifacts" in result.reason


def test_completeness_contract_returns_staging_root_and_analysis_entrypoint(
    tmp_path: Path,
) -> None:
    archive_bytes = b"canonical challenge archive"
    golden = _golden(
        tmp_path,
        fixture_contract={
            "source_artifact": {
                "path": "source/challenge.zip",
                "size_bytes": len(archive_bytes),
                "sha1": hashlib.sha1(archive_bytes).hexdigest(),
            },
            "staging_root": "canonical/response_data",
            "analysis_entrypoint": "primary.evtx",
            "required_artifacts": [
                {"path": "primary.evtx", "size_bytes": 15},
                {"path": "suspect.pcap", "size_bytes": 12},
            ],
        },
    )
    fixture = tmp_path / "fixture"
    source = fixture / "source" / "challenge.zip"
    source.parent.mkdir(parents=True)
    source.write_bytes(archive_bytes)
    staging_root = fixture / "canonical" / "response_data"
    staging_root.mkdir(parents=True)
    (staging_root / "primary.evtx").write_bytes(b"ElfFile\x00payload")
    (staging_root / "suspect.pcap").write_bytes(b"pcap payload")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is True
    assert result.staging_root == staging_root
    assert result.analysis_entrypoint == staging_root / "primary.evtx"


def test_missing_required_artifact_is_not_scorable(tmp_path: Path) -> None:
    golden = _golden(
        tmp_path,
        fixture_contract={
            "staging_root": "canonical",
            "analysis_entrypoint": "primary.evtx",
            "required_artifacts": [
                {"path": "primary.evtx", "size_bytes": 15},
                {"path": "segment.002", "size_bytes": 8},
            ],
        },
    )
    fixture = tmp_path / "fixture"
    staging_root = fixture / "canonical"
    staging_root.mkdir(parents=True)
    (staging_root / "primary.evtx").write_bytes(b"ElfFile\x00payload")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is False
    assert "missing required artifact: segment.002" in result.reason


def test_complete_artifact_without_known_integrity_is_rejected(tmp_path: Path) -> None:
    golden = _golden(
        tmp_path,
        fixture_contract={
            "staging_root": ".",
            "analysis_entrypoint": "primary.evtx",
            "required_artifacts": [
                {
                    "path": "primary.evtx",
                    "size_bytes": 15,
                    "sha512": "not-a-supported-integrity-contract",
                }
            ],
        },
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "primary.evtx").write_bytes(b"ElfFile\x00payload")

    try:
        fixture_readiness.evaluate_fixture(golden, fixture)
    except ValueError as exc:
        assert "requires a digest" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("unknown integrity algorithm must fail closed")


def test_source_artifact_hash_mismatch_is_not_scorable(tmp_path: Path) -> None:
    golden = _golden(
        tmp_path,
        fixture_contract={
            "source_artifact": {
                "path": "source/challenge.zip",
                "size_bytes": 7,
                "sha1": hashlib.sha1(b"trusted").hexdigest(),
            },
            "staging_root": ".",
            "analysis_entrypoint": ".",
            "required_artifacts": [
                {
                    "path": "challenge.mem",
                    "size_bytes": 7,
                    "sha1": hashlib.sha1(b"payload").hexdigest(),
                }
            ],
        },
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "challenge.mem").write_bytes(b"payload")
    source = fixture / "source" / "challenge.zip"
    source.parent.mkdir()
    source.write_bytes(b"altered")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is False
    assert "sha1 mismatch" in result.reason


def test_verified_zip_source_rejects_tampered_extraction(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    source = fixture / "source" / "challenge.zip"
    source.parent.mkdir(parents=True)
    expected_evidence = b"ElfFile\x00payload"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("response_data/primary.evtx", expected_evidence)
    golden = _golden(
        tmp_path,
        fixture_contract={
            "source_artifact": {
                "path": "source/challenge.zip",
                "size_bytes": source.stat().st_size,
                "sha1": hashlib.sha1(source.read_bytes()).hexdigest(),
                "archive_type": "zip",
                "member_root": "response_data",
                "strict_members": True,
            },
            "staging_root": "canonical/response_data",
            "analysis_entrypoint": ".",
            "required_artifacts": [{"path": "primary.evtx", "size_bytes": len(expected_evidence)}],
        },
    )
    staging_root = fixture / "canonical" / "response_data"
    staging_root.mkdir(parents=True)
    staging_root.joinpath("primary.evtx").write_bytes(b"ElfFile\x00tamper!")

    result = fixture_readiness.evaluate_fixture(golden, fixture)

    assert result.ready is False
    assert "archive member content mismatch" in result.reason


def test_known_placeholder_goldens_are_explicitly_not_ready() -> None:
    for case_id in ("synthetic-benign", "synthetic-decoy", "otrf-apt3-mordor"):
        golden = json.loads(
            (_REPO_ROOT / "goldens" / case_id / "expected-findings.json").read_text(
                encoding="utf-8"
            )
        )
        assert golden.get("scoring_status") == "not_ready", case_id
        assert golden.get("not_ready_reason"), case_id


def test_dfrws_golden_pins_canonical_challenge_entrypoint() -> None:
    golden = json.loads(
        (_REPO_ROOT / "goldens" / "dfrws-2008-linux" / "expected-findings.json").read_text(
            encoding="utf-8"
        )
    )

    contract = golden["fixture_contract"]
    assert contract["staging_root"] == "canonical/response_data"
    assert contract["analysis_entrypoint"] == "."
    assert contract["source_artifact"] == {
        "path": "details/dfrws2008-challenge.zip",
        "size_bytes": 94421088,
        "sha1": "52014e22c843ece2736bce59f652f43e96035825",
        "archive_type": "zip",
        "member_root": "response_data",
        "strict_members": True,
    }
    required = {item["path"]: item for item in contract["required_artifacts"]}
    assert required["challenge.mem"]["size_bytes"] == 297795584
    assert required["suspect.pcap"]["size_bytes"] == 5110493


def test_nist_golden_requires_all_official_schardt_segments() -> None:
    golden = json.loads(
        (_REPO_ROOT / "goldens" / "nist-hacking-case" / "expected-findings.json").read_text(
            encoding="utf-8"
        )
    )

    contract = golden["fixture_contract"]
    assert contract["staging_root"] == "."
    assert contract["analysis_entrypoint"] == "SCHARDT.001"
    required = contract["required_artifacts"]
    assert [item["path"] for item in required] == [f"SCHARDT.{part:03d}" for part in range(1, 9)]
    assert all(item.get("md5") for item in required)
    assert [item["size_bytes"] for item in required] == [
        *([666238976] * 7),
        207628288,
    ]


def test_fetcher_materializes_only_complete_canonical_fixture_entrypoints() -> None:
    text = (_SCRIPTS / "fetch-fixtures.sh").read_text(encoding="utf-8")

    assert "NIST_SCHARDT_SEGMENTS" in text
    assert 'golden["fixture_contract"]["required_artifacts"]' in text
    assert "dfrws2008-challenge.zip" in text
    assert "DFRWS2008_ARCHIVE_SIZE=94421088" in text
    assert "DFRWS2008_ARCHIVE_SHA1=52014e22c843ece2736bce59f652f43e96035825" in text
    assert '"${FIXTURES}/dfrws-2008-linux/canonical"' in text


def test_l3_runner_checks_readiness_before_copy_or_score() -> None:
    text = (_SCRIPTS / "l3-run-goldens.sh").read_text(encoding="utf-8")
    readiness = text.index("fixture-readiness.py")
    copy = text.index('scp_to "${staging_root}"')
    score = text.index("score-recall.py", copy)

    assert readiness < copy < score


def test_l3_runner_fails_on_readiness_errors_but_skips_not_ready() -> None:
    text = (_SCRIPTS / "l3-run-goldens.sh").read_text(encoding="utf-8")

    assert "readiness_exit=$?" in text
    assert 'if [[ "${readiness_exit}" -eq 3 ]]' in text
    assert 'log "SKIP ${fixture}: NOT_READY ${readiness_reason}"' in text
    assert 'log "FAIL ${fixture}: fixture readiness ERROR ${readiness_reason}"' in text
    assert "OVERALL_EXIT=1" in text


def test_l3_runner_excludes_not_scoreable_goldens_instead_of_failing_them() -> None:
    """Exit 3 from the scorer is EXCLUDED-by-key, not an accuracy failure.

    The runner used to map ANY non-zero from score-recall.py to
    "FAIL ... (see <case>/recall-score.json)" — and on the refusal paths that file
    is never written, so the operator was pointed at nothing. Three branches now:
    0 PASS, 3 EXCLUDED (no OVERALL_EXIT change), anything else FAIL.
    """
    text = (_SCRIPTS / "l3-run-goldens.sh").read_text(encoding="utf-8")

    assert "score_exit=$?" in text
    assert 'if [[ "${score_exit}" -eq 3 ]]' in text
    assert 'log "EXCLUDED ${fixture}:' in text
    # The excluded branch must not mark the whole run failed.
    excluded = text.index('log "EXCLUDED ${fixture}:')
    fail = text.index('log "FAIL ${fixture}: recall below target', excluded)
    assert "OVERALL_EXIT=1" not in text[excluded:fail]
    # And the real-FAIL message still points at the file that path actually writes.
    assert "recall-score.json" in text[fail : fail + 200]


def test_l3_runner_copies_only_staging_root_and_uses_analysis_entrypoint() -> None:
    text = (_SCRIPTS / "l3-run-goldens.sh").read_text(encoding="utf-8")

    assert 'scp_to "${staging_root}"' in text
    assert 'case_path="${remote_staging_root}/${analysis_entrypoint}"' in text
    assert "printf -v case_path_q '%q'" in text
    assert "find-evil-auto ${case_path_q}" in text
