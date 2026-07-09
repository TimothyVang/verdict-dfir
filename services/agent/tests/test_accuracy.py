"""Tests for the pure accuracy-scoring core in ``findevil_agent.accuracy``.

This is the single source of truth that both ``scripts/score-recall.py`` and the
``accuracy_compare`` MCP shim import. The matching / precision / verdict-consistency
logic itself is already pinned by ``test_score_recall_precision.py`` (which loads it
through the script). These tests pin the *extracted module's* public surface and the
new ``negative_coverage`` block — the negative-assertion coverage a maintainer reads
to know the run avoided every planted-bait claim it was supposed to avoid.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from findevil_agent import accuracy

_REPO_ROOT = Path(__file__).resolve().parents[3]
_NIST_GOLDEN = _REPO_ROOT / "goldens" / "nist-hacking-case" / "expected-findings.json"


def _write_verdict(case_dir: Path, verdict: str, findings: list[dict[str, object]]) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc = {"case_id": "nist-hacking-case", "verdict": verdict, "findings": findings}
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


# Seven of the 14 SCHARDT ground-truth claims, worded with the distinctive tokens
# of each golden finding so token-overlap matching is unambiguous. 7/14 = 50%,
# below the golden's 71% min_recall — so this is a deliberate recall-MISS fixture.
_SEVEN_OF_FOURTEEN = [
    {
        "finding_id": "r-001",
        "description": "Dual-boot XP install linked-list recent searches hacking tools",
    },
    {
        "finding_id": "r-002",
        "description": "USB device insertion history external drive connected staging",
    },
    {
        "finding_id": "r-003",
        "description": "Recovered deleted email discussing the intrusion plan",
    },
    {
        "finding_id": "r-004",
        "description": "Hacking tool artifacts Program Files downloaded applications",
    },
    {
        "finding_id": "r-005",
        "description": "Prefetch evidence hacking tool execution",
    },
    {
        "finding_id": "r-006",
        "description": "Internet history indicating downloads illicit content",
    },
    {
        "finding_id": "r-007",
        "description": "Shellbag entries navigation removable media holding staged files",
    },
]


class TestScoreCore:
    def test_seven_of_fourteen_schardt_recall(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = accuracy.score(case_dir, _NIST_GOLDEN)
        assert result["expected_n"] == 14
        assert result["recalled_n"] == 7
        assert result["recall_percent"] == 50
        assert result["min_recall_percent"] == 71
        # verdict polarity agrees (EVIL/EVIL) ...
        assert result["verdict_match"] is True
        # ... but 50% < 71% min_recall, so the run does NOT pass.
        assert result["pass"] is False

    def test_score_reports_precision_and_f1_keys(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = accuracy.score(case_dir, _NIST_GOLDEN)
        for key in (
            "precision_percent",
            "f1",
            "hallucination_rate",
            "negative_coverage",
        ):
            assert key in result, f"missing {key}"


class TestNegativeCoverage:
    def test_clean_decoy_run_has_full_negative_coverage(self, tmp_path: Path) -> None:
        # A run that surfaces ZERO findings against the planted-DECOY golden
        # correctly avoids every known_negative / denylisted name.
        golden = _REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json"
        case_dir = _write_verdict(tmp_path / "decoy", "NO_EVIL", [])
        result = accuracy.score(case_dir, golden)
        neg = result["negative_coverage"]
        # 4 known_negatives in the decoy golden, all avoided.
        assert neg["known_negative_total"] == 4
        assert neg["known_negative_violations"] == 0
        assert neg["denylist_terms_asserted"] == 0
        assert neg["clean"] is True
        assert neg["coverage_percent"] == 100

    def test_asserting_denylisted_name_drops_negative_coverage(self, tmp_path: Path) -> None:
        golden = _REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json"
        # A hallucinated finding that asserts a denylisted malware name on the
        # benign decoy: planted-bait false positive.
        findings = [
            {
                "finding_id": "fp-1",
                "description": ("mimikatz credential dumping observed against lsass on this host"),
            }
        ]
        case_dir = _write_verdict(tmp_path / "decoy", "SUSPICIOUS", findings)
        result = accuracy.score(case_dir, golden)
        neg = result["negative_coverage"]
        assert neg["denylist_terms_asserted"] >= 1
        assert neg["clean"] is False
        assert neg["coverage_percent"] < 100
        # planted bait always fails the run.
        assert result["pass"] is False


class TestNegativeControl:
    """Tool-less / empty-evidence negative control proves the harness measures the floor.

    A run that had NO usable tools (or empty evidence) cannot ground any Finding, so
    against a golden that DOES enumerate real expected findings it MUST score recall=0.
    ``accuracy.negative_control`` runs the same scorer and adds a SEPARATE grounding
    posture (tool_less / grounding_empty / baseline_hallucination_n) — the deliberate-
    hallucination baseline is disclosed on the side, never folded into the headline.
    """

    _TOOLLESS_GOLDEN = _REPO_ROOT / "goldens" / "synthetic-toolless" / "expected-findings.json"

    def test_toolless_golden_enumerates_real_expected_findings(self) -> None:
        # Unlike synthetic-decoy (zero expected findings), this control needs real
        # expected findings so recall=0 is meaningful (there WAS something to find).
        golden = json.loads(self._TOOLLESS_GOLDEN.read_text(encoding="utf-8"))
        assert golden["case_id"] == "synthetic-toolless"
        assert len(golden["findings"]) >= 1
        assert int(golden["min_recall_percent"]) > 0

    def test_empty_toolless_run_scores_recall_zero_and_grounding_empty(
        self, tmp_path: Path
    ) -> None:
        # The honest tool-less posture: no tools => no findings => recall=0.
        case_dir = _write_verdict(tmp_path / "toolless", "INDETERMINATE", [])
        result = accuracy.negative_control(case_dir, self._TOOLLESS_GOLDEN)

        # Headline floor: a real-findings golden, recalled by nothing.
        assert result["expected_n"] >= 1
        assert result["recall_percent"] == 0

        nc = result["negative_control"]
        assert nc["tool_less"] is True
        assert nc["grounding_empty"] is True
        assert nc["grounded_finding_n"] == 0
        assert nc["baseline_hallucination_n"] == 0
        assert nc["floor_proven"] is True

    def test_ungrounded_hallucinations_are_disclosed_separately(self, tmp_path: Path) -> None:
        # A tool-less run that nonetheless emits claims: every claim lacks a
        # tool_call_id, so it is grounding-empty. The ungrounded claims are counted
        # as baseline hallucinations in the SEPARATE posture block, and because none
        # is grounded the headline recall stays 0 — hallucinations never earn recall.
        findings = [
            {"finding_id": "h-1", "description": "fabricated lateral movement with no cited tool"},
            {"finding_id": "h-2", "description": "invented exfiltration over an imagined channel"},
        ]
        case_dir = _write_verdict(tmp_path / "halluc", "SUSPICIOUS", findings)
        result = accuracy.negative_control(case_dir, self._TOOLLESS_GOLDEN)

        nc = result["negative_control"]
        assert nc["run_finding_n"] == 2
        assert nc["grounded_finding_n"] == 0
        assert nc["grounding_empty"] is True
        assert nc["baseline_hallucination_n"] == 2
        # Not folded into the headline: recall is still the floor.
        assert result["recall_percent"] == 0

    def test_grounded_finding_is_not_counted_as_baseline_hallucination(
        self, tmp_path: Path
    ) -> None:
        # A finding that DOES cite a tool_call_id is grounded, so the run is no
        # longer tool-less and that finding is not a baseline hallucination.
        findings = [
            {
                "finding_id": "g-1",
                "tool_call_id": "tc-abc123",
                "description": "Malicious service installation persistence in the system services hive",
            },
        ]
        case_dir = _write_verdict(tmp_path / "grounded", "SUSPICIOUS", findings)
        result = accuracy.negative_control(case_dir, self._TOOLLESS_GOLDEN)

        nc = result["negative_control"]
        assert nc["grounded_finding_n"] == 1
        assert nc["grounding_empty"] is False
        assert nc["tool_less"] is False
        assert nc["baseline_hallucination_n"] == 0
        # With a grounded match the floor is no longer "proven" (this is a real run).
        assert nc["floor_proven"] is False


class TestCorpusIdentity:
    """Scope caveats: validation_class + training-data-contamination caveat.

    A golden's epistemic class drives whether its recall number carries a
    contamination caveat. A public-documented (published walkthrough) corpus may
    already be in a model's training data, so its recall is a lower bound on rigor,
    not proof of from-scratch detection — it MUST surface a non-empty caveat. A
    synthetic corpus carries no such risk and emits an empty caveat.
    """

    def test_public_documented_golden_emits_contamination_caveat(self) -> None:
        golden = {"validation_class": "public-documented", "source_url": "https://example/case"}
        ident = accuracy.corpus_identity(golden)
        assert ident["validation_class"] == "public-documented"
        assert ident["corpus_identity"] == "public"
        assert ident["contamination_caveat"]  # non-empty
        assert "contamination" in ident["contamination_caveat"].lower()

    def test_synthetic_golden_has_no_contamination_caveat(self) -> None:
        golden = {"validation_class": "synthetic"}
        ident = accuracy.corpus_identity(golden)
        assert ident["validation_class"] == "synthetic"
        assert ident["corpus_identity"] == "synthetic"
        assert ident["contamination_caveat"] == ""

    def test_held_out_golden_has_no_contamination_caveat(self) -> None:
        golden = {"validation_class": "held-out"}
        ident = accuracy.corpus_identity(golden)
        assert ident["validation_class"] == "held-out"
        assert ident["corpus_identity"] == "held-out"
        assert ident["contamination_caveat"] == ""

    def test_http_source_url_defaults_to_public_documented(self) -> None:
        # NIST golden cites an https source and declares no validation_class:
        # the conservative default is public-documented (contamination-aware).
        golden = json.loads(_NIST_GOLDEN.read_text(encoding="utf-8"))
        ident = accuracy.corpus_identity(golden)
        assert ident["validation_class"] == "public-documented"
        assert ident["corpus_identity"] == "public"
        assert ident["contamination_caveat"]

    def test_non_url_source_defaults_to_synthetic(self) -> None:
        # synthetic-decoy's source_url is a generator note, not an http URL.
        golden = json.loads(
            (_REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json").read_text(
                encoding="utf-8"
            )
        )
        ident = accuracy.corpus_identity(golden)
        assert ident["validation_class"] == "synthetic"
        assert ident["contamination_caveat"] == ""

    def test_score_surfaces_validation_class_and_does_not_measure(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = accuracy.score(case_dir, _NIST_GOLDEN)
        # NIST is a public-documented corpus by default -> caveat present.
        assert result["validation_class"] == "public-documented"
        assert result["corpus_identity"] == "public"
        assert result["contamination_caveat"]
        assert result["does_not_measure"]  # non-empty list of scope caveats


class TestArtifactNormalizer:
    """The deterministic artifact-identifier normalizer used by the matching layer.

    Cosmetic differences between how two artifact classes name the SAME file
    (path prefix, case, separators, Windows kernel EPROCESS.ImageFileName
    truncation, IOC pivot metadata) must not deflate recall or precision. These
    pin the signature-based normalizer — no image-specific literals (generic OS
    process names only), so the evidence-agnostic guard stays green.
    """

    def test_kernel_truncated_process_name_matches_full(self) -> None:
        # The kernel-clipped form names the same file as the full name.
        assert accuracy.artifacts_match("svchost.ex", "svchost.exe") is True

    def test_real_15char_eprocess_truncation_matches(self) -> None:
        full = "longprocessname.exe"  # > 15 chars
        truncated = full[:15]  # what EPROCESS.ImageFileName surfaces
        assert len(truncated) == 15
        assert accuracy.artifacts_match(truncated, full) is True

    def test_case_and_separator_variants_match(self) -> None:
        assert accuracy.artifacts_match("C:\\Windows\\System32\\SVCHOST.EXE", "svchost.exe") is True
        assert accuracy.artifacts_match("/usr/bin/Cron", "cron") is True

    def test_ioc_pivot_metadata_stripped_to_leading_token(self) -> None:
        assert accuracy.normalize_artifact_id("evil.exe (pid 1234)") == "evil.exe"
        assert accuracy.normalize_artifact_id("10.0.0.5:443") == "10.0.0.5"
        assert accuracy.artifacts_match("payload.dll -> child", "C:\\temp\\payload.dll") is True

    def test_genuinely_different_artifacts_do_not_match(self) -> None:
        assert accuracy.artifacts_match("powershell.exe", "svchost.exe") is False
        # A 3-char generic prefix is too short to be a truncation match.
        assert accuracy.artifacts_match("svc", "svchost.exe") is False
        assert accuracy.artifacts_match("", "svchost.exe") is False
        assert accuracy.artifacts_match("svchost.exe", None) is False

    def test_matching_layer_recalls_on_artifact_identity(self, tmp_path: Path) -> None:
        # A run finding sharing no distinctive description tokens still recalls an
        # expected claim when both name the same file (identifier-shaped hint +
        # kernel-truncated run artifact_path).
        golden = {
            "case_id": "syn",
            "verdict": "SUSPICIOUS",
            "min_recall_percent": 100,
            "findings": [
                {
                    "finding_id": "g1",
                    "description": "malicious persistence binary dropped on host",
                    "artifact_hint": "C:\\Windows\\System32\\longprocessname.exe",
                }
            ],
        }
        gp = tmp_path / "expected-findings.json"
        gp.write_text(json.dumps(golden), encoding="utf-8")
        run = [
            {
                "finding_id": "r1",
                "description": "anomalous service observed running",
                "artifact_path": "longprocessname",  # 15-char kernel truncation
            }
        ]
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", run)
        result = accuracy.score(case_dir, gp)
        assert result["recalled_n"] == 1

    def test_prose_hint_does_not_inflate_via_artifact_identity(self, tmp_path: Path) -> None:
        # A free-text (non-identifier) hint must NOT be reduced to a leading token
        # and matched against a run artifact_path — that would inflate recall.
        golden = {
            "case_id": "syn",
            "verdict": "SUSPICIOUS",
            "min_recall_percent": 100,
            "findings": [
                {
                    "finding_id": "g1",
                    "description": "registry persistence under the run key",
                    "artifact_hint": "SYSTEM hive service control records",
                }
            ],
        }
        gp = tmp_path / "expected-findings.json"
        gp.write_text(json.dumps(golden), encoding="utf-8")
        run = [
            {
                "finding_id": "r1",
                "description": "unrelated network beacon observed",
                "artifact_path": "C:\\Windows\\System32\\config\\SYSTEM",
            }
        ]
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", run)
        result = accuracy.score(case_dir, gp)
        assert result["recalled_n"] == 0


class TestScriptStillImportsCore:
    def test_score_recall_script_delegates_to_core(self, tmp_path: Path) -> None:
        # The hyphenated maintainer script must keep working by loading the
        # extracted core from the SAME source file — single source of truth, no
        # logic fork. (It loads accuracy.py by path, not via `import
        # findevil_agent.accuracy`, to stay stdlib-only / bare-python3 runnable;
        # so we assert same-source-file, then identical output.)
        import importlib.util

        script = _REPO_ROOT / "scripts" / "score-recall.py"
        spec = importlib.util.spec_from_file_location("score_recall_core", script)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Same source file backs both the script and the package import.
        assert Path(mod._ACC_PATH).resolve() == Path(accuracy.__file__).resolve()

        # And both produce byte-identical results on the same fixture.
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        assert mod.score(case_dir, _NIST_GOLDEN) == accuracy.score(case_dir, _NIST_GOLDEN)


def _write_attack_coverage_verdict(case_dir: Path, targets: list[dict[str, object]]) -> Path:
    """Write a verdict.json carrying only the attack_coverage matrix the runner reads."""
    case_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "case_id": "synthetic-attack",
        "verdict": "SUSPICIOUS",
        "findings": [],
        "attack_coverage": {"targets": targets},
    }
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


class TestAttackCoverageMatrix:
    def test_full_coverage_when_every_technique_meets_minimum(self, tmp_path: Path) -> None:
        targets = [
            {
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "status": "finding",
                "finding_confidence": "HIGH",
                "artifact_classes_observed": ["disk/filesystem"],
            },
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "status": "finding",
                "finding_confidence": "HIGH",
                "artifact_classes_observed": ["memory", "evtx"],
            },
        ]
        case_dir = _write_attack_coverage_verdict(tmp_path / "case", targets)
        spec = {
            "case_id": "synthetic-attack",
            "techniques": [
                {"technique_id": "T1547.001", "min_artifact_classes": 1},
                {"technique_id": "T1003", "min_artifact_classes": 2},
            ],
        }
        result = accuracy.score_attack_coverage(case_dir, spec)
        assert result["technique_n"] == 2
        assert result["covered_n"] == 2
        assert result["under_corroborated_n"] == 0
        assert result["missing_n"] == 0
        assert result["full_coverage"] is True
        statuses = {row["technique_id"]: row["status"] for row in result["matrix"]}
        assert statuses == {"T1547.001": "covered", "T1003": "covered"}

    def test_missing_and_under_corroborated_statuses(self, tmp_path: Path) -> None:
        # T1003 observed with TWO classes -> covered.
        # T1547.001 observed with ONE class but min 2 -> under_corroborated
        #   (respects the >=2-class corroboration rule).
        # T1071.001 not present in the matrix at all -> missing.
        targets = [
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "status": "finding",
                "finding_confidence": "HIGH",
                "artifact_classes_observed": ["memory", "evtx"],
            },
            {
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "status": "covered_no_finding",
                "finding_confidence": None,
                "artifact_classes_observed": ["disk/filesystem"],
            },
        ]
        case_dir = _write_attack_coverage_verdict(tmp_path / "case", targets)
        spec = {
            "case_id": "synthetic-attack",
            "techniques": [
                {"technique_id": "T1003", "min_artifact_classes": 2},
                {"technique_id": "T1547.001", "min_artifact_classes": 2},
                {"technique_id": "T1071.001", "min_artifact_classes": 1},
            ],
        }
        result = accuracy.score_attack_coverage(case_dir, spec)
        statuses = {row["technique_id"]: row["status"] for row in result["matrix"]}
        assert statuses["T1003"] == "covered"
        assert statuses["T1547.001"] == "under_corroborated"
        assert statuses["T1071.001"] == "missing"
        assert result["covered_n"] == 1
        assert result["under_corroborated_n"] == 1
        assert result["missing_n"] == 1
        assert result["full_coverage"] is False

    def test_accepts_assertions_path_directly(self, tmp_path: Path) -> None:
        # The runner accepts either a parsed spec dict or a path to the YAML file.
        targets = [
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "status": "finding",
                "finding_confidence": "HIGH",
                "artifact_classes_observed": ["memory", "evtx"],
            },
        ]
        case_dir = _write_attack_coverage_verdict(tmp_path / "case", targets)
        yaml_path = tmp_path / "attack-assertions.yaml"
        yaml_path.write_text(
            "case_id: synthetic-attack\n"
            "techniques:\n"
            "  - technique_id: T1003\n"
            "    min_artifact_classes: 2\n",
            encoding="utf-8",
        )
        result = accuracy.score_attack_coverage(case_dir, yaml_path)
        assert result["full_coverage"] is True
        assert result["matrix"][0]["status"] == "covered"


class TestAntiFakeReplay:
    """The scorer is physically unable to fake a 'live' number: scoring stays
    model-free (a live client raises) and the result is content-addressed, so a
    rerun replays bit-identically and any altered input misses the cache."""

    def test_non_fake_client_raises(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)

        class _LiveClient:
            pass

        with pytest.raises(TypeError):
            accuracy.score_replayable(case_dir, _NIST_GOLDEN, model_client=_LiveClient())

    def test_fake_client_and_none_are_accepted(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        # None (no client) and the offline FakeModelClient are the only allowed values.
        accuracy.score_replayable(case_dir, _NIST_GOLDEN, model_client=None)
        accuracy.score_replayable(case_dir, _NIST_GOLDEN, model_client=accuracy.FakeModelClient())

    def test_cache_hit_returns_identical_output(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        cache: dict[str, dict[str, object]] = {}
        first = accuracy.score_replayable(case_dir, _NIST_GOLDEN, cache=cache)
        second = accuracy.score_replayable(case_dir, _NIST_GOLDEN, cache=cache)
        assert len(cache) == 1
        assert first == second
        # A genuine cache hit returns the same object the first run stored.
        assert second is cache[first["cache_key"]]

    def test_cache_miss_on_altered_verdict(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        cache: dict[str, dict[str, object]] = {}
        before = accuracy.score_replayable(case_dir, _NIST_GOLDEN, cache=cache)
        # Drift the run output -> different content -> different key -> recompute.
        _write_verdict(case_dir, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN[:6])
        after = accuracy.score_replayable(case_dir, _NIST_GOLDEN, cache=cache)
        assert before["cache_key"] != after["cache_key"]
        assert len(cache) == 2

    def test_cache_miss_on_provenance_drift(self, tmp_path: Path) -> None:
        # Same artifacts, different model/prompt provenance -> different key, so a
        # number from one model/prompt can never replay as another's.
        case_dir = _write_verdict(tmp_path / "case", "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        k1 = accuracy.cache_key(case_dir, _NIST_GOLDEN, model_snapshot_id="m-1")
        k2 = accuracy.cache_key(case_dir, _NIST_GOLDEN, model_snapshot_id="m-2")
        k3 = accuracy.cache_key(case_dir, _NIST_GOLDEN, prompt_template_hash="p-9")
        assert len({k1, k2, k3}) == 3
