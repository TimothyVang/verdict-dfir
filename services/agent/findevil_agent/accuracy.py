"""Pure ground-truth accuracy-scoring core — the single source of truth.

This module holds the *domain logic* for grading a finished Case against a curated
ground-truth golden: recall, precision/F1, hallucination rate, verdict consistency,
planted-bait detection, and negative-assertion coverage. It is offline and
read-only — it reads a case directory's ``verdict.json`` and a matching
``goldens/<id>/expected-findings.json`` and returns a plain report dict. It never
touches the sealed audit chain and is never part of the investigation pipeline.

Two callers share this one core (no logic fork):

  * ``scripts/score-recall.py`` — the hyphenated maintainer/grading CLI, which
    imports :func:`score` (and the resolver helpers) and adds only the CLI/printing
    layer; and
  * the ``accuracy_compare`` MCP shim — a read-only, audit-chained *diagnostic*
    tool. It is NOT a Finding: per CLAUDE.md, optional automation/scoring sidecars
    are never evidence and never create Findings, so the shim appends only a
    non-Finding ``accuracy_diagnostic`` audit record.

Matching: an expected finding is RECALLED when some run finding covers enough of
its distinctive description/artifact-hint tokens (coverage over the expected token
set, not symmetric Jaccard, so a verbose-but-correct run finding still matches a
concise ground-truth claim). MITRE technique is deliberately not a match shortcut.

Precision: a run finding matched to no expected claim is ``extra``. On an
``exhaustive`` (closed-world) key every extra is a false positive; on an open-world
key an extra is only PROVABLY wrong when it asserts a planted ``anti_fact``, a
``known_negative`` (benign IOC-lookalike), or a ``named_claim_denylist`` term.

Negative-assertion coverage: of the negative assertions a correct run must AVOID
(every ``anti_fact`` / ``known_negative`` / denylisted name in the key), how many
did the run correctly stay away from. 100% coverage means zero planted-bait
hallucinations.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

# A run finding matches an expected one when it COVERS this fraction of the
# expected finding's distinctive tokens. Recall asks "did the run surface this
# ground-truth claim?" — so we normalize the overlap by the expected token set,
# not by the union (symmetric Jaccard unfairly penalizes verbose run findings
# that fully state the claim and then add caveats). Set at 0.5 so a match needs the
# *distinctive* tokens of the claim, not just shared generic DFIR vocabulary
# (email/host/http) that a semantically-unrelated finding can accumulate to ~0.4.
MATCH_COVERAGE = 0.5
# Floor on absolute shared tokens so a tiny expected set can't match on one or
# two generic words that survived stopword removal.
MATCH_MIN_SHARED = 3

# Tokens with no discriminating power for DFIR finding descriptions.
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "via",
        "with",
        "within",
        "shows",
        "show",
        "indicates",
        "indicating",
        "evidence",
        "artifact",
        "artifacts",
        "file",
        "files",
        "entry",
        "entries",
        "consistent",
        "suspicious",
        "recent",
        "recently",
    ]
)

# Verdict words the product emits, grouped by polarity. INDETERMINATE is handled
# separately (always accepted). Goldens use the same vocabulary as verdict.json.
_EVIL_WORDS = frozenset({"CONFIRMED_EVIL", "SUSPICIOUS", "SUSPICION", "EVIL"})
_BENIGN_WORDS = frozenset({"NO_EVIL", "BENIGN"})
_NEUTRAL_WORDS = frozenset({"UNKNOWN", "INDETERMINATE"})

# Epistemic class of a golden's evidence corpus, by how strong a recall number on
# it actually is. A golden may declare ``validation_class`` explicitly; otherwise
# it is derived conservatively (see :func:`_default_validation_class`).
#   * synthetic         — purpose-built fixture; no public walkthrough exists, so a
#                         model cannot have memorized its answer.
#   * public-documented — a published, documented case (e.g. a NIST/CTF dataset
#                         with a public writeup). A foundation model's training
#                         data may already contain its analysis, so recall here
#                         can reflect MEMORIZATION, not from-scratch detection.
#   * held-out          — a private/embargoed case kept out of public corpora; a
#                         recall number on it is the strongest generalization
#                         signal of the three.
_VALIDATION_CLASSES = frozenset({"synthetic", "public-documented", "held-out"})

# Short corpus-identity label the accuracy report prints per class.
_CORPUS_IDENTITY = {
    "synthetic": "synthetic",
    "public-documented": "public",
    "held-out": "held-out",
}

# Inline caveat emitted ONLY for a public-documented corpus. Synthetic and held-out
# corpora do not carry training-data-contamination risk, so their caveat is empty.
_CONTAMINATION_CAVEAT = (
    "validation_class=public-documented: this golden is a PUBLISHED, documented "
    "case, so a foundation model's training data may already contain its analysis. "
    "Recall here can reflect memorization, not from-scratch detection — read it as "
    "a lower bound on rigor, not proof of generalization. Synthetic and held-out "
    "corpora do not carry this training-data-contamination risk."
)

# What ground-truth accuracy scoring does NOT measure, surfaced alongside every
# score so a reader never reads recall/precision as more than it is.
DOES_NOT_MEASURE = (
    "custody integrity of the run (that is manifest_verify, not this score)",
    "generalization beyond the scored corpus and artifact classes",
    "coverage of artifact classes absent from this case",
    "whether a public-documented case was solved from scratch vs. recalled from "
    "training data (see contamination_caveat / validation_class)",
)


def _default_validation_class(golden: dict[str, Any]) -> str:
    """Conservative default when a golden omits ``validation_class``.

    A golden whose ``source_url`` is a real http(s) link is assumed
    public-documented (the contamination-aware default — a public dataset usually
    has a public writeup). Anything else (no URL, or a generator note like
    ``generated by scripts/fetch-fixtures.sh``) is treated as synthetic. Goldens
    should declare ``validation_class`` explicitly to override this default,
    especially to claim ``held-out``.
    """
    src = (golden.get("source_url") or "").strip().lower()
    return "public-documented" if src.startswith(("http://", "https://")) else "synthetic"


def corpus_identity(golden: dict[str, Any]) -> dict[str, Any]:
    """Classify a golden's corpus for honest accuracy reporting.

    Returns ``{validation_class, corpus_identity, contamination_caveat}``. The
    caveat is non-empty ONLY for a public-documented corpus (a published
    walkthrough whose answer may sit in model training data); synthetic and
    held-out corpora get an empty caveat. A golden's declared ``validation_class``
    wins; an unrecognized or missing value falls back to
    :func:`_default_validation_class`.
    """
    declared = (golden.get("validation_class") or "").strip().lower()
    vc = declared if declared in _VALIDATION_CLASSES else _default_validation_class(golden)
    return {
        "validation_class": vc,
        "corpus_identity": _CORPUS_IDENTITY[vc],
        "contamination_caveat": _CONTAMINATION_CAVEAT if vc == "public-documented" else "",
    }


# --- Artifact-identifier normalization ---------------------------------------
# Cosmetic differences in how two artifact classes name the SAME file must not
# deflate recall/precision. Windows kernel EPROCESS.ImageFileName is a fixed-width
# field, so a process name longer than the field is truncated by the kernel: vol
# pslist/psscan surface the clipped form while disk / Prefetch / Amcache artifacts
# carry the full name. The field holds 15 bytes (one reserved for the trailing
# NUL), so the observable truncation boundary is 14-15 visible characters.
_KERNEL_IMAGENAME_LEN = 15
# Shortest prefix that can stand in for a truncation match — a 1-3 char fragment
# is too generic to assert "same file" and would over-match distinct names.
_MIN_TRUNCATION_STEM = 4
# Trailing chars a non-kernel cosmetic truncation may drop (e.g. a clipped ext).
_TRUNCATION_TAIL_TOLERANCE = 2

# IOC pivot strings carry trailing metadata after the identifier
# (``name.exe (pid 1234)``, ``name.exe -> child``); split it off at the first
# whitespace / list separator so only the leading filename/host token remains.
_IOC_PIVOT_SPLIT_RE = re.compile(r"[\s,;|>()\[\]]+")
# An artifact-identifier-shaped hint: a path, a single token with a short file
# extension, or a host[:port] / IPv4. Prose hints ("SYSTEM hive USBSTOR + ...")
# are deliberately NOT identifiers, so they never feed the filename matcher and
# cannot inflate recall by collapsing to a generic leading token.
_IDENTIFIER_RE = re.compile(
    r"""^(?:
        [a-z0-9._*:-]*[\\/][a-z0-9._*\\/:-]*   # contains a path separator
      | [a-z0-9._*-]+\.[a-z0-9]{1,6}           # token.ext
      | (?:\d{1,3}\.){3}\d{1,3}(?::\d+)?       # ipv4[:port]
      | [a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?   # host.name[:port]
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def normalize_artifact_id(value: str | None) -> str:
    """Deterministically normalize an artifact identifier for comparison.

    Reduces an IOC pivot string to its leading filename/host token, strips any
    directory path to the basename, normalizes case and path separators, and
    drops a trailing ``:port``/``:pid`` from a host token. Returns ``""`` for
    empty input. Pure and signature-based — no image-specific values.
    """
    if not value:
        return ""
    text = value.strip().lower()
    if not text:
        return ""
    # IOC pivot metadata -> leading token (filename / host before the first
    # whitespace or list separator).
    head = _IOC_PIVOT_SPLIT_RE.split(text, 1)[0]
    # path -> basename (handle both Windows '\' and POSIX '/').
    base = re.split(r"[\\/]", head)[-1]
    # drop a trailing :port / :pid on a host token ('host:443' -> 'host'); a
    # Windows drive letter was already removed by the basename split above.
    return base.split(":", 1)[0].strip()


def _is_truncation_match(short: str, long: str) -> bool:
    """``short`` is a kernel/cosmetic truncation of ``long`` (same file)."""
    if len(short) < _MIN_TRUNCATION_STEM or not long.startswith(short):
        return False
    # Genuine EPROCESS truncation: the short form sits at the 14-15 char boundary.
    if len(short) >= _KERNEL_IMAGENAME_LEN - 1:
        return True
    # Otherwise only a small trailing clip counts (e.g. a dropped extension char).
    return 0 < len(long) - len(short) <= _TRUNCATION_TAIL_TOLERANCE


def artifacts_match(a: str | None, b: str | None) -> bool:
    """Two artifact identifiers refer to the same artifact.

    True when they are equal after :func:`normalize_artifact_id`, or when one is a
    Windows-kernel-truncated (or otherwise cosmetically clipped) form of the
    other. A short generic prefix (e.g. 3 chars) is NOT a match.
    """
    na = normalize_artifact_id(a)
    nb = normalize_artifact_id(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    short, long = (na, nb) if len(na) <= len(nb) else (nb, na)
    return _is_truncation_match(short, long)


def _artifact_identity_match(expected: dict[str, Any], rf: dict[str, Any]) -> bool:
    """Same-file match between an expected hint and a run finding's path.

    Only fires when the expected ``artifact_hint`` is identifier-shaped (a path /
    filename / host); a prose hint never inflates recall via this path. Additive
    to token-coverage matching — it can recall a same-file claim, never reject one.
    """
    hint = expected.get("artifact_hint")
    if not hint or not _IDENTIFIER_RE.match(str(hint).strip()):
        return False
    return artifacts_match(str(hint), rf.get("artifact_path"))


def _tokens(*parts: str | None) -> set[str]:
    text = " ".join(p for p in parts if p).lower()
    return {t for t in re.findall(r"[a-z0-9]+", text) if t not in _STOPWORDS and len(t) > 2}


def _coverage(expected: set[str], candidate: set[str]) -> tuple[float, int]:
    """How much of the expected token set the candidate covers.

    Returns (coverage_fraction, shared_count). Normalizing by the expected set
    (not the union) makes a verbose-but-correct run finding match a concise
    ground-truth claim.
    """
    if not expected or not candidate:
        return 0.0, 0
    shared = len(expected & candidate)
    return shared / len(expected), shared


def newest_case_dir() -> Path | None:
    root = Path("tmp/auto-runs")
    if not root.is_dir():
        return None
    cases = [d for d in root.iterdir() if d.is_dir() and (d / "verdict.json").is_file()]
    return max(cases, key=lambda d: d.stat().st_mtime) if cases else None


def resolve_golden(case_dir: Path, override: str | None) -> Path | None:
    """Find the expected-findings.json for this case.

    Order: explicit override, then goldens/<verdict.case_id>, then a goldens dir
    whose name is a substring of the case dir name (handles auto-<uuid> dirs that
    record their logical case_id inside verdict.json).
    """
    if override:
        p = Path(override)
        cand = p if p.is_file() else p / "expected-findings.json"
        return cand if cand.is_file() else None

    goldens = Path("goldens")
    verdict = case_dir / "verdict.json"
    if verdict.is_file():
        try:
            cid = json.loads(verdict.read_text(encoding="utf-8")).get("case_id")
        except json.JSONDecodeError:
            cid = None
        if cid:
            cand = goldens / str(cid) / "expected-findings.json"
            if cand.is_file():
                return cand
    if goldens.is_dir():
        name = case_dir.name
        for sub in sorted(goldens.iterdir()):
            cand = sub / "expected-findings.json"
            if cand.is_file() and (sub.name in name or name in sub.name):
                return cand
    return None


def _verdict_consistent(run_verdict: str | None, golden_verdict: str | None) -> bool:
    """Honest verdict consistency — deliberately ASYMMETRIC.

    The product's three verdict words carry an epistemic polarity: EVIL
    (CONFIRMED_EVIL/SUSPICIOUS), BENIGN (NO_EVIL), NEUTRAL (INDETERMINATE/UNKNOWN).

    Rules, in order:
      1. A NEUTRAL *run* verdict is always accepted. We never punish honest
         uncertainty — a scoped-partial or "saw leads, couldn't corroborate" run
         is the correct posture, not a failure (matches the live-test gate).
      2. Once the run makes a *definite* call (EVIL or BENIGN), a NEUTRAL *golden*
         means the case was authored to expect uncertainty — so the definite call
         is over/under-confident and FAILS. This is what makes a false-positive
         control (e.g. alihadi-09 "Encrypt Them All", golden INDETERMINATE) bite:
         a run that escalates to CONFIRMED_EVIL/SUSPICIOUS is wrong.
      3. Otherwise the polarity must agree.
    """
    rv = (run_verdict or "").upper()
    gv = (golden_verdict or "").upper()
    if rv in _NEUTRAL_WORDS:
        return True
    if gv in _NEUTRAL_WORDS:
        return False
    if rv in _EVIL_WORDS and gv in _EVIL_WORDS:
        return True
    if rv in _BENIGN_WORDS and gv in _BENIGN_WORDS:
        return True
    return rv == gv


def _is_eligible(expected: dict[str, Any], rf: dict[str, Any]) -> bool:
    """Can this run finding satisfy this expected finding?

    Eligibility is purely description-content overlap: the run finding must cover
    enough of the expected finding's distinctive tokens. MITRE technique is
    deliberately NOT a shortcut here — in cases where every finding shares one
    technique (e.g. all T1071.001), a MITRE match would make any finding eligible
    for any claim and inflate recall. Content overlap is the honest signal.
    """
    # Same-file artifact identity (path/case/separator/kernel-truncation/IOC-pivot
    # normalized) is an additive recall signal when an identifier-shaped hint and a
    # run artifact_path name the same file; it never rejects a token-coverage match.
    if _artifact_identity_match(expected, rf):
        return True
    exp_tokens = _tokens(expected.get("description"), expected.get("artifact_hint"))
    cov, shared = _coverage(exp_tokens, _tokens(rf.get("description"), rf.get("artifact_path")))
    return shared >= MATCH_MIN_SHARED and cov >= MATCH_COVERAGE


def _max_matching(
    expected: list[dict[str, Any]], run_findings: list[dict[str, Any]]
) -> dict[int, int]:
    """Maximum bipartite matching (Kuhn's algorithm): expected_idx -> run_idx.

    A run finding may back at most one expected claim (no double-counting), and we
    find the assignment that covers the *most* expected claims — so neither greedy
    order nor a shared MITRE technique can under- or over-count recall.
    """
    adj: list[list[int]] = [
        [j for j, rf in enumerate(run_findings) if _is_eligible(exp, rf)] for exp in expected
    ]
    run_to_exp: dict[int, int] = {}

    def _augment(i: int, seen: set[int]) -> bool:
        for j in adj[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in run_to_exp or _augment(run_to_exp[j], seen):
                run_to_exp[j] = i
                return True
        return False

    for i in range(len(expected)):
        _augment(i, set())
    return {i: j for j, i in run_to_exp.items()}


def _negative_coverage(
    violations: list[dict[str, Any]],
    denylist_hits: list[dict[str, Any]],
    anti_facts: list[dict[str, Any]],
    known_negatives: list[dict[str, Any]],
    named_denylist: list[str],
) -> dict[str, Any]:
    """Negative-assertion coverage: did the run AVOID every planted-bait claim?

    The golden declares negative assertions a correct run must never make:
    ``anti_fact`` claims (false for this case), ``known_negative`` benign
    IOC-lookalikes, and a ``named_claim_denylist`` of terms (named malware /
    technique phrases) that must not appear in any finding. ``coverage_percent`` is
    the fraction of those negative-assertion controls the run respected; 100% means
    zero planted-bait hallucinations. ``clean`` is True iff the run asserted none.
    """
    anti_fact_violations = sum(1 for v in violations if v.get("violation") == "anti_fact")
    known_negative_violations = sum(1 for v in violations if v.get("violation") == "known_negative")
    denylist_terms_asserted = len(
        {term for hit in denylist_hits for term in (hit.get("terms") or [])}
    )

    anti_fact_total = len(anti_facts)
    known_negative_total = len(known_negatives)
    denylist_total = len(named_denylist)
    controls_total = anti_fact_total + known_negative_total + denylist_total

    # Respected controls: a control is "asserted" (violated) when the run makes the
    # forbidden claim. We cap each violation class at its declared total so a single
    # finding tripping multiple denylist terms can't push coverage negative.
    af_bad = min(anti_fact_violations, anti_fact_total)
    kn_bad = min(known_negative_violations, known_negative_total)
    dl_bad = min(denylist_terms_asserted, denylist_total)
    asserted = af_bad + kn_bad + dl_bad
    respected = controls_total - asserted

    # No declared negative controls -> vacuously full coverage (nothing to avoid).
    coverage_percent = 100 if controls_total == 0 else round(respected * 100 / controls_total)

    return {
        "controls_total": controls_total,
        "controls_respected": respected,
        "coverage_percent": coverage_percent,
        "clean": asserted == 0,
        "anti_fact_total": anti_fact_total,
        "anti_fact_violations": anti_fact_violations,
        "known_negative_total": known_negative_total,
        "known_negative_violations": known_negative_violations,
        "denylist_terms_total": denylist_total,
        "denylist_terms_asserted": denylist_terms_asserted,
    }


def _catch_reason(entry: dict[str, Any]) -> str:
    """Name the planted-bait control that caught a false-positive (P0-1).

    Makes the "reasoned-away" story explicit on each caught FP rather than leaving
    it implicit in the ``violation`` tag.
    """
    violation = entry.get("violation")
    if violation == "anti_fact":
        return "anti_fact control in the golden caught this false claim"
    if violation == "known_negative":
        return "known_negative (benign IOC-lookalike) control caught this false claim"
    if violation == "named_claim_denylist":
        terms = ", ".join(str(t) for t in (entry.get("terms") or []))
        return f"named_claim_denylist term(s) [{terms}] caught this false claim"
    return "planted-bait control caught this false claim"


# A finding is "asserted" — and thus eligible to count against precision — only at
# the top confidence tiers. A run that already hedged a finding to INFERRED /
# HYPOTHESIS / LOW / SPECULATIVE has not over-claimed it. An unlabelled finding is
# treated as asserted (fail safe: a missing tier must not let a claim dodge scoring).
HIGH_CONFIDENCE_TIERS = {"CONFIRMED", "HIGH"}


def _is_asserted(confidence: object) -> bool:
    tier = str(confidence or "").upper().strip()
    return tier == "" or tier in HIGH_CONFIDENCE_TIERS


class FakeModelClient:
    """Inert offline sentinel — the ONLY model client accuracy scoring accepts.

    Accuracy scoring is model-FREE by construction: :func:`score` reads finished
    artifacts (``verdict.json`` + golden) and grades them deterministically, never
    calling a model. This sentinel exists so the anti-fake invariant is *typed*: a
    caller cannot wire a live model client into the scoring path to silently
    fabricate a "live" accuracy number — see :func:`_ensure_offline_scoring`.
    """

    offline = True


def _ensure_offline_scoring(model_client: Any) -> None:
    """Refuse any non-offline model client wired into the scorer.

    ``None`` (no client) and :class:`FakeModelClient` are the only acceptable
    values: scoring must stay model-free so the number ties to the cited artifacts,
    not to a live model call that could differ run-to-run. Anything else raises.
    """
    if model_client is None or isinstance(model_client, FakeModelClient):
        return
    raise TypeError(
        "accuracy scoring is model-free: refusing a live model client "
        f"({type(model_client).__name__}); pass FakeModelClient() or None"
    )


def cache_key(
    case_dir: Path,
    golden_path: Path,
    *,
    model_snapshot_id: str = "",
    prompt_template_hash: str = "",
) -> str:
    """Content-addressed replay key for a scoring run.

    ``sha256`` over the exact bytes that determine the score: the run's
    ``verdict.json``, the ground-truth golden, the model snapshot id, and the
    prompt-template hash. Each field is length-prefixed so no two distinct inputs
    can collide by concatenation. Any drift in any input flips the key, so a cached
    number can only be replayed when it ties to the *same* inputs — a hand-edited
    ``verdict.json``, a swapped golden, or a different model/prompt provenance
    invalidates the cache instead of silently reusing a stale "live" score.
    """
    h = hashlib.sha256()
    for label, data in (
        ("verdict", (case_dir / "verdict.json").read_bytes()),
        ("golden", golden_path.read_bytes()),
        ("model_snapshot_id", model_snapshot_id.encode("utf-8")),
        ("prompt_template_hash", prompt_template_hash.encode("utf-8")),
    ):
        h.update(label.encode("utf-8"))
        h.update(b"\x00")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def score_replayable(
    case_dir: Path,
    golden_path: Path,
    *,
    cache: dict[str, dict[str, Any]] | None = None,
    model_client: Any = None,
    model_snapshot_id: str = "",
    prompt_template_hash: str = "",
) -> dict[str, Any]:
    """Content-addressed, model-free wrapper around :func:`score`.

    Enforces two anti-fake invariants without changing the scoring math:

      * scoring is model-free — a non-offline model client raises
        (:func:`_ensure_offline_scoring`); and
      * the result is keyed on :func:`cache_key`, so a rerun on identical inputs
        replays bit-identically from ``cache`` and any altered input field misses
        the cache and is recomputed.

    A cache miss delegates to :func:`score` (the committed scoring path is
    untouched); the returned dict is the same report plus a ``cache_key`` field.
    """
    _ensure_offline_scoring(model_client)
    key = cache_key(
        case_dir,
        golden_path,
        model_snapshot_id=model_snapshot_id,
        prompt_template_hash=prompt_template_hash,
    )
    if cache is not None and key in cache:
        return cache[key]
    result = {**score(case_dir, golden_path), "cache_key": key}
    if cache is not None:
        cache[key] = result
    return result


def _tactic_of(mitre_technique: str | None) -> str:
    """Bucket a finding by its MITRE technique family (the prefix of its ATT&CK ID).

    A finding's ``mitre_technique`` is an ATT&CK ID such as ``T1052.001``; the
    family prefix is the base technique before any sub-technique suffix
    (``T1052``). Missing, blank, or non-ATT&CK-shaped values bucket as
    ``UNMAPPED``. Deterministic and key-free: it keys only on the general ATT&CK
    ID the finding already carries, never an image-specific value.
    """
    tech = (mitre_technique or "").strip().upper()
    base = tech.split(".", 1)[0]
    return base if re.fullmatch(r"T\d+", base) else "UNMAPPED"


def _per_tactic_recall(
    expected: list[dict[str, Any]], assignment: dict[int, int]
) -> dict[str, dict[str, int]]:
    """ADDITIVE per-MITRE-tactic recall breakdown.

    Groups the expected (ground-truth) findings into MITRE buckets via
    :func:`_tactic_of`, then reports how many in each bucket the run recalled (an
    expected index appears in ``assignment`` when it was matched). Purely derived
    from inputs :func:`score` already has — it adds no key input, changes no
    existing scoring math, and is deterministic: buckets are emitted in sorted
    order and each carries ``expected_n`` / ``recalled_n`` / ``recall_percent``.
    """
    buckets: dict[str, dict[str, int]] = {}
    for i, exp in enumerate(expected):
        tactic = _tactic_of(exp.get("mitre_technique"))
        slot = buckets.setdefault(tactic, {"expected_n": 0, "recalled_n": 0})
        slot["expected_n"] += 1
        if i in assignment:
            slot["recalled_n"] += 1
    out: dict[str, dict[str, int]] = {}
    for tactic in sorted(buckets):
        exp_n = buckets[tactic]["expected_n"]
        rec_n = buckets[tactic]["recalled_n"]
        out[tactic] = {
            "expected_n": exp_n,
            "recalled_n": rec_n,
            "recall_percent": 100 if exp_n == 0 else round(rec_n * 100 / exp_n),
        }
    return out


def _wilson_ci(k: int, n: int, z: float = 1.96) -> list[float] | None:
    """Wilson score 95% confidence interval for a k/n rate, as ``[low%, high%]``.

    Returns ``None`` when ``n == 0`` (no trials, no interval). The Wilson interval
    is used rather than the naive normal approximation because it stays inside
    [0, 100] and is well-behaved at the small n and extreme rates a golden corpus
    produces — e.g. a 7/7 recall must not report a symmetric band that runs past
    100%, and a rate should carry the honest uncertainty of its sample size
    (recall 7/14 on one image is 50% with a wide band, not a settled number).
    """
    if n <= 0:
        return None
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    low = max(0.0, center - margin)
    high = min(1.0, center + margin)
    return [round(low * 100, 1), round(high * 100, 1)]


def score(case_dir: Path, golden_path: Path) -> dict[str, Any]:
    """Grade a finished Case directory against a ground-truth golden.

    Reads ``case_dir/verdict.json`` and ``golden_path`` and returns a plain report
    dict with recall, precision/F1, hallucination rate, verdict consistency,
    planted-bait findings, negative-assertion coverage, and a ``pass`` flag.
    Offline and read-only; never touches the audit chain.
    """
    verdict_doc = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    run_findings: list[dict[str, Any]] = verdict_doc.get("findings") or []
    expected: list[dict[str, Any]] = golden.get("findings") or []

    assignment = _max_matching(expected, run_findings)  # expected_idx -> run_idx (1:1)
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for i, exp in enumerate(expected):
        record = {
            "finding_id": exp.get("finding_id"),
            "description": exp.get("description"),
            "mitre_technique": exp.get("mitre_technique"),
        }
        if i in assignment:
            record["matched_run_finding_id"] = run_findings[assignment[i]].get("finding_id")
            matched.append(record)
        else:
            unmatched.append(record)

    expected_n = len(expected)
    recalled_n = len(matched)
    # An empty golden (e.g. synthetic-benign) is 100% recalled by definition: a
    # clean case has nothing to find, so a run with no findings is a perfect score.
    recall_percent = 100 if expected_n == 0 else round(recalled_n * 100 / expected_n)
    min_recall = int(golden.get("min_recall_percent", 0))

    run_verdict = verdict_doc.get("verdict")
    golden_verdict = golden.get("verdict")
    verdict_match = _verdict_consistent(run_verdict, golden_verdict)

    # --- False-positive / precision side -------------------------------------
    # Recall asks "did the run surface the ground truth?"; precision asks "did it
    # over-claim?". A run finding matched to no expected claim is `extra`. Whether
    # an extra finding is a false positive depends on the key:
    #   - exhaustive (closed-world) key  -> every extra is a false positive;
    #   - open-world key                 -> an extra is only PROVABLY wrong when it
    #     matches a planted `anti_fact` (a claim that is false for this case) or a
    #     `known_negative` (a benign IOC-lookalike a correct run must not assert),
    #     because the key may simply omit a real finding the run legitimately made.
    exhaustive = bool(golden.get("exhaustive", False))
    anti_facts = golden.get("anti_facts") or []
    known_negatives = golden.get("known_negatives") or []

    matched_run_idx = set(assignment.values())
    extra: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for j, rf in enumerate(run_findings):
        if j in matched_run_idx:
            continue
        entry = {
            "finding_id": rf.get("finding_id"),
            "description": rf.get("description"),
            "confidence": rf.get("confidence"),
        }
        if any(_is_eligible(spec, rf) for spec in anti_facts):
            entry["violation"] = "anti_fact"
            violations.append(entry)
        elif any(_is_eligible(spec, rf) for spec in known_negatives):
            entry["violation"] = "known_negative"
            violations.append(entry)
        extra.append(entry)

    # Planted-bait: terms a correct run must NEVER assert for this case (benign
    # IOC-lookalikes / named malware like "mimikatz" or "cobalt strike"). Scanned
    # across ALL run findings (a denylisted claim is wrong whether or not the
    # finding also matched an expected claim), substring + case-insensitive.
    named_denylist = [str(t).lower() for t in (golden.get("named_claim_denylist") or [])]
    denylist_hits: list[dict[str, Any]] = []
    for rf in run_findings:
        desc = (rf.get("description") or "").lower()
        terms = sorted({t for t in named_denylist if t and t in desc})
        if terms:
            denylist_hits.append(
                {
                    "finding_id": rf.get("finding_id"),
                    "description": rf.get("description"),
                    "violation": "named_claim_denylist",
                    "terms": terms,
                }
            )

    # Planted-bait failures = anti_fact / known_negative assertions plus any
    # denylisted-term assertion; deduped per finding for the headline count.
    planted_bait = violations + denylist_hits
    for entry in planted_bait:
        entry["catch_reason"] = _catch_reason(entry)
    fp_planted = len({(e.get("finding_id"), e.get("description")) for e in planted_bait})

    extra_n = len(extra)
    total_run = len(run_findings)
    # Confidence-aware precision: only an unmatched ASSERTED (CONFIRMED/HIGH)
    # finding is a potential over-claim. These are surfaced for human review in
    # BOTH worlds, and on a closed-world key they ARE the precision FP set — a
    # finding the run already hedged below CONFIRMED never costs precision.
    candidate_fp_for_human_review = [e for e in extra if _is_asserted(e.get("confidence"))]
    precision_scored = (
        exhaustive or bool(anti_facts) or bool(known_negatives) or bool(named_denylist)
    )
    false_positives = candidate_fp_for_human_review if exhaustive else violations
    fp_n = len(false_positives)

    precision_denom = recalled_n + fp_n
    precision_frac = recalled_n / precision_denom if precision_denom else 1.0
    precision_percent = round(precision_frac * 100)
    recall_frac = 1.0 if expected_n == 0 else recalled_n / expected_n
    pr_sum = precision_frac + recall_frac
    f1 = round(2 * precision_frac * recall_frac / pr_sum, 4) if pr_sum else 0.0
    hallucination_rate = round(fp_n / total_run, 4) if total_run else 0.0

    negative_coverage = _negative_coverage(
        violations, denylist_hits, anti_facts, known_negatives, named_denylist
    )

    # Scope caveats: classify the golden's corpus so a public-documented (possibly
    # training-contaminated) recall number is never read as proof of generalization.
    identity = corpus_identity(golden)

    # Gate: any planted-bait assertion (anti_fact / known_negative / denylisted
    # named claim) always fails the run. Generic extra findings (closed-world FPs)
    # are reported but do not fail, so a run that surfaces a real claim the key
    # omitted is not punished as a failure.
    passed = recall_percent >= min_recall and verdict_match and not planted_bait

    return {
        "case_id": golden.get("case_id") or verdict_doc.get("case_id"),
        "case_dir": str(case_dir),
        "golden": str(golden_path),
        "expected_n": expected_n,
        "recalled_n": recalled_n,
        "recall_percent": recall_percent,
        # Wilson 95% CI on the recall rate (recalled_n of expected_n): the honest
        # sample-size uncertainty behind the point estimate, not a settled number.
        "recall_ci_95": _wilson_ci(recalled_n, expected_n),
        "per_tactic_recall": _per_tactic_recall(expected, assignment),
        "min_recall_percent": min_recall,
        "run_finding_n": total_run,
        "extra_n": extra_n,
        "false_positives_n": fp_n,
        "candidate_fp_for_human_review": candidate_fp_for_human_review,
        "candidate_fp_n": len(candidate_fp_for_human_review),
        "fp_planted": fp_planted,
        "precision_percent": precision_percent,
        # Wilson 95% CI on the precision rate (recalled_n of recalled_n + fp_n).
        "precision_ci_95": _wilson_ci(recalled_n, precision_denom),
        "precision_scored": precision_scored,
        "exhaustive": exhaustive,
        "f1": f1,
        "hallucination_rate": hallucination_rate,
        "negative_coverage": negative_coverage,
        "validation_class": identity["validation_class"],
        "corpus_identity": identity["corpus_identity"],
        "contamination_caveat": identity["contamination_caveat"],
        "does_not_measure": list(DOES_NOT_MEASURE),
        "run_verdict": run_verdict,
        "golden_verdict": golden_verdict,
        "verdict_match": verdict_match,
        "pass": passed,
        "matched": matched,
        "unmatched": unmatched,
        # False negatives surfaced BY NAME: which expected claims the run did NOT
        # recall, not just a recall percent. Each item carries finding_id /
        # description / mitre_technique so a reader sees the gap, not infers it.
        "missed_by_name": {"count": len(unmatched), "items": unmatched},
        "extra": extra,
        "false_positives": false_positives,
        "planted_bait": planted_bait,
    }


# Tier B (recall/precision/F1) is only valid against an external answer key; with
# none, the report emits this sentinel instead of fabricating a number.
NO_EXTERNAL_KEY: dict[str, Any] = {"value": None, "reason": "no_external_answer_key"}


def _corpus_identity(case_id: str | None, golden: dict[str, Any]) -> str:
    """Name the corpus so a synthetic/seed recall is never read as field accuracy.

    Honours an explicit ``validation_class`` in the golden; otherwise infers
    ``synthetic`` for the seeded control fixtures and ``public`` for the published
    DFIR datasets. Never guesses beyond these — unknown stays ``unknown``.
    """
    declared = golden.get("validation_class")
    if isinstance(declared, str) and declared.strip():
        return declared.strip()
    cid = (case_id or "").lower()
    if "synthetic" in cid or "decoy" in cid:
        return "synthetic"
    return "public"


def score_report(
    case_dir: Path,
    golden_path: Path | None,
    *,
    grounding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Two-axis accuracy report for one case — recall and grounding, never blended.

    The two axes are explicitly TIER-LABELLED so a reader never mistakes one for
    the other, and so a recall number can never appear without the key it needs:

    * **Tier A** — ``deterministic_grounding`` (``tier: "A"``): the goldens-FREE
      discipline view (citation / replay / custody) the caller injects (e.g. via
      ``scripts/score-overclaim.py``'s ``score``). Computable NOW with no answer
      key — "provably consistent, not proven correct." When the caller supplies
      nothing it is recorded ``{"available": False, "tier": "A"}`` rather than a
      verified default — a missing manifest must never read as "custody OK".
    * **Tier B** — ``investigative_recall`` (``tier: "B"``): recall / precision /
      F1 / verdict-match / planted bait, recomputed from ``case_dir/verdict.json``
      and the golden, valid ONLY against that external key (``corpus_identity``
      names whether it is synthetic or public). Each caught false-positive carries
      a ``catch_reason`` naming the control (P0-1).

    When ``golden_path`` is ``None`` no external key resolved, so Tier B is NOT
    fabricated: ``recall_percent`` / ``precision_percent`` / ``f1`` are emitted as
    ``{"value": null, "reason": "no_external_answer_key"}``, ``scored`` is ``False``,
    and ``pass`` is ``None`` — while Tier A stays fully populated and disclosed.
    """
    deterministic_grounding = dict(grounding) if grounding is not None else {"available": False}
    deterministic_grounding["tier"] = "A"

    if golden_path is None:
        verdict_doc = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
        investigative_recall = {
            "tier": "B",
            "scored": False,
            "corpus_identity": "unknown",
            "reason": "no_external_answer_key",
            "expected_n": None,
            "recalled_n": None,
            "recall_percent": dict(NO_EXTERNAL_KEY),
            "min_recall_percent": None,
            "precision_percent": dict(NO_EXTERNAL_KEY),
            "precision_scored": False,
            "f1": dict(NO_EXTERNAL_KEY),
            "hallucination_rate": None,
            "verdict_match": None,
            "fp_planted": 0,
            "planted_bait_caught": [],
            "candidate_fp_for_human_review": [],
            "candidate_fp_n": 0,
            "missed_by_name": {
                "count": None,
                "reason": "no_external_answer_key",
                "items": [],
            },
        }
        return {
            "case_id": verdict_doc.get("case_id"),
            "case_dir": str(case_dir),
            "golden": None,
            "investigative_recall": investigative_recall,
            "deterministic_grounding": deterministic_grounding,
            "pass": None,
        }

    recall = score(case_dir, golden_path)
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    planted_bait_caught = [
        {
            "finding_id": entry.get("finding_id"),
            "description": entry.get("description"),
            "violation": entry.get("violation"),
            "catch_reason": entry.get("catch_reason"),
        }
        for entry in recall["planted_bait"]
    ]
    investigative_recall = {
        "tier": "B",
        "scored": True,
        "corpus_identity": _corpus_identity(recall["case_id"], golden),
        "expected_n": recall["expected_n"],
        "recalled_n": recall["recalled_n"],
        "recall_percent": recall["recall_percent"],
        "min_recall_percent": recall["min_recall_percent"],
        "precision_percent": recall["precision_percent"],
        "precision_scored": recall["precision_scored"],
        "f1": recall["f1"],
        "hallucination_rate": recall["hallucination_rate"],
        "verdict_match": recall["verdict_match"],
        "fp_planted": recall["fp_planted"],
        "planted_bait_caught": planted_bait_caught,
        "candidate_fp_for_human_review": recall["candidate_fp_for_human_review"],
        "candidate_fp_n": recall["candidate_fp_n"],
        "missed_by_name": recall["missed_by_name"],
    }
    return {
        "case_id": recall["case_id"],
        "case_dir": recall["case_dir"],
        "golden": recall["golden"],
        "investigative_recall": investigative_recall,
        "deterministic_grounding": deterministic_grounding,
        "pass": recall["pass"],
    }


def _is_grounded(finding: dict[str, Any]) -> bool:
    """A Finding is grounded iff it cites a non-empty ``tool_call_id``.

    ``tool_call_id`` is the REQUIRED grounding field on a product Finding (the
    verifier vetoes any Finding without one). A run that had no usable tools can
    cite none, so grounding is the honest signal for a tool-less / empty-evidence
    run — not the presence of finding text, which an LLM can fabricate.
    """
    return bool(str(finding.get("tool_call_id") or "").strip())


def negative_control(case_dir: Path, golden_path: Path) -> dict[str, Any]:
    """Tool-less / empty-evidence NEGATIVE CONTROL — proves the harness measures the floor.

    This is the deliberate-hallucination baseline. It runs the same :func:`score`
    against a golden that DOES enumerate real expected findings, then adds a SEPARATE
    grounding posture describing what a run that had NO usable tools could produce:

      * ``tool_less`` / ``grounding_empty`` — no Finding cites a ``tool_call_id``;
      * ``baseline_hallucination_n`` — ungrounded claims a tool-less run still emitted
        (every such claim is a hallucination: nothing in the audit chain backs it);
      * ``floor_proven`` — True when a golden WITH expected findings is recalled by a
        run with zero grounded findings, i.e. recall=0. That is the floor: recall is
        earned only by grounded tool output, never assumed.

    The posture is returned under a dedicated ``negative_control`` key and is NEVER
    folded into the headline recall / precision / pass math — :func:`score` is reused
    unchanged, so a tool-less floor can never be mistaken for a real run's score.
    Offline and read-only; never touches the audit chain.
    """
    result = score(case_dir, golden_path)
    verdict_doc = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
    run_findings: list[dict[str, Any]] = verdict_doc.get("findings") or []

    grounded_n = sum(1 for f in run_findings if _is_grounded(f))
    ungrounded_n = len(run_findings) - grounded_n
    grounding_empty = grounded_n == 0

    posture = {
        "expected_n": result["expected_n"],
        "recall_percent": result["recall_percent"],
        "run_finding_n": len(run_findings),
        "grounded_finding_n": grounded_n,
        "grounding_empty": grounding_empty,
        "tool_less": grounding_empty,
        # Any ungrounded claim a tool-less run emitted is a baseline hallucination.
        "baseline_hallucination_n": ungrounded_n,
        # The floor: a golden with real expected findings, recalled by nothing.
        "floor_proven": result["expected_n"] > 0
        and result["recall_percent"] == 0
        and grounding_empty,
    }
    return {**result, "negative_control": posture}


# --- Measured ATT&CK coverage matrix (YAML golden assertions) ----------------
#
# verdict.json already exposes ``attack_coverage`` — a matrix of ATT&CK targets
# the run actually covered with typed-tool output (each row carries
# ``technique_id`` / ``status`` / ``finding_confidence`` /
# ``artifact_classes_observed``). The functions below grade that observed matrix
# against a per-case ``attack-assertions.yaml`` golden that declares which
# techniques the run is expected to surface and the minimum number of distinct
# artifact classes each must show. The output is a coverage matrix with a
# per-technique status:
#
#   * ``covered``            — observed with >= the declared minimum artifact classes;
#   * ``under_corroborated`` — observed but with fewer classes than the minimum
#     (the >=2-class corroboration doctrine encoded per technique in the golden);
#   * ``missing``            — absent from the matrix, or observed with no class.
#
# Like the recall scorer this is offline, read-only, and never touches the audit
# chain — it reads ``case_dir/verdict.json`` and a goldens YAML and returns a
# plain report dict. The assertions golden uses a deliberately tiny YAML subset so
# the parser stays stdlib-only (no PyYAML), keeping this module bare-python3
# runnable for the ``scripts/accuracy`` CLI and the ``score-recall.py`` path-load.

# Default minimum artifact classes when a technique omits ``min_artifact_classes``.
DEFAULT_MIN_ARTIFACT_CLASSES = 1


def _coerce_scalar(raw: str) -> Any:
    """Coerce a YAML-subset scalar: strip quotes, parse plain ints, else str."""
    value = raw.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def load_attack_assertions(path: Path) -> dict[str, Any]:
    """Parse an ``attack-assertions.yaml`` golden (a constrained YAML subset).

    The supported grammar is intentionally minimal so this stays stdlib-only:
    top-level ``key: value`` scalars, plus a ``techniques:`` block of list items
    (``- key: value`` followed by indented ``key: value`` lines). Blank lines and
    ``#`` comment lines are ignored. Anything outside this subset is not parsed —
    the goldens are authored to fit it, not the other way around.
    """
    spec: dict[str, Any] = {}
    techniques: list[dict[str, Any]] = []
    in_techniques = False
    current: dict[str, Any] | None = None

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())

        if indent == 0:
            in_techniques = False
            current = None
            key, _, value = stripped.partition(":")
            key = key.strip()
            if key == "techniques":
                in_techniques = True
                continue
            spec[key] = _coerce_scalar(value)
            continue

        if not in_techniques:
            continue

        if stripped.startswith("- "):
            current = {}
            techniques.append(current)
            stripped = stripped[2:].strip()

        if current is None:
            continue
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        current[key.strip()] = _coerce_scalar(value)

    spec["techniques"] = techniques
    return spec


def score_attack_coverage(
    case_dir: Path, assertions: dict[str, Any] | Path | str
) -> dict[str, Any]:
    """Grade a Case's observed ATT&CK coverage matrix against golden assertions.

    ``assertions`` may be an already-parsed spec dict or a path to an
    ``attack-assertions.yaml`` golden. Reads ``case_dir/verdict.json``'s
    ``attack_coverage.targets`` and, for each asserted technique, compares the
    distinct ``artifact_classes_observed`` against the declared
    ``min_artifact_classes`` to assign ``covered`` / ``under_corroborated`` /
    ``missing``. Returns a coverage matrix plus per-status counts and a
    ``full_coverage`` flag. Offline and read-only; never touches the audit chain.
    """
    if isinstance(assertions, str | Path):
        spec = load_attack_assertions(Path(assertions))
        assertions_ref: str | None = str(assertions)
    else:
        spec = assertions
        assertions_ref = None

    verdict_doc = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
    coverage = verdict_doc.get("attack_coverage") or {}
    targets_by_id: dict[str, dict[str, Any]] = {
        str(row.get("technique_id")): row
        for row in (coverage.get("targets") or [])
        if row.get("technique_id")
    }

    matrix: list[dict[str, Any]] = []
    for technique in spec.get("techniques") or []:
        technique_id = str(technique.get("technique_id") or "")
        try:
            min_classes = int(technique.get("min_artifact_classes", DEFAULT_MIN_ARTIFACT_CLASSES))
        except (TypeError, ValueError):
            min_classes = DEFAULT_MIN_ARTIFACT_CLASSES
        min_classes = max(min_classes, 1)

        target = targets_by_id.get(technique_id)
        observed_classes = (
            sorted(set(target.get("artifact_classes_observed") or [])) if target else []
        )
        observed_n = len(observed_classes)

        if observed_n == 0:
            status = "missing"
        elif observed_n < min_classes:
            status = "under_corroborated"
        else:
            status = "covered"

        matrix.append(
            {
                "technique_id": technique_id,
                "technique_name": technique.get("technique_name")
                or (target.get("technique_name") if target else None),
                "min_artifact_classes": min_classes,
                "observed_artifact_classes": observed_classes,
                "observed_class_count": observed_n,
                "finding_confidence": target.get("finding_confidence") if target else None,
                "matrix_status": target.get("status") if target else None,
                "status": status,
            }
        )

    covered_n = sum(1 for row in matrix if row["status"] == "covered")
    under_n = sum(1 for row in matrix if row["status"] == "under_corroborated")
    missing_n = sum(1 for row in matrix if row["status"] == "missing")
    technique_n = len(matrix)

    return {
        "case_id": spec.get("case_id") or verdict_doc.get("case_id"),
        "case_dir": str(case_dir),
        "assertions": assertions_ref,
        "technique_n": technique_n,
        "covered_n": covered_n,
        "under_corroborated_n": under_n,
        "missing_n": missing_n,
        "full_coverage": technique_n > 0 and covered_n == technique_n,
        "summary": (
            f"{covered_n}/{technique_n} asserted ATT&CK technique(s) covered; "
            f"{under_n} under-corroborated; {missing_n} missing"
        ),
        "matrix": matrix,
    }


__all__ = [
    "newest_case_dir",
    "resolve_golden",
    "score",
    "score_report",
    "NO_EXTERNAL_KEY",
    "negative_control",
    "corpus_identity",
    "score_attack_coverage",
    "load_attack_assertions",
    "DOES_NOT_MEASURE",
    "FakeModelClient",
    "cache_key",
    "score_replayable",
    "artifacts_match",
    "normalize_artifact_id",
]
