"""Judge node — credibility-weighted merge of Pool A + Pool B findings.

Spec #2 §8.2 + ``project_adversarial_agents_pattern.md`` formula
(Estornell, ICML 2025). Replaces simple consensus with a
credibility-weighted score so the judge resists "weak-agent
poisoning".

Formula (per §8.2):

  score_X = pool_X_confidence(F) * credibility_X
  merged_confidence = (score_A + score_B) / (credibility_A + credibility_B)

  pool_X_confidence(F):
    1.0  if F.confidence == "CONFIRMED"
    0.6  if F.confidence == "INFERRED"
    0.3  if F.confidence == "HYPOTHESIS"

  credibility_X = prior_accuracy_X * (1 + corroboration_bonus_X)

  prior_accuracy_X:
    fraction of Pool X findings the verifier accepted as replay-backed
    (approved or downgraded) this run. Initialized to 0.5 for both pools.

  corroboration_bonus_X:
    0.2 if a Pool X finding is corroborated by a tool call from a
    different artifact class (disk vs log vs memory).
    0.0 otherwise.

  Threshold mapping for output confidence:
    merged >= 0.80 → CONFIRMED
    merged >= 0.50 → INFERRED
    merged <  0.50 → HYPOTHESIS

Wall-clock budget for the entire judge stage is 2 minutes (Spec #2
§8.1 + ``config.JUDGE_WALL_CLOCK_BUDGET_SECONDS``); the merge
itself is O(n) over candidate findings, so the budget mostly
guards against pathological inputs.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from findevil_agent.events import Finding, VerifierAction

CONFIDENCE_VALUE = {"CONFIRMED": 1.0, "INFERRED": 0.6, "HYPOTHESIS": 0.3}
THRESHOLD_CONFIRMED = 0.80
THRESHOLD_INFERRED = 0.50
INITIAL_PRIOR_ACCURACY = 0.5
CORROBORATION_BONUS = 0.2

ARTIFACT_CLASS_DISK = {
    "disk",
    "filesystem",
    "registry",
    "mft",
    "prefetch",
    "amcache",
    "shimcache",
    "usnjrnl",
}
ARTIFACT_CLASS_LOG = {"log", "evtx", "sysmon", "iis", "powershell"}
ARTIFACT_CLASS_MEMORY = {"memory", "volatility", "vad"}


class JudgeBudgetExceeded(RuntimeError):
    """Raised when the judge runs longer than its wall-clock budget."""


@dataclass(frozen=True)
class PoolStats:
    """Per-pool inputs the judge needs.

    ``verified_actions`` is the verifier's ``VerifierAction`` list
    for that pool's findings — used to compute ``prior_accuracy``.
    """

    pool: str  # "A" or "B"
    findings: list[Finding]
    verified_actions: list[VerifierAction] = field(default_factory=list)


@dataclass(frozen=True)
class MergedFinding:
    """One output of the judge: a Finding plus the math behind it."""

    finding: Finding
    """The judge-merged finding (clone of one input with confidence
    re-derived from the merged score)."""

    merged_confidence: float
    chosen_pool: str  # "A" | "B" | "merged"
    pool_a_score: float
    pool_b_score: float
    credibility_a: float
    credibility_b: float
    corroborated: bool


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def judge_findings(
    pool_a: PoolStats,
    pool_b: PoolStats,
    *,
    budget_seconds: float = 120.0,
) -> list[MergedFinding]:
    """Merge findings from the two pools into a single approved set.

    Strategy:
      1. Group findings by a stable key — currently
         ``(tool_call_id, artifact_path)`` — so corroborated claims
         from both pools collapse into one MergedFinding.
      2. Compute prior_accuracy + credibility per pool from
         verifier actions.
      3. Score each candidate; threshold-map to a confidence label;
         clone the winning Finding with the new label.
      4. Watch wall clock; raise JudgeBudgetExceeded if we go over.

    Returns the merged list. Findings that fail to clear
    THRESHOLD_INFERRED and don't have artifact-class corroboration
    drop to HYPOTHESIS but are still emitted (Spec #2 §"Epistemic
    hierarchy is strict" — HYPOTHESIS is a legal label).
    """
    started = time.monotonic()

    # Opt-in counter-hypothesis discipline (FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS=1,
    # default-off). When on, a SOLO finding (only one pool raised the claim — the
    # opposing pool did not corroborate it) is NOT preserved at its drafted tier;
    # it takes the merged score, so a solo CONFIRMED collapses to INFERRED unless
    # cross-pool corroboration raises it back. This is the devil's-advocate /
    # counter-hypothesis stance (project-mantis / vigia): a CONFIRMED claim must
    # survive the other pool's challenge. DEFAULT-OFF because VERDICT already
    # covers this via the verifier (which re-ran and accepted the finding) and the
    # >=2-artifact-class execution gate; enabling it trades recall for a stricter
    # corroboration bar, so it is a deliberate operator choice, not the default.
    require_counter_hyp = os.environ.get("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS") == "1"

    cred_a = _credibility(pool_a)
    cred_b = _credibility(pool_b)

    grouped: dict[tuple[str, str, str, str], list[tuple[Finding, str]]] = {}
    for f in pool_a.findings:
        grouped.setdefault(_group_key(f), []).append((f, "A"))
    for f in pool_b.findings:
        grouped.setdefault(_group_key(f), []).append((f, "B"))

    # Cross-class corroboration set: which artifact classes does
    # each pool already have at least one finding in? Spec #2 §8.2
    # "different artifact class" bonus.
    a_classes = {_classify_artifact(f) for f in pool_a.findings}
    a_classes.discard(None)
    b_classes = {_classify_artifact(f) for f in pool_b.findings}
    b_classes.discard(None)

    out: list[MergedFinding] = []
    for items in grouped.values():
        a_items = [f for (f, p) in items if p == "A"]
        b_items = [f for (f, p) in items if p == "B"]

        # A single coarse group can legitimately hold several DISTINCT findings
        # from the SAME pool: one tool call routinely surfaces many subjects —
        # e.g. one pcap_triage yields an anonymous-email POST, an authenticated
        # webmail session, and a social login, all T1071.001 on the same capture.
        # Pair A[i] with B[i] so genuine cross-pool corroboration of the *same*
        # claim still merges into one, while surplus same-pool findings emit
        # individually. Taking only a_items[0]/b_items[0] (the old behavior)
        # collapsed all of them into one and silently destroyed recall.
        for i in range(max(len(a_items), len(b_items))):
            # ``>=`` so a budget of 0.0 always raises on the first iteration,
            # even on fast systems where time.monotonic() drift is sub-microsecond.
            if time.monotonic() - started >= budget_seconds:
                raise JudgeBudgetExceeded(
                    f"judge exceeded {budget_seconds}s budget after {len(out)} merged findings"
                )

            a_finding = a_items[i] if i < len(a_items) else None
            b_finding = b_items[i] if i < len(b_items) else None

            score_a = CONFIDENCE_VALUE.get(a_finding.confidence, 0.0) * cred_a if a_finding else 0.0
            score_b = CONFIDENCE_VALUE.get(b_finding.confidence, 0.0) * cred_b if b_finding else 0.0

            # Corroboration bonus: this pair has findings from BOTH pools AND the
            # artifact classes overlap with at least one different class on the
            # other pool.
            corroborated = False
            if a_finding and b_finding:
                cls = _classify_artifact(a_finding) or _classify_artifact(b_finding)
                other_a = a_classes - {cls}
                other_b = b_classes - {cls}
                if other_a or other_b:
                    corroborated = True
                    # Boost both scores symmetrically.
                    score_a *= 1.0 + CORROBORATION_BONUS
                    score_b *= 1.0 + CORROBORATION_BONUS

            denom = max(cred_a + cred_b, 1e-9)
            merged = (score_a + score_b) / denom

            # Pick the originating Finding to clone (richer description
            # wins; tiebreak on highest input confidence).
            chosen, chosen_pool = _pick_chosen(a_finding, b_finding)
            if chosen is None:
                continue  # impossible — pair has at least one item
            new_label = _confidence_for_score(merged)
            # A directly-observed CONFIRMED fact reported by a single pool must not
            # be downgraded purely for lack of cross-pool corroboration. The merge
            # divides a solo finding's score by BOTH pools' credibility
            # (score_a / (cred_a + cred_b)), collapsing 1.0 → ~0.5 (INFERRED). But
            # the verifier already re-executed and accepted this finding before the
            # judge ran — rejected findings never reach here, and downgraded
            # CONFIRMED findings no longer keep that label — so the judge's job is
            # to corroborate and *raise*,
            # not to re-litigate a confirmed observation (e.g. an EID 1102
            # log-clear). Corroboration across pools can still only push higher.
            is_solo = not (a_finding and b_finding)
            if (
                is_solo
                and chosen.confidence in {"CONFIRMED", "INFERRED"}
                and not require_counter_hyp
            ):
                new_label = chosen.confidence
            merged_finding = chosen.model_copy(
                update={
                    "confidence": new_label,
                    "pool_origin": chosen_pool if not (a_finding and b_finding) else "merged",
                }
            )
            out.append(
                MergedFinding(
                    finding=merged_finding,
                    merged_confidence=merged,
                    chosen_pool=chosen_pool if not (a_finding and b_finding) else "merged",
                    pool_a_score=score_a,
                    pool_b_score=score_b,
                    credibility_a=cred_a,
                    credibility_b=cred_b,
                    corroborated=corroborated,
                )
            )

    return out


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _credibility(pool: PoolStats) -> float:
    accuracy = _prior_accuracy(pool.verified_actions)
    return accuracy * (1.0 + CORROBORATION_BONUS)


def _prior_accuracy(actions: Iterable[VerifierAction]) -> float:
    actions_list = list(actions)
    if not actions_list:
        return INITIAL_PRIOR_ACCURACY
    replay_backed = sum(1 for a in actions_list if a.action in {"approved", "downgraded"})
    return replay_backed / len(actions_list)


def _claim_id(finding_id: str) -> str:
    """Pool-independent claim identity: the finding id without its pool tag.

    Pool A and Pool B versions of the *same* claim are emitted as ``f-A-<base>``
    / ``f-B-<base>`` (and may carry an artifact-hash suffix, which is identical
    for both because it derives from the same artifact path). Stripping the
    ``f-A-`` / ``f-B-`` prefix yields the shared base, so the two corroborate;
    findings about *different* subjects keep different bases and stay apart.
    """
    for prefix in ("f-A-", "f-B-", "f-a-", "f-b-"):
        if finding_id.startswith(prefix):
            return finding_id[len(prefix) :]
    return finding_id


def _group_key(f: Finding) -> tuple[str, str, str, str]:
    """Group findings that make the *same claim* so the A+B judge can corroborate.

    Keyed on ``(tool_call_id, artifact_path, mitre_technique, claim_id)`` where
    ``claim_id`` is the finding id with its pool prefix stripped. The coarse
    triple alone is too loose: a single tool call routinely yields MANY distinct
    findings that share it — one ``pcap_triage`` surfaces an anonymous-email POST,
    an authenticated webmail session, and a social login, all ``T1071.001`` on the
    same capture. Merging by the triple alone collapsed all of them into one and
    silently destroyed recall. The pool-stripped id keeps distinct subjects apart
    while still letting a genuine ``f-A-x`` / ``f-B-x`` pair (the same claim seen
    by both pools) land together and merge. ``description`` stays OUT of the key —
    the two pools word the same claim differently.
    """
    return (
        f.tool_call_id or "",
        f.artifact_path or "",
        f.mitre_technique or "",
        _claim_id(f.finding_id or ""),
    )


def _classify_artifact(f: Finding) -> str | None:
    """Best-effort artifact class for the corroboration bonus."""
    blob = (f.artifact_path + " " + f.description).lower()
    if any(tok in blob for tok in ARTIFACT_CLASS_DISK):
        return "disk"
    if any(tok in blob for tok in ARTIFACT_CLASS_LOG):
        return "log"
    if any(tok in blob for tok in ARTIFACT_CLASS_MEMORY):
        return "memory"
    return None


def _confidence_for_score(score: float) -> str:
    if score >= THRESHOLD_CONFIRMED:
        return "CONFIRMED"
    if score >= THRESHOLD_INFERRED:
        return "INFERRED"
    return "HYPOTHESIS"


def _pick_chosen(a: Finding | None, b: Finding | None) -> tuple[Finding | None, str]:
    if a and b:
        # Prefer the longer description (richer evidence).
        if len(a.description) >= len(b.description):
            return a, "A"
        return b, "B"
    if a:
        return a, "A"
    if b:
        return b, "B"
    return None, "?"


__all__ = [
    "CONFIDENCE_VALUE",
    "CORROBORATION_BONUS",
    "INITIAL_PRIOR_ACCURACY",
    "THRESHOLD_CONFIRMED",
    "THRESHOLD_INFERRED",
    "JudgeBudgetExceeded",
    "MergedFinding",
    "PoolStats",
    "judge_findings",
]
