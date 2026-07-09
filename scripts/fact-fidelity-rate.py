#!/usr/bin/env python3
"""fact-fidelity-rate.py — rejection-rate calibration AND blind held-out validation.

Two arms run by default; the gate passes only if BOTH pass:

  1. SEEDED CALIBRATION (``findevil_agent.fact_fidelity_metric``): seed
     deliberately-false asserted values across every match mode, run the REAL
     check (``findevil_agent.entailment.check_entailment``), and report the
     fraction rejected (target 1.0) plus the control that the TRUE values are
     still accepted (target 1.0). The fabrications are false by construction
     (known-wrong mutations of values that genuinely match the evidence), so the
     number is meaningful rather than tautological.
  2. HELD-OUT ADVERSARIAL VALIDATION (``goldens/fact-fidelity/held-out-findings.json``):
     a committed, frozen fixture set of grounded + hallucinated findings the
     detector was not tuned against. Score precision/recall per arm (positive
     class = hallucinated, the detector MUST reject) and record the
     ``detector_sha256`` the run validated — a blind set removes the "graded its
     own fixtures" critique, and the source hash forces re-validation on a silent
     detector edit.

No LLM in the loop. Scope: grades the structured-value entailment fence over
recorded tool-output fixtures spanning the production artifact classes; it is not
a live end-to-end run.

Usage:
  python3 scripts/fact-fidelity-rate.py                  # print tables; exit non-zero on miss
  python3 scripts/fact-fidelity-rate.py --json out.json  # also write the metric JSON

Exit 0 only when the calibration rates are 1.0 over a non-empty corpus AND every
held-out arm meets its recall/precision bar (default 1.0). Run under the agent venv
(`uv run --directory services/agent python scripts/fact-fidelity-rate.py`).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_AGENT = _ROOT / "services" / "agent"
sys.path.insert(0, str(_AGENT))

from findevil_agent.entailment import check_entailment  # noqa: E402
from findevil_agent.events import AssertedValue  # noqa: E402
from findevil_agent.fact_fidelity_metric import builtin_cases, measure  # noqa: E402

_DETECTOR_SRC = _AGENT / "findevil_agent" / "entailment.py"
_HELD_OUT = _ROOT / "goldens" / "fact-fidelity" / "held-out-findings.json"
# Held-out arms must reach perfect recall (catch every hallucination) AND
# precision (never reject a genuine finding) — same 1.0 bar as the calibration arm.
_HELD_OUT_MIN = 1.0


def detector_sha256() -> str:
    """SHA-256 of the detector source — the frozen identity this run validated."""
    return hashlib.sha256(_DETECTOR_SRC.read_bytes()).hexdigest()


def load_fixtures(path: Path = _HELD_OUT) -> list[dict[str, Any]]:
    """Load the committed adversarial fixture set (the ``fixtures`` array)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError(f"no fixtures in {path}")
    return fixtures


def _asserted_values(fixture: dict[str, Any]) -> list[AssertedValue]:
    return [
        AssertedValue(
            path=av["path"],
            expected=av["expected"],
            match=av.get("match", "exact"),
            count=av.get("count"),
        )
        for av in fixture.get("asserted_values", [])
    ]


def detector_verdict(fixture: dict[str, Any]) -> bool:
    """The detector's binary GROUNDED decision for one fixture.

    GROUNDED iff every asserted value entails AND no multiplicity over-count was
    demoted — mirroring how the verifier treats the result (an absent value
    rejects; an over-count demotes below CONFIRMED). Either failure means the
    finding is not fully grounded in its cited evidence.
    """
    result = check_entailment(_asserted_values(fixture), fixture["parsed_output"])
    return bool(result.passed) and not result.multiplicity_demotions


def _score_arm(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fn = fp = tn = 0  # positive class = hallucinated (detector must reject)
    for fx in fixtures:
        grounded = detector_verdict(fx)
        if fx["label"] == "hallucinated":
            fn += 1 if grounded else 0
            tp += 0 if grounded else 1
        else:  # grounded truth
            tn += 1 if grounded else 0
            fp += 0 if grounded else 1
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    return {
        "total": len(fixtures),
        "hallucinated_truth": tp + fn,
        "grounded_truth": tn + fp,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
    }


def score(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    """Score every held-out arm separately; record the frozen detector SHA-256."""
    arms: dict[str, list[dict[str, Any]]] = {}
    for fx in fixtures:
        arms.setdefault(fx.get("arm", "unlabeled"), []).append(fx)
    return {
        "detector_sha256": detector_sha256(),
        "fixture_count": len(fixtures),
        "arms": {name: _score_arm(group) for name, group in sorted(arms.items())},
    }


def _held_out_passes(report: dict[str, Any]) -> bool:
    return all(
        m["recall"] >= _HELD_OUT_MIN and m["precision"] >= _HELD_OUT_MIN
        for m in report["arms"].values()
    )


def main(argv: list[str]) -> int:
    # --- Arm 1: seeded calibration (the original rejection-rate metric) ---------
    cases = builtin_cases()
    metrics = measure(cases)
    cal = metrics.to_dict()
    print("VERDICT - fact-fidelity (entailment) rejection rate")
    print(
        f"  corpus: {len(cases)} recorded tool-output cases; "
        f"modes: {', '.join(cal['modes_covered'])}"
    )
    print(
        f"  rejection rate:  {cal['rejected_fabrications']}/{cal['seeded_fabrications']} "
        f"= {cal['rejection_rate'] * 100:.1f}%  (seeded false values rejected)"
    )
    print(
        f"  acceptance rate: {cal['accepted_true_values']}/{cal['true_values']} "
        f"= {cal['acceptance_rate'] * 100:.1f}%  (true values accepted)"
    )
    if cal["rejection_escapes"]:
        print(f"  REJECTION ESCAPES (verifier bug): {cal['rejection_escapes']}")
    if cal["acceptance_escapes"]:
        print(f"  ACCEPTANCE DROPS (over-strict check): {cal['acceptance_escapes']}")
    cal_ok = metrics.meets_targets()

    # --- Arm 2: blind held-out adversarial validation --------------------------
    held = score(load_fixtures())
    print("VERDICT - fact-fidelity held-out adversarial validation")
    print(f"  detector_sha256: {held['detector_sha256']}")
    print(f"  fixtures: {held['fixture_count']}")
    for name, m in held["arms"].items():
        print(
            f"  [{name}] n={m['total']} "
            f"precision={m['precision']:.3f} recall={m['recall']:.3f} "
            f"(TP={m['true_positives']} FN={m['false_negatives']} "
            f"FP={m['false_positives']} TN={m['true_negatives']})"
        )
    held_ok = _held_out_passes(held)

    if len(argv) >= 2 and argv[0] == "--json":
        out = Path(argv[1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps({"calibration": cal, "held_out": held}, indent=2) + "\n"
        )
        print(f"  wrote {out}")

    ok = cal_ok and held_ok
    print(f"  meets_targets: calibration={cal_ok} held_out={held_ok} -> {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
