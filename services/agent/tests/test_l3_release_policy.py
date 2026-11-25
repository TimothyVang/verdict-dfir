"""Policy guards for L3 release workflow semantics."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]


def _workflow_step(text: str, name: str) -> str:
    _, remainder = text.split(f"- name: {name}", 1)
    return remainder.split("\n      - name:", 1)[0]


def test_l3_nightly_failure_notification_covers_fallback_failures() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "l3-nightly.yml").read_text(encoding="utf-8")

    notify_step = _workflow_step(workflow, "Notify Slack on failure")

    assert "failure()" in notify_step
    assert "steps.kvm-check.outputs.kvm_ok == 'true'" not in notify_step
    assert "env.SLACK_WEBHOOK_CI != ''" not in notify_step
    assert 'if [[ -z "${SLACK_WEBHOOK_CI:-}" ]]' in notify_step


def test_ci_checklist_does_not_treat_l3_fallback_as_skip_green() -> None:
    checklist = (_ROOT / "docs" / "runbooks" / "ci-smoke-checklist.md").read_text(encoding="utf-8")

    assert "when L3 gracefully skips" not in checklist
    assert "failed or below-bar L3 evidence is not green" in checklist


def test_branch_protection_requires_ci_required_aggregate() -> None:
    branch_protection = (_ROOT / "scripts" / "setup-branch-protection.sh").read_text(
        encoding="utf-8"
    )

    assert "required_status_checks[contexts][]=ci-required" in branch_protection
