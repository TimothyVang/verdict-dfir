"""Cross-source PID discrepancy check (memory vs. on-disk execution records).

A cross-artifact DEPTH lead for fileless / injected / DKOM-hidden activity: when a
case carries BOTH memory process evidence (``vol_pslist`` / ``vol_psscan``) AND
on-disk execution records (Prefetch / Amcache), a process that is (a) independently
suspicious in memory — an injected executable region (``vol_malfind``) or hidden
from a process view (``vol_psxview``) — AND (b) absent from every on-disk execution
artifact is worth a HYPOTHESIS lead.

Why the ``suspicious`` gate exists (validated against real fusion evidence): "in
memory, not on disk" ALONE is common and benign — Prefetch ages out at ~1024
entries and UWP/service processes never prefetch, so an ungated check flags ~40
normal processes per host. Requiring a second, independent memory signal
(injection or hidden-view) turns the discrepancy from noise into the genuine
fileless/injected tell it is meant to catch.

Pure logic — no LLM, no I/O — so it is deterministic and unit-testable, and each
Finding cites the memory ``tool_call_id`` so the verifier can replay the evidence.

Engine wiring is the follow-up step and is NOT yet connected. When wired,
``scripts/find_evil_auto.py`` will assemble ``memory_processes`` from the
``vol_pslist``/``vol_psscan`` rows (marking each ``suspicious`` from ``vol_malfind``
/ ``vol_psxview``) and ``disk_executables`` from ``prefetch_parse`` / Amcache
(``ez_parse``), call this, and append any Findings to Pool A — a change that must
be validated against a memory+disk fusion case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from findevil_agent.events import Finding

# Kernel / session-0 processes that never leave a Prefetch (.pf) record — their
# absence from disk execution artifacts is expected, not suspicious, so they are
# excluded from the discrepancy check.
_NO_PREFETCH_PROCESSES: frozenset[str] = frozenset(
    {
        "system",
        "system idle process",
        "idle",
        "registry",
        "memcompression",
        "memory compression",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
        "svchost.exe",
        "fontdrvhost.exe",
    }
)

# Volatility truncates a process image_name to ~14 chars. At/above this length a
# memory name is likely truncated, so exact equality against a full disk/exclusion
# name fails; fall back to a prefix match.
_TRUNC_LEN = 14


def _basename_lower(name: str) -> str:
    """Normalize a process/executable name to its lowercase basename.

    Prefetch stores names uppercase (``CMD.EXE``); memory rows are mixed case and
    Amcache rows may carry a full path. Matching is basename + case-insensitive.
    """
    return name.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()


def _in_set_trunc(name: str, names: set[str] | frozenset[str]) -> bool:
    """True if ``name`` is in ``names`` exactly, or — for a likely-truncated
    (>=14 char) memory name — is a prefix of some member.

    Volatility ``psscan``/``pslist`` truncate ``image_name`` to ~14 chars, so
    ``applicationframehost.exe`` appears as ``applicationfra`` and never equals
    the full disk name (or the exclusion-list entry). Prefix-matching a truncated
    name recovers the real match.
    """
    if name in names:
        return True
    if len(name) >= _TRUNC_LEN:
        stem = name.rstrip(".")
        return any(m.startswith(name) or m.startswith(stem) for m in names)
    return False


@dataclass(frozen=True)
class MemoryProcess:
    """A process observed in a memory image (one ``vol_pslist``/``vol_psscan`` row).

    ``tool_call_id`` is the audit id of the memory tool call this came from; any
    Finding the discrepancy check emits cites it so the verifier can replay the
    memory-side evidence.

    ``suspicious`` marks a process that INDEPENDENTLY trips a memory injection
    (``vol_malfind``) or hidden-view (``vol_psxview``) signal; ``suspicion_reason``
    is the short, verb-neutral phrase describing which. The discrepancy check only
    considers ``suspicious`` processes — a plain memory-vs-disk gap is too common
    on real hosts to report on its own.
    """

    pid: int
    name: str
    tool_call_id: str
    source: str = "pslist"  # "pslist" | "psscan"
    suspicious: bool = False
    suspicion_reason: str = ""


def cross_artifact_pid_check(
    memory_processes: list[MemoryProcess],
    disk_executables: set[str],
    *,
    case_id: str,
    memory_artifact_path: str,
) -> list[Finding]:
    """Flag independently-suspicious memory processes with no on-disk execution record.

    A cross-source DEPTH lead: a process that is (a) suspicious in memory (injected
    region via ``vol_malfind`` or hidden via ``vol_psxview``) and (b) absent from
    every on-disk execution artifact (Prefetch / Amcache) — the fileless/injected
    tell — is worth a HYPOTHESIS lead.

    Honesty constraints (deliberate):
    - Returns ``[]`` unless BOTH sources are present — a mixed-case-only signal.
    - Returns ``[]`` when ``disk_executables`` is empty: Prefetch may be disabled
      (SSD / ``EnablePrefetcher=0``), so absence would prove nothing.
    - Only ``suspicious`` processes are considered — "no on-disk record" alone is
      common and benign, so an independent injection/hidden signal is required.
    - Matching is truncation-tolerant (``vol_pslist``/``vol_psscan`` truncate names
      to ~14 chars), so a real disk match is not missed as a spurious discrepancy.
    - Emits HYPOTHESIS only — a discrepancy lead, not proof of injection.
    - The wording is verb-neutral (``has no matching …``) so ``is_execution_claim``
      stays False and the correlator's execution >=2-artifact gate never fires.
    - Kernel/session-0 processes that never produce Prefetch are excluded.

    Pure logic — no LLM calls, no I/O. Deterministic given the same inputs.
    """
    disk = {_basename_lower(d) for d in disk_executables if d and d.strip()}
    if not memory_processes or not disk:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    for proc in memory_processes:
        if not proc.suspicious:
            continue
        name = _basename_lower(proc.name)
        if not name or _in_set_trunc(name, _NO_PREFETCH_PROCESSES):
            continue
        if _in_set_trunc(name, disk) or name in seen:
            continue
        seen.add(name)
        slug = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
        reason = proc.suspicion_reason.strip() or "is flagged as suspicious in memory"
        findings.append(
            Finding(
                case_id=case_id,
                finding_id=f"f-A-xartifact-nodisk-{slug}",
                tool_call_id=proc.tool_call_id,
                artifact_path=memory_artifact_path,
                confidence="HYPOTHESIS",
                description=(
                    f"hypothesis: memory-resident process {proc.name} (PID {proc.pid}, "
                    f"{proc.source}) {reason} and has no matching Prefetch (.pf) or "
                    f"Amcache entry on disk — a cross-source injection/fileless "
                    f"discrepancy worth review (possible in-memory-only or injected "
                    f"code, prefetch-disabled host, or a timeline gap); not proof of "
                    f"compromise"
                ),
                pool_origin="A",
                mitre_technique=None,
            )
        )
    return findings


def build_cross_artifact_findings(
    psscan_rows: list[dict],
    malfind_rows: list[dict],
    psxview_rows: list[dict],
    disk_executables: set[str],
    *,
    memory_tool_call_id: str,
    memory_artifact_path: str,
    case_id: str,
) -> list[Finding]:
    """Assemble the check's inputs from raw parsed tool rows and run it.

    This is the engine-facing entry point: ``scripts/find_evil_auto.py`` captures
    the parsed ``vol_psscan`` rows, ``vol_malfind`` rows, ``vol_psxview`` rows, and
    the on-disk executable names, then calls this. Kept a pure function (raw rows
    in, Findings out) so it is unit-testable and validatable against a real
    fusion case independently of the engine plumbing.

    Suspicion is derived here: a process PID is suspicious if it appears in
    ``vol_malfind`` (an injected/executable private region) or is hidden from the
    active-process list in ``vol_psxview`` (present in the psscan pool scan but
    unlinked from pslist — a DKOM tell). Only those processes are considered.
    """
    malfind_pids = {
        int(r["pid"]) for r in malfind_rows if isinstance(r, dict) and r.get("pid") is not None
    }
    hidden: dict[int, str] = {}
    for r in psxview_rows:
        if not isinstance(r, dict) or r.get("pid") is None:
            continue
        # None = view not applicable; only an explicit False is "hidden".
        if r.get("psscan") is True and r.get("pslist") is False:
            hidden[int(r["pid"])] = (
                "is hidden from the active-process list "
                "(psxview: in psscan, unlinked from pslist)"
            )

    def _reason(pid: int) -> str:
        if pid in malfind_pids:
            return "shows an injected memory region (malfind)"
        return hidden.get(pid, "")

    procs: list[MemoryProcess] = []
    for r in psscan_rows:
        if not isinstance(r, dict) or not r.get("image_name"):
            continue
        try:
            pid = int(r.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        reason = _reason(pid)
        procs.append(
            MemoryProcess(
                pid=pid,
                name=str(r["image_name"]),
                tool_call_id=memory_tool_call_id,
                source="psscan",
                suspicious=bool(reason),
                suspicion_reason=reason,
            )
        )

    return cross_artifact_pid_check(
        procs,
        set(disk_executables),
        case_id=case_id,
        memory_artifact_path=memory_artifact_path,
    )


__all__ = [
    "MemoryProcess",
    "build_cross_artifact_findings",
    "cross_artifact_pid_check",
]
