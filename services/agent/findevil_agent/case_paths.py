"""Portable, /home-free recording of extracted-artifact paths in the audit chain.

On disk/memory cases VERDICT extracts artifacts under
``<case_home>/cases/<id>/extracted/...`` and records that ABSOLUTE path in each
tool call's ``arguments`` (the replay-bearing dict). Recorded verbatim, the signed
audit chain then leaks ``/home/<user>/...`` and a disk case dir cannot be publicly
committed.

The ``*_path`` arguments are operationally load-bearing: the verifier replays a
cited call by re-running the tool with its recorded ``arguments``. So the recorded
value must be /home-free AND still resolvable at replay time. The portable anchor
is ``case_home`` (``$FINDEVIL_HOME`` else ``$HOME/.findevil`` — see
:func:`resolve_case_home`), which is reconstructable identically at record and
replay time. An extracted path is recorded RELATIVE to ``case_home``
(``cases/<id>/extracted/...``) and resolved back to absolute before replay.

Only paths genuinely under ``case_home`` are rewritten. ``/evidence/`` source
paths and any other absolute path pass through untouched — relativizing them would
either leak nothing (already /home-free) or break replay (no resolvable anchor).
"""

from __future__ import annotations

import os
from pathlib import Path

from findevil_agent.config import resolve_case_home

# Marker segment that distinguishes a case-relative recorded path from an
# absolute one or an unrelated relative string. Recorded extracted paths always
# start ``cases/<id>/extracted/...`` (POSIX), so a leading ``cases/`` is the
# resolve-side signal.
_CASE_PREFIX = "cases/"


def _case_home(env: os._Environ[str] | dict[str, str] | None) -> Path:
    return resolve_case_home(env=env)


def relativize_extracted_path(
    path: str, *, env: os._Environ[str] | dict[str, str] | None = None
) -> str:
    """Record an extracted-artifact path /home-free.

    If ``path`` is absolute and under ``case_home``, return its POSIX path
    relative to ``case_home`` (e.g. ``cases/<id>/extracted/disk/.../$MFT``).
    Otherwise return ``path`` unchanged: ``/evidence/`` source paths, paths
    outside the case store, and already-relative values must survive verbatim so
    replay can still resolve them.
    """
    if not path:
        return path
    candidate = Path(path)
    if not candidate.is_absolute():
        return path
    try:
        base = _case_home(env)
    except RuntimeError:
        return path
    try:
        rel = candidate.relative_to(base)
    except ValueError:
        return path
    return rel.as_posix()


def resolve_extracted_path(
    path: str, *, env: os._Environ[str] | dict[str, str] | None = None
) -> str:
    """Reverse :func:`relativize_extracted_path` for replay.

    A case-relative recorded path (``cases/...``) is joined onto ``case_home`` and
    returned absolute. Any already-absolute path (``/evidence/...`` or a path that
    was never relativized) is returned unchanged, as is a relative value that does
    not start with the ``cases/`` case-store prefix.
    """
    if not path:
        return path
    if os.path.isabs(path):
        return path
    if not path.startswith(_CASE_PREFIX):
        return path
    try:
        base = _case_home(env)
    except RuntimeError:
        return path
    return str(base / path)


def rewrite_arguments_for_replay(
    arguments: dict[str, object], *, env: os._Environ[str] | dict[str, str] | None = None
) -> dict[str, object]:
    """Return a copy of ``arguments`` with every ``*_path`` value resolved back to
    its absolute, on-disk form for replay.

    Mirrors the verifier's ``*_path`` convention (every Rust DFIR tool names its
    evidence input ``evtx_path`` / ``memory_path`` / ``artifact_path`` / …). Only
    string ``*_path`` values that were recorded case-relative are rewritten; all
    other keys and values are copied verbatim. The input dict is never mutated.
    """
    rewritten: dict[str, object] = {}
    for key, value in arguments.items():
        if (
            isinstance(key, str)
            and key.endswith("_path")
            and isinstance(value, str)
            and value.strip()
        ):
            rewritten[key] = resolve_extracted_path(value, env=env)
        else:
            rewritten[key] = value
    return rewritten


__all__ = [
    "relativize_extracted_path",
    "resolve_extracted_path",
    "rewrite_arguments_for_replay",
]
