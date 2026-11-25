"""Internal proxy (netsh portproxy) detection from the SYSTEM registry hive.

An attacker's `netsh interface portproxy add v4tov4` writes
HKLM\\SYSTEM\\...\\Services\\PortProxy\\v4tov4\\tcp with a value mapping
listen -> connect (e.g. 0.0.0.0/8443 -> 127.0.0.1/3389). This is Volt Typhoon
tradecraft (AA24-038A). registry_portproxy_candidates classifies such rows and
the emitter raises T1090.001 (Internal Proxy).
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_KEY = "HKLM\\SYSTEM\\ControlSet001\\Services\\PortProxy\\v4tov4\\tcp"


def _row(values, key=_KEY):
    return {"key_path": key, "values": values, "last_write_time_iso": "2026-07-12T01:58:46Z"}


def test_portproxy_key_yields_candidate() -> None:
    rows = [_row([{"name": "0.0.0.0/8443", "data_str": "127.0.0.1/3389"}])]
    cands = fea.registry_portproxy_candidates(rows)
    assert len(cands) == 1, cands
    c = cands[0]
    assert c["kind"] == "portproxy"
    assert c["listen"] == "0.0.0.0/8443"
    assert c["connect"] == "127.0.0.1/3389"


def test_non_portproxy_key_ignored() -> None:
    rows = [_row([{"name": "x", "data_str": "y"}], key="HKLM\\SYSTEM\\ControlSet001\\Services\\Foo")]
    assert fea.registry_portproxy_candidates(rows) == []


def test_portproxy_key_without_values_ignored() -> None:
    assert fea.registry_portproxy_candidates([_row([])]) == []
