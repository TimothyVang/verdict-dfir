from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_file_like_tokens_are_paths_not_domains() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    "Recovered ntds.dit, deleted stage.rar, and reviewed "
                    "collect_helper.ps1. Contact response.example for escalation."
                )
            }
        ],
        None,
    )

    assert {"ntds.dit", "stage.rar", "collect_helper.ps1"} <= set(indicators["file_paths"])
    assert indicators["domains"] == ["response.example"]


def test_windows_path_extraction_stops_before_prose() -> None:
    extracted = fea._extract_iocs_from_texts(
        [
            "Recovered C:\\temp\\ifm\\Active Directory\\ntds.dit; deleted archive "
            "C:\\temp\\stage.rar and reviewed C:\\temp\\collect_helper.ps1."
        ]
    )

    assert extracted["paths"] == [
        "C:\\temp\\collect_helper.ps1",
        "C:\\temp\\ifm\\Active Directory\\ntds.dit",
        "C:\\temp\\stage.rar",
    ]


def test_finding_registry_and_hash_iocs_reach_indicator_channels() -> None:
    digest = "a" * 64
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    "Observed HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp; "
                    f"SHA-256 {digest}"
                )
            }
        ],
        {"aggregate_iocs": {"hashes": [digest]}},
    )

    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp"
    ]
    assert indicators["hashes"] == [digest]


def test_registry_indicator_drops_trailing_prose() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    r"Observed HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "
                    "was observed during triage."
                )
            }
        ],
        None,
    )

    assert indicators["registry_values"] == [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]


def test_system_hive_relative_path_becomes_registry_value() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "artifact_path": "SYSTEM",
                "description": (
                    "Configuration present at "
                    "ControlSet001\\Services\\PortProxy\\v4tov4\\tcp, last_write recorded."
                ),
            }
        ],
        None,
    )

    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp"
    ]


def test_generic_file_paths_survive_indicator_extraction() -> None:
    extracted = fea._extract_iocs_from_texts(
        [
            r"Opened C:\temp\bundle.zip, \\server\share\payload.custom, "
            r"/var/lib/cases/artifact and C:\Windows\System32\drivers."
        ]
    )
    paths = set(extracted["paths"])
    assert r"C:\temp\bundle.zip" in paths
    assert r"\\server\share\payload.custom" in paths
    assert "/var/lib/cases/artifact" in paths
    assert r"C:\Windows\System32\drivers" in paths
    assert r"C:\Program Files\Acme Tool\payload.custom" in set(
        fea._extract_iocs_from_texts(
            [r"Opened C:\Program Files\Acme Tool\payload.custom; review complete."]
        )["paths"]
    )
    assert r"\\server\share\Acme Tool\payload.custom" in set(
        fea._extract_iocs_from_texts(
            [r"Opened \\server\share\Acme Tool\payload.custom; review complete."]
        )["paths"]
    )


def test_finding_prose_does_not_blindly_emit_hashes() -> None:
    indicators = fea.build_indicators(
        [],
        [{"description": f"Audit chain output hash {'a' * 64}"}],
        None,
    )
    assert indicators["hashes"] == []


def test_non_finding_ioc_extraction_preserves_bare_hashes() -> None:
    digest = "a" * 64

    assert fea._extract_iocs_from_texts([digest])["hashes"] == [digest]


def test_negated_finding_prose_does_not_emit_registry_or_file_indicators() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    r"No registry key HKLM\SOFTWARE\Bad existed. "
                    "Did not observe payload.exe. "
                    r"Did not observe C:\staging.dir\nested.exe."
                )
            },
            {
                "artifact_path": "SYSTEM",
                "description": r"No registry key ControlSet001\Services\Bad existed.",
            },
        ],
        None,
    )

    assert indicators["registry_values"] == []
    assert indicators["file_paths"] == []


def test_observed_finding_hash_is_emitted_but_negated_hash_is_not() -> None:
    observed = "a" * 64
    negated = "b" * 64
    indicators = fea.build_indicators(
        [],
        [{"description": (f"Observed SHA-256 {observed}. Did not observe SHA-256 {negated}.")}],
        None,
    )

    assert indicators["hashes"] == [observed]


def test_postfix_negation_does_not_emit_finding_indicators() -> None:
    digest = "c" * 64
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    "payload.exe was not observed. "
                    r"HKLM\SOFTWARE\Bad was not observed. "
                    f"Observed SHA-256 {digest} was not present."
                )
            }
        ],
        None,
    )

    assert indicators["file_paths"] == []
    assert indicators["registry_values"] == []
    assert indicators["hashes"] == []


def test_mixed_clause_keeps_positive_observable_after_negated_one() -> None:
    indicators = fea.build_indicators(
        [],
        [{"description": ("payload.exe was not observed, but observed helper.exe.")}],
        None,
    )

    assert indicators["file_paths"] == ["helper.exe"]


def test_prefix_and_postfix_ip_negation_keep_only_positive_ip() -> None:
    prefix = fea._extract_iocs_from_texts(["Did not observe 10.0.0.1, but observed 10.0.0.2"])
    postfix = fea._extract_iocs_from_texts(["10.0.0.1 was not observed, but 10.0.0.2 was observed"])

    assert prefix["ips"] == ["10.0.0.2"]
    assert postfix["ips"] == ["10.0.0.2"]


def test_negation_filters_url_email_and_domain_channels() -> None:
    extracted = fea._extract_iocs_from_texts(
        [
            "Did not observe https://bad.example/path",
            "analyst@example.org was not observed",
            "Neither first.example nor second.example was observed",
        ]
    )

    assert extracted["urls"] == []
    assert extracted["emails"] == []
    assert extracted["domains"] == []


def test_and_clause_keeps_positive_file_after_negated_file() -> None:
    extracted = fea._extract_iocs_from_texts(
        ["payload.exe was not observed and helper.exe was observed"]
    )

    assert extracted["paths"] == ["helper.exe"]


def test_neither_nor_files_are_not_emitted() -> None:
    extracted = fea._extract_iocs_from_texts(["Neither first.exe nor second.exe was observed"])

    assert extracted["paths"] == []


def test_positive_network_indicator_extraction_is_preserved() -> None:
    extracted = fea._extract_iocs_from_texts(
        [
            "Observed https://good.example/path",
            "Observed analyst@example.org",
            "Observed 10.0.0.2",
            "Observed beacon.example.net",
        ]
    )

    assert extracted["urls"] == ["https://good.example/path"]
    assert extracted["emails"] == ["analyst@example.org"]
    assert extracted["ips"] == ["10.0.0.2"]
    assert "beacon.example.net" in extracted["domains"]


def test_coordinated_subjects_share_postfix_negation() -> None:
    files = fea._extract_iocs_from_texts(["payload.exe and helper.exe were not observed"])
    network = fea._extract_iocs_from_texts(
        ["https://bad.example/path and second.example were not observed"]
    )

    assert files["paths"] == []
    assert network["urls"] == []
    assert network["domains"] == []


def test_comma_separated_observation_resets_negated_ip_polarity() -> None:
    extracted = fea._extract_iocs_from_texts(["Did not observe 10.0.0.1, observed 10.0.0.2"])

    assert extracted["ips"] == ["10.0.0.2"]


def test_contrastive_bare_negation_is_scoped_per_indicator() -> None:
    files = fea._extract_iocs_from_texts(["Observed payload.exe, but not helper.exe"])
    ips = fea._extract_iocs_from_texts(["Observed 10.0.0.1, but not 10.0.0.2"])
    urls = fea._extract_iocs_from_texts(
        ["Observed https://good.example/path but not https://bad.example/path"]
    )
    domains = fea._extract_iocs_from_texts(["Observed first.example, but not second.example"])

    assert files["paths"] == ["payload.exe"]
    assert ips["ips"] == ["10.0.0.1"]
    assert urls["urls"] == ["https://good.example/path"]
    assert domains["domains"] == ["first.example"]


def test_adjacent_registry_values_are_extracted_separately() -> None:
    extracted = fea._extract_iocs_from_texts([r"Observed HKLM\SOFTWARE\One and HKCU\SOFTWARE\Two"])

    assert extracted["registry_keys"] == [
        r"HKCU\SOFTWARE\Two",
        r"HKLM\SOFTWARE\One",
    ]


def test_system_hive_registry_value_stops_before_prose() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "artifact_path": "SYSTEM",
                "description": (r"Found ControlSet001\Services\PortProxy\v4tov4\tcp during triage"),
            }
        ],
        None,
    )
    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp"
    ]


def test_system_hive_registry_value_preserves_spaces_in_key_segments() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "artifact_path": "SYSTEM",
                "description": (
                    r"Found ControlSet001\Services\Acme Service\Parameters during triage"
                ),
            }
        ],
        None,
    )
    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\ControlSet001\Services\Acme Service\Parameters"
    ]
