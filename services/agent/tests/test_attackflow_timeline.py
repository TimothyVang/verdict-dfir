import json
from pathlib import Path

from findevil_agent.attackflow.model import load_case
from findevil_agent.attackflow.timeline_html import timeline_html

FIX = Path(__file__).resolve().parent / "fixtures" / "attackflow"


def _write_case(tmp_path: Path, events: list[dict]) -> Path:
    case = tmp_path / "case"
    case.mkdir(parents=True, exist_ok=True)
    verdict = {
        "case_id": "case-fixture-timeline",
        "verdict": "SUSPICIOUS",
        "attack_story": {"headline": "Test Timeline Headline"},
        "normalized_timeline": {"events": events},
        "findings": [],
    }
    (case / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
    return case


def _two_day_events() -> list[dict]:
    return [
        {
            "event_id": "t-1",
            "timestamp_utc": "2021-05-01T01:00:00Z",
            "attck_techniques": ["T1543.003"],
            "entities": {"host": "HOST-A"},
            "summary": "Service installed",
            "source_record_ref": "svc.evtx#1",
        },
        {
            "event_id": "t-2",
            "timestamp_utc": "2021-05-01T02:00:00Z",
            "attck_techniques": ["T1070.001"],
            "entities": {"host": "HOST-A"},
            "summary": "Log cleared",
            "source_record_ref": "sec.evtx#2",
        },
        {
            "event_id": "t-3",
            "timestamp_utc": "2021-05-02T09:00:00Z",
            "attck_techniques": ["T1059"],
            "entities": {"host": "HOST-A"},
            "summary": "Suspicious command executed",
            "source_record_ref": "cmd.evtx#3",
            "linked_finding_ids": ["f-1"],
        },
        {
            "event_id": "t-null",
            "timestamp_utc": "1601-01-01T00:00:00Z",
            "summary": "epoch placeholder, must be excluded",
        },
    ]


def test_load_case_populates_timeline_events(tmp_path):
    case = _write_case(tmp_path, _two_day_events())
    model = load_case(case)
    assert len(model.timeline_events) == 4  # raw, unfiltered — emitter does the filtering


def test_timeline_html_masthead_fonts_and_days(tmp_path):
    case = _write_case(tmp_path, _two_day_events())
    model = load_case(case)
    html = timeline_html(model)

    assert "Test Timeline Headline" in html
    assert "@font-face" in html
    assert html.count("<details") == 2  # one per real day
    assert "Service installed" in html
    assert "Log cleared" in html
    assert "Suspicious command executed" in html


def test_timeline_html_has_histogram_facets_and_brush(tmp_path):
    case = _write_case(tmp_path, _two_day_events())
    model = load_case(case)
    html = timeline_html(model)

    assert "<svg" in html
    assert "<rect" in html
    assert 'class="tl-chip"' in html
    assert 'data-val="CONFIRMED"' in html
    assert 'data-val="INFERRED"' in html
    assert 'data-val="HYPOTHESIS"' in html
    assert "<script" in html
    assert 'data-ms="' in html


def test_timeline_html_auto_expands_day_with_linked_finding(tmp_path):
    case = _write_case(tmp_path, _two_day_events())
    model = load_case(case)
    html = timeline_html(model)

    # 2021-05-02 carries the linked-finding event and must be the open day;
    # 2021-05-01 has no linked_finding_ids anywhere, so it stays collapsed.
    import re

    details_blocks = re.findall(r"<details[^>]*>.*?</details>", html, re.S)
    assert len(details_blocks) == 2
    block_01 = next(b for b in details_blocks if "01 MAY 2021" in b)
    block_02 = next(b for b in details_blocks if "02 MAY 2021" in b)
    tag_01 = re.match(r"<details[^>]*>", block_01).group(0)
    tag_02 = re.match(r"<details[^>]*>", block_02).group(0)
    assert " open" in tag_02
    assert " open" not in tag_01


def test_timeline_html_excludes_epoch_events(tmp_path):
    case = _write_case(tmp_path, _two_day_events())
    model = load_case(case)
    html = timeline_html(model)
    assert "epoch placeholder" not in html


def test_timeline_html_escapes_summary(tmp_path):
    events = [
        {
            "event_id": "t-xss",
            "timestamp_utc": "2022-03-03T00:00:00Z",
            "summary": "<script>alert(1)</script>",
        }
    ]
    case = _write_case(tmp_path, events)
    model = load_case(case)
    html = timeline_html(model)
    assert "&lt;script" in html
    assert "<script>alert(1)</script>" not in html


def test_timeline_html_empty_when_no_real_events(tmp_path):
    events = [{"event_id": "t-null", "timestamp_utc": "1601-01-01T00:00:00Z", "summary": "x"}]
    case = _write_case(tmp_path, events)
    model = load_case(case)
    html = timeline_html(model)
    assert "no timeline events" in html.lower()
    assert "<details" not in html


def test_timeline_html_falls_back_to_busiest_day_without_any_linked_finding(tmp_path):
    events = [
        {
            "event_id": "t-1",
            "timestamp_utc": "2021-05-01T01:00:00Z",
            "summary": "single event day",
        },
        {
            "event_id": "t-2",
            "timestamp_utc": "2021-05-02T01:00:00Z",
            "summary": "busy day event 1",
        },
        {
            "event_id": "t-3",
            "timestamp_utc": "2021-05-02T02:00:00Z",
            "summary": "busy day event 2",
        },
    ]
    case = _write_case(tmp_path, events)
    model = load_case(case)
    html = timeline_html(model)

    import re

    details_blocks = re.findall(r"<details[^>]*>.*?</details>", html, re.S)
    block_01 = next(b for b in details_blocks if "01 MAY 2021" in b)
    block_02 = next(b for b in details_blocks if "02 MAY 2021" in b)
    tag_01 = re.match(r"<details[^>]*>", block_01).group(0)
    tag_02 = re.match(r"<details[^>]*>", block_02).group(0)
    assert " open" in tag_02
    assert " open" not in tag_01
