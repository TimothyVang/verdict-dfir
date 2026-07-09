"""Branded vertical editorial timeline fragment from a case's normalized_timeline.

Presentation only: renders ``model.timeline_events`` (the raw
``normalized_timeline.events`` from verdict.json) as a self-contained,
brand-styled vertical timeline. Creates no Findings, makes no network or LLM
calls, and is fully deterministic (stable event-timestamp ordering, no
wall-clock or random values). Every evidence-derived field is HTML-escaped
before it reaches the page, since timeline event text originates in
attacker-influenceable evidence.

Fonts are inlined from the vendored ``_fonts/`` directory next to this module
(brand woff2s, base64 data URIs) so the emitted HTML has no external
dependencies. A missing font file is skipped gracefully -- the CSS
font-family stacks fall back to system fonts.

Day expansion is data-driven, not hard-coded to any specific year, host, or
image: every day collapses by default except the single busiest day that has
at least one event with ``linked_finding_ids`` (or, if none do, the single day
with the most events overall).

On top of the collapsible day timeline, this module also renders:

- A confidence-stacked activity-density histogram (events bucketed across the
  real event span into ~96 buckets, stacked bottom-to-top hypothesis /
  inferred / confirmed), with a handful of JetBrains-Mono date ticks.
- A brushable time axis: dragging across the histogram selects a time window
  (client-side JS maps pixel -> SVG viewBox -> epoch ms) that filters the
  visible event rows and dims out-of-range histogram bars.
- Faceted filter chips (confidence tier + significance) that compose with the
  brush selection and the existing free-text filter using AND logic.

All of the above is derived purely from the sorted, filtered event list --
same input always produces the same buckets, ticks, and default-open day.
"""

from __future__ import annotations

import base64
from collections import OrderedDict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from .model import AttackFlowModel

_FONTS_DIR = Path(__file__).parent / "_fonts"

# (family, weight, filename) -- filenames match the vendored _fonts/ tree.
_FONT_FACES: list[tuple[str, int, str]] = [
    ("Archivo Narrow", 700, "archivonarrow-700.woff2"),
    ("Archivo", 600, "archivo-600.woff2"),
    ("Inter", 400, "inter-400.woff2"),
    ("Inter", 600, "inter-600.woff2"),
    ("JetBrains Mono", 400, "jetbrainsmono-400.woff2"),
    ("JetBrains Mono", 600, "jetbrainsmono-600.woff2"),
    ("Caveat", 700, "caveat-700.woff2"),
]

# Confidence -> brand token (canonical report mapping; matches docs/brand.md).
_TIER_COLOR: dict[str, str] = {
    "CONFIRMED": "#73D9C2",  # Seafoam
    "INFERRED": "#FFD76A",  # Butter
    "HYPOTHESIS": "#4D5DFF",  # Cobalt
}
_CORAL = "#FF6257"

_MONTHS = [
    "JAN",
    "FEB",
    "MAR",
    "APR",
    "MAY",
    "JUN",
    "JUL",
    "AUG",
    "SEP",
    "OCT",
    "NOV",
    "DEC",
]

# Histogram: number of buckets spanning the real event range.
_HIST_BUCKETS = 96
# Histogram inner geometry (SVG viewBox units).
_HIST_WIDTH = 900
_HIST_HEIGHT = 120
# Number of evenly spaced date ticks drawn under the histogram (inclusive of
# the first and last tick, so this is intervals + 1 labels).
_HIST_TICKS = 6

_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


def _font_face_css() -> str:
    rules: list[str] = []
    for family, weight, filename in _FONT_FACES:
        path = _FONTS_DIR / filename
        if not path.exists():
            continue
        b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        rules.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};font-style:normal;"
            f"font-display:swap;src:url(data:font/woff2;base64,{b64}) format('woff2');}}"
        )
    return "\n".join(rules)


def _is_real_timestamp(ts: Any) -> bool:
    return str(ts or "")[:4] not in ("", "1600", "1601")


def _tier_of(event: dict[str, Any]) -> str:
    tier = str(event.get("confidence") or "").upper()
    return tier if tier in _TIER_COLOR else "HYPOTHESIS"


def _parse_epoch_ms(ts: str) -> int | None:
    """Parse a timestamp string into epoch milliseconds (UTC), or None.

    Tries full datetime formats first, then falls back to a bare date. Never
    raises -- an unparseable timestamp is simply excluded from the histogram
    (it has already passed ``_is_real_timestamp`` so this is only a format
    mismatch, not a placeholder epoch value).
    """
    candidate = ts[:26]
    for fmt in _TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(candidate, fmt).replace(tzinfo=timezone.utc)  # noqa: UP017 -- 3.10-safe, no datetime.UTC
            return int(parsed.timestamp() * 1000)
        except ValueError:
            continue
    try:
        parsed = datetime.strptime(ts[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)  # noqa: UP017 -- 3.10-safe
        return int(parsed.timestamp() * 1000)
    except ValueError:
        return None


def _day_label(day: str) -> str:
    try:
        parsed = datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        return day
    return f"{parsed.day:02d} {_MONTHS[parsed.month - 1]} {parsed.year}"


def _tech_chip(technique: str) -> str:
    return f'<span class="tl-tech">{escape(str(technique))}</span>'


def _event_row(event: dict[str, Any], ms: int | None) -> str:
    tier = _tier_of(event)
    color = _TIER_COLOR[tier]
    ts = str(event.get("timestamp_utc") or "")
    hhmmss = ts[11:19] or "--:--:--"
    summary = escape(str(event.get("summary") or "").strip())
    techniques = [str(t) for t in (event.get("attck_techniques") or [])][:4]
    tech_html = "".join(_tech_chip(t) for t in techniques)
    significance_raw = str(event.get("significance") or "").strip()
    significance = escape(significance_raw.replace("_", " "))
    entities = event.get("entities") or {}
    host = escape(str(entities.get("host") or ""))
    ref = str(event.get("source_record_ref") or event.get("tool_call_id") or "")
    ref_html = escape(ref)

    meta_bits = []
    if host:
        meta_bits.append(f'<span class="tl-host">{host}</span>')
    if ref_html:
        meta_bits.append(f'<span class="tl-ref">{ref_html}</span>')
    meta = " ".join(meta_bits)
    search = _event_row_search(summary, techniques, ref)
    sig_attr = escape(significance_raw)
    ms_attr = str(ms) if ms is not None else ""

    return (
        f'<div class="tl-row" data-ms="{ms_attr}" data-tier="{escape(tier)}" '
        f'data-sig="{sig_attr}" data-search="{search}">'
        f'<div class="tl-time">{escape(hhmmss)}</div>'
        f'<div class="tl-dot" style="--dot:{color}"></div>'
        f'<div class="tl-card">'
        f'<div class="tl-summary">{summary or "(no summary)"}</div>'
        f'<div class="tl-meta">{tech_html}{(" " + significance) if significance else ""} {meta}</div>'
        "</div></div>"
    )


def _event_row_search(summary_escaped: str, techniques: list[str], ref_raw: str) -> str:
    # data-search is used only for client-side substring filtering; escape the
    # raw (unescaped) pieces once combined, since summary_escaped is already
    # HTML-escaped and safe to reuse here as-is.
    raw = f"{summary_escaped} {' '.join(escape(t) for t in techniques)} {escape(ref_raw)}".lower()
    return raw


def _choose_open_days(groups: OrderedDict[str, list[dict[str, Any]]]) -> set[str]:
    """Pick the day(s) to auto-expand, purely from the data at hand.

    Prefers the busiest day that has at least one event carrying
    ``linked_finding_ids``; falls back to the day with the most events overall
    if no event links to a finding. Never keys on a specific year/host/image.
    """
    if not groups:
        return set()

    def has_linked_finding(day_events: list[dict[str, Any]]) -> bool:
        return any(ev.get("linked_finding_ids") for ev in day_events)

    finding_days = {day: evs for day, evs in groups.items() if has_linked_finding(evs)}
    candidates = finding_days if finding_days else groups
    busiest_day = max(candidates.items(), key=lambda kv: len(kv[1]))[0]
    return {busiest_day}


def _build_histogram(timed: list[tuple[int, dict[str, Any]]]) -> tuple[str, str, int, int]:
    """Build the stacked-bar SVG markup and axis ticks for the event span.

    Returns ``(bars_svg, ticks_svg, lo_ms, hi_ms)``. ``timed`` must be sorted
    ascending by epoch ms and contain only events with a resolved timestamp.
    """
    if not timed:
        return "", "", 0, 1

    lo = timed[0][0]
    hi = timed[-1][0]
    span = max(1, hi - lo)
    buckets: list[dict[str, int]] = [
        {"CONFIRMED": 0, "INFERRED": 0, "HYPOTHESIS": 0} for _ in range(_HIST_BUCKETS)
    ]
    for ms, event in timed:
        idx = min(_HIST_BUCKETS - 1, int((ms - lo) / span * _HIST_BUCKETS))
        buckets[idx][_tier_of(event)] += 1

    max_bucket_total = max((sum(bucket.values()) for bucket in buckets), default=1) or 1
    bar_width = _HIST_WIDTH / _HIST_BUCKETS

    bars: list[str] = []
    for i, bucket in enumerate(buckets):
        x = i * bar_width
        y = float(_HIST_HEIGHT)
        # Stack order: hypothesis (cobalt) at the bottom, then inferred
        # (butter), then confirmed (seafoam) on top.
        for tier in ("HYPOTHESIS", "INFERRED", "CONFIRMED"):
            count = bucket[tier]
            if not count:
                continue
            height = (count / max_bucket_total) * _HIST_HEIGHT
            y -= height
            bars.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(1.0, bar_width - 0.6):.1f}" '
                f'height="{height:.1f}" fill="{_TIER_COLOR[tier]}" data-b="{i}"/>'
            )

    ticks: list[str] = []
    for k in range(_HIST_TICKS + 1):
        ms = lo + int(span * k / _HIST_TICKS)
        x = (k / _HIST_TICKS) * _HIST_WIDTH
        d = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)  # noqa: UP017 -- 3.10-safe
        anchor = "start" if k == 0 else "end" if k == _HIST_TICKS else "middle"
        ticks.append(
            f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{_HIST_HEIGHT}" '
            f'stroke="#262c46" stroke-width="1"/>'
            f'<text x="{x:.1f}" y="{_HIST_HEIGHT + 14:.1f}" class="tl-axis-lbl" '
            f'text-anchor="{anchor}">{d.year}-{d.month:02d}</text>'
        )

    return "".join(bars), "".join(ticks), lo, hi


def timeline_html(model: AttackFlowModel) -> str:
    events = list(model.timeline_events or [])
    real = [e for e in events if isinstance(e, dict) and _is_real_timestamp(e.get("timestamp_utc"))]
    real.sort(key=lambda e: str(e.get("timestamp_utc") or ""))

    if not real:
        return (
            "<div class='tl-root tl-empty'>"
            "<p>No timeline events (no real timestamps in this case's normalized_timeline).</p>"
            "</div>"
        )

    timed: list[tuple[int, dict[str, Any]]] = []
    for e in real:
        ms = _parse_epoch_ms(str(e.get("timestamp_utc") or ""))
        if ms is not None:
            timed.append((ms, e))
    timed.sort(key=lambda pair: pair[0])

    groups: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    for e in real:
        day = str(e.get("timestamp_utc") or "")[:10]
        groups.setdefault(day, []).append(e)

    open_days = _choose_open_days(groups)
    span = f"{str(real[0]['timestamp_utc'])[:10]} → {str(real[-1]['timestamp_utc'])[:10]}"

    hist_bars, hist_ticks, lo_ms, hi_ms = _build_histogram(timed)

    n_confirmed = sum(1 for _, e in timed if _tier_of(e) == "CONFIRMED")
    n_inferred = sum(1 for _, e in timed if _tier_of(e) == "INFERRED")
    n_hypothesis = sum(1 for _, e in timed if _tier_of(e) == "HYPOTHESIS")

    sections: list[str] = []
    for day, evs in groups.items():
        is_open = day in open_days
        ctx_class = "" if is_open else " tl-context"
        kind = "primary" if is_open else "context"
        open_attr = " open" if is_open else ""
        marker = (
            "" if is_open else '<span class="tl-fold">collapsed &middot; click to expand</span>'
        )
        day_ms = [
            ms
            for e in evs
            for ms in [_parse_epoch_ms(str(e.get("timestamp_utc") or ""))]
            if ms is not None
        ]
        ms0 = min(day_ms) if day_ms else ""
        ms1 = max(day_ms) if day_ms else ""
        rows = "".join(
            _event_row(e, _parse_epoch_ms(str(e.get("timestamp_utc") or ""))) for e in evs
        )
        sections.append(
            f'<details class="tl-day{ctx_class}"{open_attr} data-kind="{kind}" '
            f'data-ms0="{ms0}" data-ms1="{ms1}">'
            f'<summary class="tl-day-head"><h2>{escape(_day_label(day))}</h2>'
            f'<span class="tl-day-count">{len(evs)} events</span>{marker}</summary>'
            f'<div class="tl-rows">{rows}</div>'
            "</details>"
        )

    headline = escape(str(model.headline or "Forensic Timeline"))
    case_id = escape(str(model.case_id or ""))

    return f"""<div class="tl-root">
<style>
{_font_face_css()}
.tl-root {{
  --ink:#101426; --nearblack:#12131A; --line:#262c46;
  --cream:#F5F1E8; --lilac:#B8A8FF; --cobalt:#4D5DFF; --seafoam:#73D9C2;
  --coral:{_CORAL}; --butter:#FFD76A;
  --display:'Archivo Narrow','Arial Narrow',sans-serif;
  --label:'Archivo',system-ui,sans-serif;
  --body:'Inter',system-ui,sans-serif;
  --mono:'JetBrains Mono','Courier New',monospace;
  --hand:'Caveat',cursive;
  margin:0;background:var(--ink);color:var(--cream);font-family:var(--body);
  -webkit-font-smoothing:antialiased;line-height:1.5;
}}
.tl-root *{{box-sizing:border-box}}
.tl-wrap{{max-width:920px;margin:0 auto;padding:clamp(24px,4vw,56px) clamp(16px,4vw,44px) 80px}}
.tl-kicker{{font-family:var(--label);font-weight:600;text-transform:uppercase;
  letter-spacing:.28em;font-size:11px;color:var(--lilac);margin:0 0 14px}}
.tl-masthead{{display:flex;flex-wrap:wrap;align-items:flex-end;gap:14px 20px}}
.tl-headline{{font-family:var(--display);font-weight:700;font-size:clamp(30px,5.5vw,58px);
  line-height:.98;letter-spacing:-.01em;margin:0;text-transform:none;max-width:16ch}}
.tl-verdict{{font-family:var(--display);font-weight:700;font-size:15px;letter-spacing:.14em;
  color:var(--ink);background:var(--coral);padding:8px 15px;border-radius:3px}}
.tl-sub{{font-family:var(--mono);font-size:12px;color:var(--lilac);margin:18px 0 4px;
  display:flex;flex-wrap:wrap;gap:6px 20px}}
.tl-sub b{{color:var(--cream);font-weight:600}}
.tl-voice{{font-family:var(--hand);font-size:26px;color:var(--seafoam);margin:6px 0 26px;transform:rotate(-1.2deg)}}
.tl-hist-wrap{{background:var(--nearblack);border:1px solid var(--line);border-radius:12px;
  padding:16px 18px 8px;margin:0 0 20px;position:relative}}
.tl-hist-head{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px;
  flex-wrap:wrap;gap:6px}}
.tl-hist-title{{font-family:var(--label);font-weight:600;text-transform:uppercase;
  letter-spacing:.16em;font-size:10px;color:var(--lilac)}}
.tl-brush-info{{font-family:var(--mono);font-size:11px;color:var(--seafoam)}}
.tl-brush-info button{{font-family:var(--mono);font-size:10px;color:var(--ink);
  background:var(--seafoam);border:0;border-radius:4px;padding:2px 7px;margin-left:8px;cursor:pointer}}
svg.tl-hist{{display:block;width:100%;height:auto;overflow:visible;cursor:crosshair;user-select:none}}
.tl-axis-lbl{{font-family:var(--mono);font-size:9px;fill:#6b7196}}
.tl-brush-rect{{fill:rgba(115,217,194,0.14);stroke:var(--seafoam);stroke-width:1;pointer-events:none}}
svg.tl-hist rect[data-b]{{transition:opacity .12s}}
.tl-facets{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 22px}}
.tl-chip{{font-family:var(--mono);font-size:11px;color:var(--cream);background:var(--nearblack);
  border:1px solid var(--line);border-radius:20px;padding:4px 11px;cursor:pointer;
  display:inline-flex;align-items:center;gap:6px;user-select:none}}
.tl-chip .tl-sw{{width:9px;height:9px;border-radius:50%}}
.tl-chip.off{{opacity:.38}}
.tl-filter{{flex:1;min-width:180px;font-family:var(--mono);font-size:12px;color:var(--cream);
  background:var(--nearblack);border:1px solid var(--line);border-radius:8px;padding:7px 12px}}
.tl-filter::placeholder{{color:#6b7196}}
.tl-day{{position:relative;margin:0 0 8px}}
.tl-day>summary{{list-style:none;cursor:pointer}}
.tl-day>summary::-webkit-details-marker{{display:none}}
.tl-day-head{{position:sticky;top:0;z-index:3;display:flex;align-items:baseline;gap:14px;
  background:linear-gradient(var(--ink) 72%,transparent);padding:16px 0 10px}}
.tl-fold{{font-family:var(--mono);font-size:10px;color:#6b7196;letter-spacing:.04em}}
.tl-day[open]>summary .tl-fold{{opacity:0}}
.tl-day-head h2{{font-family:var(--display);font-weight:700;font-size:clamp(20px,3vw,30px);
  letter-spacing:.02em;margin:0;color:var(--cream)}}
.tl-day-count{{font-family:var(--mono);font-size:11px;color:var(--lilac);
  border:1px solid var(--line);border-radius:20px;padding:2px 10px}}
.tl-context .tl-day-head h2{{color:#8087ac}}
.tl-context{{opacity:.62}}
.tl-rows{{position:relative;margin-left:78px;border-left:2px solid var(--line);padding:2px 0}}
.tl-row{{position:relative;display:grid;grid-template-columns:1fr;gap:0;padding:7px 0 7px 26px}}
.tl-time{{position:absolute;left:-104px;top:9px;width:74px;text-align:right;
  font-family:var(--mono);font-size:11px;color:var(--lilac);font-variant-numeric:tabular-nums}}
.tl-dot{{position:absolute;left:-7px;top:12px;width:12px;height:12px;border-radius:50%;
  background:var(--dot);box-shadow:0 0 0 4px var(--ink)}}
.tl-card{{min-width:0}}
.tl-summary{{font-family:var(--body);font-size:14px;color:var(--cream);word-break:break-word}}
.tl-meta{{margin-top:4px;font-family:var(--mono);font-size:11px;color:#7e84a8;
  display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px}}
.tl-tech{{font-family:var(--mono);font-size:10px;color:var(--cobalt);
  border:1px solid var(--cobalt);border-radius:4px;padding:1px 6px}}
.tl-host{{color:var(--seafoam)}}
.tl-ref{{color:#5f6690}}
.tl-legend{{display:flex;gap:16px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;
  color:var(--lilac);margin:0 0 12px}}
.tl-legend span{{display:inline-flex;align-items:center;gap:7px}}
.tl-sw{{width:11px;height:11px;border-radius:50%}}
.tl-hidden{{display:none}}
.tl-empty{{padding:2rem;font-family:var(--body,system-ui,sans-serif);opacity:.75}}
@media (max-width:640px){{
  .tl-rows{{margin-left:8px}}
  .tl-time{{position:static;text-align:left;width:auto;display:block;margin-bottom:2px}}
  .tl-row{{padding-left:22px}}
}}
</style>
<div class="tl-wrap">
  <p class="tl-kicker">VERDICT DFIR &middot; Forensic Timeline</p>
  <div class="tl-masthead">
    <h1 class="tl-headline">{headline}</h1>
  </div>
  <div class="tl-sub">
    <span>case <b>{case_id}</b></span>
    <span>events <b>{len(real)}</b></span>
    <span>span <b>{escape(span)}</b></span>
    <span>confirmed <b>{n_confirmed}</b> &middot; inferred <b>{n_inferred}</b> &middot; hypothesis <b>{n_hypothesis}</b></span>
    <span>presentation only</span>
  </div>
  <p class="tl-voice">Trace it. Test it. Trust it.</p>
  <div class="tl-legend">
    <span><i class="tl-sw" style="background:var(--seafoam)"></i>Confirmed</span>
    <span><i class="tl-sw" style="background:var(--butter)"></i>Inferred</span>
    <span><i class="tl-sw" style="background:var(--cobalt)"></i>Hypothesis</span>
  </div>
  <div class="tl-hist-wrap">
    <div class="tl-hist-head">
      <span class="tl-hist-title">Activity density &middot; drag to focus a window</span>
      <span class="tl-brush-info" id="tl-brush-info"></span>
    </div>
    <svg class="tl-hist" id="tl-hist" viewBox="0 -6 {_HIST_WIDTH} {_HIST_HEIGHT + 22}" preserveAspectRatio="none">
      {hist_ticks}
      <g id="tl-bars">{hist_bars}</g>
      <rect id="tl-brush" class="tl-brush-rect" x="0" y="0" width="0" height="{_HIST_HEIGHT}" style="display:none"/>
    </svg>
  </div>
  <div class="tl-facets">
    <span class="tl-chip" data-facet="tier" data-val="CONFIRMED"><i class="tl-sw" style="background:var(--seafoam)"></i>Confirmed</span>
    <span class="tl-chip" data-facet="tier" data-val="INFERRED"><i class="tl-sw" style="background:var(--butter)"></i>Inferred</span>
    <span class="tl-chip" data-facet="tier" data-val="HYPOTHESIS"><i class="tl-sw" style="background:var(--cobalt)"></i>Hypothesis</span>
    <span class="tl-chip" data-facet="sig" data-val="finding_support">finding support</span>
    <span class="tl-chip" data-facet="sig" data-val="context">context</span>
    <input class="tl-filter" id="tl-filter" type="text" placeholder="filter events (summary / T-code / ref)" aria-label="filter events"/>
  </div>
  {"".join(sections)}
  <div class="tl-empty tl-hidden" id="tl-empty">No events match the current filters.</div>
</div>
<script>
(function(){{
  var root = document.currentScript.closest('.tl-root');
  if (!root) return;
  var LO = {lo_ms}, HI = {hi_ms}, HW = {_HIST_WIDTH}, NB = {_HIST_BUCKETS};
  var rows = [].slice.call(root.querySelectorAll('.tl-row'));
  var days = [].slice.call(root.querySelectorAll('.tl-day'));
  var chips = [].slice.call(root.querySelectorAll('.tl-chip'));
  var filter = root.querySelector('#tl-filter');
  var bars = [].slice.call(root.querySelectorAll('#tl-bars rect'));
  var hist = root.querySelector('#tl-hist');
  var brush = root.querySelector('#tl-brush');
  var info = root.querySelector('#tl-brush-info');
  var empty = root.querySelector('#tl-empty');
  var offTiers = {{}}, offSigs = {{}}, range = null;

  function apply(){{
    var q = (filter && filter.value ? filter.value : '').trim().toLowerCase();
    var shown = 0;
    rows.forEach(function(r){{
      var msAttr = r.getAttribute('data-ms');
      var ms = msAttr ? +msAttr : null;
      var tier = r.getAttribute('data-tier');
      var sig = r.getAttribute('data-sig');
      var ok = (!q || (r.getAttribute('data-search') || '').indexOf(q) >= 0)
        && !offTiers[tier]
        && !(sig && offSigs[sig])
        && (!range || (ms !== null && ms >= range[0] && ms <= range[1]));
      r.classList.toggle('tl-hidden', !ok);
      if (ok) shown++;
    }});
    days.forEach(function(d){{
      var any = d.querySelector('.tl-row:not(.tl-hidden)');
      d.classList.toggle('tl-hidden', !any);
      var filtering = q || range || Object.keys(offTiers).length || Object.keys(offSigs).length;
      if (any && filtering) d.open = true;
      else if (!filtering && d.getAttribute('data-kind') === 'context') d.open = false;
    }});
    bars.forEach(function(b){{
      if (!range) {{ b.style.opacity = 1; return; }}
      var i = +b.getAttribute('data-b');
      var t0 = LO + (HI - LO) * i / NB, t1 = LO + (HI - LO) * (i + 1) / NB;
      b.style.opacity = (t1 >= range[0] && t0 <= range[1]) ? 1 : 0.2;
    }});
    if (empty) empty.classList.toggle('tl-hidden', shown > 0);
  }}

  chips.forEach(function(c){{
    c.addEventListener('click', function(){{
      var f = c.getAttribute('data-facet'), v = c.getAttribute('data-val');
      var m = (f === 'tier') ? offTiers : offSigs;
      if (m[v]) {{ delete m[v]; c.classList.remove('off'); }}
      else {{ m[v] = 1; c.classList.add('off'); }}
      apply();
    }});
  }});
  if (filter) filter.addEventListener('input', apply);

  if (hist && brush) {{
    var dragging = false, x0 = 0;
    function pxToVB(clientX){{
      var r = hist.getBoundingClientRect();
      return Math.max(0, Math.min(HW, (clientX - r.left) / r.width * HW));
    }}
    function vbToMs(x){{ return LO + (HI - LO) * x / HW; }}
    function setBrush(a, b){{
      var lo = Math.min(a, b), hi = Math.max(a, b);
      if (hi - lo < 3) {{
        brush.style.display = 'none'; range = null;
        if (info) info.textContent = '';
        apply();
        return;
      }}
      brush.style.display = '';
      brush.setAttribute('x', lo);
      brush.setAttribute('width', hi - lo);
      range = [vbToMs(lo), vbToMs(hi)];
      if (info) {{
        var d0 = new Date(range[0]).toISOString().slice(0, 10);
        var d1 = new Date(range[1]).toISOString().slice(0, 10);
        info.innerHTML = d0 + ' \\u2192 ' + d1 + ' <button id="tl-brush-clear">clear</button>';
        var clearBtn = root.querySelector('#tl-brush-clear');
        if (clearBtn) {{
          clearBtn.addEventListener('click', function(ev){{
            ev.stopPropagation();
            brush.style.display = 'none';
            range = null;
            info.textContent = '';
            apply();
          }});
        }}
      }}
      apply();
    }}
    hist.addEventListener('mousedown', function(e){{
      dragging = true; x0 = pxToVB(e.clientX); setBrush(x0, x0);
    }});
    window.addEventListener('mousemove', function(e){{
      if (dragging) setBrush(x0, pxToVB(e.clientX));
    }});
    window.addEventListener('mouseup', function(){{ dragging = false; }});
  }}
}})();
</script>
</div>"""
